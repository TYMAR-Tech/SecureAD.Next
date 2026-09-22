using System.Globalization;
using System.Resources;
using SecureAD.Audit.Connect;
using SecureAD.Audit.Sysvol;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Naming;

namespace SecureAD.Audit.Capture;

/// <summary>
/// How long one domain took to read, and whether it was read from nearby.
/// </summary>
/// <remarks>
/// <para>
/// <b>Neither value is persisted anywhere, which is the only reason this type exists.</b> The
/// bundle records what a domain held and what became of reading it; how long that took, and
/// whether the controller answering was in the capture machine's own site, are known while the run
/// is happening and nowhere afterwards. Recording them in the evidence would bump its format for a
/// diagnostic field, so the run hands them to whoever wants them instead.
/// </para>
/// <para>
/// The site relationship is not settled here - it is <c>DomainPreflight.ControllerIsInOperatorSite</c>,
/// established before any object was read - so this carries only the timing and the naming context
/// the two are joined by.
/// </para>
/// </remarks>
/// <param name="NamingContext">The domain partition, which is how a caller joins this to anything else.</param>
/// <param name="ElapsedMilliseconds">
/// How long the whole domain took, failover attempts included. A domain read twice because its
/// first controller failed cost both attempts, and that is what an operator asking why the run was
/// long is asking about.
/// </param>
public readonly record struct DomainReadTiming(string NamingContext, long ElapsedMilliseconds);

/// <summary>
/// What a run produces: the outcome, and where the evidence went.
/// </summary>
/// <param name="Outcome">How the run ended.</param>
/// <param name="BundleDirectory">The directory the run wrote into, whatever became of it.</param>
/// <param name="Error">Why it ended badly, or null where it did not.</param>
public sealed record CaptureRunResult(
    RunCompletion Outcome, string BundleDirectory, AuditError? Error)
{
    /// <summary>Whether there is a sealed bundle at <see cref="BundleDirectory"/>.</summary>
    public bool ProducedABundle => Outcome == RunCompletion.Sealed;

    /// <summary>
    /// How long each domain took, in plan order. Empty for a run that ended before the domains
    /// were read, which is not a claim that they took no time.
    /// </summary>
    /// <remarks>
    /// <b>Internal, and an <c>init</c> property rather than a fourth positional value.</b> The one
    /// caller is <c>CaptureSession</c>, which writes the run's portable summary; handing a bare
    /// list outside the assembly would be a collection that cannot say whether it was measured,
    /// which is gate 4. Positional would mean a run that ended badly - several exits, none with
    /// timings to give - supplying an empty list at each, and an empty list that was never filled
    /// reads as a measurement.
    /// </remarks>
    internal IReadOnlyList<DomainReadTiming> DomainTimings { get; init; } = [];
}

/// <summary>
/// How a run ended.
/// </summary>
/// <remarks>
/// Two endings and no third. There is no partially successful run, because
/// <c>docs/decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md</c> refuses an incomplete
/// capture and a bundle that is not sealed is not evidence.
/// </remarks>
public enum RunCompletion
{
    /// <summary>Every planned partition was read and the bundle was sealed.</summary>
    Sealed,

    /// <summary>The run stopped, and said so in the outcome file.</summary>
    Ended,
}

/// <summary>
/// Reads a forest into a bundle: inventory row B20's run driver.
/// </summary>
/// <remarks>
/// <para>
/// This is the thing three rows in a row were forecast to be and were not. Connect opens a
/// connection, capture reads a partition, the schema stores an object and run identity names a
/// run - and until this existed no two of them were joined, so the product had never run end to
/// end.
/// </para>
/// <para>
/// <b>It is fail-fast, and that is the whole of its error handling.</b> A partition that cannot be
/// read fully produces no bundle at all, per
/// <c>docs/decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md</c>. There is no attempt to
/// carry on with the partitions that did work, because a bundle missing a partition is a bundle
/// whose every silence means something different, and nothing downstream could tell.
/// </para>
/// <para>
/// <b>A run that ends badly says so.</b> On any failure the partial evidence file is left where it
/// is and <c>run-outcome.json</c> is written beside it, per
/// <c>docs/decisions/0029-a-run-that-ends-badly-says-so.md</c>. The evidence is never given the
/// name a reader asks for, so there is nothing a later run or a reader can mistake for a finished
/// bundle - and the outcome file is what stops a dead run being indistinguishable from a live one.
/// </para>
/// <para>
/// <b>Order is the plan's, not this class's.</b> <c>CapturePlan</c> puts configuration and schema
/// first because everything else is interpreted against them, and this walks the units as given.
/// </para>
/// </remarks>
public sealed class CaptureRun
{
    private static readonly ResourceManager Wording = new(
        "SecureAD.Audit.Resources.CaptureFailures", typeof(CaptureRun).Assembly);

    private readonly IDirectoryChannelFactory _connections;
    private readonly ISysvolFileReader _sysvolFiles;
    private readonly TimeProvider _time;
    private readonly IRunLog _log;
    private readonly int _domainsAtOnce;

    /// <summary>
    /// Creates a run driver.
    /// </summary>
    /// <remarks>
    /// <b>It takes the connection factory rather than a capture loop.</b> A capture loop is
    /// constructed with the sink it hands objects to, and the sink writes into a bundle that does
    /// not exist until a run starts - so a run handed a ready-made loop could not put its own
    /// bundle behind it. The first draft of this class did exactly that, and the sink it built was
    /// silently ignored.
    /// </remarks>
    /// <param name="connections">How a connection to a unit's controller is opened.</param>
    /// <param name="sysvolFiles">
    /// How the SYSVOL share is read. Required rather than optional, per gate 1: a collaborator that
    /// may be omitted is a collaborator that ends up omitted, and a run with no SYSVOL reader would
    /// seal a bundle reporting that no policy was examined without anyone having decided that.
    /// </param>
    /// <param name="time">The clock the run's start, finish and object times are read from.</param>
    /// <param name="log">
    /// Where each partition's start and finish is written down. Required for the same reason as the
    /// SYSVOL reader: this loop is the only thing that knows when one domain ended and the next
    /// began, and a capture that ran for hours and stopped leaves nothing else to read.
    /// </param>
    /// <param name="domainsAtOnce">
    /// How many domains this machine may read at the same time, per
    /// <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c>. Stated rather than
    /// defaulted, because a run driver that could be built without it is one that would be, and
    /// the setting would go on reading as plumbed and consumed by nothing.
    /// <see cref="DirectoryConnectionSettings.DefaultDomainsAtOnce"/> is what an ordinary run
    /// passes.
    /// </param>
    public CaptureRun(
        IDirectoryChannelFactory connections,
        ISysvolFileReader sysvolFiles,
        TimeProvider time,
        IRunLog log,
        int domainsAtOnce)
    {
        ArgumentNullException.ThrowIfNull(connections);
        ArgumentNullException.ThrowIfNull(sysvolFiles);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(log);

        // Zero waits forever while looking exactly like a capture that is working, which is the
        // reason DirectoryConnectionSettings refuses it at construction too. Refused twice because
        // a run driver reached by any other route would have no other wall.
        ArgumentOutOfRangeException.ThrowIfLessThan(domainsAtOnce, 1);

        _connections = connections;
        _sysvolFiles = sysvolFiles;
        _time = time;
        _log = log;
        _domainsAtOnce = domainsAtOnce;
    }

    /// <summary>
    /// Reads every partition the plan names into a bundle, and seals it.
    /// </summary>
    /// <remarks>
    /// The bundle directory is supplied rather than chosen, per
    /// <c>docs/decisions/0039-one-way-to-start-a-capture.md</c>. What creates it is
    /// <see cref="RunLibrary"/>, so that every run lands inside the root the operator configured.
    /// </remarks>
    /// <param name="plan">The units to read, in the order they are to be read.</param>
    /// <param name="bundleDirectory">The run's own directory, already created.</param>
    /// <param name="exclusions">
    /// What an operator stated for each domain the run leaves out, keyed by naming context. Empty
    /// for a run that leaves nothing out. A plan that does not cover every declared domain is only
    /// allowed to proceed where every missing domain appears here, per
    /// <c>docs/decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md</c>.
    /// </param>
    /// <param name="cancellationToken">Cancellation for a capture an operator stopped.</param>
    public async Task<CaptureRunResult> RunAsync(
        CapturePlan plan,
        string bundleDirectory,
        IReadOnlyDictionary<string, AttestedExclusion> exclusions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(exclusions);

        // The denominator, recorded before anything is read. A run that worked out afterwards how
        // much of the forest it had covered would be measuring against whatever it managed to
        // reach, which is the arithmetic that made F-S28-1 invisible.
        //
        // The excluded set goes into the identity beside it, per 0052. Without it two runs of one
        // forest leaving out DIFFERENT domains hash alike, and the product offers them as like for
        // like - so the difference between two domains nobody read reads as drift in the directory.
        // The DNS name is taken from the attestation, which carries it for exactly this reason;
        // deriving it from the naming context here is the string surgery AttestedExclusion refuses.
        var declared = CoverageId.ForDomainsExcluding(
            plan.ForestFqdn,
            plan.DeclaredDomains,
            exclusions.Values.Select(e => e.DomainFqdn));

        // A plan that leaves a declared domain unread is allowed only where somebody has put a name
        // to every one of them. Before 0062 had a surface this was refused outright; what has
        // changed is that an attestation now exists, not that an unread domain has become
        // acceptable. A shortfall larger than the attestations still produces no bundle, because
        // that is a sealed bundle silently covering part of a forest.
        //
        // COUNTED, NOT MATCHED BY NAME, and deliberately - for the reason CapturePlan.IsComplete
        // gives. A declaration is a DNS name and a unit is a naming context, and pairing them here
        // would mean this type deciding that one can be derived from the other. That holds only
        // while controllers are reached through dnsRoot and would break silently the day a
        // configuration file pins real controllers. The caller keys its attestations by naming
        // context, which is where that fact is actually known.
        var planned = plan.Units.Count(u => u.Kind == NamingContextKind.Domain);
        var unread = plan.DeclaredDomains.Count - planned;

        if (unread > exclusions.Count)
        {
            return End(
                bundleDirectory,
                RunOutcome.Failed,
                $"The forest declared {plan.DeclaredDomains.Count} domains and the plan reads "
                + $"{planned}. {unread - exclusions.Count} of the rest are left out with no "
                + "attestation against them. A capture that leaves a declared domain unread and "
                + "unaccounted for produces no bundle, per "
                + "docs/decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md - a sealed "
                + "bundle covering part of a forest is evidence a customer would act on.",
                error: null);
        }

        var startedUtc = _time.GetUtcNow();

        using var writer = BundleWriter.Create(bundleDirectory, startedUtc);

        var sink = new BundleCaptureSink(writer, _time);
        var capture = new PartitionCapture(_connections, sink, _time, _log, plan.ObjectScope);

        // Written before the first read, because it is a fact about the plan rather than about
        // anything a pass discovered. These are the partitions the forest declares and this product
        // does not read - the DNS zone partitions, under the DNS scope decision of 2026-08-11. The
        // run also prints them, and a console that has scrolled away is not evidence. F-S31-5.
        foreach (var partition in plan.NotRead)
        {
            writer.RecordUnreadPartition(partition);
        }

        // Written before the first read, for the same reason: it is a fact about the plan, and a
        // run that dies at hour two must still leave behind who said this domain could be left out
        // and why. 0062.
        foreach (var exclusion in exclusions.Values)
        {
            writer.RecordExcludedDomain(exclusion);
        }

        var recorded = new List<PartitionCoverage>();

        // THE PLAN IS READ IN TWO PASSES, and the split is 0041's. The forest-wide partitions -
        // configuration and schema - come first and finish before any domain starts, because the
        // schema partition says what the attributes a domain's objects carry actually mean. A
        // domain read beside the schema rather than after it would be interpreted against whatever
        // had arrived so far.
        //
        // CapturePlan already orders them first and tags each unit with its Kind, so this is a
        // partition at the point of use rather than a change to the plan.
        var prologue = plan.Units.Where(u => u.Kind != NamingContextKind.Domain).ToList();
        var domains = plan.Units.Where(u => u.Kind == NamingContextKind.Domain).ToList();

        foreach (var unit in prologue)
        {
            var outcome = await ReadOneUnitAsync(
                capture, unit, plan, cancellationToken, CancellationToken.None)
                .ConfigureAwait(false);

            if (outcome.Ending is { } ended)
                return End(bundleDirectory, ended);

            recorded.Add(outcome.Coverage!);
        }

        // THE DOMAINS ARE READ TOGETHER, which is what 0041 is for and what the prologue above
        // exists to have finished first. A forest of nine domains costs roughly its largest domain
        // rather than the sum of all nine.
        //
        // THE CEILING IS ON THIS MACHINE, NOT ON THE DIRECTORY. Every domain in flight holds a
        // connection and writes its own database, so what binds is this laptop's disk rather than
        // anything a controller experiences - see DirectoryConnectionSettings.DefaultDomainsAtOnce.
        // It is never raised above the number of domains there are, because a ceiling of nine over
        // three domains is a number that reads as a promise the run cannot keep.
        //
        // NEVER TWO REQUESTS AT ONE CONTROLLER. Each domain takes that controller's turn from the
        // dispatcher before it reads. Two domains on one machine is not something Active Directory
        // produces, but ControllerSelection has no rule against it, and a concurrency that is safe
        // because the directory happens to be shaped a certain way is the defect this arrangement
        // exists to avoid.
        var shards = new List<DomainShard>(domains.Count);
        for (var at = 0; at < domains.Count; at++)
        {
            // Shard zero is the bundle itself, which the prologue has just been written into, so
            // the domains start at one. That is also why an unsharded run stays byte-for-byte what
            // the product wrote before shards existed: nothing else numbers from 1.
            shards.Add(new DomainShard(domains[at], BundleShard.Number(at + 1)));
        }

        var atOnce = Math.Min(_domainsAtOnce, Math.Max(domains.Count, 1));

        _log.Note(
            PartitionCapture.PhaseName,
            "reading the domains",
            [
                new RunLogDetail("domains", domains.Count.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("atOnce", atOnce.ToString(CultureInfo.InvariantCulture)),
            ]);

        using var failedDomainCancellation = new CancellationTokenSource();
        using var domainCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, failedDomainCancellation.Token);
        RunEnding? terminalFailure = null;
        DomainRead[] readDomains;

        try
        {
            readDomains = await DirectoryWorkDispatch.TogetherAsync(
                shards,
                atOnce,
                async (shard, turns) =>
                {
                    var read = await ReadOneDomainAsync(
                        bundleDirectory, startedUtc, shard, plan, turns,
                        domainCancellation.Token, failedDomainCancellation.Token)
                        .ConfigureAwait(false);

                    // Recovery is exhausted only when the whole domain read returns. Remember
                    // its cause before signalling siblings: their cancellation is not the reason
                    // the run failed, even if they precede this domain in the plan (P-215).
                    if (read.Ending is { Outcome: RunOutcome.Failed } ending
                        && Interlocked.CompareExchange(ref terminalFailure, ending, null) is null)
                        await failedDomainCancellation.CancelAsync().ConfigureAwait(false);

                    return read;
                },
                domainCancellation.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (terminalFailure is not null)
        {
            // TogetherAsync has awaited every admitted task, including its writer disposal.
            // A cancelled queue slot supplies no DomainRead, but must not erase the real cause.
            return End(bundleDirectory, terminalFailure);
        }

        if (terminalFailure is not null)
            return End(bundleDirectory, terminalFailure);

        // EVERY OUTCOME IS EXAMINED BEFORE ANYTHING IS MERGED. A terminal domain failure has
        // already stopped the run; any remaining ending here is an operator cancellation.
        //
        // A FAILED DOMAIN'S SHARD IS SIMPLY NOT MERGED, which is the whole of how 0003 survives the
        // fan-out. The run ends and no bundle is sealed; the shards that did finish are left on
        // disk beside the partial file, because deleting the record of how far a run got is a
        // decision for the run library rather than for the code that has just failed.
        foreach (var domain in readDomains)
        {
            if (domain.Ending is { } ended)
                return End(bundleDirectory, ended);
        }

        foreach (var domain in readDomains)
        {
            foreach (var failure in domain.Failures)
                writer.RecordDomainCaptureFailure(failure);
        }

        // MERGED IN PLAN ORDER, one at a time, into the writer already holding the prologue.
        // TogetherAsync answers in the order it was handed its subjects rather than the order they
        // arrived, so this is the plan's order and not the forest's timing - two runs of one forest
        // assemble their bundles the same way round.
        foreach (var domain in readDomains)
        {
            var shardPath = BundleLayout.ShardPath(bundleDirectory, domain.Shard.Shard);
            var mergeStartedUtc = _time.GetUtcNow();

            var merged = writer.Absorb(shardPath, domain.Shard.Shard);

            // Deleted as soon as its rows are in the bundle. A shard is scaffolding rather than
            // evidence - never sealed, never given the name a reader asks for - and nine of them
            // left behind would roughly double what a capture costs on disk at the moment the
            // bundle is at its largest.
            File.Delete(shardPath);

            // THE TWO THINGS THE SHARD DATABASE DOES NOT CARRY. The policy inventory and the
            // unreadable-descriptor tally are accumulated in memory by each domain's own sink, so
            // without this the SYSVOL pass below would run against the prologue's inventory alone
            // and report full coverage of a denominator missing every domain's policies.
            sink.Absorb(domain.Sink!);

            recorded.Add(domain.Coverage!);

            _log.Note(
                PartitionCapture.PhaseName,
                "domain merged into the bundle",
                [
                    new RunLogDetail("namingContext", domain.Shard.Unit.NamingContext),
                    new RunLogDetail(
                        "shard", domain.Shard.Shard.Index.ToString(CultureInfo.InvariantCulture)),
                    new RunLogDetail("trustees", Count(merged.Trustees)),
                    new RunLogDetail(
                        "trusteesAlreadyPresent", Count(merged.TrusteesAlreadyPresent)),
                    new RunLogDetail("descriptors", Count(merged.Descriptors)),
                    new RunLogDetail(
                        "descriptorsAlreadyPresent", Count(merged.DescriptorsAlreadyPresent)),
                    new RunLogDetail(
                        "accessControlEntries", Count(merged.AccessControlEntries)),
                    Elapsed(mergeStartedUtc),
                ]);
        }

        var reconciled = ContinuationReferenceReconciliation.Reconcile(
            plan.Units,
            recorded.SelectMany(coverage => coverage.ContinuationReferences),
            recorded
                .Where(coverage => coverage.ReferralsSuppressed)
                .Select(coverage => plan.Units.Single(unit =>
                    string.Equals(
                        unit.NamingContext,
                        coverage.NamingContextDn,
                        StringComparison.OrdinalIgnoreCase))));

        if (reconciled.IsComplete && reconciled.Unplanned.Count > 0)
        {
            return End(
                bundleDirectory,
                RunOutcome.Failed,
                "The directory referred this run to naming context(s) absent from its authorized "
                + $"capture plan: {string.Join(", ", reconciled.Unplanned)}. No bundle was sealed. "
                + "Run discovery and capture again so the new scope is either captured or "
                + "explicitly accounted for.",
                AuditError.Create(
                    ErrorCategory.Capture,
                    "UnplannedNamingContext",
                    ErrorSeverity.Failed,
                    "A complete continuation-reference reconciliation found directory scope "
                    + "absent from the authorized capture plan.",
                    string.Join(", ", reconciled.Unplanned)));
        }

        var reconciliation = new ContinuationReconciliation(
            reconciled.IsComplete
                ? ContinuationReconciliationOutcome.Complete
                : ContinuationReconciliationOutcome.Incomplete,
            reconciled.Unplanned,
            reconciled.UnreadableReferences,
            reconciled.UnitsWithSuppressedReferrals
                .Select(unit => unit.NamingContext)
                .ToList());

        // SYSVOL is read after the directory and before the seal, and it is the one read in this
        // method that does not end the run when it fails. Per docs/decisions/0044 a policy folder
        // that could not be opened is recorded and the bundle is still sealed - because SYSVOL is a
        // file share, permission problems on it are ordinary, and a run that died over one folder
        // out of four hundred would be unusable in the field. What stops that becoming a silence is
        // the coverage record, which names every policy that was missed.
        //
        // TIMED AND LOGGED, because until 2026-09-13 the log jumped from the last partition
        // straight to "finished" and this was inside the gap. A share that answers slowly looks
        // exactly like a capture that has hung, and an operator had nothing to tell them apart.
        var sysvolStartedUtc = _time.GetUtcNow();
        var declaredPolicies = sink.Policies.Policies.Count
            .ToString(CultureInfo.InvariantCulture);

        _log.Note(
            PartitionCapture.PhaseName,
            "reading the policy share",
            [new RunLogDetail("policies", declaredPolicies)]);

        var sysvol = await new SysvolCapture(_sysvolFiles, writer, _log, _time)
            .ReadAsync(sink.Policies, cancellationToken)
            .ConfigureAwait(false);

        _log.Note(
            PartitionCapture.PhaseName,
            "policy share read",
            [
                new RunLogDetail("policies", declaredPolicies),
                Elapsed(sysvolStartedUtc),
            ]);

        _log.Note(PartitionCapture.PhaseName, "sealing the bundle", []);

        // The seal, the checkpoint and the rename happen here, and only here. Until Complete
        // returns there is no file by the name a reader opens.
        //
        // The coverage handed to the bundle is derived from the rows capture actually recorded, not
        // from the plan's declaration. Asserting plan.DeclaredDomains.Select(DomainCoverage.Read)
        // made every declared domain report as read because it had been declared, which is the
        // statement RunCoverage.Of's guard exists to refuse - and while the assertion held, that
        // guard could not fire. Deriving costs a projection and makes the check real. F-S29-3, D3.
        var coverage = RunCoverage.Of(
            declared,
            recorded
                .Where(c => c.Kind == NamingContextKind.Domain)
                .Select(c => DomainCoverage.Read(DnHelper.DnToFqdn(c.NamingContextDn)))
                // Every declared domain needs an outcome, and an excluded one was never read,
                // so nothing above reports it. Without this the run throws at the seal - the
                // guard in RunCoverage.Of refusing a declared domain that no outcome accounts
                // for, which is exactly its job.
                //
                // The cause is carried into the outcome rather than left to the reason text,
                // per docs/decisions/0063-excluded-never-looks-like-unreachable.md: a reader of
                // coverage tells a domain the operator left out from one nothing could reach
                // without going back to another table.
                .Concat(exclusions.Values.Select(e => DomainCoverage.Excluded(
                    e.DomainFqdn,
                    e.Kind,
                    $"Left out of this run under an attestation ({e.Reason}), authorised by "
                    + $"{e.AuthorisedBy} and recorded against {e.RunBy}."))),
            recorded
                .Where(c => c.Kind != NamingContextKind.Domain)
                .Select(c => ForestPartitionCoverage.Read(c.NamingContextDn, c.Kind)),
            sysvol);

        BundleSealTimings sealing;
        try
        {
            sealing = writer.Complete(
                coverage, _time.GetUtcNow(), reconciliation, plan.ObjectScope, cancellationToken);
        }
        catch (OperationCanceledException cancellation) when (
            cancellationToken.IsCancellationRequested && cancellation.CancellationToken == cancellationToken)
        {
            return End(
                bundleDirectory,
                RunOutcome.Cancelled,
                Wording.GetString("StoppedWhileSealing", CultureInfo.CurrentUICulture)
                    ?? throw new InvalidOperationException("StoppedWhileSealing"),
                error: null);
        }

        // The five phases behind the one word "sealing". They are separated because they fail and
        // scale differently: the index build is three sorts of the entries table, the backfill is
        // two set-based passes over every object, and the seal is a hash of the whole file. A
        // capture that spent twenty minutes here should say which of them it was.
        _log.Note(PartitionCapture.PhaseName, "bundle sealed", SealDetail(sealing));

        // CARRIED OUT OF THE RUN BECAUSE NOTHING PERSISTS IT. The bundle says what each domain held
        // and what became of reading it; how long each took is known here and nowhere afterwards,
        // and recording it in the evidence would bump the evidence format for a diagnostic figure.
        return new CaptureRunResult(RunCompletion.Sealed, bundleDirectory, Error: null)
        {
            DomainTimings = [.. readDomains.Select(d => new DomainReadTiming(
                d.Shard.Unit.NamingContext, d.ElapsedMilliseconds))],
        };
    }

    /// <summary>
    /// Records how a run ended and leaves the evidence unpromoted.
    /// </summary>
    /// <remarks>
    /// Nothing is deleted. The partial file is a record of how far the run got, and the decision to
    /// delete a failed run belongs to the run library rather than to the thing that failed - which
    /// is inventory row F15, and is a decision an operator should be told about rather than have
    /// happen silently.
    /// </remarks>
    private static CaptureRunResult End(
        string bundleDirectory, RunOutcome outcome, string detail, AuditError? error)
    {
        RunOutcomeFile.Write(bundleDirectory, outcome, detail);

        return new CaptureRunResult(RunCompletion.Ended, bundleDirectory, error);
    }

    /// <summary>
    /// Writes down an ending a read described, at the one place entitled to write it.
    /// </summary>
    private static CaptureRunResult End(string bundleDirectory, RunEnding ending) =>
        End(bundleDirectory, ending.Outcome, ending.Detail, ending.Error);

    /// <summary>
    /// What became of reading one naming context: its coverage, or how the run has to end.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Both are carried so that a caller cannot forget to check.</b> The read either produced
    /// coverage or ended the run, never neither and never both, and a method returning only the
    /// coverage would need the caller to remember that a failure had happened. Under the fan-out,
    /// several of these come back at once and each has to be examined; an ending that could be
    /// dropped would be a domain that failed and a bundle that sealed anyway.
    /// </para>
    /// <para>
    /// <b>The ending is described here and written by <see cref="RunAsync"/>, which is not a
    /// tidiness.</b> It used to be written where it was discovered. Nine domains read at once
    /// means nine threads that can fail, and <c>run-outcome.json</c> is one file - so the account
    /// a customer reads would have been whichever thread wrote last. The coordinator writes once,
    /// preserving the terminal domain failure that triggered shutdown rather than a sibling's
    /// induced cancellation or later failure.
    /// </para>
    /// </remarks>
    private sealed record UnitOutcome(PartitionCoverage? Coverage, RunEnding? Ending);

    /// <summary>
    /// How a run has to end, before anything has been written down about it.
    /// </summary>
    /// <param name="Outcome">Whether the operator stopped it or it failed.</param>
    /// <param name="Detail">What to tell whoever opens the run directory.</param>
    /// <param name="Error">The error to log, or null where the ending is not one.</param>
    private sealed record RunEnding(RunOutcome Outcome, string Detail, AuditError? Error);

    /// <summary>
    /// One domain of the plan, paired with the database it will be read into.
    /// </summary>
    /// <remarks>
    /// The pairing is made before any reading starts, so which shard a domain owns is decided by
    /// its place in the plan rather than by the order the controllers happen to answer in. A shard
    /// handed out on arrival would give the same forest different identifiers every run, and the
    /// bundle's own numbering would stop being something two runs could be compared through.
    /// </remarks>
    private sealed record DomainShard(CaptureUnit Unit, BundleShard Shard);

    /// <summary>
    /// What reading one domain produced: its coverage and the sink that accumulated beside it, or
    /// how the run has to end.
    /// </summary>
    /// <remarks>
    /// <b>The sink comes back because two of the things it holds are not in the shard
    /// database.</b> The policy inventory and the unreadable-descriptor tally live in memory, and
    /// under the fan-out there is one of each per domain. They are folded into the run's own sink
    /// at the merge; see <see cref="BundleCaptureSink.Absorb"/> for why the inventory is the half
    /// that would produce a wrong answer rather than an error.
    /// </remarks>
    private sealed record DomainRead(
        DomainShard Shard,
        PartitionCoverage? Coverage,
        BundleCaptureSink? Sink,
        RunEnding? Ending)
    {
        public IReadOnlyList<DomainCaptureFailure> Failures { get; init; } = [];

        /// <summary>
        /// How long this domain took, failover attempts included.
        /// </summary>
        /// <remarks>
        /// Measured around the whole of <see cref="ReadOneDomainAsync"/> rather than around one
        /// attempt, because a domain whose first controller refused after ten minutes cost the run
        /// those ten minutes. Attributing only the attempt that worked would make a slow domain
        /// look fast and leave the difference in the unexplained remainder.
        /// </remarks>
        public long ElapsedMilliseconds { get; init; }
    }

    private async Task<DomainRead> ReadOneDomainAsync(
        string bundleDirectory,
        DateTimeOffset startedUtc,
        DomainShard domain,
        CapturePlan plan,
        DirectoryWorkDispatch turns,
        CancellationToken cancellationToken,
        CancellationToken failedDomainCancellationToken)
    {
        var domainStartedUtc = _time.GetUtcNow();
        var alternatives = plan.Failover.TryGetValue(domain.Unit.NamingContext, out var ranked)
            ? ranked : [];
        var controllers = new[] { domain.Unit.DomainController }.Concat(alternatives)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var failures = new List<DomainCaptureFailure>();
        DomainRead? firstFailure = null;

        long Spent() => (long)(_time.GetUtcNow() - domainStartedUtc).TotalMilliseconds;

        foreach (var controller in controllers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // 0040: a new pairing, never a channel substituted beneath an existing unit.
            var attempt = domain with { Unit = domain.Unit with { DomainController = controller } };
            var attemptStartedUtc = _time.GetUtcNow();
            var read = await ReadDomainAttemptAsync(
                bundleDirectory, startedUtc, attempt, plan, turns,
                cancellationToken, failedDomainCancellationToken)
                .ConfigureAwait(false);

            if (read.Ending is null)
                return read with { Failures = failures, ElapsedMilliseconds = Spent() };

            // ReadDomainAttemptAsync has disposed the writer, including its transaction and
            // connection. Only now may this domain's stable shard slot be reused; no other
            // domain can own it, and no failed attempt's database is opened as its replacement.
            File.Delete(BundleLayout.ShardPath(bundleDirectory, domain.Shard));

            if (read.Ending.Outcome == RunOutcome.Cancelled)
                return read with { ElapsedMilliseconds = Spent() };

            firstFailure ??= read;
            failures.Add(new DomainCaptureFailure(
                domain.Unit.NamingContext, controller, failures.Count + 1,
                attemptStartedUtc, _time.GetUtcNow(), read.Ending.Error!));
        }

        return firstFailure! with { Failures = failures, ElapsedMilliseconds = Spent() };
    }

    /// <summary>
    /// Reads one domain into a database of its own, on its controller's turn.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A writer, a sink and a capture pass each, and that is the point of the method.</b> All
    /// three were built once for the whole run before 0041's fan-out. <c>BundleWriter</c> is one
    /// SQLite connection inside one transaction and is not thread-safe; <c>BundleCaptureSink</c>
    /// refuses a second partition while one is open, by design. Sharing either between domains
    /// read at once would not be a race to find later - it would be immediate and loud.
    /// </para>
    /// <para>
    /// <b>The turn is taken around the whole read, not around each request.</b> A paged search
    /// keeps state on the controller between its pages out of one budget, so two paged reads at
    /// one machine can truncate each other silently; holding the turn for the duration is what
    /// makes that impossible rather than unlikely.
    /// </para>
    /// <para>
    /// <b>A failed attempt is disposed before its caller discards the shard under 0040.</b>
    /// It never reaches <c>CompleteShard</c> and cannot contribute coverage or policy inventory.
    /// </para>
    /// </remarks>
    /// <param name="bundleDirectory">The run's directory, which the shard is written inside.</param>
    /// <param name="startedUtc">When the run started.</param>
    /// <param name="domain">The domain and the shard it owns.</param>
    /// <param name="plan">The plan, for the progress line.</param>
    /// <param name="turns">Whose turn it is on each controller.</param>
    /// <param name="cancellationToken">Cancellation for an operator stop or terminal domain failure.</param>
    /// <param name="failedDomainCancellationToken">Distinguishes a domain failure from an operator stop.</param>
    private async Task<DomainRead> ReadDomainAttemptAsync(
        string bundleDirectory,
        DateTimeOffset startedUtc,
        DomainShard domain,
        CapturePlan plan,
        DirectoryWorkDispatch turns,
        CancellationToken cancellationToken,
        CancellationToken failedDomainCancellationToken)
    {
        using var writer = BundleWriter.Create(bundleDirectory, startedUtc, domain.Shard);

        var sink = new BundleCaptureSink(writer, _time);
        var capture = new PartitionCapture(_connections, sink, _time, _log, plan.ObjectScope);

        var outcome = await turns.OneAtATimeAsync(
            domain.Unit.DomainController,
            () => ReadOneUnitAsync(
                capture, domain.Unit, plan, cancellationToken, failedDomainCancellationToken),
            cancellationToken)
            .ConfigureAwait(false);

        if (outcome.Ending is { } ending)
            return new DomainRead(domain, null, null, ending);

        var finished = writer.CompleteShard();

        _log.Note(
            PartitionCapture.PhaseName,
            "domain written to its own database",
            [
                new RunLogDetail("namingContext", domain.Unit.NamingContext),
                new RunLogDetail(
                    "shard", domain.Shard.Index.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("commitSeconds", Seconds(finished.Commit)),
                new RunLogDetail("checkpointSeconds", Seconds(finished.Checkpoint)),
            ]);

        return new DomainRead(domain, outcome.Coverage, sink, null);
    }

    /// <summary>
    /// Reads one naming context, logging what it did.
    /// </summary>
    /// <remarks>
    /// Extracted from the loop it used to be the body of so that the prologue and the domains can
    /// be read differently without the reading itself differing. Two copies of this would be two
    /// accounts of what a partition read means, and the first sign of them disagreeing would be a
    /// bundle whose domains and whose configuration partition were recorded on different terms.
    /// </remarks>
    /// <param name="capture">The pass that does the reading, which holds the sink it writes to.</param>
    /// <param name="unit">Which naming context, on which controller.</param>
    /// <param name="plan">The plan, for the count in the progress line.</param>
    /// <param name="cancellationToken">Cancellation for an operator stop or terminal domain failure.</param>
    /// <param name="failedDomainCancellationToken">Distinguishes a domain failure from an operator stop.</param>
    private async Task<UnitOutcome> ReadOneUnitAsync(
        PartitionCapture capture,
        CaptureUnit unit,
        CapturePlan plan,
        CancellationToken cancellationToken,
        CancellationToken failedDomainCancellationToken)
    {
        Result<PartitionCoverage> read;

        // Written before the read rather than after it, and that is the whole point. A capture
        // that stops at hour two leaves a "started" line with a controller name and a clock
        // time on it, which is the difference between diagnosing the run and repeating it.
        var unitStartedUtc = _time.GetUtcNow();

        _log.Note(
            PartitionCapture.PhaseName,
            "reading a partition",
            [
                new RunLogDetail("namingContext", unit.NamingContext),
                new RunLogDetail("kind", unit.Kind.ToString()),
                new RunLogDetail("controller", unit.DomainController),

                // WHERE THIS UNIT SITS IN THE PLAN, not how many have finished. It was the latter
                // until the fan-out landed, which was a counter shared by every domain in flight -
                // so nine domains would have reported themselves as unit 3 of 12 together, and the
                // number an operator reads as "which one is this" would have been "how many were
                // done when I started". The plan's own order is fixed, so this is the same figure
                // it always was for a serial run and a true one for a parallel one.
                new RunLogDetail(
                    "unit",
                    $"{PositionInPlan(plan, unit)} of {plan.Units.Count}"),
            ]);

        try
        {
            read = await capture.ReadAsync(unit, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _log.Note(
                PartitionCapture.PhaseName,
                failedDomainCancellationToken.IsCancellationRequested
                    ? Wording.GetString("PartitionStoppedAfterDomainFailure", CultureInfo.CurrentUICulture)
                        ?? throw new InvalidOperationException("PartitionStoppedAfterDomainFailure")
                    : "partition stopped by the operator",
                [
                    new RunLogDetail("namingContext", unit.NamingContext),
                    new RunLogDetail("controller", unit.DomainController),
                    Elapsed(unitStartedUtc),
                ]);

            return new UnitOutcome(
                null,
                new RunEnding(
                    RunOutcome.Cancelled,
                    $"The run was stopped while reading {unit.NamingContext} from "
                    + $"{unit.DomainController}.",
                    Error: null));
        }

        if (!read.IsSuccess)
        {
            var error = read.Error!;

            // The elapsed time goes on the failure as well as on the success. How long a
            // partition ran before it gave up is what separates a controller that refused at
            // once from one that answered for an hour and then stopped.
            _log.Record(
                PartitionCapture.PhaseName,
                error,
                [
                    new RunLogDetail("namingContext", unit.NamingContext),
                    new RunLogDetail("controller", unit.DomainController),
                    Elapsed(unitStartedUtc),
                ]);

            return new UnitOutcome(
                null,
                new RunEnding(
                    RunOutcome.Failed,
                    $"{unit.NamingContext} could not be read from {unit.DomainController}: "
                    + $"{error.Description}",
                    error));
        }

        var coverage = read.Value!;

        _log.Note(
            PartitionCapture.PhaseName,
            "partition read",
            [
                new RunLogDetail("namingContext", coverage.NamingContextDn),
                new RunLogDetail("controller", coverage.Controller),
                new RunLogDetail("connection", coverage.ConnectionSecurity.ToString()),
                new RunLogDetail(
                    "objects", coverage.ObjectsRead.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail(
                    "pages", coverage.PagesRead.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail(
                    "attributeBlocks",
                    coverage.AttributeBlocksFetched.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail(
                    "continuationReferences",
                    coverage.ContinuationReferences.Count.ToString(
                        CultureInfo.InvariantCulture)),
                new RunLogDetail(
                    "referralsSuppressed",
                    coverage.ReferralsSuppressed ? "yes" : "no"),
                Elapsed(unitStartedUtc),
            ]);

        return new UnitOutcome(coverage, null);
    }

    /// <summary>
    /// Which unit of the plan this is, counting from one.
    /// </summary>
    /// <remarks>
    /// By naming context rather than by reference, because a unit can be re-pinned to a different
    /// controller by preflight and a re-pinned unit is a different record of the same naming
    /// context. Matched without regard to case, as a distinguished name is.
    /// </remarks>
    private static int PositionInPlan(CapturePlan plan, CaptureUnit unit)
    {
        for (var at = 0; at < plan.Units.Count; at++)
        {
            if (string.Equals(
                    plan.Units[at].NamingContext,
                    unit.NamingContext,
                    StringComparison.OrdinalIgnoreCase))
            {
                return at + 1;
            }
        }

        throw new InvalidOperationException(
            $"'{unit.NamingContext}' is being read but is not in the plan. A partition nothing "
            + "authorised would be captured into a bundle whose coverage never mentions it.");
    }

    /// <summary>
    /// How long a partition has taken so far, as a log detail.
    /// </summary>
    /// <remarks>
    /// Seconds, to one decimal place, because the reader is a person deciding whether one domain
    /// out of nine took an unreasonable share of a run. A duration formatted as a timespan sorts
    /// badly by eye and hides the difference between four seconds and forty.
    /// </remarks>
    private RunLogDetail Elapsed(DateTimeOffset startedUtc) =>
        new(
            "elapsedSeconds",
            (_time.GetUtcNow() - startedUtc).TotalSeconds
                .ToString("0.#", CultureInfo.InvariantCulture));

    /// <summary>
    /// The five phases of sealing, in the order they happened.
    /// </summary>
    /// <remarks>
    /// <b>Formatted here rather than on <see cref="BundleSealTimings"/>, and gate 4 is the reason.</b>
    /// A public member handing back a collection must come from a type that can say whether it
    /// looked, so an empty list is never mistaken for a failed one. Those timings cannot be
    /// incomplete - they exist only if every phase ran - so the honest answer was to leave them as
    /// plain data and put the formatting where every other line of this log is already built.
    /// Same shape of seconds as <see cref="Elapsed"/>, because a reader compares the two.
    /// </remarks>
    private static IReadOnlyList<RunLogDetail> SealDetail(BundleSealTimings sealing) =>
    [
        new("commitSeconds", Seconds(sealing.Commit)),
        new("indexSeconds", Seconds(sealing.Indexes)),
        new("backfillSeconds", Seconds(sealing.Backfill)),
        new("checkpointSeconds", Seconds(sealing.Checkpoint)),
        new("sealSeconds", Seconds(sealing.Seal)),
        new("totalSeconds", Seconds(sealing.Total)),
    ];

    private static string Seconds(TimeSpan span) =>
        span.TotalSeconds.ToString("0.#", CultureInfo.InvariantCulture);

    /// <summary>A count, spelled the one way every log line spells one.</summary>
    private static string Count(int value) => value.ToString(CultureInfo.InvariantCulture);
}
