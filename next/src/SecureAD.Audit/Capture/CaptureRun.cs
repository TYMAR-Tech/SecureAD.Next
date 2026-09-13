using System.Globalization;
using SecureAD.Audit.Sysvol;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;

namespace SecureAD.Audit.Capture;

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
    private readonly IDirectoryChannelFactory _connections;
    private readonly ISysvolFileReader _sysvolFiles;
    private readonly TimeProvider _time;
    private readonly IRunLog _log;

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
    public CaptureRun(
        IDirectoryChannelFactory connections,
        ISysvolFileReader sysvolFiles,
        TimeProvider time,
        IRunLog log)
    {
        ArgumentNullException.ThrowIfNull(connections);
        ArgumentNullException.ThrowIfNull(sysvolFiles);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(log);

        _connections = connections;
        _sysvolFiles = sysvolFiles;
        _time = time;
        _log = log;
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
        var capture = new PartitionCapture(_connections, sink, _time, _log);

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
                capture, bundleDirectory, unit, plan, recorded.Count, cancellationToken)
                .ConfigureAwait(false);

            if (outcome.Ended is { } ended)
                return ended;

            recorded.Add(outcome.Coverage!);
        }

        foreach (var unit in domains)
        {
            var outcome = await ReadOneUnitAsync(
                capture, bundleDirectory, unit, plan, recorded.Count, cancellationToken)
                .ConfigureAwait(false);

            if (outcome.Ended is { } ended)
                return ended;

            recorded.Add(outcome.Coverage!);
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

        var sysvol = await new SysvolCapture(_sysvolFiles, writer)
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
        var sealing = writer.Complete(
            RunCoverage.Of(
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
                sysvol),
            _time.GetUtcNow(),
            reconciliation);

        // The five phases behind the one word "sealing". They are separated because they fail and
        // scale differently: the index build is three sorts of the entries table, the backfill is
        // two set-based passes over every object, and the seal is a hash of the whole file. A
        // capture that spent twenty minutes here should say which of them it was.
        _log.Note(PartitionCapture.PhaseName, "bundle sealed", SealDetail(sealing));

        return new CaptureRunResult(RunCompletion.Sealed, bundleDirectory, Error: null);
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
    /// What became of reading one naming context: its coverage, or the run's ending.
    /// </summary>
    /// <remarks>
    /// <b>Both are carried so that a caller cannot forget to check.</b> The read either produced
    /// coverage or ended the run, never neither and never both, and a method returning only the
    /// coverage would need the caller to remember that a failure had already written the outcome
    /// file. Under the fan-out that follows, several of these come back at once and each has to be
    /// examined; an ending that could be dropped would be a domain that failed and a bundle that
    /// sealed anyway.
    /// </remarks>
    private sealed record UnitOutcome(PartitionCoverage? Coverage, CaptureRunResult? Ended);

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
    /// <param name="bundleDirectory">The run's directory, for the outcome file if it ends.</param>
    /// <param name="unit">Which naming context, on which controller.</param>
    /// <param name="plan">The plan, for the count in the progress line.</param>
    /// <param name="alreadyRead">How many units have finished, for the progress line.</param>
    /// <param name="cancellationToken">Cancellation for a run an operator stopped.</param>
    private async Task<UnitOutcome> ReadOneUnitAsync(
        PartitionCapture capture,
        string bundleDirectory,
        CaptureUnit unit,
        CapturePlan plan,
        int alreadyRead,
        CancellationToken cancellationToken)
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
                new RunLogDetail(
                    "unit",
                    $"{alreadyRead + 1} of {plan.Units.Count}"),
            ]);

        try
        {
            read = await capture.ReadAsync(unit, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _log.Note(
                PartitionCapture.PhaseName,
                "partition stopped by the operator",
                [
                    new RunLogDetail("namingContext", unit.NamingContext),
                    new RunLogDetail("controller", unit.DomainController),
                    Elapsed(unitStartedUtc),
                ]);

            return new UnitOutcome(
                null,
                End(
                    bundleDirectory,
                    RunOutcome.Cancelled,
                    $"The run was stopped while reading {unit.NamingContext} from "
                    + $"{unit.DomainController}.",
                    error: null));
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
                End(
                    bundleDirectory,
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
}
