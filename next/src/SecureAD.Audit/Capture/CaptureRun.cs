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
    public CaptureRun(
        IDirectoryChannelFactory connections,
        ISysvolFileReader sysvolFiles,
        TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(connections);
        ArgumentNullException.ThrowIfNull(sysvolFiles);
        ArgumentNullException.ThrowIfNull(time);

        _connections = connections;
        _sysvolFiles = sysvolFiles;
        _time = time;
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
        var capture = new PartitionCapture(_connections, sink, _time);

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

        foreach (var unit in plan.Units)
        {
            Result<PartitionCoverage> read;

            try
            {
                read = await capture.ReadAsync(unit, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return End(
                    bundleDirectory,
                    RunOutcome.Cancelled,
                    $"The run was stopped while reading {unit.NamingContext} from "
                    + $"{unit.DomainController}.",
                    error: null);
            }

            if (!read.IsSuccess)
            {
                var error = read.Error!;

                return End(
                    bundleDirectory,
                    RunOutcome.Failed,
                    $"{unit.NamingContext} could not be read from {unit.DomainController}: "
                    + $"{error.Description}",
                    error);
            }

            recorded.Add(read.Value!);
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
        var sysvol = await new SysvolCapture(_sysvolFiles, writer)
            .ReadAsync(sink.Policies, cancellationToken)
            .ConfigureAwait(false);

        // The seal, the checkpoint and the rename happen here, and only here. Until Complete
        // returns there is no file by the name a reader opens.
        //
        // The coverage handed to the bundle is derived from the rows capture actually recorded, not
        // from the plan's declaration. Asserting plan.DeclaredDomains.Select(DomainCoverage.Read)
        // made every declared domain report as read because it had been declared, which is the
        // statement RunCoverage.Of's guard exists to refuse - and while the assertion held, that
        // guard could not fire. Deriving costs a projection and makes the check real. F-S29-3, D3.
        writer.Complete(
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
}
