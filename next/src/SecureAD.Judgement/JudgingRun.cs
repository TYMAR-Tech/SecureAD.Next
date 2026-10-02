using System.Globalization;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>
/// Judging a sealed bundle: read every object once, offer it to every rule, and write what they
/// concluded beside the evidence.
/// </summary>
/// <remarks>
/// <para>
/// <b>One pass over the bundle, not one per rule.</b> The evidence is read sequentially and each
/// object is offered to every scheduled rule while it is in hand. Judging forty rules therefore
/// costs the same read as judging one, and adding a rule costs comparisons rather than another walk
/// of the forest.
/// </para>
/// <para>
/// <b>A rule that throws loses only itself.</b> It is recorded as
/// <see cref="RuleExecutionOutcome.Error"/>, offered no further objects, and the rules beside it
/// carry on. Its findings are discarded, because a rule that failed part way through has no verdict
/// and its partial output would read as a complete one.
/// </para>
/// <para>
/// <b>Nothing here decides what a run means.</b> The outcome of each rule follows from what it did,
/// and the state of the run follows from those outcomes, in
/// <see cref="JudgementWriter.Complete"/>. A coordinator that could name the state would be able to
/// call a judging complete while a rule had read nothing.
/// </para>
/// <para>
/// <b>Judging is measured in hours, not seconds, and is built for that.</b> The predecessor took
/// four to five hours over the owner's production forest. So this reports progress as it goes and
/// stops when asked, and a caller that offers neither is asking an operator to watch a still screen
/// for an afternoon with no way out.
/// </para>
/// </remarks>
public static class JudgingRun
{
    /// <summary>Production activation remains a separate approval from offline integration and measurement.</summary>
    public const PathRequesterPolicy ProductionPathRequesterPolicy = PathRequesterPolicy.Disabled;

    /// <summary>
    /// How far a judging has got.
    /// </summary>
    /// <remarks>
    /// <b>Objects rather than a percentage.</b> Nothing counts a bundle's objects before streaming
    /// it, so a percentage would need a count this does not have, and one wrong by a little would
    /// stall at 99 or pass 100 in front of an operator watching for hours.
    /// </remarks>
    /// <param name="ObjectsRead">How many objects have been offered to the rules so far.</param>
    public readonly record struct JudgingProgress(long ObjectsRead)
    {
        /// <summary>The current operation, not an indication that a judgement has been published.</summary>
        public JudgingPhase Phase { get; init; }

        /// <summary>How many objects Tier-0 discovery has inspected, when it is running.</summary>
        /// <remarks>
        /// <b>Not the same as <see cref="ObjectsRead"/>.</b> Discovery inspects the stream alongside
        /// rule evaluation, so the two advance together but count different work, and an unscoped
        /// judging leaves this at zero because discovery never runs.
        /// </remarks>
        public long Tier0ObjectsObserved { get; init; }

        /// <summary>
        /// Time spent inside Tier-0 discovery so far, so an operator can see a long scan progressing.
        /// </summary>
        /// <remarks>
        /// <b>Elapsed, never remaining.</b> The scan has no work ceiling, so there is no endpoint to
        /// forecast from and any estimate would be a guess on a screen an auditor trusts. This is the
        /// accumulated discovery time only, not the wall clock of the whole judging.
        /// </remarks>
        public TimeSpan Tier0DiscoveryElapsed { get; init; }

        /// <summary>Diagnostic requester work within the existing screen phase, not a published result.</summary>
        public PathRequesterWorkPhase? RequesterPhase { get; init; }

        /// <summary>The staged generation performing requester work; it is not current until publication.</summary>
        public Guid? JudgementGenerationId { get; init; }
    }

    /// <summary>
    /// Judges the bundle in <paramref name="bundleDirectory"/> and writes the judgement beside it.
    /// </summary>
    /// <remarks>
    /// Replaces any judgement already there, and only at the end: a judging that fails part way
    /// leaves the previous answer intact rather than replacing it with a partial one.
    /// </remarks>
    /// <param name="bundleDirectory">The bundle to judge.</param>
    /// <param name="rules">The rules to run. Each is recorded whatever becomes of it.</param>
    /// <param name="startedUtc">When judging started.</param>
    /// <param name="evaluationAsOf">
    /// The reference time temporal rules are evaluated against, recorded so that the same sealed
    /// evidence gives the same answer next year.
    /// </param>
    /// <param name="progress">
    /// Told how many objects have been read. Pass <see cref="NobodyIsWatching"/> where there is no
    /// operator to tell - required rather than defaulted, because gate 1 records that progress,
    /// cancellation and the performance log all became quietly unused in the predecessor by being
    /// optional. Reported every <see cref="ProgressEvery"/> objects rather than every object,
    /// because a run of millions would otherwise spend its time raising events.
    /// </param>
    /// <param name="cancellationToken">Stops the judging. See the remarks on what that leaves.</param>
    /// <returns>What became of the run, or why it could not be judged at all.</returns>
    /// <exception cref="OperationCanceledException">
    /// The judging was cancelled. <b>The earlier judgement is left intact</b>: the partial file is
    /// never renamed over it, so a cancelled re-judging costs the operator nothing but the time it
    /// ran for. That is the same guarantee a crash gets, by the same mechanism.
    /// </exception>
    public static Result<JudgementRunState> Judge(
        string bundleDirectory,
        IReadOnlyList<IRule> rules,
        DateTimeOffset startedUtc,
        DateTimeOffset evaluationAsOf,
        IProgress<JudgingProgress> progress,
        IRunLog log,
        CancellationToken cancellationToken) =>
        Judge(bundleDirectory, rules, (SelfMembershipDiscoveryBudget?)null, startedUtc, evaluationAsOf, progress, log, cancellationToken);

    /// <summary>Judges with an explicitly configured automatic-discovery budget, without supplied requester identities.</summary>
    public static Result<JudgementRunState> Judge(
        string bundleDirectory,
        IReadOnlyList<IRule> rules,
        SelfMembershipDiscoveryBudget? discoveryBudget,
        DateTimeOffset startedUtc,
        DateTimeOffset evaluationAsOf,
        IProgress<JudgingProgress> progress,
        IRunLog log,
        CancellationToken cancellationToken)
    {
        discoveryBudget?.Validate();
        return JudgeCore(bundleDirectory, rules, [], SelfMembershipBudget.Default, true, discoveryBudget, null, startedUtc, evaluationAsOf,
            progress, log, cancellationToken, tier0DiscoveryRequested: false, requesterDaclRequests: [], ownAccountRequests: [], membershipDaclRequests: []);
    }

    /// <summary>Judges a bundle and evaluates only the explicit bounded Self-Membership requests supplied.</summary>
    public static Result<JudgementRunState> Judge(
        string bundleDirectory,
        IReadOnlyList<IRule> rules,
        IReadOnlyList<SelfMembershipRequest> selfMembershipRequests,
        SelfMembershipBudget selfMembershipBudget,
        DateTimeOffset startedUtc,
        DateTimeOffset evaluationAsOf,
        IProgress<JudgingProgress> progress,
        IRunLog log,
        CancellationToken cancellationToken) =>
        JudgeCore(bundleDirectory, rules, selfMembershipRequests, selfMembershipBudget, false, null, null, startedUtc,
            evaluationAsOf, progress, log, cancellationToken, tier0DiscoveryRequested: false, requesterDaclRequests: [], ownAccountRequests: [], membershipDaclRequests: []);

    /// <summary>Judges with an explicit offline member-attribution budget; requester discovery remains inactive.</summary>
    public static Result<JudgementRunState> JudgeWithMemberAttribution(
        string bundleDirectory, IReadOnlyList<IRule> rules, MemberAttributionBudget memberBudget,
        DateTimeOffset startedUtc, DateTimeOffset evaluationAsOf, IProgress<JudgingProgress> progress,
        IRunLog log, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(memberBudget);
        memberBudget.Validate();
        return JudgeCore(bundleDirectory, rules, [], SelfMembershipBudget.Default, true, null, memberBudget,
            startedUtc, evaluationAsOf, progress, log, cancellationToken, tier0DiscoveryRequested: false, requesterDaclRequests: [], ownAccountRequests: [], membershipDaclRequests: []);
    }

    /// <summary>
    /// Judges with Tier-0 discovery deciding which objects receive detailed control assessment.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the work boundary decision 0116 describes, and it is opt-in for now.</b> Detailed
    /// control, full-control and owner-transition products are derived only for objects a supported
    /// incoming route from a Tier-0 seed reached. Ordinary rule evaluation is unchanged: every rule
    /// is still offered every streamed object exactly once.
    /// </para>
    /// <para>
    /// <b>Why the other entry points still assess everything.</b> Under this boundary the stored
    /// control counts cover the assessed scope rather than the captured forest, and a large body of
    /// existing acceptance fixtures state their expectations as forest-wide totals. Those are the
    /// counts 0116 calls history rather than oracles, and re-anchoring them is deliberate work in
    /// its own right - not something to do by quietly changing what they measure underneath them.
    /// Until that is done, choosing this behaviour is explicit.
    /// </para>
    /// </remarks>
    /// <para>
    /// <b>The scan has no work ceiling.</b> It reads what was captured, and cancellation is the only
    /// thing that stops it early - which throws, so a partial scan is never published as a whole one.
    /// A configured limit was removed deliberately: the only value ever defined exceeded the recorded
    /// production forest several times over, so it stopped nothing while implying the product would.
    /// Progress is reported as elapsed time through <see cref="JudgingProgress.Tier0DiscoveryElapsed"/>.
    /// </para>
    /// </remarks>
    public static Result<JudgementRunState> JudgeWithTier0Discovery(
        string bundleDirectory,
        IReadOnlyList<IRule> rules,
        DateTimeOffset startedUtc,
        DateTimeOffset evaluationAsOf,
        IProgress<JudgingProgress> progress,
        IRunLog log,
        CancellationToken cancellationToken,
        SelfMembershipDiscoveryBudget? selfMembershipDiscoveryBudget)
        => JudgeWithTier0Discovery(bundleDirectory, rules, [], startedUtc, evaluationAsOf, progress, log,
            selfMembershipDiscoveryBudget, cancellationToken);

    /// <summary>
    /// Judges with explicit offline requester WRITE_DAC questions in addition to Tier-0 discovery.
    /// This does not discover requesters, expand production membership work or predict authentication.
    /// </summary>
    public static Result<JudgementRunState> JudgeWithTier0Discovery(
        string bundleDirectory,
        IReadOnlyList<IRule> rules,
        IReadOnlyList<RequesterDaclRequest> requesterDaclRequests,
        DateTimeOffset startedUtc,
        DateTimeOffset evaluationAsOf,
        IProgress<JudgingProgress> progress,
        IRunLog log,
        SelfMembershipDiscoveryBudget? selfMembershipDiscoveryBudget,
        CancellationToken cancellationToken)
        => JudgeWithTier0Discovery(bundleDirectory, rules, requesterDaclRequests, [], startedUtc, evaluationAsOf,
            progress, log, selfMembershipDiscoveryBudget, cancellationToken);

    /// <summary>
    /// Judges explicit offline requester DACL and own-account membership-obtainability questions.
    /// This neither discovers requester pairs nor changes ordinary Add readiness or production scheduling.
    /// </summary>
    public static Result<JudgementRunState> JudgeWithTier0Discovery(
        string bundleDirectory,
        IReadOnlyList<IRule> rules,
        IReadOnlyList<RequesterDaclRequest> requesterDaclRequests,
        IReadOnlyList<OwnAccountMembershipRequest> ownAccountRequests,
        DateTimeOffset startedUtc,
        DateTimeOffset evaluationAsOf,
        IProgress<JudgingProgress> progress,
        IRunLog log,
        SelfMembershipDiscoveryBudget? selfMembershipDiscoveryBudget,
        CancellationToken cancellationToken)
        => JudgeWithTier0Discovery(bundleDirectory, rules, requesterDaclRequests, ownAccountRequests, [], startedUtc,
            evaluationAsOf, progress, log, selfMembershipDiscoveryBudget, cancellationToken);

    /// <summary>
    /// Judges explicit combined own-account membership and fixed-target WRITE_DAC questions.
    /// Pre-change membership authorization and post-membership requester checks are saved separately;
    /// this does not activate requester discovery, change host scheduling or predict live success.
    /// </summary>
    public static Result<JudgementRunState> JudgeWithTier0Discovery(
        string bundleDirectory, IReadOnlyList<IRule> rules,
        IReadOnlyList<RequesterDaclRequest> requesterDaclRequests,
        IReadOnlyList<OwnAccountMembershipRequest> ownAccountRequests,
        IReadOnlyList<MembershipDaclRequest> membershipDaclRequests,
        DateTimeOffset startedUtc, DateTimeOffset evaluationAsOf, IProgress<JudgingProgress> progress,
        IRunLog log, SelfMembershipDiscoveryBudget? selfMembershipDiscoveryBudget, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(membershipDaclRequests);
        selfMembershipDiscoveryBudget?.Validate();
        return JudgeCore(bundleDirectory, rules, [], SelfMembershipBudget.Default, true, selfMembershipDiscoveryBudget, null,
            startedUtc, evaluationAsOf, progress, log, cancellationToken, tier0DiscoveryRequested: true,
            requesterDaclRequests, ownAccountRequests, membershipDaclRequests);
    }

    /// <summary>
    /// Selects supported path requester questions from captured permissions for offline verification.
    /// This does not enable production requester discovery or change authorization semantics.
    /// </summary>
    public static Result<JudgementRunState> JudgeWithOfflinePathRequesterSelection(
        string bundleDirectory, IReadOnlyList<IRule> rules, DateTimeOffset startedUtc, DateTimeOffset evaluationAsOf,
        IProgress<JudgingProgress> progress, IRunLog log, CancellationToken cancellationToken) =>
        JudgeCore(bundleDirectory, rules, [], SelfMembershipBudget.Default, true, null, null, startedUtc,
            evaluationAsOf, progress, log, cancellationToken, tier0DiscoveryRequested: true,
            requesterDaclRequests: [], ownAccountRequests: [], membershipDaclRequests: [], offlineSelection: true);

    /// <summary>
    /// Runs the shared host judging policy against sealed evidence. Supported selection reuses the
    /// existing three proof families; production activation, legacy discovery and budgets are separate.
    /// Failed and cancelled attempts are logged separately and never replace a previous valid generation.
    /// </summary>
    public static Result<JudgementRunState> JudgeAudit(
        string bundleDirectory, IReadOnlyList<IRule> rules, PathRequesterPolicy requesterPolicy,
        DateTimeOffset startedUtc, DateTimeOffset evaluationAsOf, IProgress<JudgingProgress> progress,
        IRunLog log, CancellationToken cancellationToken, SelfMembershipDiscoveryBudget? selfMembershipDiscoveryBudget)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(progress);
        ArgumentNullException.ThrowIfNull(log);
        if (!Enum.IsDefined(requesterPolicy)) throw new ArgumentOutOfRangeException(nameof(requesterPolicy));
        selfMembershipDiscoveryBudget?.Validate();
        if (requesterPolicy == PathRequesterPolicy.Disabled)
            return JudgeWithTier0Discovery(bundleDirectory, rules, startedUtc, evaluationAsOf, progress, log,
                cancellationToken, selfMembershipDiscoveryBudget);

        var previous = AnalysisStoreLifecycle.Resolve(bundleDirectory, AnalysisStoreKind.Judgement);
        var attempt = Guid.NewGuid();
        var watched = new RequesterProgress(progress);
        var recorded = false;
        void Record(string state) => log.Note(JudgePhase, "path-requester-attempt",
        [
            new("attempt", attempt.ToString("D")), new("state", state), new("policy", requesterPolicy.ToString()),
            new("previous-generation", previous.IsSuccess ? previous.Value.GenerationId.ToString("D") : "none"),
            new("generation", watched.GenerationId?.ToString("D") ?? "none"),
        ]);
        Record("Started");
        try
        {
            var result = JudgeCore(bundleDirectory, rules, [], SelfMembershipBudget.Default, true,
                selfMembershipDiscoveryBudget, null, startedUtc, evaluationAsOf, watched, log, cancellationToken,
                tier0DiscoveryRequested: true, requesterDaclRequests: [], ownAccountRequests: [], membershipDaclRequests: [], offlineSelection: true);
            Record(result.IsSuccess ? "Published" : "Failed");
            recorded = true;
            return result;
        }
        catch (OperationCanceledException)
        {
            Record("Cancelled");
            recorded = true;
            throw;
        }
        finally
        {
            // Preserve unexpected failures without catching or replacing their exception. A process
            // interruption leaves Started without a terminal record, not a fabricated completed batch.
            if (!recorded) Record("Failed");
        }
    }

    private sealed class RequesterProgress(IProgress<JudgingProgress> target) : IProgress<JudgingProgress>
    {
        internal Guid? GenerationId { get; private set; }
        public void Report(JudgingProgress value)
        {
            GenerationId = value.JudgementGenerationId ?? GenerationId;
            target.Report(value);
        }
    }

    /// <summary>
    /// Judges one bundle, and appends what it did to the run's portable summary.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A wrapper, because the summary is read back out of the judgement store</b> and
    /// <see cref="JudgeIntoStore"/> holds that store open until it returns. Reading it from inside
    /// the body would be reading a file something still has open, which is the shape P-255 records
    /// an unexplained SQLite failure against.
    /// </para>
    /// <para>
    /// <b>Nothing is appended for a judging that refused to start.</b> A missing seal or an
    /// unopenable bundle leaves no store to read and no judging to describe; the run log says what
    /// happened, and an absent section claims nothing where a section of noughts would claim a
    /// forest nobody found anything in.
    /// </para>
    /// </remarks>
    private static Result<JudgementRunState> JudgeCore(
        string bundleDirectory,
        IReadOnlyList<IRule> rules,
        IReadOnlyList<SelfMembershipRequest> selfMembershipRequests,
        SelfMembershipBudget selfMembershipBudget,
        bool automaticDiscovery,
        SelfMembershipDiscoveryBudget? discoveryBudget,
        MemberAttributionBudget? memberBudget,
        DateTimeOffset startedUtc,
        DateTimeOffset evaluationAsOf,
        IProgress<JudgingProgress> progress,
        IRunLog log,
        CancellationToken cancellationToken,
        bool tier0DiscoveryRequested,
        IReadOnlyList<RequesterDaclRequest> requesterDaclRequests,
        IReadOnlyList<OwnAccountMembershipRequest> ownAccountRequests,
        IReadOnlyList<MembershipDaclRequest> membershipDaclRequests,
        bool offlineSelection = false)
    {
        var account = new JudgingAccount();
        var began = System.Diagnostics.Stopwatch.GetTimestamp();
        using var status = new JudgingStatus(log, progress, TimeProvider.System, PostPassMemory.Read);
        try
        {
            status.RecordBuildIdentity();
            var judged = JudgeIntoStore(
                bundleDirectory, rules, selfMembershipRequests, selfMembershipBudget, automaticDiscovery,
                discoveryBudget, memberBudget, startedUtc, evaluationAsOf, status, log, cancellationToken,
                tier0DiscoveryRequested, requesterDaclRequests, ownAccountRequests, membershipDaclRequests,
                offlineSelection, account);

            if (judged.IsSuccess)
            {
                AppendPortableSummary(
                    bundleDirectory, System.Diagnostics.Stopwatch.GetElapsedTime(began), account);
            }
            else
            {
                status.RecordRefusal(judged.Error);
            }
            return judged;
        }
        catch (Exception error) when (status.RecordException(error, cancellationToken.IsCancellationRequested))
        {
            throw;
        }
    }

    /// <summary>
    /// What a judging did, gathered as it goes because the objects are streamed and gone.
    /// </summary>
    /// <remarks>
    /// Durations only, and the counts that travel with them. What was found is read back out of
    /// the store, per the owner's decision of 2026-09-22: a summary that counted its own findings
    /// would be a second answer to a question the judgement has already answered.
    /// </remarks>
    private sealed class JudgingAccount
    {
        /// <summary>Where the object pass spent its time, which is what P-257 turns on.</summary>
        public IReadOnlyList<StageTiming> Phases { get; set; } = [];

        /// <summary>One row per scheduled rule, and what became of it.</summary>
        public IReadOnlyList<RuleTiming> Rules { get; set; } = [];

        /// <summary>How many captured objects were streamed through the pass.</summary>
        public long ObjectsJudged { get; set; }
    }

    /// <summary>
    /// Appends what this judging did to the run's portable summary.
    /// </summary>
    /// <remarks>
    /// <b>Findings are counted by severity in the database and never listed.</b> A finding names
    /// the object it is about, so the findings themselves stay in the bundle; how many there were
    /// of each kind is the part that may travel.
    /// </remarks>
    /// <param name="bundleDirectory">The run's directory.</param>
    /// <param name="elapsed">How long judging took.</param>
    /// <param name="account">What the run measured while it was happening.</param>
    private static void AppendPortableSummary(
        string bundleDirectory, TimeSpan elapsed, JudgingAccount account)
    {
        var opened = JudgementReader.Open(bundleDirectory);

        if (!opened.IsSuccess)
            return;

        using var reader = opened.Value!;
        var executions = reader.ReadRuleExecutions();

        PortableSummaryFile.AppendJudging(
            bundleDirectory,
            PortableSummaryReading.OfJudging(
                executions.State.ToString(),
                (long)elapsed.TotalMilliseconds,
                account.ObjectsJudged,
                account.Phases,
                account.Rules,
                reader.ReadFindingCountsBySeverity(),
                Problems(executions)));
    }

    /// <summary>
    /// Turns the rules that did not reach every verdict into the shape the summary may carry.
    /// </summary>
    /// <remarks>
    /// <b>Counted by outcome rather than named.</b> Which rule stopped is in the run log and on the
    /// rules table of the summary itself; this is the tally beside it, and the stored error text is
    /// deliberately not read because a rule that threw quotes what it was looking at.
    /// </remarks>
    /// <param name="executions">Every scheduled rule, read back.</param>
    /// <returns>One error per rule that did not succeed.</returns>
    private static IEnumerable<AuditError> Problems(StoredRuleExecutions executions) =>
        executions.Executions
            .Where(execution => execution.Outcome != RuleExecutionOutcome.Succeeded)
            .Select(execution => AuditError.Create(
                ErrorCategory.Evidence,
                "Rule" + execution.Outcome,
                ErrorSeverity.Degraded,
                $"A rule ended as {execution.Outcome} rather than reaching every verdict.",
                context: null));

    private static Result<JudgementRunState> JudgeIntoStore(
        string bundleDirectory,
        IReadOnlyList<IRule> rules,
        IReadOnlyList<SelfMembershipRequest> selfMembershipRequests,
        SelfMembershipBudget selfMembershipBudget,
        bool automaticDiscovery,
        SelfMembershipDiscoveryBudget? discoveryBudget,
        MemberAttributionBudget? memberBudget,
        DateTimeOffset startedUtc,
        DateTimeOffset evaluationAsOf,
        JudgingStatus progress,
        IRunLog log,
        CancellationToken cancellationToken,
        bool tier0DiscoveryRequested,
        IReadOnlyList<RequesterDaclRequest> requesterDaclRequests,
        IReadOnlyList<OwnAccountMembershipRequest> ownAccountRequests,
        IReadOnlyList<MembershipDaclRequest> membershipDaclRequests,
        bool offlineSelection,
        JudgingAccount account)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(selfMembershipRequests);
        ArgumentNullException.ThrowIfNull(selfMembershipBudget);
        ArgumentNullException.ThrowIfNull(progress);
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(requesterDaclRequests);
        var requesterQuestions = new Dictionary<string, RequesterDaclRequest>(StringComparer.Ordinal);
        foreach (var request in requesterDaclRequests)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (request is null || string.IsNullOrWhiteSpace(request.RequesterDn) || string.IsNullOrWhiteSpace(request.TargetDn))
                throw new ArgumentException(Tier0PathStorage.InvalidRequestMessage(), nameof(requesterDaclRequests));
            requesterQuestions.TryAdd(RequesterDaclProofs.Key(request), request);
        }
        ArgumentNullException.ThrowIfNull(ownAccountRequests);
        var ownAccountQuestions = new Dictionary<string, OwnAccountMembershipRequest>(StringComparer.Ordinal);
        foreach (var request in ownAccountRequests)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (request is null || string.IsNullOrWhiteSpace(request.RequesterDn) || string.IsNullOrWhiteSpace(request.TargetDn)
                || !Enum.IsDefined(request.PermissionKind))
                throw new ArgumentException(Tier0PathStorage.InvalidOwnAccountRequestMessage(), nameof(ownAccountRequests));
            ownAccountQuestions.TryAdd(OwnAccountMembershipProofs.Key(request), request);
        }
        var membershipDaclQuestions = new Dictionary<string, MembershipDaclRequest>(StringComparer.Ordinal);
        foreach (var request in membershipDaclRequests)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!MembershipDaclProofs.Valid(request))
                throw new ArgumentException(Tier0PathStorage.InvalidMembershipDaclRequestMessage(), nameof(membershipDaclRequests));
            membershipDaclQuestions.TryAdd(MembershipDaclProofs.Key(request), request);
        }
        if (selfMembershipRequests.Count > selfMembershipBudget.Requests)
            throw new ArgumentException($"The request batch contains {selfMembershipRequests.Count} requests; its explicit budget is {selfMembershipBudget.Requests}.", nameof(selfMembershipRequests));

        Entering(progress, log, JudgingPhase.PreparingInputs, 0);
        var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(bundleDirectory));

        if (seal is null || string.IsNullOrWhiteSpace(seal.Hash))
        {
            var refusal = Failure(
                "EvidenceSealUnreadable",
                $"There is no readable evidence seal in '{bundleDirectory}', so a judgement written "
                + "here could not say which capture it was made against. A judgement that cannot "
                + "name its evidence is not one this product will write.",
                bundleDirectory);

            log.Record(JudgePhase, refusal.Error!, []);
            return refusal;
        }

        var protectedEvidence = ProtectedStoreFile.OpenEvidence(bundleDirectory, cancellationToken);
        if (!protectedEvidence.IsSuccess)
        {
            log.Record(JudgePhase, protectedEvidence.Error!, []);
            return Result<JudgementRunState>.Failure(protectedEvidence.Error!);
        }
        using var evidence = protectedEvidence.Value;
        if (!string.Equals(evidence.Fingerprint, seal.Hash, StringComparison.OrdinalIgnoreCase))
            return Failure("EvidenceChanged", "The evidence seal changed while judging was opening it.", bundleDirectory);

        var opened = BundleReader.Open(evidence, cancellationToken);
        if (!opened.IsSuccess)
        {
            log.Record(JudgePhase, opened.Error!, []);
            return Result<JudgementRunState>.Failure(opened.Error!);
        }

        using var bundle = opened.Value!;

        var scope = bundle.ReadScope();
        if (!scope.IsSuccess)
        {
            log.Record(JudgePhase, scope.Error!, []);
            return Result<JudgementRunState>.Failure(scope.Error!);
        }

        // What the scheduled rules say they read beyond the captured object. Gathered before any
        // object is offered, because the answer decides whether this judging can run at all.
        var wanted = rules
            .SelectMany(r => r.Definition.RequiredDerivedFacts)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        DerivationReader? derivation = null;

        // The reference time reaches the rules from the same value that is written to
        // evaluation_as_of, so a rule's answer and the record of what it was answering against
        // cannot drift apart. A rule reading the clock instead would give a different answer every
        // time this sealed evidence was re-judged, and nothing in the bundle would say why.
        JudgingContext context = JudgingContext.At(evaluationAsOf);
        Guid? derivationGeneration = null;

        if (wanted.Count > 0)
        {
            // Opened rather than merely checked for. DerivationReader.Open is what enforces the
            // binding - it refuses a store whose generation does not match the manifest, and one
            // whose evidence seal is not this bundle's - so asking it to open is a stronger question
            // than asking whether a file is present. A derivation belonging to different evidence
            // would produce confidently wrong findings, which docs/decisions/0091 names as the one
            // thing this product must not do.
            var openedDerivation = DerivationReader.Open(bundleDirectory);

            if (!openedDerivation.IsSuccess)
            {
                var refusal = Failure(
                    "DerivationUnavailable",
                    $"{string.Join(", ", wanted)} was declared by a scheduled rule, and this bundle's "
                    + $"derivation could not be opened: {openedDerivation.Error!.Description} A rule "
                    + "that reads derived facts is not run against evidence alone, because silence "
                    + "from it would read as nothing found. Derive this bundle and judge it again.",
                    bundleDirectory);

                log.Record(JudgePhase, refusal.Error!, []);
                return refusal;
            }

            derivation = openedDerivation.Value!;
            var stored = derivation.Read();
            derivationGeneration = stored.Description.GenerationId;

            var product = stored.ProtectedPrincipals;

            if (wanted.Contains(
                    nameof(DerivedFactKind.ProtectedPrincipals), StringComparer.OrdinalIgnoreCase)
                && product.Availability != ProtectedPrincipalProductAvailability.Available)
            {
                derivation.Dispose();

                var refusal = Failure(
                    "DerivedFactsAbsent",
                    $"A scheduled rule reads {DerivedFactKind.ProtectedPrincipals}, and this "
                    + $"bundle's derivation does not carry it ({product.Availability}). The phase "
                    + "not having run is not the same as nothing being protected, so this judging "
                    + "stops rather than reporting an answer it does not have.",
                    bundleDirectory);

                log.Record(JudgePhase, refusal.Error!, []);
                return refusal;
            }

            context = context with
            {
                ForestFqdn = bundle.Description.ForestFqdn,
                ProtectedPrincipals = product.Value,
                Permissions = bundle.ReadPermissions,

                // Not a derived fact and so not gated by a declaration: every bundle carries the
                // schema rows, and a rule reading an object-specific access control entry cannot
                // tell which attribute the entry names without them.
                SchemaGuids = bundle.ReadSchemaGuids(),

                // Memoised for the same reason the expansion is: one delegated group appears on
                // every computer under an organisational unit, so its name would otherwise be
                // looked up once per machine to say the same thing.
                PrincipalNames = Memoised(bundle.PrincipalNameFor),

                // Not a derived fact either: a policy's settings are captured from its own SYSVOL
                // files and sit in the bundle. Unmemoised, because a policy is judged once and its
                // settings are not asked for a second time.
                GpoMachineRegistrySettings = bundle.ReadGpoMachineRegistrySettings,

                // Read once for the whole forest, not per object. Whether an owner keeps the right
                // to rewrite an object's permissions turns partly on this, so a rule that could not
                // read it must refuse rather than assume the permissive default.
                OwnerImplicitRights = DirectoryHeuristics.OwnerImplicitRights(
                    bundle.ReadForestHeuristics()),
            };

            // The same refusal for the same reason, and the consequence of skipping it is worse
            // here than for the protected principals. A rule that reads a LAPS timestamp treats an
            // absent value as a fact about a machine; without this answer it cannot know the forest
            // was not withholding the attribute, and SEC-094 would report every modern-capable
            // machine in the estate.
            if (wanted.Contains(
                nameof(DerivedFactKind.AttributeVisibility), StringComparer.OrdinalIgnoreCase))
            {
                var visibility = stored.AttributeVisibility;

                if (visibility.Availability != AttributeVisibilityAvailability.Available)
                {
                    derivation.Dispose();

                    var refusal = Failure(
                        "DerivedFactsAbsent",
                        $"A scheduled rule reads {DerivedFactKind.AttributeVisibility}, and this "
                        + $"bundle's derivation does not carry it ({visibility.Availability}). "
                        + "Whether this forest withholds an attribute is what separates a machine "
                        + "that is unmanaged from one this run was not allowed to see, so this "
                        + "judging stops rather than reporting an answer it does not have.",
                        bundleDirectory);

                    log.Record(JudgePhase, refusal.Error!, []);
                    return refusal;
                }

                context = context with { AttributeVisibility = visibility.Value };
            }

            // The expansion is a lookup rather than a product, so what is checked here is that the
            // nesting it walks was derived at all. A rule handed a walk over an empty edge table
            // would find nothing inside every group it asked about and report a scoped delegation
            // as safe - which is worse than silence, and is why this refuses instead.
            if (wanted.Contains(
                nameof(DerivedFactKind.PrincipalExpansion), StringComparer.OrdinalIgnoreCase))
            {
                if (!derivation.NestingWasDerived())
                {
                    derivation.Dispose();

                    var refusal = Failure(
                        "DerivedFactsAbsent",
                        $"A scheduled rule reads {DerivedFactKind.PrincipalExpansion}, and this "
                        + "bundle's derivation carries no group nesting to walk. Expanding a group "
                        + "over nothing finds nothing inside it, so every delegation would look "
                        + "scoped and every broad principal would go unreported. This judging "
                        + "stops rather than reporting an answer it does not have.",
                        bundleDirectory);

                    log.Record(JudgePhase, refusal.Error!, []);
                    return refusal;
                }

                // Captured by reference to the open reader, the same way permissions are read off
                // the open bundle. Both live as long as the loop below, and no longer.
                var reader = derivation;

                // MEMOISED FOR THE RUN, because the same principal is asked about once per object.
                // Every computer under one organisational unit inherits the same delegation, so a
                // rule expanding the delegated group repeats an identical walk for each of them - a
                // hundred thousand machines is a hundred thousand identical answers. The walk is
                // over persisted edges and the derivation does not change while a judging runs, so
                // the second answer cannot differ from the first.
                //
                // Invisible on a small forest, which is why nothing surfaced it: the lab has
                // fourteen computers.
                var expansions = new Dictionary<(string Sid, string Scope), PrincipalExpansion>();

                context = context with
                {
                    MembersOfPrincipal = (sid, scope) =>
                    {
                        var key = (sid, scope);

                        if (expansions.TryGetValue(key, out var known))
                            return known;

                        var walked = reader.MembersOf(sid, scope);
                        expansions[key] = walked;
                        return walked;
                    },
                };
            }
        }

        // Ownership is a control product even when no scheduled finding requests derivation.
        // Optional inputs never turn an evidence-only judging into a falsely complete owner answer.
        if (derivation is null)
        {
            var ownershipInputs = DerivationReader.Open(bundleDirectory);
            if (ownershipInputs.IsSuccess)
            {
                derivation = ownershipInputs.Value;
                var stored = derivation.Read();
                derivationGeneration = stored.Description.GenerationId;
                context = context with { ProtectedPrincipals = stored.ProtectedPrincipals.Value };
            }
        }
        if (context.MembersOfPrincipal is null && derivation?.NestingWasDerived() == true)
        {
            var reader = derivation;
            var expansions = new Dictionary<(string Sid, string Scope), PrincipalExpansion>();
            context = context with
            {
                MembersOfPrincipal = (sid, scope) =>
                {
                    var key = (sid, scope);
                    if (!expansions.TryGetValue(key, out var result))
                        expansions[key] = result = reader.MembersOf(sid, scope);
                    return result;
                },
            };
        }

        using var _ = derivation;

        if (memberBudget is not null && derivation is null)
            return Failure("MemberAttributionInputUnavailable", MemberAttributionMessages.Get("InputUnavailable"), bundleDirectory);
        CapturedMembershipInput? memberInput = null;
        if (derivation is not null)
        {
            try { memberInput = derivation.ReadMembershipInput(); }
            catch (Exception error) when (error is InvalidOperationException or System.Text.Json.JsonException or Microsoft.Data.Sqlite.SqliteException)
            {
                var refusal = memberBudget is not null
                    ? Failure("MemberAttributionInputUnavailable", MemberAttributionMessages.Get("InputUnavailable") + " " + error.Message, bundleDirectory)
                    : Failure("OwnershipScopeInputUnavailable", OwnershipAuditCoverage.Text("InvalidProof") + " " + error.Message, bundleDirectory);
                log.Record(JudgePhase, refusal.Error!, []);
                return refusal;
            }
        }

        var namingContexts = bundle.ReadNamingContexts();
        if (!namingContexts.IsSuccess)
        {
            log.Record(JudgePhase, namingContexts.Error, []);
            return Result<JudgementRunState>.Failure(namingContexts.Error);
        }

        using var writer = JudgementWriter.Create(
            bundleDirectory,
            seal.Hash,
            derivationGeneration,
            startedUtc,
            evaluationAsOf);
        progress.RecordGeneration(writer.GenerationId, seal.Hash, derivationGeneration);
        writer.RecordEvidenceScope(scope.Value!);

        log.Note(
            JudgePhase,
            "started",
            [new RunLogDetail("rules", rules.Count.ToString(CultureInfo.InvariantCulture))]);

        var tallies = rules.Select(r => new Tally(r)).ToList();

        long objectsRead = 0;
        writer.StartSelfMembershipAssessments();
        // Control capabilities always consume captured schema, even when no rule requests derived facts.
        var attributes = Memoised<ObjectAttributes?>(dn => bundle.ReadObjectAttributes(dn));
        var controlContext = context with
        {
            ForestFqdn = bundle.Description.ForestFqdn,
            SchemaGuids = context.SchemaGuids ?? bundle.ReadSchemaGuids(),
            OwnerImplicitRights = context.OwnerImplicitRights ?? DirectoryHeuristics.OwnerImplicitRights(bundle.ReadForestHeuristics()),
            NamingContexts = namingContexts.Value,
            ControlPrincipals = attributes,
        };
        var domainSids = Memoised(domain =>
        {
            var root = bundle.ReadObjectAttributes(string.Join(',', domain.Split('.').Select(part => "DC=" + part)));
            var value = root?.Find("objectSid")?.OnlyValue;
            return value?.Bytes is { } bytes ? Sid.ToText(bytes) : value?.Text;
        });

        var ownershipDescription = new JudgementDescription(seal.Hash, writer.GenerationId, derivationGeneration,
            JudgementRunState.Running, evaluationAsOf, startedUtc, default);
        var ownershipBinding = memberInput is not null && derivationGeneration is { } sourceGeneration
            ? OwnershipAuditRun.Binding(bundleDirectory, seal.Hash, sourceGeneration, bundle.Description.ForestFqdn, namingContexts.Value) : null;

        // STARTED HERE BECAUSE THE SCOPING FLAG MUST MATCH WHAT ACTUALLY HAPPENS. Discovery needs a
        // pinned derivation binding to qualify seeds against; without one it does not run and every
        // object is assessed. Recording "scoped" on the strength of the request alone would put the
        // scope caveat on screen for a run that in fact covered the whole capture, understating real
        // coverage - the opposite error to the one the caveat exists to prevent.
        var gated = tier0DiscoveryRequested && ownershipBinding is not null;
        writer.StartControlEdges(scope.Value!.AllDeclaredDomainsAreComplete, gated);
        writer.StartAutomaticOwnership(ownershipDescription, OwnershipAuditRun.OwnerRightsHash(controlContext.OwnerImplicitRights));
        writer.StartPathInputs(ownershipDescription, tier0DiscoveryRequested);
        writer.StartLapsInventory();
        var classificationSchema = controlContext.SchemaGuids
            ?? throw new InvalidOperationException(nameof(controlContext.SchemaGuids));
        writer.StartPermissionClassifications(classificationSchema.HasCapturedEntries);

        var work = new ObjectWork();
        var unobservedRoots = controlContext.NamingContexts.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var discovery = automaticDiscovery ? new SelfMembershipScheduler(discoveryBudget,
            scope.Value!.AllDeclaredDomainsAreComplete, attributes,
            bundle.Description.ForestFqdn, cancellationToken) : null;

        // TIER-0 DISCOVERY, WHICH DECIDES WHAT THE EXPENSIVE PASS BELOW WILL LOOK AT. Per decision
        // 0116 this reads the same captured owners and ACLs the detailed evaluators read, but only
        // to collect candidates - it invokes no evaluator and writes no control product. Without a
        // pinned derivation binding there is nothing to classify seeds against, so discovery does
        // not run and every object falls back to being assessed, which is the previous behaviour
        // rather than a silent claim that nothing mattered.
        var tier0Discovery = gated
            ? new Tier0DiscoveryScheduler(ownershipBinding!,
                scope.Value!.AllDeclaredDomainsAreComplete, attributes,
                subject => OwnershipAuditRun.Target(subject, namingContexts.Value), cancellationToken)
            : null;

        Entering(progress, log, JudgingPhase.EvaluatingObjects, 0);
        work.Pass.Start();
        progress.BeginOperation("order-descriptor-groups");
        work.Order.Start();
        using var descriptors = bundle.StreamDescriptorObjects(cancellationToken);
        work.Order.Stop();
        var permissionPreparation = new PermissionClassificationPreparation(descriptors, classificationSchema, writer.GenerationId);
        progress.BeginOperation("read-object");
        foreach (var subject in descriptors.Objects)
        {
            // Checked per object rather than per batch. A rule catalogue that has grown expensive
            // could spend a long time on one object, and a cancel that waits for the batch boundary
            // is a cancel the operator has to press twice to believe.
            cancellationToken.ThrowIfCancellationRequested();

            progress.BeginOperation("store-laps");
            work.Laps.Start();
            writer.WriteLapsInventory(subject);
            work.Laps.Stop();
            unobservedRoots.Remove(subject.DistinguishedName);
            progress.BeginOperation("read-permissions");
            work.Read.Start();
            var reading = descriptors.ReadPermissions(subject);
            var permissions = reading.Permissions;
            work.Read.Stop();

            // THE DESCRIPTOR RECORD IS WRITTEN FOR EVERY OBJECT; THE EDGES ARE NOT. Whether the
            // descriptor could be read is cheap and is the difference between "captured but not
            // assessed", "captured and unreadable" and "not captured at all" - three answers a
            // reader must be able to tell apart. Deriving the edges is the expensive part, and it
            // now waits until discovery has said whether this object is in scope.
            //
            // DERIVING AND STORING ARE CLOCKED SEPARATELY because they are the two halves any
            // optimisation must choose between, and one combined figure cannot say which.
            progress.BeginOperation("derive-control-edges");
            work.ControlDerive.Start();
            var edges = tier0Discovery is null
                ? ControlEdgeDeriver.Derive(subject,
                    permissions, controlContext, writer.GenerationId, derivationGeneration, domainSids)
                : ControlEdgeDeriver.Derive(subject,
                    permissions: null, controlContext, writer.GenerationId, derivationGeneration, domainSids)
                    with { DescriptorOutcome = DescriptorOutcome(permissions), Uncertainty = DescriptorUncertainty(permissions) };
            work.ControlDerive.Stop();
            progress.BeginOperation("store-control-edges");
            work.ControlWrite.Start();
            writer.WriteControlEdges(edges, OwnershipAuditRun.Target(subject, namingContexts.Value));
            work.ControlWrite.Stop();
            if (tier0Discovery is not null)
            {
                progress.BeginOperation("tier0-scan");
                work.Tier0Scan.Start();
                tier0Discovery.Observe(subject, permissions);
                work.Tier0Scan.Stop();
            }

            // REACHING A VERDICT AND STORING IT ARE CLOCKED SEPARATELY, and this is the split
            // P-249 has twice tried to optimise without ever measuring: two storage redesigns were
            // built and rejected while nothing here could say whether the cost was the verdicts or
            // the writing of them.
            progress.BeginOperation("classify-permissions");
            work.Verdicts.Start();
            var classified = permissionPreparation.Prepare(reading, writer.PermissionWrites, cancellationToken);
            work.Verdicts.Stop();
            progress.BeginOperation("store-permissions");
            work.StorePermissions.Start();
            writer.WritePermissionClassification(classified, cancellationToken);
            work.StorePermissions.Stop();
            progress.BeginOperation("membership-scan");
            work.MembershipScan.Start();
            discovery?.Observe(subject, permissions);
            work.MembershipScan.Stop();

            // Reuse only the exact lookup already performed for this object. Other names retain
            // the evidence reader's matching/ambiguity behavior; nothing survives this iteration.
            var objectContext = context.Permissions is { } readPermissions
                ? context with
                {
                    Permissions = dn => string.Equals(dn, subject.DistinguishedName, StringComparison.Ordinal)
                        ? permissions : readPermissions(dn),
                }
                : context;
            work.Rules.Start();
            foreach (var tally in tallies)
            {
                progress.BeginRule(tally.RuleId);
                try { tally.Offer(subject, objectContext); }
                finally { progress.EndRule(tally.RuleId, tally.Elapsed, tally.Judged, tally.NotApplicable); }
            }
            work.Rules.Stop();

            progress.BeginOperation("commit");
            work.Commit.Start();
            writer.CompleteObject();
            work.Commit.Stop();

            objectsRead++;
            progress.CompleteObject(objectsRead);

            if (objectsRead % ProgressEvery == 0)
                progress.Report(new JudgingProgress(objectsRead)
                {
                    Tier0ObjectsObserved = tier0Discovery?.Observed.Count ?? 0,
                    Tier0DiscoveryElapsed = work.Tier0Scan.Elapsed,
                });

            // Copy detailed totals only on the worker thread. The independent status/rule timer
            // keeps reporting the active operation if this safe boundary cannot be reached.
            if (progress.AccountingDue())
            {
                progress.BeginOperation("write-accounting");
                work.Note(log, JudgePhase, objectsRead);
                writer.PermissionWrites.Note(log, JudgePhase);
            }
            progress.BeginOperation("read-object");
        }

        descriptors.Dispose();
        log.Note(JudgePhase, "descriptor preparation", [
            new RunLogDetail("preparedDescriptors", descriptors.PreparedDescriptors.ToString(CultureInfo.InvariantCulture)),
            new RunLogDetail("preparedEntries", descriptors.PreparedEntries.ToString(CultureInfo.InvariantCulture)),
            new RunLogDetail("classifiedDescriptors", permissionPreparation.ClassifiedDescriptors.ToString(CultureInfo.InvariantCulture)),
            new RunLogDetail("classifiedEntries", permissionPreparation.ClassifiedEntries.ToString(CultureInfo.InvariantCulture)),
            new RunLogDetail("orderingMs", ((long)work.Order.Elapsed.TotalMilliseconds).ToString(CultureInfo.InvariantCulture)),
            new RunLogDetail("orderingTemporaryBytes", descriptors.OrderingTemporaryBytes.ToString(CultureInfo.InvariantCulture)),
        ]);

        progress.BeginOperation("commit");
        work.Commit.Start();
        writer.FlushObjects();
        work.Commit.Stop();

        progress.BeginOperation("complete-laps");
        work.LapsComplete.Start();
        writer.CompleteLapsInventory();
        work.LapsComplete.Stop();
        progress.BeginOperation("complete-permissions");
        work.ClosePermissions.Start();
        writer.CompletePermissionClassifications(objectsRead);
        work.ClosePermissions.Stop();

        progress.BeginOperation("unobserved-roots");
        work.UnobservedRoots.Start();
        foreach (var root in unobservedRoots.Order(StringComparer.Ordinal))
            writer.WriteControlEdges(new(root, null, null, "DescriptorNotRead",
                ControlUncertainty.ReplicationRootNotEstablished | ControlUncertainty.DescriptorUnreadable, []),
                new Tier0Target(null, root, root, null, null, null));
        writer.FlushObjects();
        work.UnobservedRoots.Stop();
        work.Pass.Stop();
        work.Note(log, JudgePhase, objectsRead);
        writer.PermissionWrites.Note(log, JudgePhase);

        // The last report is unconditional, so a run that ends between two reports does not leave
        // the operator looking at a count short of what was actually read. The discovery figures
        // travel with it for the same reason: a capture smaller than one reporting interval would
        // otherwise finish a scan the screen never mentioned.
        progress.Report(new JudgingProgress(objectsRead)
        {
            Tier0ObjectsObserved = tier0Discovery?.Observed.Count ?? 0,
            Tier0DiscoveryElapsed = work.Tier0Scan.Elapsed,
        });
        if (tier0Discovery is not null)
        {
            Entering(progress, log, JudgingPhase.SelectingOwnershipScope, objectsRead);
            var admitted = writer.AdmitDiscoveredScope(bundle, ownershipDescription, memberInput, ownershipBinding!,
                tier0Discovery, controlContext, domainSids, derivationGeneration, cancellationToken, progress);
            log.Note(JudgePhase, "tier0-discovery",
            [
                new RunLogDetail("scan-ms", ((long)work.Tier0Scan.Elapsed.TotalMilliseconds).ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("candidates", tier0Discovery.Coverage().CandidatesDiscovered.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("admitted", admitted.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("objects", objectsRead.ToString(CultureInfo.InvariantCulture)),
            ]);
        }
        writer.AssessAutomaticOwnership(bundle, ownershipDescription, memberInput, ownershipBinding, controlContext,
            domainSids, objectsRead, progress, log, cancellationToken, scopeAlreadyPlanned: tier0Discovery is not null);
        writer.CompleteControlEdges();

        if (memberInput is not null && memberBudget is not null)
        {
            Entering(progress, log, JudgingPhase.AttributingMembers, objectsRead);
            var memberWatch = System.Diagnostics.Stopwatch.StartNew();
            writer.WriteMemberAttributions(memberInput, memberBudget, bundle.Description.ForestFqdn, namingContexts.Value, cancellationToken);
            log.Note("MemberAttribution", "finished", [new RunLogDetail("elapsedMs",
                memberWatch.Elapsed.TotalMilliseconds.ToString("F1", CultureInfo.InvariantCulture))]);
        }

        // ORDERED BY TARGET FIRST, WHICH IS A PERFORMANCE DECISION AND NOTHING ELSE. Every question
        // about one group needs that group's permissions and its stored control edges, and both are
        // reads that cost the same whether one requester is asked or four hundred. Grouping the
        // questions by target means each is fetched once and reused while that target is in hand,
        // so the caches below stay a single slot rather than growing with the forest.
        //
        // Measured 2026-09-07 on synthetic captures before this change: 10,000 objects with 25,000
        // account/group pairs cost 211 seconds of discovery, and the cost per pair rose from 2.2 ms
        // to 8.5 ms as the work grew - the same target's evidence was being re-read once per
        // question. The answers were never affected: this changes the order rows are written in,
        // not what any of them says.
        Entering(progress, log, JudgingPhase.EvaluatingRequesters, objectsRead);
        string? loadedTarget = null;
        ObjectPermissions? loadedPermissions = null;
        var loadedEdges = new Dictionary<string, IReadOnlyList<long>>(StringComparer.Ordinal);

        // WHERE THE REQUESTER PHASE SPENT ITS TIME, WRITTEN TO THE RUN LOG. Recorded rather than
        // guessed: two rounds of optimisation were aimed at the wrong half of this loop before
        // anything measured which half was expensive. A run that takes an unexpected hour should
        // leave behind the reason, per docs/decisions/0088.
        var readWatch = new System.Diagnostics.Stopwatch();
        var assessWatch = new System.Diagnostics.Stopwatch();
        var writeWatch = new System.Diagnostics.Stopwatch();
        var assessed = 0L;

        foreach (var request in (discovery?.Requests() ?? selfMembershipRequests)
            .DistinctBy(value => (value.RequesterDn.ToUpperInvariant(), value.TargetDn.ToUpperInvariant(), value.Operation,
                (value.MemberDn ?? string.Empty).ToUpperInvariant()))
            .OrderBy(value => value.TargetDn, StringComparer.OrdinalIgnoreCase)
            .ThenBy(value => value.RequesterDn, StringComparer.OrdinalIgnoreCase)
            .ThenBy(value => value.Operation)
            .ThenBy(value => value.MemberDn ?? string.Empty, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (loadedTarget is null || !string.Equals(loadedTarget, request.TargetDn, StringComparison.OrdinalIgnoreCase))
            {
                readWatch.Start();
                loadedTarget = request.TargetDn;
                loadedPermissions = bundle.ReadPermissions(request.TargetDn);
                loadedEdges.Clear();
                readWatch.Stop();
            }

            assessWatch.Start();
            var requester = attributes(request.RequesterDn);
            var target = attributes(request.TargetDn);
            var member = attributes(request.MemberDn ?? request.RequesterDn);
            var assessment = SelfMembershipEvaluator.Assess(request, requester, target, member,
                loadedPermissions, trustee => trustee.DistinguishedName is { } dn ? attributes(dn) : null,
                bundle.Description.ForestFqdn, seal.Hash,
                writer.GenerationId, derivationGeneration, selfMembershipBudget, []);
            assessWatch.Stop();
            var possibleSids = assessment.Evidence.Where(item => item.Trustee.State != RequesterTrusteeState.DoesNotMatch)
                .Select(item => item.Entry.Trustee.Sid == "S-1-5-10" ? assessment.TargetSid : item.Entry.Trustee.Sid)
                .Where(sid => sid is not null).Cast<string>();

            // Keyed on the trustees this answer actually matched, because two requesters on one
            // group commonly match the same entries and would otherwise repeat an identical query.
            writeWatch.Start();
            var sids = possibleSids.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).ToArray();
            var key = string.Join('\u0000', sids);
            if (!loadedEdges.TryGetValue(key, out var edges))
            {
                edges = writer.SelfMembershipEdgeIds(request.TargetDn, sids);
                loadedEdges[key] = edges;
            }

            writer.WriteSelfMembershipAssessment(assessment with
            {
                HolderEdgeIds = edges,
            });
            writeWatch.Stop();
            assessed++;
        }
        writer.CompleteSelfMembershipAssessments(discovery?.Coverage());

        if (assessed > 0)
        {
            log.Note(JudgePhase, "self-membership",
            [
                new RunLogDetail("answers", assessed.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("scan-ms", ((long)work.MembershipScan.Elapsed.TotalMilliseconds).ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("read-ms", ((long)readWatch.Elapsed.TotalMilliseconds).ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("assess-ms", ((long)assessWatch.Elapsed.TotalMilliseconds).ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("write-ms", ((long)writeWatch.Elapsed.TotalMilliseconds).ToString(CultureInfo.InvariantCulture)),
            ]);
        }

        Entering(progress, log, JudgingPhase.WritingFindings, objectsRead);
        foreach (var tally in tallies)
            writer.Write(tally.ToExecution());

        var pathWatch = new System.Diagnostics.Stopwatch();
        PathRequesterWorkPhase? pathPhase = null;
        void RecordPathPhase(bool completed)
        {
            if (pathPhase is not { } phase) return;
            log.Note(JudgePhase, "path-requester-phase",
            [
                new("generation", writer.GenerationId.ToString("D")), new("phase", phase.ToString()),
                new("selection-requested", offlineSelection.ToString(CultureInfo.InvariantCulture)),
                new("completed", completed.ToString(CultureInfo.InvariantCulture)),
                new("ms", pathWatch.Elapsed.TotalMilliseconds.ToString("F1", CultureInfo.InvariantCulture)),
            ]);
        }
        void BeginPathPhase(PathRequesterWorkPhase phase)
        {
            RecordPathPhase(completed: true);
            pathPhase = null;
            cancellationToken.ThrowIfCancellationRequested();
            pathPhase = phase;
            pathWatch.Restart();
            progress.Report(new JudgingProgress(objectsRead) { Phase = JudgingPhase.WritingFindings,
                RequesterPhase = phase, JudgementGenerationId = writer.GenerationId });
            cancellationToken.ThrowIfCancellationRequested();
        }
        var pathsCompleted = false;
        try
        {
            writer.CalculateTier0Paths(ownershipDescription, requesterQuestions.Values.ToArray(), ownAccountQuestions.Values.ToArray(),
                cancellationToken, membershipDaclQuestions.Values.ToArray(), offlineSelection, BeginPathPhase);
            pathsCompleted = true;
        }
        finally
        {
            RecordPathPhase(pathsCompleted);
        }

        cancellationToken.ThrowIfCancellationRequested();
        Entering(progress, log, JudgingPhase.PublishingJudgement, objectsRead);
        writer.Complete(DateTimeOffset.UtcNow, cancellationToken);
        progress.PublicationCompleted();

        var state = scope.Value!.AllDeclaredDomainsAreComplete
            && tallies.All(t => t.Outcome == RuleExecutionOutcome.Succeeded)
            ? JudgementRunState.Completed
            : JudgementRunState.CompletedDegraded;

        // A rule that could not reach a verdict is named rather than counted. Which rule stopped is
        // the question an operator asks next, and a tally of failures does not answer it.
        foreach (var unfinished in tallies.Where(t => t.Outcome != RuleExecutionOutcome.Succeeded))
        {
            log.Note(
                JudgePhase,
                "a rule did not reach a verdict on every object",
                [
                    new RunLogDetail("rule", unfinished.RuleId),
                    new RunLogDetail("outcome", unfinished.Outcome.ToString()),
                ]);
        }

        // ONE LINE PER RULE, SLOWEST FIRST, and the reason is the predecessor's own record: in
        // large production it found "LDAP capture may take ~30 minutes while analysis is the long
        // phase", and until now nothing here could say which rule that time belonged to. The
        // judged count travels beside the time because the two are only meaningful together - a
        // rule that took four minutes over eighty thousand objects is working, and one that took
        // four minutes over none is broken.
        foreach (var tally in tallies.OrderByDescending(t => t.Elapsed))
        {
            log.Note(
                JudgePhase,
                "a rule finished",
                [
                    new RunLogDetail("rule", tally.RuleId),
                    new RunLogDetail("outcome", tally.Outcome.ToString()),
                    new RunLogDetail(
                        "judged", tally.Judged.ToString(CultureInfo.InvariantCulture)),
                    new RunLogDetail(
                        "notAbout", tally.NotApplicable.ToString(CultureInfo.InvariantCulture)),
                    new RunLogDetail(
                        "ms",
                        ((long)tally.Elapsed.TotalMilliseconds).ToString(
                            CultureInfo.InvariantCulture)),
                ]);
        }

        log.Note(
            JudgePhase,
            "finished",
            [
                new RunLogDetail("state", state.ToString()),
                new RunLogDetail("objects", objectsRead.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail(
                    "ruleMs",
                    ((long)tallies.Sum(t => t.Elapsed.TotalMilliseconds)).ToString(
                        CultureInfo.InvariantCulture)),
            ]);

        // HANDED OUT BECAUSE NOTHING PERSISTS IT. The judgement records what each rule concluded;
        // how long each took, and where the object pass spent its time, are known here and nowhere
        // afterwards - and the per-phase breakdown is the thing P-257 was found with.
        account.ObjectsJudged = objectsRead;
        account.Phases = work.Timings();
        account.Rules =
        [
            .. tallies
                .OrderByDescending(tally => tally.Elapsed)
                .Select(tally => new RuleTiming(
                    tally.RuleId,
                    tally.Outcome.ToString(),
                    tally.Judged,
                    tally.NotApplicable,
                    (long)tally.Elapsed.TotalMilliseconds)),
        ];

        return state;
    }

    /// <summary>The name the judging coordinator logs under.</summary>
    private const string JudgePhase = "Judge";

    /// <summary>
    /// Progress for a judging nobody is watching.
    /// </summary>
    /// <remarks>
    /// <b>Named rather than defaulted.</b> A caller that passes this has said it has no operator to
    /// tell; a caller that passed nothing would only have said it did not think about it, and gate
    /// 1 exists because that is how the predecessor's progress reporting went unused.
    /// </remarks>
    public static IProgress<JudgingProgress> NobodyIsWatching { get; } = new Unwatched();

    /// <summary>Discards what it is told.</summary>
    private sealed class Unwatched : IProgress<JudgingProgress>
    {
        public void Report(JudgingProgress value)
        {
            // Nobody is watching, by the caller's own statement.
        }
    }

    /// <summary>
    /// Reports a phase to the operator watching and to the run log, in one act.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Both, or neither.</b> Every phase already reached <see cref="IProgress{T}"/> and none
    /// reached the log, which on 2026-09-24 left an eight-hour production judging with a single
    /// line - <i>Started, rules=17</i> - and an operator with no way to tell work from a hang.
    /// Reporting through one call is what stops the two drifting apart again: a phase added later
    /// cannot reach a screen and miss the artefact that outlives it.
    /// </para>
    /// <para>
    /// <b>The log is not a second screen.</b> It is what survives a cancelled run, a closed window
    /// and a machine walked away from, and it is the only account of a judging that did not finish.
    /// A line per phase is nine lines in a run measured in hours, so nothing here is written per
    /// object.
    /// </para>
    /// <para>
    /// <b>A phase name says where judging has got to, never what it concluded.</b>
    /// <c>WritingFindings</c> means the writing is under way; whether a judgement was published is
    /// <see cref="JudgementWriter.Complete"/>'s to say, as the remark on
    /// <see cref="JudgingProgress.Phase"/> records.
    /// </para>
    /// </remarks>
    internal static void Entering(
        IProgress<JudgingProgress> progress, IRunLog log, JudgingPhase phase, long objectsRead)
    {
        progress.Report(new JudgingProgress(objectsRead) { Phase = phase });
        log.Note(JudgePhase, "phase", [new RunLogDetail("name", phase.ToString())]);
    }

    /// <summary>
    /// How many objects pass between progress reports.
    /// </summary>
    /// <remarks>
    /// Screen notifications keep their existing cadence. Log status has its own timer and does
    /// not wait for these notifications, which may be hours apart during an expensive rule.
    /// </remarks>
    private const int ProgressEvery = 1_000;

    /// <summary>
    /// Wraps a lookup so it is asked once per distinct argument for the life of a judging.
    /// </summary>
    /// <remarks>
    /// <b>Safe because nothing being read changes while a judging runs.</b> The evidence is sealed
    /// and the derivation is already written, so a second answer could only ever repeat the first.
    /// What it saves is real: a rule asks about the same delegated group once per object, and an
    /// organisational unit holding a hundred thousand computers means a hundred thousand identical
    /// questions.
    /// </remarks>
    private static Func<string, string?> Memoised(Func<string, string?> lookup)
    {
        var known = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        return argument =>
        {
            if (known.TryGetValue(argument, out var answer))
                return answer;

            answer = lookup(argument);
            known[argument] = answer;
            return answer;
        };
    }

    private static Func<string, T> Memoised<T>(Func<string, T> lookup)
    {
        var known = new Dictionary<string, T>(StringComparer.OrdinalIgnoreCase);
        return argument =>
        {
            if (known.TryGetValue(argument, out var answer)) return answer;
            answer = lookup(argument);
            known[argument] = answer;
            return answer;
        };
    }

    private static Result<JudgementRunState> Failure(
        string reason, string description, string context) =>
        Result<JudgementRunState>.Failure(
            AuditError.Create(
                ErrorCategory.Evidence, reason, ErrorSeverity.Failed, description, context));

    /// <summary>
    /// Whether the descriptor was read, for an object whose edges discovery has not asked for.
    /// </summary>
    /// <remarks>
    /// An unassessed object must not be recorded as though its descriptor were missing. "Nothing
    /// looked at this" and "this could not be read" are different answers, and only the second is a
    /// gap in the evidence.
    /// </remarks>
    private static string DescriptorOutcome(ObjectPermissions? permissions) => permissions is null
        || permissions.Availability != DescriptorAvailability.Read ? "DescriptorNotRead"
        : permissions.DaclState == DaclState.Unreadable ? "DescriptorNotRead" : "NotAssessed";

    private static ControlUncertainty DescriptorUncertainty(ObjectPermissions? permissions) => permissions is null
        || permissions.Availability != DescriptorAvailability.Read || permissions.DaclState == DaclState.Unreadable
        ? ControlUncertainty.DescriptorUnreadable
        : permissions.DaclCompleteness != DaclCompleteness.Complete ? ControlUncertainty.DescriptorIncomplete
        : ControlUncertainty.None;

    /// <summary>
    /// Where the object pass spent its time, in buckets that do not contain one another.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The rules were already clocked, and they were not the answer.</b> The offline
    /// reproduction of the reported 108-second audit spent 115.12 s in object processing, of which
    /// the per-rule clocks accounted for 7.03 s. The remaining interval was measured by nothing at
    /// all, and two saved-permission storage redesigns were built and rejected while aimed into it.
    /// </para>
    /// <para>
    /// <b>Flat, never nested.</b> An earlier diagnostic ledger attributed 16.26 s of a 27.69 s run
    /// to permission storage "including nested work", which cannot be added to anything else and so
    /// settled nothing. Each watch here brackets one call, no bucket contains another, and the
    /// figures are therefore meant to be summed.
    /// </para>
    /// <para>
    /// <b>Whatever is left over is printed as its own line.</b> An unexplained interval is the
    /// finding; absorbing it into the nearest bucket is how it stayed unexplained for eight
    /// sessions. <see cref="Pass"/> brackets the entire pass, so the remainder is exact.
    /// </para>
    /// <para>
    /// <b>Cost.</b> Two counter reads per bucket per object, on the same argument the per-rule
    /// clocks already make: a few million reads across a forest of 347,000 objects, against a phase
    /// measured in minutes.
    /// </para>
    /// </remarks>
    private sealed class ObjectWork
    {
        /// <summary>The whole pass, against which every other bucket is accounted.</summary>
        public System.Diagnostics.Stopwatch Pass { get; } = new();

        /// <summary>Creating the temporary descriptor-group order; sidecar reads remain in the pass.</summary>
        public System.Diagnostics.Stopwatch Order { get; } = new();

        /// <summary>Preparing each captured descriptor and binding its permissions to each object.</summary>
        public System.Diagnostics.Stopwatch Read { get; } = new();

        /// <summary>Reaching and validating per-right verdicts and fingerprints once per descriptor.</summary>
        public System.Diagnostics.Stopwatch Verdicts { get; } = new();

        /// <summary>Storing those verdicts. The half P-249 exists to make cheaper.</summary>
        public System.Diagnostics.Stopwatch StorePermissions { get; } = new();

        /// <summary>Deriving one object's control edges.</summary>
        public System.Diagnostics.Stopwatch ControlDerive { get; } = new();

        /// <summary>Storing those control edges.</summary>
        public System.Diagnostics.Stopwatch ControlWrite { get; } = new();

        /// <summary>Collecting Tier 0 candidates, previously the only clocked part of this loop.</summary>
        public System.Diagnostics.Stopwatch Tier0Scan { get; } = new();

        /// <summary>Collecting self-membership candidates.</summary>
        public System.Diagnostics.Stopwatch MembershipScan { get; } = new();

        /// <summary>Offering the object to every rule. The per-rule lines break this down further.</summary>
        public System.Diagnostics.Stopwatch Rules { get; } = new();

        /// <summary>Writing the LAPS inventory row for one object.</summary>
        public System.Diagnostics.Stopwatch Laps { get; } = new();

        /// <summary>Closing the LAPS inventory once every object has been offered.</summary>
        public System.Diagnostics.Stopwatch LapsComplete { get; } = new();

        /// <summary>Closing the saved permission classifications.</summary>
        public System.Diagnostics.Stopwatch ClosePermissions { get; } = new();

        /// <summary>Recording naming contexts no streamed object accounted for.</summary>
        public System.Diagnostics.Stopwatch UnobservedRoots { get; } = new();

        /// <summary>Committing the batched transaction the object writes share.</summary>
        public System.Diagnostics.Stopwatch Commit { get; } = new();

        /// <summary>Writes one line per bucket, slowest first, then the accounting line.</summary>
        /// <param name="log">The run log this judging is writing to.</param>
        /// <param name="phase">The phase name the judging coordinator logs under.</param>
        /// <param name="objects">How many objects the pass read, so a bucket can be read per object.</param>
        public void Note(IRunLog log, string phase, long objects)
        {
            var buckets = Buckets();

            foreach (var bucket in buckets.OrderByDescending(b => b.Elapsed))
            {
                log.Note(
                    phase,
                    "object work",
                    [
                        new RunLogDetail("part", bucket.Part),
                        new RunLogDetail("ms", Milliseconds(bucket.Elapsed)),
                    ]);
            }

            // THE SUM AND THE WHOLE, SIDE BY SIDE. A breakdown that does not say what it failed to
            // account for invites the reader to assume it accounted for everything.
            var measured = buckets.Aggregate(TimeSpan.Zero, (total, bucket) => total + bucket.Elapsed);
            log.Note(
                phase,
                "object work accounted",
                [
                    new RunLogDetail("passMs", Milliseconds(Pass.Elapsed)),
                    new RunLogDetail("measuredMs", Milliseconds(measured)),
                    new RunLogDetail("unaccountedMs", Milliseconds(Pass.Elapsed - measured)),
                    new RunLogDetail("objects", objects.ToString(CultureInfo.InvariantCulture)),
                ]);
        }

        private static string Milliseconds(TimeSpan value) =>
            ((long)value.TotalMilliseconds).ToString(CultureInfo.InvariantCulture);

        /// <summary>
        /// Where the object pass spent its time, slowest first, beside what it failed to account
        /// for.
        /// </summary>
        /// <remarks>
        /// <b>The same buckets the log gets, from the same list.</b> The portable summary and the
        /// run log are two readers of one breakdown; building a second list for the summary would
        /// be two accounts of where a judging's time went, and the first sign of them disagreeing
        /// would be a customer holding figures the log cannot reproduce.
        /// </remarks>
        /// <returns>One timing per bucket, then the interval nothing measured.</returns>
        public IReadOnlyList<StageTiming> Timings()
        {
            var buckets = Buckets();
            var measured = buckets.Aggregate(TimeSpan.Zero, (total, bucket) => total + bucket.Elapsed);

            return
            [
                .. buckets
                    .OrderByDescending(bucket => bucket.Elapsed)
                    .Select(bucket => new StageTiming(bucket.Part, (long)bucket.Elapsed.TotalMilliseconds)),

                // AN UNEXPLAINED INTERVAL IS THE FINDING, and absorbing it into the nearest bucket
                // is how it stayed unexplained for eight sessions. It travels with the breakdown
                // rather than being left for a reader to subtract.
                new StageTiming("unaccounted", (long)(Pass.Elapsed - measured).TotalMilliseconds),
            ];
        }

        /// <summary>The flat, never-nested buckets the pass measured, in a fixed order.</summary>
        private (string Part, TimeSpan Elapsed)[] Buckets() =>
        [
            ("order-descriptor-groups", Order.Elapsed),
            ("read-permissions", Read.Elapsed),
            ("classify-permissions", Verdicts.Elapsed),
            ("store-permissions", StorePermissions.Elapsed),
            ("derive-control-edges", ControlDerive.Elapsed),
            ("store-control-edges", ControlWrite.Elapsed),
            ("tier0-scan", Tier0Scan.Elapsed),
            ("membership-scan", MembershipScan.Elapsed),
            ("rules", Rules.Elapsed),
            ("commit", Commit.Elapsed),
            ("store-laps", Laps.Elapsed),
            ("complete-laps", LapsComplete.Elapsed),
            ("complete-permissions", ClosePermissions.Elapsed),
            ("unobserved-roots", UnobservedRoots.Elapsed),
        ];
    }

    /// <summary>
    /// What one rule has made of the objects offered to it so far.
    /// </summary>
    /// <remarks>
    /// <b>Counted as it goes rather than derived at the end.</b> The objects are streamed and gone,
    /// so anything not counted while an object is in hand cannot be recovered without reading the
    /// bundle again.
    /// </remarks>
    private sealed class Tally(IRule rule)
    {
        private readonly List<Finding> _findings = [];
        private readonly Dictionary<string, int> _missing = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// How long this rule has spent being offered objects.
        /// </summary>
        /// <remarks>
        /// <b>The open half of P-193, and the predecessor says it is the half that matters.</b> Its
        /// own notes record that in large production "LDAP capture may take ~30 minutes while
        /// analysis is the long phase", and nothing in this product has ever said which rule that
        /// time went to. Two counter reads per object per rule - about 12 million across a forest of
        /// 347,000 - cost well under a second against a phase measured in hours.
        /// </remarks>
        private readonly System.Diagnostics.Stopwatch _clock = new();

        private int _judged;
        private int _notApplicable;
        private int _notJudged;
        private string? _error;

        public RuleExecutionOutcome Outcome =>
            _error is not null ? RuleExecutionOutcome.Error
            : _notJudged > 0 ? RuleExecutionOutcome.Indeterminate
            : RuleExecutionOutcome.Succeeded;

        /// <summary>Which rule this is tallying, so a log line can name it.</summary>
        public string RuleId => rule.Definition.Id;

        /// <summary>How long this rule took, across every object it was offered.</summary>
        public TimeSpan Elapsed => _clock.Elapsed;

        /// <summary>How many objects this rule actually judged, as opposed to filtered out.</summary>
        public int Judged => _judged;

        /// <summary>How many objects were not this rule's concern.</summary>
        public int NotApplicable => _notApplicable;

        /// <summary>
        /// Offers one object to the rule, unless it has already thrown or the rule is not about
        /// objects of this kind.
        /// </summary>
        /// <remarks>
        /// <b>An object the rule is not about is counted apart and never offered.</b> It is not a
        /// gap in the evidence, and treating it as one told an operator that three objects in four
        /// of a real forest were unreadable.
        /// </remarks>
        /// <param name="subject">The object to judge.</param>
        /// <param name="context">
        /// The reference time, and the derived facts - which are empty for an Evidence-only
        /// judging.
        /// </param>
        public void Offer(ObjectAttributes subject, JudgingContext context)
        {
            if (_error is not null)
                return;

            // THE FILTER IS INSIDE THE CLOCK, deliberately. IsAbout runs on every object for every
            // rule and a costly one is a costly rule, whatever it goes on to judge. The judged count
            // travels with the time on the log line so a rule that examined nothing cannot read as
            // one that did.
            _clock.Start();

            try
            {
                Judge(subject, context);
            }
            finally
            {
                _clock.Stop();
            }
        }

        private void Judge(ObjectAttributes subject, JudgingContext context)
        {
            if (!rule.Definition.IsAbout(subject))
            {
                _notApplicable++;
                return;
            }

            RuleVerdict verdict;

            try
            {
                verdict = rule.Judge(subject, context);
            }
            catch (Exception error) when (error is not OutOfMemoryException
                                              and not StackOverflowException)
            {
                // A rule is code, and code has defects. One that throws is a fact about this
                // product rather than about the forest, and it must not take the rules beside it
                // down - so it is recorded, its partial findings are dropped, and it is offered
                // nothing further.
                _error = error.ToString();
                _findings.Clear();
                _judged = 0;
                _notApplicable = 0;
                _notJudged = 0;
                _missing.Clear();
                return;
            }

            // An unresolved part of an answer does not erase its established findings. A thrown
            // rule still loses everything above; partial evidence is not a thrown rule (0108).
            _findings.AddRange(verdict.Findings);
            if (verdict.IsComplete)
            {
                _judged++;
                return;
            }

            _notJudged++;

            foreach (var attribute in verdict.InputsNotCaptured)
                _missing[attribute] = _missing.GetValueOrDefault(attribute) + 1;

            // Counted in the same table as a missing attribute, under a token that names the kind
            // and the reason. The store already groups these by name, and a second table would let
            // one report a judging as complete while the other disagreed.
            foreach (var unresolved in verdict.Unresolved)
                _missing[unresolved.Token] = _missing.GetValueOrDefault(unresolved.Token) + 1;
        }

        public RuleExecution ToExecution() =>
            _error is not null
                ? RuleExecution.Threw(rule.Definition, _error)
                : new RuleExecution(
                    rule.Definition,
                    Outcome,
                    _judged,
                    _notApplicable,
                    _notJudged,
                    [.. _missing
                        .OrderBy(m => m.Key, StringComparer.OrdinalIgnoreCase)
                        .Select(m => new MissingInput(m.Key, m.Value))],
                    _findings,
                    null);
    }
}
