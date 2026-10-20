using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Storage;

namespace SecureAD.Judgement;

/// <summary>
/// What one judging concluded, read back.
/// </summary>
/// <param name="EvidenceSeal">The capture this was judged against.</param>
/// <param name="GenerationId">The immutable Judgement generation selected by its manifest.</param>
/// <param name="DerivationGenerationId">The Derivation generation consumed, or null for Evidence-only judging.</param>
/// <param name="State">What became of the judging.</param>
/// <param name="EvaluationAsOf">The reference time temporal rules were evaluated against.</param>
/// <param name="StartedUtc">When judging started.</param>
/// <param name="CompletedUtc">When it finished.</param>
public sealed record JudgementDescription(
    string EvidenceSeal,
    Guid GenerationId,
    Guid? DerivationGenerationId,
    JudgementRunState State,
    DateTimeOffset EvaluationAsOf,
    DateTimeOffset StartedUtc,
    DateTimeOffset CompletedUtc);

/// <summary>
/// One rule's execution, read back, without the findings it produced.
/// </summary>
/// <param name="RuleId">The rule.</param>
/// <param name="RuleVersion">The version of its logic that ran.</param>
/// <param name="Outcome">What became of it.</param>
/// <param name="ObjectsJudged">Objects it reached a verdict on.</param>
/// <param name="ObjectsNotJudged">Objects it could not.</param>
/// <param name="MissingInputs">The declared attributes that were absent.</param>
/// <param name="FindingsProduced">
/// How many findings this rule wrote.
/// <para>
/// <b>Zero is not the same claim as a rule that could not run</b>, which is why it is carried
/// beside the outcome rather than inferred from an empty grid. A rule that judged every object it
/// was about and reported nothing has established something; one recorded as
/// <see cref="RuleExecutionOutcome.Indeterminate"/> has not, and both write zero findings.
/// </para>
/// </param>
/// <param name="Error">Why it threw, when it did.</param>
public sealed record StoredRuleExecution(
    string RuleId,
    int RuleVersion,
    RuleExecutionOutcome Outcome,
    int ObjectsJudged,
    int ObjectsNotApplicable,
    int ObjectsNotJudged,
    IReadOnlyList<MissingInput> MissingInputs,
    int FindingsProduced,
    string? Error);

/// <summary>
/// What every scheduled rule did to one bundle, without the findings they produced.
/// </summary>
/// <remarks>
/// <para>
/// <b>A container rather than a bare list, because the empty list has two meanings.</b> No
/// executions can mean a bundle nobody judged, or a judging that opened and recorded nothing before
/// it stopped. A screen handed a bare list would draw the same thing for both and an operator would
/// read either as "no rules apply here".
/// </para>
/// <para>
/// <b>It carries the run's state so the reason is available where the list is.</b> Until now the
/// executions could only be had through <see cref="StoredJudgement"/>, which says this in the same
/// way; reading them on their own would have removed that statement from the one caller who needs
/// it most - the screen whose whole subject is what was and was not checked.
/// </para>
/// </remarks>
/// <param name="Executions">Every rule that was scheduled, and what became of it.</param>
/// <param name="State">What became of the judging as a whole.</param>
public sealed record StoredRuleExecutions(
    IReadOnlyList<StoredRuleExecution> Executions,
    JudgementRunState State)
{
    /// <summary>
    /// Whether this bundle was never judged, so an empty list says nothing about the rules.
    /// </summary>
    public bool DidNotRun => Executions.Count == 0;
}

/// <summary>
/// Everything one judging concluded: what it found, and which rules were run to produce it.
/// </summary>
/// <remarks>
/// <para>
/// <b>The second list is why this type exists.</b> A list of findings on its own cannot say whether
/// anyone looked: no findings and no rules run means a bundle nobody judged, and no findings beside
/// rules that did run means a forest where nothing matched. Those are opposite answers to the
/// question a customer is actually asking, and a bare list of findings hands both to a screen in
/// the same shape.
/// </para>
/// <para>
/// <b>And the rules are executions rather than names</b>, because a rule that ran and could not read
/// its inputs has not established anything either. Counting it among the rules that ran, with no
/// more said, would be the same failure one level further in.
/// </para>
/// </remarks>
/// <param name="Description">What the judging recorded about itself.</param>
/// <param name="RulesRun">Every rule that was scheduled, and what became of it.</param>
/// <param name="Findings">What was found. Empty is meaningful only beside <paramref name="RulesRun"/>.</param>
internal sealed record StoredJudgement(
    JudgementDescription Description,
    IReadOnlyList<StoredRuleExecution> RulesRun,
    IReadOnlyList<Finding> Findings)
{
    /// <summary>
    /// Whether this bundle was never judged, so an empty finding list says nothing about the
    /// forest.
    /// </summary>
    public bool DidNotRun => RulesRun.Count == 0;

    /// <summary>
    /// Whether every scheduled rule reached a verdict on everything it was offered.
    /// </summary>
    /// <remarks>
    /// <b>False means the findings are a floor, not a total.</b> Somewhere a rule could not read
    /// what it declared, so the forest has not been shown to be clean of what that rule looks for.
    /// </remarks>
    public bool EveryRuleReachedEveryVerdict =>
        RulesRun.Count > 0
        && RulesRun.All(r => r.Outcome == RuleExecutionOutcome.Succeeded);
}

/// <summary>
/// Reads a judgement store back, and refuses one that does not belong to the bundle it sits in.
/// </summary>
/// <remarks>
/// <para>
/// <b>Opening checks three things, and each is a different way of being wrong.</b> The seal says
/// whether these bytes are the bytes that were written. The schema version says whether this build
/// understands the tables. The evidence fingerprint says whether this judgement is about
/// <i>this capture</i> - and that is the one no amount of care by the writer can establish, because
/// a store is an ordinary file that can be moved.
/// </para>
/// <para>
/// <b>The fingerprint check is the reason a judgement may be copied at all.</b> Two captures of one
/// forest produce directories with identical file names holding mostly the same objects, so a
/// judgement dropped into the wrong bundle would resolve nearly all of its findings and be wrong
/// about every one of them. Refusing here turns a silent wrong answer into a stated one.
/// </para>
/// </remarks>
public sealed partial class JudgementReader : IDisposable
{
    private readonly SqliteConnection _connection;
    private string? _findingDerivationSeal;
    private ProtectedStoreFile.Lease? _protection;
    private ProtectedStoreFile? _ownedStore;
    private StoreRootManifest? _publicationRoot;
    private CancellationToken _readCancellation;
    private readonly HashSet<StoreSegmentRole> _openedParts = [];
    private sealed class BrowseCache
    {
        internal readonly Dictionary<ControlEdgeStorage.Question, ControlEdgeStorage.Counts> Controls = [];
        internal readonly Dictionary<GroupInventoryQuery, int> Groups = [];
        internal readonly Dictionary<(string Container, ListingScope Scope), IReadOnlyDictionary<LapsManagement, int>> Laps = [];
        internal FindingsFilterValues? Filters;
    }
    // A new connection must not repeat counts already answered under the same file protection.
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<ProtectedStoreFile, BrowseCache> BrowseCaches = new();
    private BrowseCache _browsing = new();
    private bool _disposed;

    private JudgementReader(
        string bundleDirectory, SqliteConnection connection, JudgementDescription description)
    {
        BundleDirectory = bundleDirectory;
        _connection = connection;
        Description = description;
    }

    /// <summary>The bundle this judgement was opened from.</summary>
    public string BundleDirectory { get; }

    /// <summary>What the judging recorded about itself.</summary>
    public JudgementDescription Description { get; }

    /// <summary>
    /// Reads saved path inputs and their exact source binding, without reclassifying objects,
    /// replaying source proofs or returning a reachability verdict.
    /// </summary>
    public PathInputs ReadPathInputs()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireCurrentPathGeneration();
        OpenPart(StoreSegmentRole.PathProof);
        OpenPart(StoreSegmentRole.PermissionProof);
        return PathInputStorage.Read(_connection, Description);
    }

    /// <summary>
    /// Reads one saved Tier-0 path and its supporting answers without replaying permissions,
    /// source qualification, requester selection or path calculation.
    /// An uncaptured subject remains Unknown, not NotReachable.
    /// </summary>
    internal Tier0PathResult ReadTier0Path(string subjectDn)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectDn);
        RequireCurrentPathGeneration();
        OpenPart(StoreSegmentRole.PathProof);
        OpenPart(StoreSegmentRole.PermissionProof);
        return Tier0PathStorage.Read(_connection, Description, subjectDn);
    }

    /// <summary>Reads path and requester coverage from the same saved inputs and generation, without proof replay.</summary>
    internal (Tier0PathResult Path, PathRequesterCoverage Coverage) ReadTier0PathWithCoverage(
        string subjectDn, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectDn);
        cancellationToken.ThrowIfCancellationRequested();
        RequireCurrentPathGeneration();
        OpenPart(StoreSegmentRole.PathProof);
        OpenPart(StoreSegmentRole.PermissionProof);
        return Tier0PathStorage.ReadWithCoverage(_connection, Description, subjectDn, cancellationToken);
    }

    /// <summary>
    /// Reads coverage from the saved selection and reconciled proof batches in this exact generation.
    /// Never re-evaluates proof questions, selects accounts or publishes analysis.
    /// This complete detail/validation read visits every saved question; completion uses <see cref="ReadPathRequesterSummary"/>.
    /// </summary>
    internal PathRequesterCoverage ReadPathRequesterCoverage()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireCurrentPathGeneration();
        OpenPart(StoreSegmentRole.PathProof);
        OpenPart(StoreSegmentRole.PermissionProof);
        return Tier0PathStorage.ReadCoverage(_connection, Description);
    }

    /// <summary>Reads saved completion counters without loading selection details or requester proofs.</summary>
    public PathRequesterSummary ReadPathRequesterSummary(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        RequireCurrentPathGeneration();
        OpenPart(StoreSegmentRole.PathProof);
        return Tier0PathStorage.ReadSummary(_connection, Description, cancellationToken);
    }

    /// <summary>Reads saved qualification counts for existing requester questions, not whole-forest risk coverage.</summary>
    public PathRiskCoverage ReadPathRiskCoverage(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireCurrentPathGeneration();
        OpenPart(StoreSegmentRole.PathProof);
        return PathRequesterRiskStorage.ReadCoverage(_connection, Description, cancellationToken);
    }

    /// <summary>Reads only this requester's saved risk qualifications without replaying authorization or expectedness.</summary>
    internal PathRequesterRiskSet ReadPathRequesterRisks(string requesterDn, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(requesterDn);
        RequireCurrentPathGeneration();
        OpenPart(StoreSegmentRole.PathProof);
        return PathRequesterRiskStorage.Read(_connection, Description, requesterDn, cancellationToken);
    }

    /// <summary>Reads only one saved qualification group and its original proofs for this requester.</summary>
    public PathRiskPage ReadPathRiskPage(string requesterDn, PathRiskVerdict verdict,
        PathRiskPageMark? after, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(requesterDn);
        cancellationToken.ThrowIfCancellationRequested();
        RequireCurrentPathGeneration();
        OpenPart(StoreSegmentRole.PathProof);
        return PathRequesterRiskStorage.ReadPage(_connection, Description, requesterDn, verdict, after, cancellationToken);
    }

    /// <summary>Reads the complete saved SEC-071 production summary; null means this rule was not scheduled.</summary>
    public Tier0FindingSummary? ReadTier0FindingSummary(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        RequireCurrentPathGeneration();
        return Tier0RouteFindingStorage.ReadSummary(_connection, Description, cancellationToken);
    }

    /// <summary>Reads saved whole-generation path totals, including explicit unavailable/not-requested status; null means no saved product.</summary>
    public Tier0RunSummary? ReadTier0RunSummary(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        RequireCurrentPathGeneration();
        return Tier0DistanceStorage.ReadSummary(_connection, Description, cancellationToken);
    }

    /// <summary>Reads only the selected recorded object's saved distance; null means no saved product or no recorded subject.</summary>
    internal Tier0ObjectDistance? ReadTier0ObjectDistance(string distinguishedName, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        cancellationToken.ThrowIfCancellationRequested();
        RequireCurrentPathGeneration();
        OpenPart(StoreSegmentRole.PathProof);
        OpenPart(StoreSegmentRole.PermissionProof);
        return Tier0DistanceStorage.ReadObject(_connection, Description, distinguishedName, cancellationToken);
    }

    /// <summary>Reads the selected subject's saved best evaluated route, independently of shortest distance and page order.</summary>
    internal SavedBestSupportedRoute? ReadBestSupportedRoute(string distinguishedName, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        cancellationToken.ThrowIfCancellationRequested();
        RequireCurrentPathGeneration();
        OpenPart(StoreSegmentRole.PathProof);
        OpenPart(StoreSegmentRole.PermissionProof);
        return BestSupportedRouteStorage.Read(_connection, Description, distinguishedName, cancellationToken);
    }

    public Tier0OverviewPage? ReadTier0Overview(
        Tier0OverviewScope scope,
        Tier0OverviewMark? after,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        RequireCurrentPathGeneration();
        return Tier0Browsing.ReadPage(_connection, Description, scope, after, cancellationToken);
    }

    public Tier0RouteDetails? ReadTier0RouteDetails(string distinguishedName, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        cancellationToken.ThrowIfCancellationRequested();
        RequireCurrentPathGeneration();
        OpenPart(StoreSegmentRole.PathProof);
        OpenPart(StoreSegmentRole.PermissionProof);
        return Tier0Browsing.ReadObject(_connection, Description, distinguishedName, cancellationToken);
    }

    /// <summary>Reads a bounded saved group page without replaying membership analysis.</summary>
    public GroupInventoryPage ReadGroupInventory(GroupInventoryQuery query, GroupInventoryMark? after,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(query);
        cancellationToken.ThrowIfCancellationRequested();
        RequireCurrentPathGeneration();
        return GroupInventoryStorage.Read(_connection, Description, query, after, cancellationToken, _browsing.Groups);
    }

    private void RequireCurrentPathGeneration()
    {
        var judgement = AnalysisStoreLifecycle.ResolveRoot(BundleDirectory, AnalysisStoreKind.Judgement);
        if (!judgement.IsSuccess || judgement.Value.GenerationId != Description.GenerationId
            || judgement.Value.Hash != _publicationRoot?.Hash) throw OwnershipAuditStorage.InvalidProof();
        if (Description.DerivationGenerationId is not { } generation) return;
        var derivation = AnalysisStoreLifecycle.Resolve(BundleDirectory, AnalysisStoreKind.Derivation);
        if (!derivation.IsSuccess || derivation.Value.GenerationId != generation) throw OwnershipAuditStorage.InvalidProof();
    }

    /// <summary>Reads the stored control product, object-first or named-trustee-first, with coverage and hidden counts.</summary>
    public ControlEdgePage ReadControlEdges(string? target, string? holderSid, string? holderScope, bool includeExpected, long afterId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (target is not null && holderSid is not null)
            throw new ArgumentException("Choose an object or a holder, not both.");
        ArgumentOutOfRangeException.ThrowIfNegative(afterId);
        OpenPart(StoreSegmentRole.PermissionProof);
        return ControlEdgeStorage.Read(_connection, Description, target, holderSid, holderScope, includeExpected, afterId, _browsing.Controls)
            with { GenerationId = Description.GenerationId,
                OwnershipCoverage = OwnershipAuditStorage.ReadCoverage(_connection, Description, target) };
    }

    /// <summary>
    /// Reads one original permission by its stored ID and target, retaining the control product's
    /// source and generation validation. The ID is not a display-page cursor.
    /// </summary>
    public ControlEdge ReadControlEdge(string target, long id)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(id);
        OpenPart(StoreSegmentRole.PermissionProof);
        return ControlEdgeStorage.ReadExact(_connection, Description, target, id);
    }

    /// <summary>Reads explicit requester assessments object-first, requester-first, or together.</summary>
    public SelfMembershipAssessmentSet ReadSelfMembershipAssessments(string? target, string? requester)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        OpenPart(StoreSegmentRole.PathProof);
        return SelfMembershipStorage.Read(_connection, Description, target, requester);
    }

    /// <summary>Reads stored requester counts and capture-wide coverage; null means no requester product was derived.</summary>
    public SelfMembershipSummary? ReadSelfMembershipSummary()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        OpenPart(StoreSegmentRole.PathProof);
        return SelfMembershipCoverageStorage.Read(_connection, Description);
    }

    /// <summary>Reads persisted membership beneath a named holder's permission, without walking the directory graph.</summary>
    public MemberAttributionDetail ReadMemberAttribution(string holderSid, string? holderScope, string target)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(holderSid);
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        OpenPart(StoreSegmentRole.PermissionProof);
        return MemberAttributionStorage.Read(_connection, Description, holderSid, holderScope, target)
            with { GenerationId = Description.GenerationId };
    }

    /// <summary>Reads source group permissions through stored membership, separately from named-holder edge counts.</summary>
    public MemberPermissionPage ReadPermissionsThroughMembership(string memberSid, string? memberScope, bool includeExpected, long afterId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(memberSid);
        ArgumentOutOfRangeException.ThrowIfNegative(afterId);
        OpenPart(StoreSegmentRole.PermissionProof);
        return MemberAttributionStorage.ReadReverse(_connection, Description, memberSid, memberScope, includeExpected, afterId);
    }

    /// <summary>
    /// Verifies the judgement's seal and, only if it is intact and it belongs to this bundle, opens
    /// it for reading.
    /// </summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    /// <returns>
    /// The open reader, or an <see cref="AuditError"/> saying which check refused it.
    /// </returns>
    public static Result<JudgementReader> Open(string bundleDirectory) => Open(bundleDirectory, CancellationToken.None);

    /// <summary>Opens the selected saved results under cancellable file protection.</summary>
    public static Result<JudgementReader> Open(string bundleDirectory, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        cancellationToken.ThrowIfCancellationRequested();

        var resolved = AnalysisStoreLifecycle.Resolve(
            bundleDirectory,
            AnalysisStoreKind.Judgement);
        if (!resolved.IsSuccess)
            return Result<JudgementReader>.Failure(resolved.Error!);

        var generation = resolved.Value!;
        var file = ProtectedStoreFile.OpenAnalysis(bundleDirectory, generation, cancellationToken);
        if (!file.IsSuccess)
        {
            var reason = file.Error.Code switch
            {
                "Evidence.ProtectedStoreAbsent" => ReasonFor(SealState.Absent),
                "Evidence.ProtectedStoreUnreadable" => ReasonFor(SealState.Unreadable),
                "Evidence.ProtectedStoreMismatch" => ReasonFor(SealState.Mismatch),
                _ => null,
            };
            return reason is null ? Result<JudgementReader>.Failure(file.Error)
                : Failure(reason, file.Error.Description, bundleDirectory);
        }
        try
        {
            var opened = Open(file.Value, cancellationToken);
            if (opened.IsSuccess) opened.Value._ownedStore = file.Value;
            else file.Value.Dispose();
            return opened;
        }
        catch
        {
            file.Value.Dispose();
            throw;
        }
    }

    /// <summary>Opens an independent stored-result reader under an existing protected generation.</summary>
    public static Result<JudgementReader> Open(ProtectedStoreFile store, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (store.Generation is not { Kind: AnalysisStoreKind.Judgement } generation
            || store.Role != StoreSegmentRole.Judgement) throw new ArgumentException(nameof(store));
        if (!store.Root.Segments.Select(segment => segment.Role).SequenceEqual(BundleLayout.JudgementParts.Prepend(StoreSegmentRole.Judgement))
            || store.Root.Segments.Any(segment => segment.SchemaVersion != JudgementSchema.Version))
            return Failure("JudgementUnreadable", "The judgement does not declare the supported independently sealed products.", store.BundleDirectory);
        ProtectedStoreFile.Lease? lease = store.Acquire(cancellationToken);
        try
        {
            var opened = OpenConnection(store.BundleDirectory, generation, lease.Connection);
            if (opened.IsSuccess)
            {
                var reader = opened.Value;
                if (reader.Description.EvidenceSeal != store.Root.EvidenceSeal)
                {
                    reader.Dispose();
                    return Failure("JudgementIsNotForThisEvidence", "The judgement header contradicts its publication root.", store.BundleDirectory);
                }
                reader._protection = lease;
                reader._browsing = BrowseCaches.GetValue(store, static _ => new());
                reader._publicationRoot = store.Root;
                reader._readCancellation = cancellationToken;
                JudgementStoreLayout.RegisterReader(reader._connection, reader.OpenPart);
                lease = null;
            }
            return opened;
        }
        finally { lease?.Dispose(); }
    }

    private void OpenPart(StoreSegmentRole role)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        if (_openedParts.Contains(role)) return;
        var protection = _protection ?? throw new InvalidOperationException("The judgement reader has no protected publication.");
        var schema = protection.Attach(role, _readCancellation);
        using var query = _connection.CreateCommand();
        query.CommandText = $"SELECT schema_version,role,generation,evidence_seal,derivation_generation FROM \"{schema}\".judgement_part";
        using var header = query.ExecuteReader();
        if (!header.Read() || header.GetInt32(0) != JudgementSchema.Version || header.GetString(1) != role.ToString()
            || header.GetString(2) != Description.GenerationId.ToString("D") || header.GetString(3) != Description.EvidenceSeal
            || (header.IsDBNull(4) ? null : header.GetString(4)) != Description.DerivationGenerationId?.ToString("D")
            || header.Read())
            throw new InvalidDataException("The saved proof part does not match its role, source or generation.");
        _openedParts.Add(role);
    }

    private static Result<JudgementReader> OpenConnection(string bundleDirectory, AnalysisStoreGeneration generation, SqliteConnection connection)
    {
        var judgementPath = BundleLayout.AnalysisGenerationDataPath(bundleDirectory, generation.Kind, generation.GenerationId);
        try
        {
            if (connection.State != System.Data.ConnectionState.Open) connection.Open();
            var description = ReadDescription(connection);

            if (description is null)
            {
                connection.Dispose();
                return Failure(
                    "JudgementUnreadable",
                    $"The judgement at '{judgementPath}' records no run. Its seal is intact, so "
                    + "this is a defect in the build that wrote it rather than damage to the file.",
                    judgementPath);
            }

            if (description.GenerationId != generation.GenerationId)
            {
                connection.Dispose();
                return Failure(
                    "JudgementGenerationMismatch",
                    $"The judgement manifest selects generation '{generation.GenerationId:D}', but "
                    + $"the database identifies itself as '{description.GenerationId:D}'.",
                    judgementPath);
            }

            var mismatch = EvidenceMismatch(bundleDirectory, description.EvidenceSeal);
            if (mismatch is not null)
            {
                connection.Dispose();
                return Failure("JudgementIsNotForThisEvidence", mismatch, judgementPath);
            }

            var derivationMismatch = DerivationMismatch(
                bundleDirectory,
                description.DerivationGenerationId);
            if (derivationMismatch is not null)
            {
                connection.Dispose();
                return Failure("JudgementIsNotForThisDerivation", derivationMismatch, judgementPath);
            }

            return new JudgementReader(bundleDirectory, connection, description);
        }

        catch (Exception error) when (
            error is SqliteException
            or FormatException
            or ArgumentException
            or InvalidOperationException)
        {
            connection.Dispose();
            return Failure(
                "JudgementUnreadable",
                $"The seal on the judgement in '{bundleDirectory}' is intact and the store could "
                + $"not be read: {error.Message}. The bytes are the bytes that were sealed, so this "
                + "is a defect in this build rather than damage to the store.",
                judgementPath);
        }
    }

    /// <summary>
    /// Complete original proof for correctness verification; production reads summaries or bounded pages.
    /// </summary>
    /// <remarks>
    /// <b>One call, because the parts are only meaningful together.</b> Handing back findings on
    /// their own would let a caller render an empty list as a clean forest without ever asking
    /// whether a rule had run - which is the failure this product exists to prevent, so the type
    /// system is where it is prevented rather than the documentation.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// A finding is stored with no evidence row, so what it rests on has been lost.
    /// </exception>
    internal StoredJudgement Read()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return new StoredJudgement(Description, ReadExecutions(), ReadFindings());
    }

    /// <summary>
    /// One page of findings, worst first, for a grid that must not hold a forest in memory.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the one place findings leave without the rules beside them, and it is guarded
    /// rather than trusted.</b> <see cref="Read"/> hands the two out together because an empty list
    /// means nothing on its own. A page cannot carry every rule execution on every page, so instead
    /// a judging where no rule ran is <i>refused</i> here: there is no page of findings to show,
    /// and a caller that received an empty page would draw a clean grid over a bundle nobody
    /// judged.
    /// </para>
    /// <para>
    /// <b>Ordered worst first, by rank rather than by the word.</b> The stored severity is the
    /// enum's name, so ordering on it is alphabetical - Critical, High, Low, Medium - which puts
    /// Low above Medium on a security screen and looks entirely normal.
    /// </para>
    /// <para>
    /// <b>The distinguished name ends the sort, and is not decoration.</b> Findings that share a
    /// severity and a rule have no order between them otherwise, so a page boundary landing inside
    /// such a group shows some of them twice and loses others - silently, and differently each
    /// time.
    /// </para>
    /// <para>
    /// <b>One row more than the page is fetched, and not returned.</b> That is how a page knows
    /// another follows without a second query counting rows nobody asked to see.
    /// </para>
    /// </remarks>
    /// <param name="query">Which findings, and where to carry on from.</param>
    /// <returns>The page, or why no page of findings can honestly be shown.</returns>
    public Result<FindingsPage> ReadPage(FindingsQuery query)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(query);
        OpenPart(StoreSegmentRole.PermissionProof);
        var versions = ReadRuleVersions();
        var page = ReadPageRows(query, FindingColumns, EvidenceJoins, row => ReadFinding(row, versions));
        return page.IsSuccess
            ? Result<FindingsPage>.Success(new(page.Value.Rows, page.Value.Next, page.Value.RulesRan))
            : Result<FindingsPage>.Failure(page.Error);
    }

    private sealed record FindingRows<T>(IReadOnlyList<T> Rows, FindingsPageMark? Next, int RulesRan);

    private Result<FindingRows<T>> ReadPageRows<T>(
        FindingsQuery query, string columns, string joins, Func<SqliteDataReader, T> readRow)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(query);

        if (query.PageSize < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(query),
                query.PageSize,
                "A page holds at least one finding.");
        }

        var executions = ReadExecutions();

        if (executions.Count == 0)
        {
            return Result<FindingRows<T>>.Failure(AuditError.Create(
                ErrorCategory.Evidence,
                "JudgementDidNotRun",
                ErrorSeverity.Failed,
                "No rule was run over this bundle, so there is no page of findings to show. An "
                + "empty grid here would say the forest is clean, and what is true is that nobody "
                + "has looked.",
                BundleDirectory));
        }

        var findings = new List<T>();
        FindingsPageMark? next = null;

        using var command = _connection.CreateCommand();
        command.CommandText =
            $"""
            SELECT {columns}
            FROM finding f
            {joins}
            WHERE ($severity IS NULL OR f.severity = $severity)
              AND ($rule IS NULL OR f.rule_id = $rule)
              AND (
                (($domain IS NULL OR f.domain_fqdn = $domain)
                 AND ($container IS NULL OR f.distinguished_name LIKE $containerLike ESCAPE '\')
                 AND ($object IS NULL OR f.distinguished_name = $object))
                OR (f.rule_id='SEC-052' AND EXISTS (
                    SELECT 1 FROM finding_circular_group cg WHERE cg.finding_id=f.finding_id
                      AND ($domain IS NULL OR cg.domain_fqdn=$domain)
                      AND ($container IS NULL OR cg.distinguished_name LIKE $containerLike ESCAPE '\')
                      AND ($object IS NULL OR cg.distinguished_name=$object))))
              AND ($afterRank IS NULL OR
                   f.severity_rank < $afterRank OR
                   (f.severity_rank = $afterRank AND f.rule_id > $afterRule) OR
                   (f.severity_rank = $afterRank AND f.rule_id = $afterRule
                    AND f.distinguished_name > $afterDn) OR
                   (f.severity_rank = $afterRank AND f.rule_id = $afterRule
                    AND f.distinguished_name = $afterDn AND f.finding_id > $afterId))
            ORDER BY f.severity_rank DESC, f.rule_id ASC, f.distinguished_name ASC, f.finding_id ASC
            LIMIT $limit
            """;

        Bind(command, "$severity", query.Severity?.ToString());
        Bind(command, "$rule", query.RuleId);
        Bind(command, "$domain", query.DomainFqdn);
        Bind(command, "$container", query.Container);
        Bind(command, "$containerLike", ContainerPattern(query.Container));
        Bind(command, "$object", query.Object);
        Bind(command, "$afterRank", query.After?.SeverityRank);
        Bind(command, "$afterRule", query.After?.RuleId);
        Bind(command, "$afterDn", query.After?.DistinguishedName);
        Bind(command, "$afterId", query.After?.FindingId);

        // One more than asked for, so the extra row answers "is there another page" and is then
        // dropped. The alternative is a second query counting everything that matched.
        command.Parameters.AddWithValue("$limit", query.PageSize + 1);

        using var reader = command.ExecuteReader();

        // Tracked alongside rather than taken from the finding, which does not carry its own
        // identity. The mark needs the identity of the last row SHOWN, so it is recorded as each
        // row is added rather than read from the extra row that ends the page.
        FindingsPageMark? lastMark = null;

        while (reader.Read())
        {
            _readCancellation.ThrowIfCancellationRequested();
            if (findings.Count == query.PageSize)
            {
                // The extra row. Its existence is the whole answer, so it is not read as a finding
                // and not shown - the mark points at the last row that was.
                next = lastMark;
                break;
            }

            lastMark = new((int)Enum.Parse<Severity>(reader.GetString(5)), reader.GetString(1),
                reader.GetString(6), reader.GetInt64(0)) { GenerationId = Description.GenerationId };
            findings.Add(readRow(reader));
        }

        return Result<FindingRows<T>>.Success(new(findings, next, executions.Count));
    }

    /// <summary>
    /// Binds a value that may be absent, where absent means <i>every one of them</i>.
    /// </summary>
    private static void Bind(SqliteCommand command, string name, object? value) =>
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);

    /// <summary>
    /// What a findings grid's filters may offer, taken from the findings that exist.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Read from the data rather than listed in the screen.</b> A severity list written into a
    /// view offers Critical whether or not any finding is critical, so an operator picks it, sees
    /// an empty grid, and has learned nothing except to distrust the filter. The predecessor read
    /// its values the same way.
    /// </para>
    /// <para>
    /// <b>Not scoped by the container.</b> The values are for the whole judgement, so the list does
    /// not change under the operator as he moves about the tree - a filter whose options come and
    /// go while a selection is held is a filter that silently clears itself.
    /// </para>
    /// </remarks>
    /// <returns>The severities and rules some finding has, worst and lowest first.</returns>
    public FindingsFilterValues ReadFilterValues()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_browsing) return ReadFilterValuesCore();
    }

    private FindingsFilterValues ReadFilterValuesCore()
    {
        if (_browsing.Filters is { } saved) return saved;

        var severities = new List<Severity>();
        var rules = new List<string>();

        using (var command = _connection.CreateCommand())
        {
            command.CommandText = """
                WITH RECURSIVE ranks(rank) AS (
                    SELECT MAX(severity_rank) FROM finding
                    UNION ALL
                    SELECT (SELECT MAX(severity_rank) FROM finding WHERE severity_rank<r.rank)
                    FROM ranks r WHERE rank IS NOT NULL)
                SELECT (SELECT severity FROM finding WHERE severity_rank=r.rank LIMIT 1)
                FROM ranks r WHERE rank IS NOT NULL ORDER BY rank DESC
                """;

            using var reader = command.ExecuteReader();
            while (reader.Read())
                severities.Add(Enum.Parse<Severity>(reader.GetString(0)));
        }

        using (var command = _connection.CreateCommand())
        {
            command.CommandText = """
                WITH RECURSIVE rules(rule_id) AS (
                    SELECT MIN(rule_id) FROM finding
                    UNION ALL
                    SELECT (SELECT MIN(rule_id) FROM finding WHERE rule_id>r.rule_id)
                    FROM rules r WHERE rule_id IS NOT NULL)
                SELECT rule_id FROM rules WHERE rule_id IS NOT NULL ORDER BY rule_id
                """;

            using var reader = command.ExecuteReader();
            while (reader.Read())
                rules.Add(reader.GetString(0));
        }

        return _browsing.Filters = new FindingsFilterValues(severities.AsReadOnly(), rules.AsReadOnly(), ReadExecutions().Count);
    }

    /// <summary>
    /// The pattern that matches a container and everything beneath it.
    /// </summary>
    /// <remarks>
    /// <b>The wildcards in the operator's own text are escaped first.</b> A distinguished name may
    /// contain <c>%</c> or <c>_</c>, and left alone they would quietly widen the scope of a grid
    /// that says it is showing one container.
    /// </remarks>
    private static string? ContainerPattern(string? container) =>
        container is null
            ? null
            : "%" + container.Replace(@"\", @"\\", StringComparison.Ordinal)
                             .Replace("%", @"\%", StringComparison.Ordinal)
                             .Replace("_", @"\_", StringComparison.Ordinal);

    /// <summary>
    /// What every scheduled rule did, without the findings it produced.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Public because a screen needs it without wanting the findings.</b> <see cref="Read"/>
    /// returns the whole store, findings included, which on a real forest is every row a judging
    /// wrote. A screen answering <i>what did the product check</i> wants eleven rows and would
    /// otherwise pay for thousands.
    /// </para>
    /// <para>
    /// <b>Every rule that was scheduled, whatever became of it</b>, including one recorded as
    /// having not run. Absence cannot state that a rule was skipped, which is the reason the table
    /// carries a row for it.
    /// </para>
    /// <para>
    /// <b>Vouched rather than bare</b>, per gate 4. An empty list means either a bundle nobody
    /// judged or a judging that recorded nothing before it stopped, and
    /// <see cref="StoredRuleExecutions.State"/> is what separates them.
    /// </para>
    /// </remarks>
    public StoredRuleExecutions ReadRuleExecutions()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return new StoredRuleExecutions(ReadExecutions(), Description.State);
    }

    /// <summary>
    /// How many findings this judging wrote, by severity, counted in the database.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Counted rather than derived from a list of findings</b>, for the reason
    /// <see cref="ReadFindingCountsByRule"/> gives: the caller that wants this wants it
    /// <i>instead of</i> the findings, and a real forest's judgement holds far too many rows to
    /// read in order to arrive at four numbers.
    /// </para>
    /// <para>
    /// <b>A severity with no findings has no row, and that is not a zero.</b> The dictionary says
    /// what was found, not what could have been - a caller wanting to know whether anyone looked
    /// asks <see cref="ReadRuleExecutions"/>, which is the only thing that can answer it.
    /// </para>
    /// <para>
    /// <b>Internal, because the caller that wants it is in this assembly and gate 4 is right about
    /// the rest.</b> A dictionary of counts handed outside cannot say whether anyone looked, and
    /// the thing that can - <see cref="ReadRuleExecutions"/> - is a separate call a distant caller
    /// could forget to make. <see cref="ReadSummary"/> keeps them together for completion and the
    /// portable summary, without opening original finding proof.
    /// </para>
    /// </remarks>
    /// <returns>Each severity some finding has, and how many have it.</returns>
    internal IReadOnlyDictionary<Severity, int> ReadFindingCountsBySeverity()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var counts = new Dictionary<Severity, int>();

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT severity, COUNT(*) FROM finding GROUP BY severity";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            if (Enum.TryParse<Severity>(reader.GetString(0), out var severity)
                && Enum.IsDefined(severity))
            {
                counts[severity] = reader.GetInt32(1);
            }
            else
                throw new InvalidDataException("A saved finding has an unsupported severity.");
        }

        return counts;
    }

    private IReadOnlyList<StoredRuleExecution> ReadExecutions()
    {
        var missing = ReadMissingInputs();
        var produced = ReadFindingCountsByRule();
        var executions = new List<StoredRuleExecution>();

        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT rule_id, rule_version, outcome, objects_judged, objects_not_applicable, "
            + "objects_not_judged, error FROM rule_execution ORDER BY rule_id";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var ruleId = reader.GetString(0);

            executions.Add(new StoredRuleExecution(
                ruleId,
                reader.GetInt32(1),
                Enum.Parse<RuleExecutionOutcome>(reader.GetString(2)),
                reader.GetInt32(3),
                reader.GetInt32(4),
                reader.GetInt32(5),
                missing.TryGetValue(ruleId, out var inputs) ? inputs : [],
                produced.GetValueOrDefault(ruleId),
                reader.IsDBNull(6) ? null : reader.GetString(6)));
        }

        return executions;
    }

    /// <summary>
    /// Every finding this judging produced, with the evidence each rests on.
    /// </summary>
    /// <remarks>
    /// Private, and deliberately. An empty list never means the forest is clean - it means no rule
    /// matched anything, which is only a statement about the forest beside the rules that ran. The
    /// two leave this class together or not at all.
    /// </remarks>
    private IReadOnlyList<Finding> ReadFindings()
    {
        OpenPart(StoreSegmentRole.PermissionProof);
        var versions = ReadRuleVersions();
        var findings = new List<Finding>();

        using var command = _connection.CreateCommand();
        command.CommandText =
            $"""
            SELECT {FindingColumns}
            FROM finding f
            {EvidenceJoins}
            ORDER BY f.finding_id
            """;

        using var reader = command.ExecuteReader();

        while (reader.Read())
            findings.Add(ReadFinding(reader, versions));

        return findings;
    }

    /// <summary>
    /// Every column <see cref="ReadFinding"/> reads, aliased so the name is the same whichever
    /// query selected it.
    /// </summary>
    /// <remarks>
    /// <b>One list, used by both queries.</b> They had two, and they disagreed - see the remarks on
    /// <see cref="ReadFinding"/> for what that showed an operator. A single list cannot disagree
    /// with itself, and adding a kind of evidence is then one edit here rather than two that must
    /// be kept in step by whoever remembers.
    /// </remarks>
    private const string FindingColumns =
        """
        f.finding_id, f.rule_id, f.subject_kind, f.subject_key, f.object_guid,
        f.severity, f.distinguished_name, f.detail, f.coverage,
        f.domain_fqdn, f.object_class, f.principal_name,
        z.proof                             AS z_proof,
        z.fingerprint                       AS z_fingerprint,
        zc.fingerprint                      AS z_calculation_fingerprint,
        d.user_account_control              AS d_user_account_control,
        d.is_computer                       AS d_is_computer,
        d.server_trust_account_bit          AS d_server_trust_account_bit,
        d.primary_group_is_domain_controller AS d_primary_group_is_domain_controller,
        d.under_domain_controllers_ou       AS d_under_domain_controllers_ou,
        a.sid                               AS a_sid,
        p.user_account_control              AS p_user_account_control,
        h.finding_id                        AS h_finding_id,
        h.object_sid                        AS h_object_sid,
        h.unreadable_values                 AS h_unreadable_values,
        k.finding_id                        AS k_finding_id,
        k.object_sid                        AS k_object_sid,
        k.user_account_control              AS k_user_account_control,
        k.unreadable_service_names          AS k_unreadable_service_names,
        k.protection_catalogue_version      AS k_protection_catalogue_version,
        k.direct_protection_entry_id        AS k_direct_protection_entry_id,
        k.direct_protection_name            AS k_direct_protection_name,
        l.windows_laps_expiration           AS l_windows_laps_expiration,
        l.legacy_laps_expiration            AS l_legacy_laps_expiration,
        l.capability_kind                   AS l_capability_kind,
        l.capability_basis                  AS l_capability_basis,
        l.operating_system                  AS l_operating_system,
        l.operating_system_version          AS l_operating_system_version,
        r.trustee_sid                       AS r_trustee_sid,
        r.trustee_name                      AS r_trustee_name,
        r.broad_principal_sid               AS r_broad_principal_sid,
        r.broad_principal_name              AS r_broad_principal_name,
        r.attribute                         AS r_attribute,
        r.rights                            AS r_rights,
        r.reach                             AS r_reach,
        r.inherited_from                    AS r_inherited_from,
        r.expansion_was_complete            AS r_expansion_was_complete,
        r.route_length                      AS r_route_length,
        r.finding_id                        AS r_finding_id,
        e.policy_display_name               AS e_policy_display_name,
        e.configured_value                  AS e_configured_value,
        e.form                              AS e_form,
        e.decryptor_sid                     AS e_decryptor_sid,
        e.decryptor_name                    AS e_decryptor_name,
        e.expansion_was_complete            AS e_expansion_was_complete,
        e.route_count                       AS e_route_count,
        e.finding_id                        AS e_finding_id,
        t.trustee_sid                       AS t_trustee_sid,
        t.trustee_name                      AS t_trustee_name,
        t.broad_principal_sid               AS t_broad_principal_sid,
        t.broad_principal_name              AS t_broad_principal_name,
        t.takeover_right                    AS t_takeover_right,
        t.inherited_from                    AS t_inherited_from,
        t.expansion_was_complete            AS t_expansion_was_complete,
        t.finding_id                        AS t_finding_id,
        w.owner_sid                         AS w_owner_sid,
        w.owner_name                        AS w_owner_name,
        w.standing                          AS w_standing,
        w.object_class                      AS w_object_class,
        w.membership_was_complete           AS w_membership_was_complete,
        w.finding_id                        AS w_finding_id,
        cy.proof                            AS cy_proof,
        cy.fingerprint                      AS cy_fingerprint,
        cy.generation                       AS cy_generation,
        spn.proof                           AS spn_proof,
        spn.fingerprint                     AS spn_fingerprint,
        spn.generation                      AS spn_generation,
        am.proof                            AS am_proof,
        am.fingerprint                      AS am_fingerprint,
        am.generation                       AS am_generation,
        svc.proof                           AS svc_proof,
        svc.fingerprint                     AS svc_fingerprint,
        svc.generation                      AS svc_generation,
        aw.finding_id                       AS aw_finding_id,
        aw.proof                            AS aw_proof,
        aw.fingerprint                      AS aw_fingerprint,
        aw.generation                       AS aw_generation,
        mr.proof                            AS mr_proof,
        mr.fingerprint                      AS mr_fingerprint,
        mr.generation                       AS mr_generation,
        dc.proof                            AS dc_proof,
        dc.fingerprint                      AS dc_fingerprint,
        dc.generation                       AS dc_generation,
        dc.account_source_hash              AS dc_account_source_hash,
        dc.resource_source_hash             AS dc_resource_source_hash,
        rp.edge_id                          AS rp_edge_id,
        rp.proof                            AS rp_proof,
        rp.fingerprint                      AS rp_fingerprint,
        rp.source_hash                      AS rp_source_hash,
        rp.generation                       AS rp_generation
        """;

    /// <summary>One join per kind of evidence, shared for the same reason the columns are.</summary>
    private const string EvidenceJoins =
        """
        LEFT JOIN finding_unconstrained_delegation d ON d.finding_id = f.finding_id
        LEFT JOIN finding_admincount_without_protection a ON a.finding_id = f.finding_id
        LEFT JOIN finding_user_account_control p ON p.finding_id = f.finding_id
        LEFT JOIN finding_privileged_sid_history h ON h.finding_id = f.finding_id
        LEFT JOIN finding_kerberoastable_account k ON k.finding_id = f.finding_id
        LEFT JOIN finding_laps_deployment l ON l.finding_id = f.finding_id
        LEFT JOIN finding_laps_password_reader r ON r.finding_id = f.finding_id
        LEFT JOIN finding_laps_decryptor e ON e.finding_id = f.finding_id
        LEFT JOIN finding_object_takeover t ON t.finding_id = f.finding_id
        LEFT JOIN finding_object_ownership w ON w.finding_id = f.finding_id
        LEFT JOIN finding_tier0_route z ON z.finding_id = f.finding_id
        LEFT JOIN finding_circular_membership cy ON cy.finding_id = f.finding_id
        LEFT JOIN finding_duplicate_spn spn ON spn.finding_id = f.finding_id
        LEFT JOIN finding_broad_group_membership am ON am.finding_id = f.finding_id
        LEFT JOIN finding_service_account svc ON svc.finding_id = f.finding_id
        LEFT JOIN finding_attribute_write aw ON aw.finding_id = f.finding_id
        LEFT JOIN finding_membership_review mr ON mr.finding_id = f.finding_id
        LEFT JOIN finding_delegation_configuration dc ON dc.finding_id = f.finding_id
        LEFT JOIN finding_replication_permission rp ON rp.finding_id = f.finding_id
        LEFT JOIN tier0_path_calculation zc ON f.rule_id='SEC-071' AND zc.id=1
        """;

    /// <summary>
    /// Reads one finding, with the evidence it rests on.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One mapping, shared by the whole read and by a page.</b> Two would be two accounts of the
    /// same row, and the day one of them gained a column the other would quietly keep answering
    /// without it.
    /// </para>
    /// <para>
    /// <b>Columns are found by name, and that is not a style preference.</b> Until 2026-09-01 this
    /// read by position while the two queries selecting into it had different column lists: position
    /// 16 was <c>a.sid</c> in one and <c>f.severity_rank</c> in the other. A severity rank is never
    /// null, so on a page every non-delegation finding took the SID branch and <b>a severity rank
    /// was shown to an operator as a security identifier</b> - the High rank 2 came back as the SID
    /// "2". It did not throw and it did not look wrong. Names cannot drift silently: a query missing
    /// a column fails here, naming it.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// The finding has no evidence row, so what it rests on has been lost.
    /// </exception>
    private Finding ReadFinding(SqliteDataReader reader, IReadOnlyDictionary<string, int> versions)
    {
        var ruleId = reader.GetString(reader.GetOrdinal("rule_id"));

        // Which table answered decides the kind. Checked before anything is read out of any of
        // them, because a finding whose evidence row is missing everywhere has lost what it rests
        // on - and presenting it anyway would show an operator a conclusion with nothing behind it.
        var delegationUac = reader.GetOrdinal("d_user_account_control");
        var markerSid = reader.GetOrdinal("a_sid");
        var preauthUac = reader.GetOrdinal("p_user_account_control");
        var sidHistory = reader.GetOrdinal("h_finding_id");
        var kerberoastable = reader.GetOrdinal("k_finding_id");

        // Discriminated on capability_kind, which is never null on a row that exists. Both
        // timestamp columns are legitimately null - that pair of absences is exactly what a SEC-091
        // finding says - so either of them as the discriminator would drop every SEC-091 finding
        // into the "no evidence" branch below and throw on a finding that is intact.
        var lapsCapability = reader.GetOrdinal("l_capability_kind");

        // trustee_sid, because it is NOT NULL on any row that exists. inherited_from and
        // trustee_name are both legitimately null - an entry set directly on the object has no
        // inherited scope, and a well-known or foreign-forest trustee has no name in this bundle -
        // so either would drop an intact finding into the "no evidence" branch. This is P-112.
        var lapsReaderTrustee = reader.GetOrdinal("r_trustee_sid");

        // configured_value, because it is NOT NULL on any row that exists. decryptor_sid is
        // legitimately null - a decryptor this capture could not resolve is exactly what one kind
        // of SEC-093 finding says - so using it as the discriminator would drop an intact finding
        // into the "no evidence" branch below and throw on it. This is P-112.
        var lapsDecryptorValue = reader.GetOrdinal("e_configured_value");

        // trustee_sid, because it is NOT NULL on any row that exists, for the same reason SEC-090's
        // discriminator is. inherited_from and trustee_name are both legitimately null. P-112.
        var takeoverTrustee = reader.GetOrdinal("t_trustee_sid");

        // owner_sid, because MS-ADTS 6.1.3 states a descriptor's owner SID cannot be null, and a
        // descriptor carrying none is refused rather than reported - so a row that exists has one.
        // owner_name is legitimately null for a well-known or foreign-forest owner. P-112.
        var ownershipOwner = reader.GetOrdinal("w_owner_sid");

        FindingEvidence evidence;

        if (ruleId == "SEC-002")
        {
            OpenPart(StoreSegmentRole.PermissionProof);
            if (reader.IsDBNull(reader.GetOrdinal("rp_proof")))
                throw new InvalidDataException("The replication finding has no saved typed permission evidence.");
            _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
            evidence = ReplicationPermissionFindingStorage.Read(_connection, reader.GetInt64(reader.GetOrdinal("rp_edge_id")),
                reader.GetString(reader.GetOrdinal("rp_proof")), (byte[])reader.GetValue(reader.GetOrdinal("rp_fingerprint")),
                (byte[])reader.GetValue(reader.GetOrdinal("rp_source_hash")), reader.GetString(reader.GetOrdinal("rp_generation")),
                Description, _findingDerivationSeal, ruleId, Guid.Parse(reader.GetString(reader.GetOrdinal("object_guid"))),
                reader.GetString(reader.GetOrdinal("distinguished_name")), reader.GetString(reader.GetOrdinal("domain_fqdn")),
                reader.GetString(reader.GetOrdinal("object_class")), reader.GetString(reader.GetOrdinal("subject_key")),
                reader.GetString(reader.GetOrdinal("subject_kind")), Enum.Parse<Severity>(reader.GetString(reader.GetOrdinal("severity"))));
        }
        else if (ruleId is "SEC-012" or "SEC-013")
        {
            OpenPart(StoreSegmentRole.PermissionProof);
            if (reader.IsDBNull(reader.GetOrdinal("dc_proof")))
                throw new InvalidDataException("The delegation-configuration finding has no saved typed evidence.");
            _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
            evidence = DelegationConfigurationFindingStorage.Read(_connection, reader.GetString(reader.GetOrdinal("dc_proof")),
                (byte[])reader.GetValue(reader.GetOrdinal("dc_fingerprint")),
                (byte[])reader.GetValue(reader.GetOrdinal("dc_account_source_hash")), (byte[])reader.GetValue(reader.GetOrdinal("dc_resource_source_hash")),
                reader.GetString(reader.GetOrdinal("dc_generation")),
                Description, _findingDerivationSeal, ruleId, Guid.Parse(reader.GetString(reader.GetOrdinal("object_guid"))),
                reader.GetString(reader.GetOrdinal("distinguished_name")), reader.GetString(reader.GetOrdinal("domain_fqdn")),
                reader.GetString(reader.GetOrdinal("object_class")), reader.GetString(reader.GetOrdinal("subject_key")),
                reader.GetString(reader.GetOrdinal("subject_kind")), Enum.Parse<Severity>(reader.GetString(reader.GetOrdinal("severity"))));
        }
        else if (ruleId is "SEC-050" or "SEC-051")
        {
            OpenPart(StoreSegmentRole.PermissionProof);
            if (reader.IsDBNull(reader.GetOrdinal("mr_proof")))
                throw new InvalidDataException("The membership review has no saved typed evidence.");
            _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
            evidence = GroupMembershipReviewFindingStorage.Read(_connection, reader.GetString(reader.GetOrdinal("mr_proof")),
                (byte[])reader.GetValue(reader.GetOrdinal("mr_fingerprint")), reader.GetString(reader.GetOrdinal("mr_generation")),
                Description, _findingDerivationSeal, ruleId, Guid.Parse(reader.GetString(reader.GetOrdinal("object_guid"))),
                reader.GetString(reader.GetOrdinal("distinguished_name")), reader.GetString(reader.GetOrdinal("domain_fqdn")),
                reader.GetString(reader.GetOrdinal("object_class")), reader.GetString(reader.GetOrdinal("subject_key")),
                reader.GetString(reader.GetOrdinal("subject_kind")), Enum.Parse<Severity>(reader.GetString(reader.GetOrdinal("severity"))));
        }
        else if (ruleId is "SEC-014" or "SEC-024" or "SEC-025")
        {
            OpenPart(StoreSegmentRole.PermissionProof);
            if (reader.IsDBNull(reader.GetOrdinal("aw_finding_id")))
                throw new InvalidDataException("The attribute-write finding has no saved typed evidence.");
            _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
            evidence = AttributeWriteFindingStorage.Read(_connection, reader.GetInt64(reader.GetOrdinal("aw_finding_id")),
                reader.GetString(reader.GetOrdinal("aw_proof")), (byte[])reader.GetValue(reader.GetOrdinal("aw_fingerprint")),
                reader.GetString(reader.GetOrdinal("aw_generation")), Description, _findingDerivationSeal, ruleId,
                Guid.Parse(reader.GetString(reader.GetOrdinal("object_guid"))), reader.GetString(reader.GetOrdinal("distinguished_name")),
                reader.GetString(reader.GetOrdinal("domain_fqdn")), reader.GetString(reader.GetOrdinal("object_class")),
                reader.GetString(reader.GetOrdinal("subject_key")), reader.GetString(reader.GetOrdinal("subject_kind")),
                Enum.Parse<Severity>(reader.GetString(reader.GetOrdinal("severity"))));
        }
        else if (ruleId is "SEC-100" or "SEC-101")
        {
            if (reader.IsDBNull(reader.GetOrdinal("svc_proof")))
                throw new InvalidDataException("The service-account finding has no saved typed evidence.");
            if (ruleId == "SEC-100")
                _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
            evidence = ServiceAccountFindingStorage.Read(reader.GetString(reader.GetOrdinal("svc_proof")),
                (byte[])reader.GetValue(reader.GetOrdinal("svc_fingerprint")), reader.GetString(reader.GetOrdinal("svc_generation")),
                Description, _findingDerivationSeal, ruleId, Guid.Parse(reader.GetString(reader.GetOrdinal("object_guid"))),
                reader.GetString(reader.GetOrdinal("distinguished_name")), reader.GetString(reader.GetOrdinal("domain_fqdn")),
                reader.GetString(reader.GetOrdinal("object_class")), reader.GetString(reader.GetOrdinal("subject_key")),
                reader.GetString(reader.GetOrdinal("subject_kind")), Enum.Parse<Severity>(reader.GetString(reader.GetOrdinal("severity"))));
        }
        else if (ruleId is "SEC-062" or "SEC-061")
        {
            if (reader.IsDBNull(reader.GetOrdinal("am_proof")))
                throw new InvalidDataException("The broad group-membership finding has no saved evidence.");
            _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
            evidence = GroupMembershipFindingStorage.Read(reader.GetString(reader.GetOrdinal("am_proof")),
                (byte[])reader.GetValue(reader.GetOrdinal("am_fingerprint")), reader.GetString(reader.GetOrdinal("am_generation")),
                Description, _findingDerivationSeal, ruleId, Guid.Parse(reader.GetString(reader.GetOrdinal("object_guid"))),
                reader.GetString(reader.GetOrdinal("distinguished_name")), reader.GetString(reader.GetOrdinal("domain_fqdn")),
                reader.GetString(reader.GetOrdinal("object_class")),
                reader.GetString(reader.GetOrdinal("subject_key")), reader.GetString(reader.GetOrdinal("subject_kind")),
                Enum.Parse<Severity>(reader.GetString(reader.GetOrdinal("severity"))));
        }
        else if (ruleId == "SEC-026")
        {
            if (reader.IsDBNull(reader.GetOrdinal("spn_proof")))
                throw new InvalidDataException("The duplicate-SPN finding has no saved evidence.");
            evidence = DuplicateSpnStorage.Read(reader.GetString(reader.GetOrdinal("spn_proof")),
                (byte[])reader.GetValue(reader.GetOrdinal("spn_fingerprint")), reader.GetString(reader.GetOrdinal("spn_generation")),
                Description, Guid.Parse(reader.GetString(reader.GetOrdinal("object_guid"))),
                reader.GetString(reader.GetOrdinal("distinguished_name")), reader.GetString(reader.GetOrdinal("domain_fqdn")),
                reader.GetString(reader.GetOrdinal("subject_key")), Enum.Parse<Severity>(reader.GetString(reader.GetOrdinal("severity"))));
        }
        else if (ruleId == "SEC-052")
        {
            if (reader.IsDBNull(reader.GetOrdinal("cy_proof")))
                throw new InvalidDataException("The circular-membership finding has no saved evidence.");
            evidence = CircularMembershipStorage.Read(reader.GetString(reader.GetOrdinal("cy_proof")),
                (byte[])reader.GetValue(reader.GetOrdinal("cy_fingerprint")), reader.GetString(reader.GetOrdinal("cy_generation")),
                Description, Guid.Parse(reader.GetString(reader.GetOrdinal("object_guid"))),
                reader.GetString(reader.GetOrdinal("distinguished_name")), reader.GetString(reader.GetOrdinal("subject_key")),
                Enum.Parse<Severity>(reader.GetString(reader.GetOrdinal("severity"))));
        }
        else if (ruleId == UnexpectedTier0Route.RuleId)
        {
            var proof = reader.GetOrdinal("z_proof");
            var calculation = reader.GetOrdinal("z_calculation_fingerprint");
            if (reader.IsDBNull(proof) || reader.IsDBNull(calculation)) throw Tier0PathStorage.InvalidProof();
            var route = Tier0RouteFindingStorage.ReadEvidence(reader.GetString(proof),
                (byte[])reader.GetValue(reader.GetOrdinal("z_fingerprint")), Description,
                Guid.Parse(reader.GetString(reader.GetOrdinal("object_guid"))),
                reader.GetString(reader.GetOrdinal("distinguished_name")), Convert.ToHexString((byte[])reader.GetValue(calculation)));
            evidence = route;
            if (reader.GetString(reader.GetOrdinal("subject_key")) != route.RequesterGuid.ToString("D")
                || reader.GetString(reader.GetOrdinal("subject_kind")) != nameof(FindingSubjectKind.Account)
                || reader.GetString(reader.GetOrdinal("severity")) != nameof(Severity.High))
                throw Tier0PathStorage.InvalidProof();
        }
        else if (!reader.IsDBNull(reader.GetOrdinal("z_proof")))
            throw Tier0PathStorage.InvalidProof();
        else if (!reader.IsDBNull(delegationUac))
        {
            evidence = new UnconstrainedDelegationEvidence(
                (uint)reader.GetInt64(delegationUac),
                reader.GetInt64(reader.GetOrdinal("d_is_computer")) != 0,
                new DomainControllerSignals(
                    reader.GetInt64(reader.GetOrdinal("d_server_trust_account_bit")) != 0,
                    reader.GetInt64(reader.GetOrdinal("d_primary_group_is_domain_controller")) != 0,
                    reader.GetInt64(reader.GetOrdinal("d_under_domain_controllers_ou")) != 0));
        }
        else if (!reader.IsDBNull(markerSid))
        {
            evidence = new AdminCountWithoutProtectionEvidence(reader.GetString(markerSid));
        }
        else if (!reader.IsDBNull(preauthUac))
        {
            evidence = new UserAccountControlEvidence((uint)reader.GetInt64(preauthUac));
        }
        else if (!reader.IsDBNull(sidHistory))
        {
            // The discriminator is the finding_id and not object_sid, because object_sid is
            // legitimately null - an account whose own identifier could not be read still carries
            // the history that was read. Keying off a nullable column would silently drop those
            // findings into the "no evidence" branch below and throw on a finding that is intact.
            var findingId = reader.GetInt64(sidHistory);
            var objectSidColumn = reader.GetOrdinal("h_object_sid");

            var values = ReadChildValues("finding_privileged_sid_history_value", "sid", findingId);

            evidence = new PrivilegedSidHistoryEvidence(
                reader.IsDBNull(objectSidColumn) ? null : reader.GetString(objectSidColumn),
                values,
                PrivilegedSidHistoryMatches(values),
                (int)reader.GetInt64(reader.GetOrdinal("h_unreadable_values")));
        }
        else if (!reader.IsDBNull(kerberoastable))
        {
            var findingId = reader.GetInt64(kerberoastable);

            evidence = new KerberoastableAccountEvidence(
                reader.GetString(reader.GetOrdinal("k_object_sid")),
                ReadChildValues("finding_kerberoastable_account_spn", "service_principal_name", findingId),
                (uint)reader.GetInt64(reader.GetOrdinal("k_user_account_control")),
                (int)reader.GetInt64(reader.GetOrdinal("k_unreadable_service_names")))
            {
                ProtectionCatalogueVersion = reader.IsDBNull(reader.GetOrdinal("k_protection_catalogue_version"))
                    ? null : reader.GetInt32(reader.GetOrdinal("k_protection_catalogue_version")),
                DirectProtectionCatalogueEntryId = reader.IsDBNull(reader.GetOrdinal("k_direct_protection_entry_id"))
                    ? null : reader.GetInt32(reader.GetOrdinal("k_direct_protection_entry_id")),
                DirectProtectionName = reader.IsDBNull(reader.GetOrdinal("k_direct_protection_name"))
                    ? null : reader.GetString(reader.GetOrdinal("k_direct_protection_name")),
                MembershipRoutes = ReadMembershipRoutes(findingId),
            };
        }
        else if (!reader.IsDBNull(lapsCapability))
        {
            var modern = reader.GetOrdinal("l_windows_laps_expiration");
            var legacy = reader.GetOrdinal("l_legacy_laps_expiration");
            var name = reader.GetOrdinal("l_operating_system");
            var version = reader.GetOrdinal("l_operating_system_version");

            evidence = new LapsDeploymentEvidence(
                reader.IsDBNull(modern) ? null : reader.GetString(modern),
                reader.IsDBNull(legacy) ? null : reader.GetString(legacy),
                new LapsCapability(
                    Enum.Parse<LapsCapabilityKind>(reader.GetString(lapsCapability)),
                    Enum.Parse<LapsCapabilityBasis>(
                        reader.GetString(reader.GetOrdinal("l_capability_basis"))),
                    reader.IsDBNull(name) ? null : reader.GetString(name),
                    reader.IsDBNull(version) ? null : reader.GetString(version)));
        }
        else if (!reader.IsDBNull(lapsReaderTrustee))
        {
            var findingId = reader.GetInt64(reader.GetOrdinal("r_finding_id"));
            var trusteeName = reader.GetOrdinal("r_trustee_name");
            var inheritedFrom = reader.GetOrdinal("r_inherited_from");

            evidence = new LapsPasswordReaderEvidence(
                reader.GetString(lapsReaderTrustee),
                reader.IsDBNull(trusteeName) ? null : reader.GetString(trusteeName),
                reader.GetString(reader.GetOrdinal("r_broad_principal_sid")),
                reader.IsDBNull(reader.GetOrdinal("r_broad_principal_name"))
                    ? null
                    : reader.GetString(reader.GetOrdinal("r_broad_principal_name")),
                ReadLapsRoute("finding_laps_password_reader_path", findingId, reader.GetInt64(reader.GetOrdinal("r_route_length"))),
                reader.GetString(reader.GetOrdinal("r_attribute")),
                Enum.Parse<LapsReadRights>(reader.GetString(reader.GetOrdinal("r_rights"))),
                Enum.Parse<LapsGrantReach>(reader.GetString(reader.GetOrdinal("r_reach"))),
                reader.IsDBNull(inheritedFrom) ? null : reader.GetString(inheritedFrom),
                reader.GetInt64(reader.GetOrdinal("r_expansion_was_complete")) != 0);
        }
        else if (!reader.IsDBNull(takeoverTrustee))
        {
            var findingId = reader.GetInt64(reader.GetOrdinal("t_finding_id"));
            var trusteeName = reader.GetOrdinal("t_trustee_name");
            var broadName = reader.GetOrdinal("t_broad_principal_name");
            var inheritedFrom = reader.GetOrdinal("t_inherited_from");

            evidence = new ObjectTakeoverEvidence(
                reader.GetString(takeoverTrustee),
                reader.IsDBNull(trusteeName) ? null : reader.GetString(trusteeName),
                reader.GetString(reader.GetOrdinal("t_broad_principal_sid")),
                reader.IsDBNull(broadName) ? null : reader.GetString(broadName),
                ReadPathSteps("finding_object_takeover_path", findingId),
                Enum.Parse<ObjectTakeoverRight>(
                    reader.GetString(reader.GetOrdinal("t_takeover_right"))),
                reader.IsDBNull(inheritedFrom) ? null : reader.GetString(inheritedFrom),
                reader.GetInt64(reader.GetOrdinal("t_expansion_was_complete")) != 0);
        }
        else if (!reader.IsDBNull(ownershipOwner))
        {
            var ownerName = reader.GetOrdinal("w_owner_name");

            evidence = new ObjectOwnershipEvidence(
                reader.GetString(ownershipOwner),
                reader.IsDBNull(ownerName) ? null : reader.GetString(ownerName),
                Enum.Parse<ObjectOwnerStanding>(
                    reader.GetString(reader.GetOrdinal("w_standing"))),
                reader.GetString(reader.GetOrdinal("w_object_class")),
                reader.GetInt64(reader.GetOrdinal("w_membership_was_complete")) != 0);
        }
        else if (!reader.IsDBNull(lapsDecryptorValue))
        {
            var findingId = reader.GetInt64(reader.GetOrdinal("e_finding_id"));
            var policyName = reader.GetOrdinal("e_policy_display_name");
            var decryptorSid = reader.GetOrdinal("e_decryptor_sid");
            var decryptorName = reader.GetOrdinal("e_decryptor_name");

            evidence = new LapsDecryptorEvidence(
                reader.IsDBNull(policyName) ? null : reader.GetString(policyName),
                reader.GetString(lapsDecryptorValue),
                Enum.Parse<LapsDecryptorForm>(reader.GetString(reader.GetOrdinal("e_form"))),
                reader.IsDBNull(decryptorSid) ? null : reader.GetString(decryptorSid),
                reader.IsDBNull(decryptorName) ? null : reader.GetString(decryptorName),
                ReadLapsDecryptorRoutes(
                    findingId,
                    reader.GetInt64(reader.GetOrdinal("e_route_count"))),
                reader.GetInt64(reader.GetOrdinal("e_expansion_was_complete")) != 0);
        }
        else
        {
            throw new InvalidOperationException(
                $"Finding {reader.GetInt64(reader.GetOrdinal("finding_id"))} ({ruleId}) is stored "
                + "with no evidence row, so what it rests on has been lost. A finding that cannot "
                + "say what it rests on must not be presented as one.");
        }
        return new Finding(
            ruleId,
            versions[ruleId],
            Enum.Parse<Severity>(reader.GetString(reader.GetOrdinal("severity"))),
            new FindingSubject(
                Enum.Parse<FindingSubjectKind>(reader.GetString(reader.GetOrdinal("subject_kind"))),
                reader.GetString(reader.GetOrdinal("subject_key"))),
            Guid.Parse(reader.GetString(reader.GetOrdinal("object_guid"))),
            reader.GetString(reader.GetOrdinal("distinguished_name")),
            reader.GetString(reader.GetOrdinal("domain_fqdn")),
            reader.GetString(reader.GetOrdinal("object_class")),
            reader.GetString(reader.GetOrdinal("detail")),
            Enum.Parse<EvidenceCompleteness>(reader.GetString(reader.GetOrdinal("coverage"))),
            evidence) { PrincipalName = reader.GetString(reader.GetOrdinal("principal_name")) };
    }

    private MembershipRouteSummary ReadMembershipRoutes(long findingId)
    {
        var subject = findingId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return MembershipRouteStorage.Read(_connection, subject).TryGetValue(subject, out var routes)
            ? routes : throw new InvalidDataException("A finding has no membership-route completeness record.");
    }

    private IReadOnlyList<PathStep> ReadLapsRoute(string table, long findingId, long expectedLength)
    {
        // Table names are fixed callers, never input. The primary key bounds this to one finding;
        // other pages' routes must neither be decoded nor used to fill missing support here.
        using var command = _connection.CreateCommand();
        command.CommandText = $"SELECT ordinal, sid, name FROM {table} WHERE finding_id=$id ORDER BY ordinal";
        command.Parameters.AddWithValue("$id", findingId);
        using var reader = command.ExecuteReader();
        var route = new List<PathStep>();
        while (reader.Read())
        {
            if (reader.GetInt64(0) != route.Count || route.Count >= expectedLength || string.IsNullOrWhiteSpace(reader.GetString(1)))
                throw new InvalidDataException(LapsInventoryStorage.Message("InvalidRoute"));
            route.Add(new(reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetString(2)));
        }
        if (route.Count != expectedLength) throw new InvalidDataException(LapsInventoryStorage.Message("InvalidRoute"));
        return route;
    }

    private LapsDecryptorRouteEvidence[] ReadLapsDecryptorRoutes(
        long findingId,
        long expectedCount)
    {
        var stored = new List<(string Sid, string? Name, long PathLength)>();

        using (var command = _connection.CreateCommand())
        {
            command.CommandText =
                "SELECT route_ordinal, broad_principal_sid, broad_principal_name, path_length "
                + "FROM finding_laps_decryptor_route WHERE finding_id=$id "
                + "ORDER BY route_ordinal";
            command.Parameters.AddWithValue("$id", findingId);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                if (reader.GetInt64(0) != stored.Count
                    || stored.Count >= expectedCount
                    || string.IsNullOrWhiteSpace(reader.GetString(1))
                    || reader.GetInt64(3) < 1)
                {
                    throw new InvalidDataException(LapsInventoryStorage.Message("InvalidRoute"));
                }

                stored.Add((
                    reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetString(2),
                    reader.GetInt64(3)));
            }
        }

        if (stored.Count != expectedCount)
            throw new InvalidDataException(LapsInventoryStorage.Message("InvalidRoute"));

        return stored
            .Select((route, ordinal) => new LapsDecryptorRouteEvidence(
                route.Sid,
                route.Name,
                ReadLapsDecryptorPath(findingId, ordinal, route.PathLength)))
            .ToArray();
    }

    private List<PathStep> ReadLapsDecryptorPath(
        long findingId,
        int routeOrdinal,
        long expectedLength)
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT step_ordinal, sid, name FROM finding_laps_decryptor_path "
            + "WHERE finding_id=$id AND route_ordinal=$route ORDER BY step_ordinal";
        command.Parameters.AddWithValue("$id", findingId);
        command.Parameters.AddWithValue("$route", routeOrdinal);

        using var reader = command.ExecuteReader();
        var route = new List<PathStep>();
        while (reader.Read())
        {
            if (reader.GetInt64(0) != route.Count
                || route.Count >= expectedLength
                || string.IsNullOrWhiteSpace(reader.GetString(1)))
            {
                throw new InvalidDataException(LapsInventoryStorage.Message("InvalidRoute"));
            }

            route.Add(new(
                reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2)));
        }

        if (route.Count != expectedLength)
            throw new InvalidDataException(LapsInventoryStorage.Message("InvalidRoute"));

        return route;
    }

    private List<PathStep> ReadPathSteps(string table, long findingId)
    {
        var values = new List<PathStep>();

        using var command = _connection.CreateCommand();
        command.CommandText = $"SELECT sid,name FROM {table} WHERE finding_id=$id ORDER BY ordinal";
        command.Parameters.AddWithValue("$id", findingId);

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            _readCancellation.ThrowIfCancellationRequested();
            values.Add(new PathStep(reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1)));
        }

        return values;
    }

    private List<string> ReadChildValues(string table, string column, long findingId)
    {
        var values = new List<string>();

        using var command = _connection.CreateCommand();
        command.CommandText = $"SELECT {column} FROM {table} WHERE finding_id=$id ORDER BY ordinal";
        command.Parameters.AddWithValue("$id", findingId);

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            _readCancellation.ThrowIfCancellationRequested();
            values.Add(reader.GetString(0));
        }

        return values;
    }

    /// <summary>
    /// Which of a finding's stored SID history values name a privileged principal.
    /// </summary>
    /// <remarks>
    /// <b>Recomputed rather than stored, like the delegation table's two answers.</b> Whether a
    /// value is privileged, and what Microsoft calls it, are both asked of
    /// <see cref="PrivilegedSidHistory.PrivilegedName"/> - the same decision the rule made when it
    /// wrote the row. Storing either would create a copy that can disagree with the value it came
    /// from, and a second copy of the decision could disagree with the rule itself.
    /// </remarks>
    private static IReadOnlyList<PrivilegedSidHistoryMatch> PrivilegedSidHistoryMatches(
        IReadOnlyList<string> values) =>
    [
        .. values
            .Select(value => (Value: value, Name: PrivilegedSidCatalogue.PrivilegedName(value)))
            .Where(v => v.Name is not null)
            .Select(v => new PrivilegedSidHistoryMatch(
                v.Value,
                Sid.RelativeIdentifier(v.Value) ?? 0,
                v.Name!)),
    ];

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
            return;

        _connection.Dispose();
        _protection?.Dispose();
        _ownedStore?.Dispose();
        _disposed = true;
    }

    /// <summary>
    /// Whether this judgement was made against the evidence it is sitting beside, and why not.
    /// </summary>
    private static string? EvidenceMismatch(string bundleDirectory, string judgedSeal)
    {
        var evidenceSealPath = BundleLayout.SealPath(bundleDirectory);
        var contents = BundleSealing.ReadSeal(evidenceSealPath);

        if (contents is null || string.IsNullOrWhiteSpace(contents.Hash))
        {
            return $"The judgement in '{bundleDirectory}' names the evidence it judged and there "
                + $"is no readable evidence seal at '{evidenceSealPath}' to check it against. A "
                + "judgement is only meaningful beside the capture it was made from.";
        }

        if (string.Equals(contents.Hash, judgedSeal, StringComparison.Ordinal))
            return null;

        return $"The judgement in '{bundleDirectory}' was made against evidence sealed as "
            + $"{judgedSeal}, and the evidence in that bundle is sealed as {contents.Hash}. This "
            + "judgement is about a different capture. Two captures of one forest hold mostly the "
            + "same objects, so its findings would resolve against this evidence and be wrong "
            + "about it; judge this bundle rather than moving a judgement into it.";
    }

    private static string? DerivationMismatch(string bundleDirectory, Guid? judgedGeneration)
    {
        if (judgedGeneration is null)
            return null;

        var current = AnalysisStoreLifecycle.Resolve(bundleDirectory, AnalysisStoreKind.Derivation);
        if (!current.IsSuccess)
        {
            return $"The judgement in '{bundleDirectory}' consumed Derivation generation "
                + $"'{judgedGeneration:D}', and no complete current Derivation generation can be "
                + "resolved beside it.";
        }

        return current.Value!.GenerationId == judgedGeneration
            ? null
            : $"The judgement in '{bundleDirectory}' consumed Derivation generation "
                + $"'{judgedGeneration:D}', while the current Derivation generation is "
                + $"'{current.Value.GenerationId:D}'. Judge the bundle again from its current inputs.";
    }

    private static JudgementDescription? ReadDescription(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT schema_version, evidence_seal, judgement_generation_id, "
            + "derivation_generation_id, state, evaluation_as_of, judging_started_utc, "
            + "judging_completed_utc FROM judgement";

        using var reader = command.ExecuteReader();

        if (!reader.Read())
            return null;

        var version = reader.GetInt32(0);
        if (version != JudgementSchema.Version)
        {
            throw new SqliteException(
                $"The judgement was written against schema version {version} and this build reads "
                + $"version {JudgementSchema.Version}. Nothing here is kept backward compatible, "
                + "and a judgement is rebuilt rather than migrated: delete it and judge the bundle "
                + "again.",
                0);
        }

        if (reader.IsDBNull(7))
            return null;

        return new JudgementDescription(
            reader.GetString(1),
            Guid.Parse(reader.GetString(2)),
            reader.IsDBNull(3) ? null : Guid.Parse(reader.GetString(3)),
            Enum.Parse<JudgementRunState>(reader.GetString(4)),
            DateTimeOffset.Parse(reader.GetString(5), System.Globalization.CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(reader.GetString(6), System.Globalization.CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(reader.GetString(7), System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// The version each rule ran at, so a finding can carry the version of the rule that made it
    /// without the store keeping a second copy on every row.
    /// </summary>
    private Dictionary<string, int> ReadRuleVersions()
    {
        var versions = new Dictionary<string, int>(StringComparer.Ordinal);

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT rule_id, rule_version FROM rule_execution";

        using var reader = command.ExecuteReader();

        while (reader.Read())
            versions[reader.GetString(0)] = reader.GetInt32(1);

        return versions;
    }

    /// <summary>
    /// How many findings each rule wrote, counted in the database.
    /// </summary>
    /// <remarks>
    /// <b>Counted rather than derived from a list of findings</b>, because the caller that wants
    /// this wants it instead of the findings, not as well: a real forest's judgement holds
    /// thousands of rows and this screen shows one line per rule.
    /// </remarks>
    private Dictionary<string, int> ReadFindingCountsByRule()
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT rule_id, COUNT(*) FROM finding GROUP BY rule_id";

        using var reader = command.ExecuteReader();

        while (reader.Read())
            counts[reader.GetString(0)] = reader.GetInt32(1);

        return counts;
    }

    private Dictionary<string, List<MissingInput>> ReadMissingInputs()
    {
        var missing = new Dictionary<string, List<MissingInput>>(StringComparer.Ordinal);

        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT rule_id, attribute, objects_affected FROM rule_execution_missing_input "
            + "ORDER BY rule_id, attribute";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var ruleId = reader.GetString(0);

            if (!missing.TryGetValue(ruleId, out var inputs))
                missing[ruleId] = inputs = [];

            inputs.Add(new MissingInput(reader.GetString(1), reader.GetInt32(2)));
        }

        return missing;
    }

    private static string ReasonFor(SealState state) => state switch
    {
        SealState.Absent => "JudgementSealAbsent",
        SealState.Unreadable => "JudgementSealUnreadable",
        SealState.Mismatch => "JudgementSealMismatch",
        _ => throw new InvalidOperationException(
            $"{state} may be opened and is not a refusal. Only SealVerdict.MayBeOpened decides "
            + "which states those are, and this switch has fallen out of step with it."),
    };

    private static Result<JudgementReader> Failure(
        string reason, string description, string context) =>
        Result<JudgementReader>.Failure(
            AuditError.Create(
                ErrorCategory.Evidence, reason, ErrorSeverity.Failed, description, context));
}
