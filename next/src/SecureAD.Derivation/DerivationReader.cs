using System.Globalization;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Storage;

namespace SecureAD.Derivation;

/// <summary>
/// What a derivation recorded about itself.
/// </summary>
/// <param name="SchemaVersion">The shape of the store, so a reader can refuse one it cannot read.</param>
/// <param name="EvidenceSeal">The capture these facts were derived from.</param>
/// <param name="GenerationId">Which derive run produced them.</param>
/// <param name="State">What became of that run.</param>
/// <param name="StartedUtc">When deriving started.</param>
/// <param name="CompletedUtc">When it finished.</param>
public sealed record DerivationDescription(
    int SchemaVersion,
    string EvidenceSeal,
    Guid GenerationId,
    DerivationRunState State,
    DateTimeOffset StartedUtc,
    DateTimeOffset CompletedUtc);

/// <summary>
/// One phase of a derivation, read back.
/// </summary>
/// <param name="Phase">The phase, as it named itself.</param>
/// <param name="Outcome">What became of it.</param>
/// <param name="Error">Why it failed, when it did.</param>
public sealed record StoredDerivationPhase(
    string Phase,
    DerivationPhaseOutcome Outcome,
    string? Error);

/// <summary>
/// How much a derivation holds.
/// </summary>
/// <remarks>
/// <b>Counts rather than the rows themselves.</b> A forest's nesting is millions of edges and
/// nothing yet has a use for them; what the window needs is to say what a derivation produced
/// instead of how far its pass read. Handing back the rows would be an API designed against no
/// caller, which is what the rule interface is still deferred for.
/// </remarks>
/// <param name="Principals">Principals the derivation knows about.</param>
/// <param name="Identities">SIDs resolving to a principal, current and historical alike.</param>
/// <param name="NestingEdges">Direct nesting relationships, each held once.</param>
public sealed record DerivationSize(long Principals, long Identities, long NestingEdges);

public enum ProtectedPrincipalProductAvailability
{
    Available,
    DidNotRun,
    Failed,
    Missing,
}

public sealed record StoredAdminSdCatalogueEntry(
    int Id,
    string Name,
    string Scope,
    int Rid,
    string PrincipalStatus,
    string PrincipalProvenance,
    string PrincipalSourceId,
    string PropagationStatus,
    string PropagationProvenance,
    string PropagationSourceId,
    bool MaskExcludable);

public sealed record StoredProtectedPrincipalFact(
    int SidId,
    string Sid,
    string? Scope,
    ProtectedPrincipalEvaluation Evaluation,
    ProtectedPrincipalBasis? Basis,
    ProtectionUnknownReason UnknownReasons,
    IReadOnlyList<int> Path,
    OwnerAcceptance OwnerAcceptance)
{
    public MembershipRouteSummary MembershipRoutes { get; init; } = MembershipRouteSummary.NotDerived;

    public bool IsComplete => Evaluation != ProtectedPrincipalEvaluation.Unknown;
}

public sealed record StoredProtectedPrincipalDerivation(
    int CatalogueVersion,
    SecureAD.Kernel.Security.AdminSdExclusionMask Mask,
    IReadOnlyList<StoredAdminSdCatalogueEntry> Catalogue,
    IReadOnlyList<StoredProtectedPrincipalFact> Principals,
    ProtectionUnknownReason StatedLimits)
{
    private IndexedPrincipals _principals = new(Principals);

    /// <summary>The stored facts, owned as a read-only snapshot with their lookup index.</summary>
    public IReadOnlyList<StoredProtectedPrincipalFact> Principals
    {
        get => _principals;
        init => _principals = new(value);
    }

    public bool IsComplete => StatedLimits == ProtectionUnknownReason.None;

    /// <summary>Finds the first stored fact for this SID and scope without scanning all principals.</summary>
    public StoredProtectedPrincipalFact? Lookup(string sid, string? scope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);
        return _principals.Lookup(sid, scope);
    }

    // Keeping the index with an owned snapshot avoids stale lookups after a caller changes its
    // original list or a record copy replaces Principals. A metadata-only copy can share it safely.
    private sealed class IndexedPrincipals : System.Collections.ObjectModel.ReadOnlyCollection<StoredProtectedPrincipalFact>
    {
        private readonly Dictionary<(string Sid, string? Scope), StoredProtectedPrincipalFact> _byIdentity =
            new(IdentityComparer.Instance);

        internal IndexedPrincipals(IReadOnlyList<StoredProtectedPrincipalFact> principals)
            : base(principals.ToArray())
        {
            foreach (var fact in this)
                _byIdentity.TryAdd((fact.Sid, fact.Scope), fact);
        }

        internal StoredProtectedPrincipalFact? Lookup(string sid, string? scope) =>
            _byIdentity.GetValueOrDefault((sid, scope));
    }

    private sealed class IdentityComparer : IEqualityComparer<(string Sid, string? Scope)>
    {
        internal static readonly IdentityComparer Instance = new();

        public bool Equals((string Sid, string? Scope) left, (string Sid, string? Scope) right) =>
            string.Equals(left.Sid, right.Sid, StringComparison.Ordinal)
            && string.Equals(left.Scope, right.Scope, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((string Sid, string? Scope) value) => HashCode.Combine(
            StringComparer.Ordinal.GetHashCode(value.Sid),
            value.Scope is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(value.Scope));
    }
}

public sealed record StoredProtectedPrincipalProduct(
    ProtectedPrincipalProductAvailability Availability,
    StoredProtectedPrincipalDerivation? Value);

/// <summary>
/// Whether this store carries an answer about membership cycles, and if not, why not.
/// </summary>
/// <remarks>
/// <b>An empty table means two opposite things and this enum is what separates them.</b> A forest
/// whose expansion ran and found no loops has no rows here, and so does a bundle nobody expanded.
/// Reading emptiness as <i>no loops</i> would report a clean directory on the strength of a phase
/// that never happened.
/// </remarks>
public enum NestingCycleAvailability
{
    /// <summary>The expansion ran in full, so the cycles listed are all of them.</summary>
    Available,

    /// <summary>
    /// The expansion stopped at a budget. Every cycle listed is real, but there may be more, so a
    /// reader may report what is here and may not call the absence of anything else a fact.
    /// </summary>
    Partial,

    /// <summary>No expansion phase ran, so nothing is known either way.</summary>
    DidNotRun,

    /// <summary>The expansion phase failed.</summary>
    Failed,

    /// <summary>The phase is not recorded at all, which a store written by this build cannot be.</summary>
    Missing,
}

/// <summary>
/// What this store knows about membership cycles.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="Cycles"/> is null unless an answer was reached</b>, rather than empty, so that a
/// caller cannot read <i>nobody looked</i> as <i>there are none</i>. That is the same shape
/// <see cref="StoredProtectedPrincipalProduct"/> uses and it exists for the same reason.
/// </para>
/// <para>
/// <b>A cycle is a bare list of SID ids and not a record of its own, which is a concession to gate
/// 4 and the right one.</b> A one-field wrapper would be the declaring type of the only collection
/// here, and it could not say whether anyone had looked - so the gate refused it. Putting the
/// lists on the type that carries the answer keeps the vouching where it belongs, and there is no
/// place left to read an empty cycle as a fact.
/// </para>
/// <para>
/// <b>Each cycle is a set, not a path.</b> The expansion finds these as strongly connected
/// components, which say that every principal reaches every other; the particular route is not
/// unique and is not recorded, because storing one route invites a reader to believe it is the only
/// one.
/// </para>
/// </remarks>
/// <param name="Availability">Whether an answer was reached, and if not, why not.</param>
/// <param name="Cycles">
/// Each cycle, as the SID dictionary ids of the principals caught in it, or null where no answer was
/// reached.
/// </param>
public sealed record StoredNestingCycleProduct(
    NestingCycleAvailability Availability,
    IReadOnlyList<IReadOnlyList<int>>? Cycles)
{
    /// <summary>
    /// Whether every cycle in this forest is here, as opposed to every cycle anyone got to.
    /// </summary>
    /// <remarks>
    /// False covers both <i>nobody looked</i> and <i>the walk stopped early</i>. A caller may report
    /// what is here in either case; what it may not do is say the forest has no further loops.
    /// </remarks>
    public bool IsComplete => Availability is NestingCycleAvailability.Available;
}

/// <summary>
/// Everything a derivation store holds about the run that wrote it.
/// </summary>
/// <remarks>
/// <b>One call, because the parts are only meaningful together</b> - the reason
/// <c>StoredJudgement</c> gives. A count of principals without the phase outcomes beside it lets a
/// caller report a degraded derivation as though it were whole, which is the failure this stage is
/// shaped around.
/// </remarks>
/// <param name="Description">What the run recorded about itself.</param>
/// <param name="Phases">Every phase, whatever became of it.</param>
/// <param name="Size">How much the store holds.</param>
/// <param name="Completeness">
/// What the derivation does not cover. Not nullable, and not omitted for a whole derivation: a
/// caller that had to check for its absence before trusting the size beside it would eventually
/// forget to, and the reading it would then give is the clean one.
/// </param>
/// <param name="AttributeVisibility">
/// Which attributes this forest withholds, so a rule can tell an absent value from a withheld one.
/// </param>
/// <param name="NestingCycles">
/// Groups that contain one another. Microsoft states that group membership may have loops, and two
/// groups in one are permanently the same group as far as authorization is concerned.
/// </param>
public sealed record StoredDerivation(
    DerivationDescription Description,
    IReadOnlyList<StoredDerivationPhase> Phases,
    DerivationSize Size,
    DerivationCompleteness Completeness,
    StoredProtectedPrincipalProduct ProtectedPrincipals,
    StoredAttributeVisibilityProduct AttributeVisibility,
    StoredNestingCycleProduct NestingCycles)
{
    /// <summary>Whether every phase that ran succeeded.</summary>
    /// <remarks>
    /// A phase that did not run is not a failure and is not counted as one - it had no input, which
    /// is a different sentence from having misbehaved.
    /// </remarks>
    public bool EveryPhaseThatRanSucceeded =>
        Phases.All(p => p.Outcome is DerivationPhaseOutcome.Succeeded or DerivationPhaseOutcome.DidNotRun);
}

/// <summary>
/// Reads a derivation store back, the way <c>BundleReader</c> reads evidence and
/// <c>JudgementReader</c> reads a judgement.
/// </summary>
/// <remarks>
/// <para>
/// <b>Refusing a store this build cannot read is its first job.</b> The SID dictionary gained a
/// scope at schema version 2, because a SID is unique within its scope and not within a forest. A
/// version 1 store keys principals by SID alone, so every domain's built-in groups are merged in it
/// - reading one as though it were current would hand back the fabricated cross-domain privilege
/// path that <c>docs/decisions/0087-a-sid-is-unique-within-its-scope.md</c> exists to prevent.
/// </para>
/// <para>
/// <b>It reads the header, the phases and the size, and no closures.</b> Nothing consumes a
/// membership closure yet; the rule interface that would is deliberately unbuilt until a rule needs
/// it. An API shaped now would be shaped against no caller, which is how the predecessor's
/// <c>GetPrecomputedClosure</c> came to have none.
/// </para>
/// </remarks>
public sealed class DerivationReader : IDisposable
{
    private readonly SqliteConnection _connection;
    private ProtectedStoreFile.Lease? _protection;
    private bool _disposed;
    private ExpansionInputs? _expansionInputs;

    // Owned by this verified reader, not shared between derivation generations. The walks below
    // never mutate these inputs; their queues, visited sets, paths and budgets remain per request.
    private sealed record ExpansionInputs(
        Dictionary<int, List<int>> Edges,
        Dictionary<int, (string Sid, string Scope)> Identities,
        Dictionary<int, bool?> Groups,
        HashSet<int> UnresolvedMembers);

    private DerivationReader(
        string bundleDirectory, SqliteConnection connection, DerivationDescription description)
    {
        BundleDirectory = bundleDirectory;
        _connection = connection;
        Description = description;
    }

    /// <summary>The bundle this derivation was opened from.</summary>
    public string BundleDirectory { get; }

    /// <summary>What the derivation recorded about itself.</summary>
    public DerivationDescription Description { get; }

    /// <summary>Reads validated, source-linked membership inputs without expanding a group.</summary>
    public CapturedMembershipInput ReadMembershipInput()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return MembershipInputStorage.Read(_connection, Description.GenerationId);
    }

    /// <summary>Reads only the saved containing-group relationships reachable from the selected current SID.</summary>
    public DelegationMembership ReadContainingGroups(string sid, string? domainFqdn, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);
        cancellationToken.ThrowIfCancellationRequested();
        if (!NestingWasDerived())
            throw new InvalidOperationException("Saved group nesting is unavailable. Uncheck Include group-held permissions to search direct entries.");
        var scope = Sid.IsBuiltinDomain(sid)
            ? !string.IsNullOrWhiteSpace(domainFqdn) ? domainFqdn.ToLowerInvariant()
                : throw new ArgumentException("Select a domain-qualified identity for this built-in SID.", nameof(domainFqdn))
            : "";
        var root = FindSidId(sid, scope)
            ?? throw new InvalidOperationException("The selected SID has no saved membership identity. Direct-only lookup remains available.");
        if (PrincipalCarrying(root) != root)
            throw new InvalidOperationException("SID history is not group nesting. Select the current principal or use direct-only lookup.");
        return ContainingGroupReader.Read(_connection, Description, root, cancellationToken);
    }

    /// <summary>
    /// Verifies the derivation's seal and, only if it is intact and this build understands the
    /// store, opens it for reading.
    /// </summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    /// <returns>The open reader, or an <see cref="AuditError"/> saying which check refused it.</returns>
    public static Result<DerivationReader> Open(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var resolved = AnalysisStoreLifecycle.Resolve(
            bundleDirectory,
            AnalysisStoreKind.Derivation);
        if (!resolved.IsSuccess)
            return Result<DerivationReader>.Failure(resolved.Error!);

        var generation = resolved.Value!;
        var verdict = BundleSealing.VerifyAnalysisGeneration(
            bundleDirectory,
            generation,
            "derived facts",
            "It does not prove every closure is complete, which is a claim the store makes in its own tables.");
        if (!verdict.MayBeOpened)
        {
            return Failure(
                "DerivationSealNotIntact",
                verdict.Detail,
                bundleDirectory);
        }

        var path = BundleLayout.AnalysisGenerationDataPath(
            bundleDirectory, generation.Kind, generation.GenerationId);
        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());

        var opened = OpenConnection(bundleDirectory, generation, connection);
        if (opened.IsSuccess)
        {
            try { _ = opened.Value.Read(); }
            catch (Exception error) when (error is SqliteException or FormatException or ArgumentException or InvalidOperationException)
            {
                opened.Value.Dispose();
                return Failure("DerivationUnreadable",
                    $"The seal on the derivation in '{bundleDirectory}' is intact and the store could "
                    + $"not be read: {error.Message}. The bytes are the bytes that were sealed, so this "
                    + "is a defect in this build rather than damage to the store.", path);
            }
        }
        return opened;
    }

    /// <summary>Opens an independent stored-fact reader under an existing protected generation.</summary>
    public static Result<DerivationReader> Open(ProtectedStoreFile store, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (store.Generation is not { Kind: AnalysisStoreKind.Derivation } generation) throw new ArgumentException(nameof(store));
        ProtectedStoreFile.Lease? lease = store.Acquire(cancellationToken);
        try
        {
            var opened = OpenConnection(store.BundleDirectory, generation, lease.Connection);
            if (opened.IsSuccess) { opened.Value._protection = lease; lease = null; }
            return opened;
        }
        finally { lease?.Dispose(); }
    }

    private static Result<DerivationReader> OpenConnection(string bundleDirectory, AnalysisStoreGeneration generation, SqliteConnection connection)
    {
        var path = BundleLayout.AnalysisGenerationDataPath(bundleDirectory, generation.Kind, generation.GenerationId);
        try
        {
            if (connection.State != System.Data.ConnectionState.Open) connection.Open();
            var description = ReadDescription(connection);

            if (description is null)
            {
                connection.Dispose();
                return Failure(
                    "DerivationUnreadable",
                    $"The derivation at '{path}' records no run. Its seal is intact, so this is a "
                    + "defect in the build that wrote it rather than damage to the file.",
                    path);
            }

            if (description.GenerationId != generation.GenerationId)
            {
                connection.Dispose();
                return Failure(
                    "DerivationGenerationMismatch",
                    $"The derivation manifest selects generation '{generation.GenerationId:D}', "
                    + $"but the database identifies itself as '{description.GenerationId:D}'. The "
                    + "database and manifest are not one generation and cannot be read together.",
                    path);
            }

            var evidenceMismatch = EvidenceMismatch(bundleDirectory, description.EvidenceSeal);
            if (evidenceMismatch is not null)
            {
                connection.Dispose();
                return Failure("DerivationIsNotForThisEvidence", evidenceMismatch, path);
            }

            if (description.SchemaVersion != DerivationSchema.Version)
            {
                connection.Dispose();
                return Failure(
                    "DerivationSchemaNotUnderstood",
                    $"The derivation at '{path}' is schema version {description.SchemaVersion} and "
                    + $"this build reads version {DerivationSchema.Version}. It is refused rather "
                    + "than read, because the versions differ in what a stored principal means: "
                    + "before version 2 a SID was keyed without its scope, so every domain's "
                    + "built-in groups were held as one principal and their memberships merged. "
                    + "Delete it and derive the bundle again - the evidence is untouched and "
                    + "nothing else rests on it.",
                    path);
            }

            return new DerivationReader(bundleDirectory, connection, description);
        }

        catch (Exception error) when (
            error is SqliteException
            or FormatException
            or ArgumentException
            or InvalidOperationException)
        {
            connection.Dispose();
            return Failure(
                "DerivationUnreadable",
                $"The seal on the derivation in '{bundleDirectory}' is intact and the store could "
                + $"not be read: {error.Message}. The bytes are the bytes that were sealed, so this "
                + "is a defect in this build rather than damage to the store.",
                path);
        }
    }

    private static string? EvidenceMismatch(string bundleDirectory, string derivedSeal)
    {
        var evidenceSealPath = BundleLayout.SealPath(bundleDirectory);
        var contents = BundleSealing.ReadSeal(evidenceSealPath);

        if (contents is null || string.IsNullOrWhiteSpace(contents.Hash))
        {
            return $"The derivation in '{bundleDirectory}' names the Evidence it was derived from "
                + $"and there is no readable Evidence seal at '{evidenceSealPath}' to check it "
                + "against. Derived facts are meaningful only beside their source capture.";
        }

        if (string.Equals(contents.Hash, derivedSeal, StringComparison.Ordinal))
            return null;

        return $"The derivation in '{bundleDirectory}' was made from Evidence sealed as "
            + $"{derivedSeal}, and the Evidence in that bundle is sealed as {contents.Hash}. "
            + "These derived facts belong to a different capture; derive this bundle again rather "
            + "than moving a derivation into it.";
    }

    /// <summary>
    /// Everything this derivation recorded about the run that wrote it.
    /// </summary>
    public StoredDerivation Read()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var phases = ReadPhases();
        return new StoredDerivation(
            Description,
            phases,
            ReadSize(),
            ReadCompleteness(),
            ReadProtectedPrincipals(phases),
            ReadSchemaVisibility(phases),
            ReadNestingCycles(phases));
    }

    /// <summary>
    /// Whether this store carries group nesting that can be walked.
    /// </summary>
    /// <remarks>
    /// <b>Asked of the reader rather than worked out by the caller.</b> The answer depends on which
    /// phase produced the edges and what became of it, and a caller that reconstructed that would
    /// need the phase's name - a second copy of a string that has already drifted once in this
    /// store. It also keeps Judgement from depending on Derivation's internals to decide whether a
    /// rule can be offered an expansion.
    /// </remarks>
    public bool NestingWasDerived()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var nesting = ReadPhases()
            .FirstOrDefault(p => p.Phase == MembershipNestingPass.PhaseName);

        return nesting is not null
            && nesting.Outcome is not (DerivationPhaseOutcome.DidNotRun or DerivationPhaseOutcome.Failed);
    }

    /// <summary>
    /// How many principals claimed a member no captured object answers to, or null where the
    /// nesting was never derived.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Null rather than zero where the phase did not run</b>, for the reason
    /// <see cref="NestingWasDerived"/> exists at all. A store with no rows because nothing was
    /// derived and a store with no rows because every member resolved are opposite facts, and a
    /// screen reading the second as the first would tell an operator his groups are fully known
    /// when nobody looked.
    /// </para>
    /// <para>
    /// <b>Distinct principals, matching what the derive run logged.</b> The question is how many
    /// answers are short, not how many names went unmatched; one group missing forty members is one
    /// group whose membership cannot be vouched for. P-164.
    /// </para>
    /// </remarks>
    public int? GroupsWithUnidentifiedMembers()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!NestingWasDerived())
            return null;

        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT COUNT(DISTINCT sid_id) FROM nesting_unresolved_link WHERE direction = $direction";
        command.Parameters.AddWithValue("$direction", nameof(NestingLinkDirection.Member));

        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Expands one principal to everything nested inside it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Walked on demand rather than read from a stored closure, and that is deliberate.</b> The
    /// transitive closure of every group is quadratic in a real forest, while every caller asks
    /// about a handful of named principals - an entry in a security descriptor, a value out of
    /// Group Policy, a group an operator typed. The edges are already stored; the answer is cheap
    /// to reach from them and expensive to keep.
    /// </para>
    /// <para>
    /// <b>Breadth first, with a visited set.</b> Microsoft is explicit that group membership may
    /// have loops and that any enumeration should keep a list of what it has seen to end the
    /// recursion - <i>Determining a User's or Group's Membership in a Group</i>. Breadth first also
    /// means the first route found to a principal is a shortest one, which is the route worth
    /// showing an operator.
    /// </para>
    /// <para>
    /// <b>A budget, because a forest can be large and a caller can be a screen.</b> Reaching it is
    /// reported rather than hidden: the members found are real and the silence about the rest is
    /// not a fact.
    /// </para>
    /// </remarks>
    /// <param name="sid">The principal to expand.</param>
    /// <param name="scope">The scope its SID is unique within, empty for a forest-wide principal.</param>
    /// <param name="budget">The most principals to return before stopping.</param>
    /// <returns>What is inside it, and what the walk could not reach.</returns>
    public PrincipalExpansion MembersOf(string sid, string scope, int budget = DefaultExpansionBudget) =>
        MembersOf(sid, scope, budget, null, CancellationToken.None);

    /// <summary>
    /// Walks the same saved nesting with a caller's source-backed link qualification. Only accepted
    /// links enter the visited set; an unsupported shortcut cannot hide a supported longer route.
    /// This finite captured-graph walk has no additional result or depth limit.
    /// </summary>
    public PrincipalExpansion MembersOf(string sid, string scope,
        Func<(string Sid, string Scope), (string Sid, string Scope), bool> qualifyLink,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(qualifyLink);
        return MembersOf(sid, scope, null, qualifyLink, cancellationToken);
    }

    private PrincipalExpansion MembersOf(string sid, string scope, int? budget,
        Func<(string Sid, string Scope), (string Sid, string Scope), bool>? qualifyLink,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);
        ArgumentNullException.ThrowIfNull(scope);
        if (budget is { } ceiling) ArgumentOutOfRangeException.ThrowIfNegativeOrZero(ceiling);
        cancellationToken.ThrowIfCancellationRequested();

        // Discriminated on the phase and not on the table being empty, for the reason the schema
        // gives everywhere else in this store: a forest with no nesting in it and a bundle whose
        // nesting pass never ran both leave nesting_edge empty, and reading the second as the first
        // would report a flat directory on the strength of a phase that did not happen.
        if (!NestingWasDerived())
            return new PrincipalExpansion(sid, PrincipalExpansionOutcome.NoNestingDerived, null);

        var rootId = FindSidId(sid, scope);

        if (rootId is null)
            return new PrincipalExpansion(sid, OutcomeForMissingPrincipal(sid), null);

        // THE SID ASKED ABOUT AND THE PRINCIPAL THAT ANSWERS TO IT ARE NOT THE SAME ROW. A group
        // carried through a migration answers to its old SID as well as its current one, both are
        // interned in the same dictionary, and the nesting edges hang off the current one alone -
        // deliberately, because sIDHistory is another identity and never an edge. Walking from the
        // identity that was matched would therefore find a group, find no edges beneath it, and
        // report it as containing nobody. An access control entry naming the old SID would read as
        // granting access to an empty group, which is the silence a customer cannot see. P-165.
        var walkFrom = PrincipalCarrying(rootId.Value);

        // A new root needs a new walk, not another read of every relationship in the forest.
        // Publish only after all four reads succeed, so a failed load cannot leave partial inputs.
        var inputs = _expansionInputs ??= new ExpansionInputs(
            ReadNestingEdges(), ReadSidIdentities(), ReadSecurityEnabledByPrincipal(),
            ReadGroupsWithUnresolvedMembers());
        var edges = inputs.Edges;
        var identities = inputs.Identities;
        var groups = inputs.Groups;
        var unresolvedMembers = inputs.UnresolvedMembers;

        // The path to each principal, kept as the parent that first reached it. Storing one parent
        // rather than a whole path per member keeps this linear in the number of principals; the
        // path is walked back out at the end, only for the members actually returned.
        var parent = new Dictionary<int, int>();
        var order = new List<int>();
        var seen = new HashSet<int> { walkFrom };
        var queue = new Queue<int>();
        queue.Enqueue(walkFrom);

        // The groups the walk went on to enter, which is not every group it listed. Kept so that a
        // member left deliberately unentered is not later mistaken for one the walk ran out of room
        // to finish.
        var entered = new HashSet<int>();
        var throughUnknownGroupType = false;

        // Seeded from the principal being expanded, which no later check would catch: the root is
        // never a member of its own answer, so a group that itself claimed an unidentifiable member
        // would otherwise report everything it holds as everything there is. P-164.
        var throughUnidentifiedMember = unresolvedMembers.Contains(walkFrom);

        var stopped = false;

        while (queue.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = queue.Dequeue();

            if (!edges.TryGetValue(current, out var members))
                continue;

            IEnumerable<int> ordered = qualifyLink is null ? members
                : members.OrderBy(member => identities[member].Sid, StringComparer.Ordinal)
                    .ThenBy(member => identities[member].Scope, StringComparer.Ordinal);
            foreach (var member in ordered)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (qualifyLink is not null && !qualifyLink(identities[current], identities[member]))
                    continue;
                // The visited set is what makes a cycle terminate. Without it a loop that Microsoft
                // says may exist would be walked until something ran out.
                if (!seen.Add(member))
                    continue;

                parent[member] = current;
                order.Add(member);
                // A qualified group with no resolved children may still name uncaptured members.
                if (qualifyLink is not null && unresolvedMembers.Contains(member))
                    throughUnidentifiedMember = true;

                // LISTED EITHER WAY, ENTERED ONLY WHERE THE HOP CARRIES AUTHORIZATION. A
                // distribution group nested in a security group really is a member of it, so it
                // belongs in the answer; but Microsoft is explicit that an account beneath it does
                // not receive the enclosing group's SID in its token, so its members are not
                // members of what contains it. Walking through one names principals who hold
                // nothing, which is a finding a customer would act on and should not - P-166.
                //
                // This is AuthorizationMembershipExpander's rule, deliberately the same one. Two
                // answers to "who is effectively inside this group" that disagree are worse than
                // either answer alone, and the stored closure has been security-aware all along.
                if (edges.ContainsKey(member))
                {
                    var carriesAuthorization = groups.GetValueOrDefault(member);

                    if (carriesAuthorization is not false)
                    {
                        // A group whose type nobody captured is not thereby a distribution group.
                        // Refusing to enter it would drop authorization that exists, so the route
                        // is followed and the answer says it cannot be vouched for.
                        if (carriesAuthorization is null)
                            throughUnknownGroupType = true;

                        // Flagged on entering rather than on merely listing it, for the reason the
                        // line above is: what is below a group the walk chose not to enter is not
                        // part of this answer, so a link missing down there does not thin it.
                        if (unresolvedMembers.Contains(member))
                            throughUnidentifiedMember = true;

                        entered.Add(member);
                        queue.Enqueue(member);
                    }
                }

                if (budget is null || order.Count < budget)
                    continue;

                stopped = true;
                break;
            }

            if (stopped)
                break;
        }

        var expanded = new List<ExpandedPrincipal>(order.Count);

        foreach (var memberId in order)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var identity = identities.GetValueOrDefault(memberId);

            // A member is complete when nothing below it was left unreached. Where the walk stopped,
            // every group still on the frontier is marked incomplete rather than quietly trusted.
            // A group the walk chose not to enter is complete on these terms and not a thinning of
            // the answer: what is below a distribution group does not belong in this answer at all.
            var reachedEverythingBelow = !stopped
                || !entered.Contains(memberId)
                || edges[memberId].All(seen.Contains);

            // The second way a member's contents can be short, and it is checked apart because it
            // has a different cause and a different remedy. The walk stopping is this product's own
            // budget; a member nobody could identify is a hole in the capture, and no larger budget
            // would find it. P-164.
            var claimedSomethingUnidentified =
                entered.Contains(memberId) && unresolvedMembers.Contains(memberId);

            expanded.Add(new ExpandedPrincipal(
                identity.Sid ?? string.Empty,
                identity.Scope ?? string.Empty,
                PathTo(memberId, walkFrom, parent, identities),
                reachedEverythingBelow && !claimedSomethingUnidentified));
        }

        // Order matters: a budget that stopped the walk is the larger silence, and saying only that
        // the types were uncertain would understate it. An unidentified member outranks an unknown
        // group type for the same reason - members that were never reached at all is a definite gap,
        // while an uncertain group type is a doubt about members that were.
        var outcome = stopped
            ? PrincipalExpansionOutcome.StoppedAtBudget
            : throughUnidentifiedMember
                ? PrincipalExpansionOutcome.ExpandedWithUnidentifiedMember
                : throughUnknownGroupType
                    ? PrincipalExpansionOutcome.ExpandedThroughUnknownGroupType
                    : PrincipalExpansionOutcome.Expanded;

        return new PrincipalExpansion(sid, outcome, expanded);
    }

    /// <summary>How many principals an expansion returns before it stops.</summary>
    /// <remarks>
    /// <b>Named rather than left to each caller.</b> A screen and a rule asking the same question
    /// with different budgets would disagree about the same group, and the one with the smaller
    /// budget would look like the correct answer because it came back faster.
    /// </remarks>
    public const int DefaultExpansionBudget = 5000;

    /// <summary>Walks the parent chain back out to the principal that was expanded.</summary>
    /// <param name="memberId">The principal to describe.</param>
    /// <param name="rootId">Where the walk started.</param>
    /// <param name="parent">What first reached each principal.</param>
    /// <param name="identities">SID text by dictionary id.</param>
    private static IReadOnlyList<string> PathTo(
        int memberId,
        int rootId,
        Dictionary<int, int> parent,
        Dictionary<int, (string Sid, string Scope)> identities)
    {
        var path = new List<string>();
        var current = memberId;

        while (true)
        {
            path.Add(identities.GetValueOrDefault(current).Sid ?? string.Empty);

            if (current == rootId || !parent.TryGetValue(current, out var next))
                break;

            current = next;
        }

        path.Reverse();
        return path;
    }

    /// <summary>
    /// Whether a principal nothing carries is definitively absent or merely out of sight.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The default is ignorance, and every condition below has to be met to leave it.</b> The
    /// identifier must be domain-relative, so that it names a domain at all; that domain must be
    /// one this derivation established a SID for; and the run must have read it <i>in full</i>.
    /// Anything else - a built-in or well-known identifier, a domain with no row, a domain read in
    /// part, unreachable or excluded - answers
    /// <see cref="PrincipalExpansionOutcome.PrincipalNotFound"/>, exactly as it did before this
    /// question could be asked.
    /// </para>
    /// <para>
    /// <b>The asymmetry is deliberate.</b> Answering "not found" where the principal really does
    /// not exist costs a rule its verdict on one object, which an operator sees and can act on.
    /// Answering "does not exist" where the domain was never read would report a live delegation as
    /// harmless, which nobody sees at all. Only the first is an acceptable way to be wrong.
    /// </para>
    /// </remarks>
    /// <param name="sid">The SID no principal in this derivation carries.</param>
    private PrincipalExpansionOutcome OutcomeForMissingPrincipal(string sid)
    {
        var domainSid = DomainRelativeSid.DomainOf(sid);

        if (domainSid is null)
            return PrincipalExpansionOutcome.PrincipalNotFound;

        return ReadDomainReadOutcome(domainSid) == DomainReadOutcome.Read
            ? PrincipalExpansionOutcome.PrincipalDoesNotExist
            : PrincipalExpansionOutcome.PrincipalNotFound;
    }

    /// <summary>
    /// What the run made of reading the domain with this SID, or null where it holds no row.
    /// </summary>
    private DomainReadOutcome? ReadDomainReadOutcome(string domainSid)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT outcome FROM domain_read_coverage WHERE domain_sid = $sid";
        command.Parameters.AddWithValue("$sid", domainSid);

        var found = command.ExecuteScalar();

        if (found is null or DBNull)
            return null;

        // Stored by name, so an unrecognised value is a store this reader does not understand
        // rather than something to guess at. Null is the cautious answer and the caller refuses on
        // it, which is what an unreadable row deserves.
        return Enum.TryParse<DomainReadOutcome>((string)found, out var outcome) ? outcome : null;
    }

    /// <summary>The dictionary id of one SID in one scope, or null where it is not held.</summary>
    /// <param name="sid">The SID.</param>
    /// <param name="scope">The scope it is unique within.</param>
    private int? FindSidId(string sid, string scope)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT sid_id FROM sid WHERE sid = $sid AND scope = $scope";
        command.Parameters.AddWithValue("$sid", sid);
        command.Parameters.AddWithValue("$scope", scope);

        var found = command.ExecuteScalar();
        return found is null or DBNull ? null : Convert.ToInt32(found, CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// The principal that answers to one identity, which is the identity itself unless it is a SID
    /// carried from a migration.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Every identity resolves through the same hop, including a principal's own.</b> The store
    /// records a row where <c>principal_sid_id</c> equals <c>sid_id</c> for a current SID, so this
    /// needs no special case for the ordinary answer and cannot acquire one that drifts.
    /// </para>
    /// <para>
    /// <b>An identity with no row at all stands for itself.</b> A SID interned only because an edge
    /// or an access control entry named it has no identity row, and redirecting it anywhere would
    /// be an invention.
    /// </para>
    /// </remarks>
    /// <param name="sidId">The identity that was matched.</param>
    private int PrincipalCarrying(int sidId)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT principal_sid_id FROM sid_identity WHERE sid_id = $sid";
        command.Parameters.AddWithValue("$sid", sidId);

        var found = command.ExecuteScalar();

        return found is null or DBNull
            ? sidId
            : Convert.ToInt32(found, CultureInfo.InvariantCulture);
    }

    /// <summary>Every nesting edge, as members by group.</summary>
    private Dictionary<int, List<int>> ReadNestingEdges()
    {
        var edges = new Dictionary<int, List<int>>();

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT group_sid_id, member_sid_id FROM nesting_edge";
        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var group = reader.GetInt32(0);

            if (!edges.TryGetValue(group, out var members))
            {
                members = [];
                edges[group] = members;
            }

            members.Add(reader.GetInt32(1));
        }

        return edges;
    }

    /// <summary>
    /// The principals that named something inside them which nothing in this bundle answers to.
    /// </summary>
    /// <remarks>
    /// <b>Only the <see cref="NestingLinkDirection.Member"/> rows, and the filter is the point.</b>
    /// A principal that named a containing group nobody captured is short in the other direction -
    /// what encloses it - which is not the question an expansion answers. Reading both here would
    /// mark a group incomplete on the strength of evidence about something else entirely. P-164.
    /// </remarks>
    private HashSet<int> ReadGroupsWithUnresolvedMembers()
    {
        var groups = new HashSet<int>();

        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT sid_id FROM nesting_unresolved_link WHERE direction = $direction";
        command.Parameters.AddWithValue("$direction", nameof(NestingLinkDirection.Member));
        using var reader = command.ExecuteReader();

        while (reader.Read())
            groups.Add(reader.GetInt32(0));

        return groups;
    }

    /// <summary>The SID text and scope of every principal, by dictionary id.</summary>
    private Dictionary<int, (string Sid, string Scope)> ReadSidIdentities()
    {
        var identities = new Dictionary<int, (string, string)>();

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT sid_id, sid, scope FROM sid";
        using var reader = command.ExecuteReader();

        while (reader.Read())
            identities[reader.GetInt32(0)] = (reader.GetString(1), reader.GetString(2));

        return identities;
    }

    /// <summary>
    /// Whether each group's flags say it can carry authorization, by dictionary id.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Tri-state, and the third state is the reason this exists.</b> True is a security group,
    /// false is a distribution group, and null is a group whose <c>groupType</c> the capture never
    /// read. A principal with no row here answers null for the same reason: nobody established what
    /// it is. Collapsing null into false would drop authorization edges that exist.
    /// </para>
    /// <para>
    /// <b>Computed through <see cref="MembershipNestingPass.IsSecurityEnabled"/> rather than here.</b>
    /// The schema stores <c>group_type</c> raw and says plainly that the answers from it are not
    /// stored; a second reading of the same flag in this file is how two parts of the product come
    /// to disagree about one group.
    /// </para>
    /// </remarks>
    private Dictionary<int, bool?> ReadSecurityEnabledByPrincipal()
    {
        var answers = new Dictionary<int, bool?>();

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT sid_id, group_type FROM principal";
        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var groupType = reader.IsDBNull(1) ? (int?)null : reader.GetInt32(1);
            answers[reader.GetInt32(0)] = MembershipNestingPass.IsSecurityEnabled(groupType);
        }

        return answers;
    }

    /// <summary>
    /// Reads the membership cycles, or says why there are none to read.
    /// </summary>
    /// <remarks>
    /// <b>Discriminated on the expansion phase and never on the table being empty</b>, because a
    /// forest with no loops and a bundle nobody expanded both produce no rows. This is the same
    /// reasoning the schema gives for <c>derivation_phase</c> existing at all.
    /// </remarks>
    /// <param name="phases">Every phase the run recorded.</param>
    private StoredNestingCycleProduct ReadNestingCycles(IReadOnlyList<StoredDerivationPhase> phases)
    {
        var phase = phases.FirstOrDefault(
            p => p.Phase == AuthorizationMembershipExpander.PhaseName);

        var availability = phase?.Outcome switch
        {
            DerivationPhaseOutcome.Succeeded => NestingCycleAvailability.Available,

            // The expansion stopped at a budget. What it found before stopping is real, so the
            // cycles are handed over - with the availability saying they are a floor rather than a
            // total, which is the distinction a caller cannot make on its own.
            DerivationPhaseOutcome.Degraded => NestingCycleAvailability.Partial,

            DerivationPhaseOutcome.DidNotRun => NestingCycleAvailability.DidNotRun,
            DerivationPhaseOutcome.Failed => NestingCycleAvailability.Failed,
            _ => NestingCycleAvailability.Missing,
        };

        if (availability is not (NestingCycleAvailability.Available or NestingCycleAvailability.Partial))
            return new StoredNestingCycleProduct(availability, null);

        var byCycle = new Dictionary<long, List<int>>();

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT cycle_id, sid_id FROM nesting_cycle ORDER BY cycle_id, sid_id";
        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var cycleId = reader.GetInt64(0);

            if (!byCycle.TryGetValue(cycleId, out var members))
            {
                members = [];
                byCycle[cycleId] = members;
            }

            members.Add(reader.GetInt32(1));
        }

        var cycles = byCycle
            .OrderBy(pair => pair.Key)
            .Select(pair => (IReadOnlyList<int>)pair.Value)
            .ToList();

        return new StoredNestingCycleProduct(availability, cycles);
    }

    /// <summary>
    /// Reads the attribute-visibility product, or says why there is none.
    /// </summary>
    /// <remarks>
    /// <b>Discriminated on the metadata row rather than on the table being empty</b>, for the
    /// reason the schema gives: a capture refused the schema partition produces a product with no
    /// rows, and that is not the same as no product at all.
    /// </remarks>
    private StoredAttributeVisibilityProduct ReadSchemaVisibility(
        IReadOnlyList<StoredDerivationPhase> phases)
    {
        using (var metadata = _connection.CreateCommand())
        {
            metadata.CommandText = "SELECT attributes_read FROM attribute_visibility_derivation";
            using var metadataReader = metadata.ExecuteReader();

            if (!metadataReader.Read())
            {
                var phase = phases.FirstOrDefault(
                    p => p.Phase == AttributeVisibilityDeriver.PhaseName);

                var availability = phase?.Outcome switch
                {
                    DerivationPhaseOutcome.DidNotRun => AttributeVisibilityAvailability.DidNotRun,
                    DerivationPhaseOutcome.Failed => AttributeVisibilityAvailability.Failed,
                    _ => AttributeVisibilityAvailability.Missing,
                };

                return new StoredAttributeVisibilityProduct(availability, null);
            }
        }

        var attributes = new List<AttributeVisibilityFact>();

        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT ldap_display_name, search_flags, system_flags FROM attribute_visibility "
            + "ORDER BY ldap_display_name";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            attributes.Add(new AttributeVisibilityFact(
                reader.GetString(0),
                reader.IsDBNull(1) ? null : reader.GetInt32(1),
                reader.IsDBNull(2) ? null : reader.GetInt32(2)));
        }

        return new StoredAttributeVisibilityProduct(
            AttributeVisibilityAvailability.Available,
            new StoredAttributeVisibility(attributes));
    }

    private StoredProtectedPrincipalProduct ReadProtectedPrincipals(
        IReadOnlyList<StoredDerivationPhase> phases)
    {
        using var metadata = _connection.CreateCommand();
        metadata.CommandText =
            "SELECT catalogue_version, mask_outcome, mask_character, stated_limits "
            + "FROM adminsd_derivation";
        using var metadataReader = metadata.ExecuteReader();
        if (!metadataReader.Read())
        {
            var phase = phases.FirstOrDefault(p => p.Phase == ProtectedPrincipalDeriver.PhaseName);
            var availability = phase?.Outcome switch
            {
                DerivationPhaseOutcome.DidNotRun => ProtectedPrincipalProductAvailability.DidNotRun,
                DerivationPhaseOutcome.Failed => ProtectedPrincipalProductAvailability.Failed,
                _ => ProtectedPrincipalProductAvailability.Missing,
            };
            return new StoredProtectedPrincipalProduct(availability, null);
        }

        var version = metadataReader.GetInt32(0);
        var maskOutcome = Enum.Parse<SecureAD.Kernel.Security.HeuristicReadOutcome>(metadataReader.GetString(1));
        char? character = metadataReader.IsDBNull(2) ? null : metadataReader.GetString(2)[0];
        var statedLimits = (ProtectionUnknownReason)metadataReader.GetInt32(3);
        metadataReader.Close();

        var catalogue = ReadAdminSdCatalogue();
        var paths = ReadProtectedPrincipalPaths();
        var membershipRoutes = MembershipRouteStorage.Read(_connection, subjectId: null);
        var principals = new List<StoredProtectedPrincipalFact>();
        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT p.sid_id, s.sid, s.scope, p.evaluation, p.basis_kind, "
            + "p.basis_catalogue_entry_id, c.rid, p.unknown_reasons, p.owner_acceptance "
            + "FROM protected_principal p JOIN sid s ON s.sid_id = p.sid_id "
            + "LEFT JOIN adminsd_catalogue_entry c "
            + "ON c.catalogue_entry_id = p.basis_catalogue_entry_id ORDER BY p.sid_id";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var sidId = reader.GetInt32(0);
            ProtectedPrincipalBasis? basis = reader.IsDBNull(4)
                ? null
                : new ProtectedPrincipalBasis(
                    Enum.Parse<ProtectedPrincipalBasisKind>(reader.GetString(4)),
                    reader.GetInt32(5),
                    reader.GetInt32(6));
            principals.Add(new StoredProtectedPrincipalFact(
                sidId,
                reader.GetString(1),
                string.IsNullOrEmpty(reader.GetString(2)) ? null : reader.GetString(2),
                Enum.Parse<ProtectedPrincipalEvaluation>(reader.GetString(3)),
                basis,
                (ProtectionUnknownReason)reader.GetInt32(7),
                paths.GetValueOrDefault(sidId, []),
                Enum.Parse<OwnerAcceptance>(reader.GetString(8)))
            {
                MembershipRoutes = membershipRoutes.TryGetValue(sidId.ToString(CultureInfo.InvariantCulture), out var summary)
                    ? summary : throw new InvalidOperationException("A principal has no membership-route completeness record."),
            });
        }

        var mask = new SecureAD.Kernel.Security.AdminSdExclusionMask(
            character is { } value && Uri.IsHexDigit(value)
                ? SecureAD.Kernel.Security.DirectoryHeuristics.AdminSdExclusions(
                    "000000000100000" + value).Excluded
                : [],
            maskOutcome,
            character);
        return new StoredProtectedPrincipalProduct(
            ProtectedPrincipalProductAvailability.Available,
            new StoredProtectedPrincipalDerivation(version, mask, catalogue, principals, statedLimits));
    }

    private IReadOnlyList<StoredAdminSdCatalogueEntry> ReadAdminSdCatalogue()
    {
        var entries = new List<StoredAdminSdCatalogueEntry>();
        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT catalogue_entry_id, name, scope, rid, principal_status, principal_provenance, "
            + "principal_source_id, propagation_status, propagation_provenance, "
            + "propagation_source_id, mask_excludable FROM adminsd_catalogue_entry "
            + "ORDER BY catalogue_entry_id";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            entries.Add(new StoredAdminSdCatalogueEntry(
                reader.GetInt32(0), reader.GetString(1), reader.GetString(2), reader.GetInt32(3),
                reader.GetString(4), reader.GetString(5), reader.GetString(6), reader.GetString(7),
                reader.GetString(8), reader.GetString(9), reader.GetInt32(10) != 0));
        }
        return entries;
    }

    private Dictionary<int, IReadOnlyList<int>> ReadProtectedPrincipalPaths()
    {
        var paths = new Dictionary<int, List<int>>();
        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT sid_id, path_sid_id FROM protected_principal_path ORDER BY sid_id, ordinal";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var sidId = reader.GetInt32(0);
            if (!paths.TryGetValue(sidId, out var path))
                paths.Add(sidId, path = []);
            path.Add(reader.GetInt32(1));
        }
        return paths.ToDictionary(pair => pair.Key, pair => (IReadOnlyList<int>)pair.Value);
    }

    /// <summary>Closes the store.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _connection.Dispose();
        _protection?.Dispose();
        _expansionInputs = null;
        _disposed = true;
    }

    private static DerivationDescription? ReadDescription(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT schema_version, evidence_seal, derivation_generation_id, "
            + "deriving_started_utc, deriving_completed_utc, state FROM derivation";

        using var reader = command.ExecuteReader();

        if (!reader.Read())
            return null;

        return new DerivationDescription(
            reader.GetInt32(0),
            reader.GetString(1),
            Guid.Parse(reader.GetString(2)),
            Enum.Parse<DerivationRunState>(reader.GetString(5)),
            DateTimeOffset.Parse(reader.GetString(3), CultureInfo.InvariantCulture),
            reader.IsDBNull(4)
                ? default
                : DateTimeOffset.Parse(reader.GetString(4), CultureInfo.InvariantCulture));
    }

    private IReadOnlyList<StoredDerivationPhase> ReadPhases()
    {
        var phases = new List<StoredDerivationPhase>();

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT phase, outcome, error FROM derivation_phase ORDER BY phase";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            phases.Add(new StoredDerivationPhase(
                reader.GetString(0),
                Enum.Parse<DerivationPhaseOutcome>(reader.GetString(1)),
                reader.IsDBNull(2) ? null : reader.GetString(2)));
        }

        return phases;
    }

    private DerivationSize ReadSize()
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT (SELECT COUNT(*) FROM principal), "
            + "(SELECT COUNT(*) FROM sid_identity), "
            + "(SELECT COUNT(*) FROM nesting_edge)";

        using var reader = command.ExecuteReader();
        reader.Read();

        return new DerivationSize(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2));
    }

    /// <remarks>
    /// A store this build opened has a completeness row, because every writer that could produce
    /// schema 3 records one. A missing row is therefore not "the derivation was complete" but a
    /// store that is not what it claims to be, and it is refused rather than read as whole.
    /// </remarks>
    private DerivationCompleteness ReadCompleteness()
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT is_complete, expansion_limit, collapsed_stubs, unscoped_builtins "
            + "FROM derivation_completeness";

        using var reader = command.ExecuteReader();

        if (!reader.Read())
        {
            throw new InvalidOperationException(
                "This derivation records no completeness, though its schema version says it must. "
                + "The store is not what it claims to be, and reading it would report a derivation "
                + "of unknown coverage as a whole one.");
        }

        var isComplete = reader.GetInt32(0) != 0;
        var limit = Enum.Parse<ExpansionLimit>(reader.GetString(1));
        var collapsedStubs = reader.GetInt32(2);
        var unscopedBuiltins = reader.GetInt32(3);

        return new DerivationCompleteness(
            isComplete,
            ReadPartialGroups(),
            ReadMissingPartitions(),
            ReadUnresolvedTrustees(),
            // Taken from the header rather than a column of its own, because the run that wrote the
            // completeness is the run that wrote the store. Two copies would be two things that can
            // disagree about which derivation this is.
            Description.GenerationId,
            limit,
            collapsedStubs,
            unscopedBuiltins);
    }

    private IReadOnlyList<int> ReadPartialGroups()
    {
        var groups = new List<int>();

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT sid_id FROM completeness_partial_group ORDER BY sid_id";

        using var reader = command.ExecuteReader();

        while (reader.Read())
            groups.Add(reader.GetInt32(0));

        return groups;
    }

    private IReadOnlyList<string> ReadUnresolvedTrustees()
    {
        var trustees = new List<string>();

        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT distinguished_name FROM completeness_unresolved_trustee "
            + "ORDER BY distinguished_name";

        using var reader = command.ExecuteReader();

        while (reader.Read())
            trustees.Add(reader.GetString(0));

        return trustees;
    }

    private IReadOnlyList<DomainCoverage> ReadMissingPartitions()
    {
        var partitions = new List<DomainCoverage>();

        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT domain_fqdn, outcome, reason FROM completeness_missing_partition "
            + "ORDER BY domain_fqdn";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var domain = reader.GetString(0);
            var outcome = Enum.Parse<DomainReadOutcome>(reader.GetString(1));
            var reason = reader.GetString(2);

            // Rebuilt through the factories rather than by setting fields, so a stored row is held
            // to the same rules as one the capture made.
            partitions.Add(outcome switch
            {
                DomainReadOutcome.PartiallyRead => DomainCoverage.PartiallyRead(domain, reason),
                DomainReadOutcome.NotRead => DomainCoverage.NotRead(domain, reason),
                DomainReadOutcome.ExcludedByChoice =>
                    DomainCoverage.Excluded(domain, ExclusionKind.ByChoice, reason),
                DomainReadOutcome.ExcludedForWantOfCandidates =>
                    DomainCoverage.Excluded(domain, ExclusionKind.ForWantOfCandidates, reason),

                // Read included: a domain that was read in full is not a missing partition, so its
                // presence here means the table holds something no writer could have put there.
                _ => throw new InvalidOperationException(
                    $"This derivation lists '{domain}' as a partition it did not read, with the "
                    + $"outcome '{outcome}', which is not a way of not reading one."),
            });
        }

        return partitions;
    }

    private static Result<DerivationReader> Failure(
        string reason, string description, string context) =>
        Result<DerivationReader>.Failure(
            AuditError.Create(
                ErrorCategory.Evidence, reason, ErrorSeverity.Failed, description, context));
}
