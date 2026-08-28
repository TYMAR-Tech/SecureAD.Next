using SecureAD.Kernel.Security;

namespace SecureAD.Derivation;

/// <summary>
/// How well established it is that a kind of edge takes part in protected-principal evaluation.
/// </summary>
/// <remarks>
/// <b>Kept because "Microsoft says so" covers three different strengths of claim.</b> A protocol
/// specification describes what a domain controller does; product documentation describes what
/// administrators are told it does; a lab observation describes what one directory did once. All
/// three beat inference, and collapsing them would lose the ability to revisit the weakest one
/// when something better turns up.
/// </remarks>
internal enum ProtectedEdgeProvenance
{
    /// <summary>Nothing establishes it. The edge is not followed.</summary>
    NotEstablished,

    /// <summary>Microsoft product documentation states it.</summary>
    Documented,

    /// <summary>A Microsoft protocol specification states it.</summary>
    Specified,

    /// <summary>Observed in a lab and recorded as such, rather than specified anywhere.</summary>
    LabVerified,
}

/// <summary>
/// Which principals Active Directory protects, and which kinds of nesting reach them.
/// </summary>
/// <remarks>
/// <para>
/// <b>The set is Microsoft's, and it is named here rather than inferred.</b> It is the fifteen
/// accounts and groups listed in
/// <see href="https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory">
/// Appendix C: Protected Accounts and Groups in Active Directory</see>. <c>adminCount</c> is not
/// used to derive it: the same documentation states the attribute stays set after an account leaves
/// a protected group, so it records history rather than current protection.
/// </para>
/// <para>
/// <b>Matched by relative identifier, never by name.</b> Group names are localised - a German
/// domain has <c>Domänen-Admins</c> - while the relative identifier is 512 everywhere. Builtin
/// principals are held separately because their SIDs are whole and domain-independent, where the
/// rest are relative to whichever domain the principal is in.
/// </para>
/// <para>
/// <b><see cref="Version"/> is stamped into anything derived from this</b>, so a closure records
/// which set it was judged against rather than being silently re-interpreted when the set changes.
/// </para>
/// </remarks>
/// <param name="Version">Which revision of the catalogue this is.</param>
/// <param name="DistributionNestingProvenance">
/// What establishes that nesting through a distribution group reaches a protected principal.
/// </param>
/// <param name="PrimaryGroupProvenance">
/// What establishes that primary-group membership reaches a protected principal.
/// </param>
/// <param name="Exclusions">
/// What the forest's own <c>dSHeuristics</c> says about which operator groups it has stopped
/// protecting, and whether that was read at all.
/// </param>
internal sealed record ProtectedGroupCatalogue(
    string Version,
    ProtectedEdgeProvenance DistributionNestingProvenance,
    ProtectedEdgeProvenance PrimaryGroupProvenance,
    AdminSdExclusionMask Exclusions)
{
    /// <summary>
    /// Whether this catalogue's exclusions name the builtin group <paramref name="sid"/> is.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Computed each time rather than cached, and the two attempts before this one are why.</b>
    /// A field initialiser is copied verbatim by a <c>with</c> expression rather than recomputed,
    /// so <see cref="NarrowedBy"/> produced a catalogue holding a new mask beside the old empty
    /// set. Replacing it with a lazily populated field was worse: <see cref="Default"/> is a static
    /// singleton, so whichever caller reached it first decided what every later copy inherited, and
    /// the tests passed alone and failed together.
    /// </para>
    /// <para>
    /// The mask names at most four groups, so this is four comparisons against a list that is
    /// almost always empty - cheaper than the allocation the cache was avoiding.
    /// </para>
    /// </remarks>
    /// <param name="sid">The SID in its canonical text form.</param>
    private bool IsExcludedByTheForest(string sid) =>
        Exclusions.Excluded.Any(
            g => string.Equals(sid, $"S-1-5-32-{(int)g}", StringComparison.Ordinal));
    /// <summary>
    /// Relative identifiers protected within their own domain.
    /// </summary>
    /// <remarks>
    /// Two of these are accounts rather than groups - 500 is the built-in Administrator and 502 is
    /// krbtgt - and they are protected in their own right, so they seed the closure like any group.
    /// <para>
    /// Cert Publishers is deliberately absent. It was protected between Windows 2000 SP4 and
    /// Windows Server 2003 and was removed afterwards, and the same source's version table is what
    /// says so.
    /// </para>
    /// </remarks>
    public static IReadOnlySet<int> DomainRelativeIdentifiers { get; } = new HashSet<int>
    {
        500, // Administrator
        502, // krbtgt
        512, // Domain Admins
        516, // Domain Controllers
        518, // Schema Admins - root domain only
        519, // Enterprise Admins - root domain only
        521, // Read-only Domain Controllers
        526, // Key Admins
        527, // Enterprise Key Admins
    };

    /// <summary>
    /// Whole SIDs of the protected builtin groups, which are the same in every domain.
    /// </summary>
    public static IReadOnlySet<string> BuiltinSids { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        "S-1-5-32-544", // Administrators
        "S-1-5-32-548", // Account Operators
        "S-1-5-32-549", // Server Operators
        "S-1-5-32-550", // Print Operators
        "S-1-5-32-551", // Backup Operators
        "S-1-5-32-552", // Replicator
    };

    /// <summary>
    /// The catalogue this product ships.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Distribution nesting is followed, on documentation rather than on a protocol
    /// specification.</b> <c>Reducing the Active Directory Attack Surface</c> states that an account
    /// with transitive membership in a protected group inherits the restricted security "regardless
    /// of whether the membership is derived from security or distribution groups", gives the nested
    /// distribution group as its worked example, and says distribution groups are included in
    /// protected group member enumeration for exactly that reason. That is the same passage this
    /// product already relies on for the separate claim that such an account does <i>not</i> receive
    /// the group's SID in its token, and trusting one sentence of it while calling the one before it
    /// unevidenced is not a position that can be defended.
    /// </para>
    /// <para>
    /// It is recorded as <see cref="ProtectedEdgeProvenance.Documented"/> rather than
    /// <see cref="ProtectedEdgeProvenance.Specified"/> because it comes from product guidance and
    /// not from an Open Specification. If one is found that contradicts it, this field and the
    /// version are what change.
    /// </para>
    /// <para>
    /// <b>Primary-group membership is not followed.</b> The specifications establish that
    /// <c>primaryGroupID</c> is real membership and that authorization honours it; none of them says
    /// how the protection process traverses it. A principal that reaches a protected group only that
    /// way is <c>Unknown</c>, never <c>NotProtected</c>.
    /// </para>
    /// <para>
    /// <b><see cref="Exclusions"/> is unread here, and that is the honest default.</b> This is the
    /// catalogue as Microsoft publishes it, before any forest has been asked whether it narrowed
    /// the set. A derivation using it states <c>ProtectedCatalogueIncomplete</c>, which is correct:
    /// nobody looked. <see cref="ForForest"/> is how a forest's own answer gets applied.
    /// </para>
    /// </remarks>
    public static ProtectedGroupCatalogue Default { get; } = new(
        Version: "appendix-c-2026-08",
        DistributionNestingProvenance: ProtectedEdgeProvenance.Documented,
        PrimaryGroupProvenance: ProtectedEdgeProvenance.NotEstablished,
        Exclusions: new AdminSdExclusionMask(
            [], HeuristicReadOutcome.NotRead, Character: null));

    /// <summary>
    /// The published catalogue, narrowed by what one forest's <c>dSHeuristics</c> says.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The forest can only take groups out, never add them.</b> <c>dwAdminSDExMask</c> names four
    /// operator groups and nothing else, so a mask cannot explain a protected principal this
    /// catalogue does not list - and a forest that excludes all four still protects the other
    /// eleven.
    /// </para>
    /// <para>
    /// <b>Named <c>NarrowedBy</c> rather than <c>ForForest</c>.</b> <c>CONCEPT-REGISTRY.md</c> gives
    /// <i>which forest a run assessed</i> to <c>ProfileId</c> with the shape <c>For*</c>, and a
    /// second member under that shape would claim a question that already has an owner. The name is
    /// also the truer one: this narrows a catalogue and identifies no forest.
    /// </para>
    /// </remarks>
    /// <param name="dsHeuristics">
    /// The forest's <c>dSHeuristics</c> value, or null where it was not read.
    /// </param>
    /// <returns>The catalogue this forest actually enforces.</returns>
    public static ProtectedGroupCatalogue NarrowedBy(string? dsHeuristics) =>
        Default with { Exclusions = DirectoryHeuristics.AdminSdExclusions(dsHeuristics) };

    /// <summary>Whether nesting through a distribution group is followed.</summary>
    public bool FollowsDistributionNesting =>
        DistributionNestingProvenance != ProtectedEdgeProvenance.NotEstablished;

    /// <summary>Whether primary-group membership is followed.</summary>
    public bool FollowsPrimaryGroup =>
        PrimaryGroupProvenance != ProtectedEdgeProvenance.NotEstablished;

    /// <summary>
    /// Whether a SID names a principal this catalogue protects.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>An instance member rather than a static one, because the answer depends on the forest.</b>
    /// <c>dwAdminSDExMask</c> can remove four operator groups from AdminSDHolder's protection, so
    /// <i>is this principal protected</i> has no answer that holds everywhere. A static method
    /// would have to ignore the mask, which is how this product came to state
    /// <c>ProtectedCatalogueIncomplete</c> on every derivation.
    /// </para>
    /// <para>
    /// <b>An excluded group is still in the published catalogue.</b> It is removed here rather than
    /// deleted from <see cref="BuiltinSids"/>, so what Microsoft publishes and what this forest
    /// does are two facts a reader can still tell apart.
    /// </para>
    /// </remarks>
    /// <param name="sid">The SID in its canonical text form.</param>
    public bool IsProtected(string sid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);

        if (IsExcludedByTheForest(sid))
            return false;

        return IsInThePublishedCatalogue(sid);
    }

    /// <summary>
    /// Whether a SID names a principal Microsoft publishes as protected, before any forest-specific
    /// exclusion is applied.
    /// </summary>
    /// <remarks>
    /// Kept separate from <see cref="IsProtected"/> so the published set stays answerable on its
    /// own: an operator asking why a group is not protected needs to know whether it was never in
    /// the catalogue or was taken out by this forest, and those are different remedies.
    /// </remarks>
    /// <param name="sid">The SID in its canonical text form.</param>
    public static bool IsInThePublishedCatalogue(string sid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);

        if (BuiltinSids.Contains(sid))
            return true;

        // Only an ordinary domain SID carries a protected relative identifier. Without this a
        // well-known SID whose last part happens to be 500 would be read as somebody's built-in
        // Administrator.
        if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal))
            return false;

        var lastSeparator = sid.LastIndexOf('-');
        return lastSeparator > 0
            && int.TryParse(sid[(lastSeparator + 1)..], out var rid)
            && DomainRelativeIdentifiers.Contains(rid);
    }
}
