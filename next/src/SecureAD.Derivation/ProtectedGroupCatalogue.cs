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
public enum ProtectedEdgeProvenance
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
public sealed record ProtectedGroupCatalogue(
    string Version,
    ProtectedEdgeProvenance DistributionNestingProvenance,
    ProtectedEdgeProvenance PrimaryGroupProvenance)
{
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
    /// </remarks>
    public static ProtectedGroupCatalogue Default { get; } = new(
        Version: "appendix-c-2026-08",
        DistributionNestingProvenance: ProtectedEdgeProvenance.Documented,
        PrimaryGroupProvenance: ProtectedEdgeProvenance.NotEstablished);

    /// <summary>Whether nesting through a distribution group is followed.</summary>
    public bool FollowsDistributionNesting =>
        DistributionNestingProvenance != ProtectedEdgeProvenance.NotEstablished;

    /// <summary>Whether primary-group membership is followed.</summary>
    public bool FollowsPrimaryGroup =>
        PrimaryGroupProvenance != ProtectedEdgeProvenance.NotEstablished;

    /// <summary>
    /// Whether a SID names a principal this catalogue protects.
    /// </summary>
    /// <param name="sid">The SID in its canonical text form.</param>
    public static bool IsProtected(string sid)
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
