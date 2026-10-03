using SecureAD.Kernel.Security;

namespace SecureAD.Derivation;

internal enum CatalogueClaimStatus
{
    Established,
    EstablishedNo,
    Disputed,
    Unverified,
    DoesNotApply,
}

internal enum CatalogueClaimProvenance
{
    None,
    ProtocolSpecification,
    MicrosoftProductDocumentation,
    MicrosoftSupport,
    ControlledLabObservation,
}

internal enum CataloguePrincipalScope
{
    PerDomainRid,
    ForestRootRid,
    BuiltinPerDomain,
}

internal sealed record CatalogueClaim(
    CatalogueClaimStatus Status,
    CatalogueClaimProvenance Provenance,
    string SourceId);

internal sealed record AdminSdHolderCatalogueEntry(
    int Id,
    string Name,
    CataloguePrincipalScope Scope,
    int Rid,
    CatalogueClaim PrincipalProtection,
    CatalogueClaim MemberPropagation,
    bool CanBeDisabledByAdminSdExMask);

/// <summary>
/// The independently evidenced AdminSDHolder principal and member-propagation catalogue.
/// </summary>
/// <remarks>
/// <para>
/// <b>Claims are evidenced individually, not inferred from adminCount.</b> The starting set is
/// Microsoft's
/// <see href="https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory">
/// Appendix C: Protected Accounts and Groups in Active Directory</see>, with separately sourced
/// negative and unresolved claims. <c>adminCount</c> is not
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
/// <param name="Exclusions">
/// What the forest's own <c>dSHeuristics</c> says about which operator groups it has stopped
/// protecting, and whether that was read at all.
/// </param>
internal sealed record ProtectedGroupCatalogue(
    int Version,
    IReadOnlyList<AdminSdHolderCatalogueEntry> Entries,
    AdminSdExclusionMask Exclusions)
{
    private static readonly CatalogueClaim EstablishedPrincipal = new(
        CatalogueClaimStatus.Established,
        CatalogueClaimProvenance.MicrosoftProductDocumentation,
        "MS-APPENDIX-C-2026-08");

    private static readonly CatalogueClaim EstablishedPropagation = new(
        CatalogueClaimStatus.Established,
        CatalogueClaimProvenance.MicrosoftProductDocumentation,
        "MS-ATTACK-SURFACE-2026-08");

    private static readonly CatalogueClaim UnverifiedPropagation = new(
        CatalogueClaimStatus.Unverified,
        CatalogueClaimProvenance.MicrosoftProductDocumentation,
        "MS-ADTS-UNVERIFIED-2026-08");

    /// <summary>
    /// Scoped principal and propagation claims, including explicit negative and unresolved answers.
    /// </summary>
    /// <remarks>
    /// Version 3 settled primary-group-only traversal under <c>0118</c>. Version 4 changes only
    /// RID 498's own protection claim under P-88; its member-propagation claim remains unresolved.
    /// </remarks>
    private static readonly IReadOnlyList<AdminSdHolderCatalogueEntry> AppendixCEntries =
    [
        Entry(1, "Administrator", CataloguePrincipalScope.PerDomainRid, 500, EstablishedPrincipal,
            Claim(CatalogueClaimStatus.DoesNotApply, "OBJECT-CLASS-NOT-GROUP")),
        Entry(2, "krbtgt", CataloguePrincipalScope.PerDomainRid, 502, EstablishedPrincipal,
            Claim(CatalogueClaimStatus.DoesNotApply, "OBJECT-CLASS-NOT-GROUP")),
        Entry(3, "Domain Admins", CataloguePrincipalScope.PerDomainRid, 512, EstablishedPrincipal,
            EstablishedPropagation),
        Entry(4, "Domain Controllers", CataloguePrincipalScope.PerDomainRid, 516, EstablishedPrincipal,
            UnverifiedPropagation),
        Entry(5, "Cert Publishers", CataloguePrincipalScope.PerDomainRid, 517,
            Claim(CatalogueClaimStatus.EstablishedNo, "MS-GROUP-PAGES-2026-08"),
            Claim(CatalogueClaimStatus.EstablishedNo, "MS-GROUP-PAGES-2026-08")),
        Entry(6, "Group Policy Creator Owners", CataloguePrincipalScope.PerDomainRid, 520,
            Claim(CatalogueClaimStatus.EstablishedNo, "MS-GROUP-PAGES-2026-08"),
            Claim(CatalogueClaimStatus.EstablishedNo, "MS-GROUP-PAGES-2026-08")),
        Entry(7, "Read-only Domain Controllers", CataloguePrincipalScope.PerDomainRid, 521,
            EstablishedPrincipal, UnverifiedPropagation),
        Entry(8, "Key Admins", CataloguePrincipalScope.PerDomainRid, 526, EstablishedPrincipal,
            UnverifiedPropagation),
        // MS-ADTS 3.1.1.6.1.2 omits RID 498 from automatic protection, unlike RID 521:
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0d0b4fa-2895-4c64-b182-ba64ad0f84b8
        // P-88 accepts that reading, corroborated by the 2026-10-03 ad.lab capture and controls.
        // The group-reference page's contrary "Yes" remains recorded; other membership can protect it.
        Entry(9, "Enterprise Read-only Domain Controllers", CataloguePrincipalScope.ForestRootRid, 498,
            new CatalogueClaim(CatalogueClaimStatus.EstablishedNo, CatalogueClaimProvenance.ProtocolSpecification,
                "MS-ADTS-3.1.1.6.1.2-P88-2026-10"),
            UnverifiedPropagation),
        Entry(10, "Schema Admins", CataloguePrincipalScope.ForestRootRid, SchemaOwnerRid, EstablishedPrincipal,
            EstablishedPropagation),
        Entry(11, "Enterprise Admins", CataloguePrincipalScope.ForestRootRid, 519, EstablishedPrincipal,
            EstablishedPropagation),
        Entry(12, "Enterprise Key Admins", CataloguePrincipalScope.ForestRootRid, 527,
            EstablishedPrincipal, UnverifiedPropagation),
        Entry(13, "Administrators", CataloguePrincipalScope.BuiltinPerDomain, 544, EstablishedPrincipal,
            EstablishedPropagation),
        Entry(14, "Account Operators", CataloguePrincipalScope.BuiltinPerDomain, 548, EstablishedPrincipal,
            EstablishedPropagation, true),
        Entry(15, "Server Operators", CataloguePrincipalScope.BuiltinPerDomain, 549, EstablishedPrincipal,
            EstablishedPropagation, true),
        Entry(16, "Print Operators", CataloguePrincipalScope.BuiltinPerDomain, 550, EstablishedPrincipal,
            EstablishedPropagation, true),
        Entry(17, "Backup Operators", CataloguePrincipalScope.BuiltinPerDomain, 551, EstablishedPrincipal,
            EstablishedPropagation, true),
        Entry(18, "Replicator", CataloguePrincipalScope.BuiltinPerDomain, 552, EstablishedPrincipal,
            EstablishedPropagation),
    ];

    /// <summary>
    /// The catalogue entries whose members this product accepts as an object's owner in silence.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This answers a different question from protection and is deliberately much smaller.</b>
    /// Protection is Microsoft's set - which principals AdminSDHolder repairs - and this is the
    /// product's, taken from <c>0099</c>: the principals whose control may be hidden as routine.
    /// Every entry here has an <i>unrestricted</i> authority scope within its own domain, or
    /// forest-wide for Enterprise Admins. An owner implicitly holds Modify Permissions, so
    /// accepting one of these means never telling a customer that it owns something.
    /// </para>
    /// <para>
    /// <b>The five operator groups are absent, and that is the point of <c>P-140</c>.</b> Account
    /// Operators, Server Operators, Print Operators, Backup Operators and Replicator are protected
    /// principals and are outside the control plane, both at once. Out does not mean safe - Backup
    /// Operators stays Tier 0-sensitive - it means its edges stay visible rather than being hidden
    /// as routine, and ownership is an edge.
    /// </para>
    /// <para>
    /// <b>Schema Admins is accepted only inside the forest's schema, per <c>0109</c>.</b>
    /// Its separate membership walk produces a scoped answer; adding it here would incorrectly
    /// accept ownership outside that scope. Its identifier is <see cref="SchemaOwnerRid"/>.
    /// </para>
    /// <para>
    /// <b>Identity-shaped principals are not here.</b> SYSTEM, Enterprise Domain Controllers and
    /// CREATOR OWNER are accepted owners because of what they are rather than who is inside them -
    /// nobody is a <i>member</i> of CREATOR OWNER - so they are matched on the identifier by the
    /// judging layer and never walked.
    /// </para>
    /// </remarks>
    public static readonly IReadOnlySet<int> AcceptedOwnerRids = PrincipalClassificationRegistry.AcceptedOwnerRootRids;

    /// <summary>The forest-root Schema Admins RID, accepted only in the schema under <c>0109</c>.</summary>
    public const int SchemaOwnerRid = 518;

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
    /// <b>Primary-group membership is not followed, and a principal reachable only that way is
    /// <c>NotProtected</c>.</b> The specifications establish that <c>primaryGroupID</c> is real
    /// membership and that authorization honours it; none of them says how the protection process
    /// traverses it. Such a principal was <c>Unknown</c> until version 3, on the ground that the
    /// question was open.
    /// </para>
    /// <para>
    /// <b>The laboratory closed it where the documentation would not, and the answer is
    /// <see cref="CatalogueClaimProvenance.ControlledLabObservation"/> rather than documented.</b>
    /// In <c>ba.ad.lab</c> on 2026-09-10 the Domain Controllers group was itself stamped, held no
    /// explicit <c>member</c> entries so the primary-group edge was the only route into it, and
    /// <c>dSHeuristics</c> excluded nothing - while its domain controller carried neither
    /// <c>adminCount</c> nor a DACL refusing inheritance, eighteen months after creation. Domain
    /// Admins was stamped and Domain Users was not in the same run, so the fingerprint means what
    /// the observation assumes. Recorded under decision <c>0118</c>; the observation is
    /// <c>tools/Observe-Ac64PrimaryGroupTraversal.ps1</c> and can be run again.
    /// </para>
    /// <para>
    /// <b>Lab-verified is a weaker warrant than specified, and the version records which.</b> One
    /// forest, one domain, one domain controller, one Windows version. A forest that contradicts it
    /// reverts the answer to <c>Unknown</c>, which is a catalogue version change and not a code
    /// change.
    /// </para>
    /// <para>
    /// <b><see cref="Exclusions"/> is unread here, and that is the honest default.</b> This is the
    /// catalogue as Microsoft publishes it, before any forest has been asked whether it narrowed
    /// the set. A derivation using it states <c>ProtectedCatalogueIncomplete</c>, which is correct:
    /// nobody looked. <see cref="ForForest"/> is how a forest's own answer gets applied.
    /// </para>
    /// </remarks>
    public static ProtectedGroupCatalogue Default { get; } = new(
        Version: 4,
        Entries: AppendixCEntries,
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

    public CatalogueClaim EffectiveMemberPropagation(AdminSdHolderCatalogueEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (!Entries.Any(candidate => candidate.Id == entry.Id))
            throw new ArgumentException("The catalogue entry does not belong to this catalogue.", nameof(entry));

        if (!entry.CanBeDisabledByAdminSdExMask
            || entry.MemberPropagation.Status != CatalogueClaimStatus.Established)
            return entry.MemberPropagation;

        if (!Exclusions.IsComplete)
            return new CatalogueClaim(
                CatalogueClaimStatus.Unverified,
                CatalogueClaimProvenance.ProtocolSpecification,
                "DSHEURISTICS-NOT-AVAILABLE");

        return Exclusions.Excluded.Any(group => (int)group == entry.Rid)
            ? new CatalogueClaim(
                CatalogueClaimStatus.EstablishedNo,
                CatalogueClaimProvenance.ProtocolSpecification,
                "DSHEURISTICS-DWADMINSD-EX-MASK")
            : entry.MemberPropagation;
    }

    private static AdminSdHolderCatalogueEntry Entry(
        int id,
        string name,
        CataloguePrincipalScope scope,
        int rid,
        CatalogueClaim principalProtection,
        CatalogueClaim memberPropagation,
        bool maskExcludable = false) =>
        new(id, name, scope, rid, principalProtection, memberPropagation, maskExcludable);

    private static CatalogueClaim Claim(CatalogueClaimStatus status, string sourceId) =>
        new(status, CatalogueClaimProvenance.MicrosoftProductDocumentation, sourceId);
}
