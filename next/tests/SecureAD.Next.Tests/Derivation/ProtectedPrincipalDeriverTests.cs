using SecureAD.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// Who AdminSDHolder covers, and what the derivation refuses to guess.
/// </summary>
/// <remarks>
/// <b>The distribution-group case is the one with a citation, and it is the one that separates this
/// closure from the authorization one.</b> The same account is not a Domain Admin and is a
/// protected account, and both halves come from the same Microsoft guidance.
/// </remarks>
public sealed class ProtectedPrincipalDeriverTests
{
    private const string DomainSid = "S-1-5-21-1111111111-2222222222-3333333333";

    /// <summary>
    /// A protected group is recognised by its relative identifier.
    /// </summary>
    [Fact]
    public void Stage2a_ProtectedGroupsAreRecognisedByRelativeIdentifier()
    {
        Assert.True(ProtectedGroupCatalogue.IsInThePublishedCatalogue(DomainSid + "-512"));
        Assert.True(ProtectedGroupCatalogue.IsInThePublishedCatalogue(DomainSid + "-500"));
        Assert.True(ProtectedGroupCatalogue.IsInThePublishedCatalogue("S-1-5-32-544"));
        Assert.False(ProtectedGroupCatalogue.IsInThePublishedCatalogue(DomainSid + "-1104"));
    }

    /// <summary>
    /// A well-known SID is not mistaken for a protected account because of its last number.
    /// </summary>
    [Fact]
    public void Stage2a_AWellKnownSidIsNotMistakenForAProtectedAccount()
    {
        Assert.False(ProtectedGroupCatalogue.IsInThePublishedCatalogue("S-1-5-500"));
        Assert.False(ProtectedGroupCatalogue.IsInThePublishedCatalogue("S-1-5-18"));
    }

    /// <summary>
    /// A member of a protected group is protected.
    /// </summary>
    [Fact]
    public void Stage2a_AMemberOfAProtectedGroupIsProtected()
    {
        var closure = Derive(
            [Security(0, rid: 512), User(1, rid: 1104)],
            edges: [(0, 1)]);

        Assert.Equal(ProtectedPrincipalEvaluation.Protected, closure.EvaluationOf(1));
    }

    /// <summary>
    /// Somebody with no path to a protected group is not protected.
    /// </summary>
    [Fact]
    public void Stage2a_SomebodyUnconnectedIsNotProtected()
    {
        var closure = Derive(
            [Security(0, rid: 512), User(1, rid: 1104)],
            edges: []);

        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(1));
    }

    /// <summary>
    /// Nesting through a distribution group reaches protection, though it carries no authorization.
    /// </summary>
    /// <remarks>
    /// Microsoft states that transitive membership in a protected group confers the restricted
    /// security regardless of whether it came through a security or a distribution group, and gives
    /// this exact arrangement as the example.
    /// </remarks>
    [Fact]
    public void Stage2a_DistributionNestingReachesProtection()
    {
        var closure = Derive(
            [Security(0, rid: 512), Distribution(1, rid: 1200), User(2, rid: 1104)],
            edges: [(0, 1), (1, 2)]);

        Assert.Equal(ProtectedPrincipalEvaluation.Protected, closure.EvaluationOf(2));
    }

    /// <summary>
    /// The same account is protected and is not a Domain Admin.
    /// </summary>
    /// <remarks>
    /// The whole reason these are separate products. One closure answering both would have to be
    /// wrong about one of them.
    /// </remarks>
    [Fact]
    public void Stage2a_ProtectedThroughDistributionIsStillNotAuthorized()
    {
        var principals = new[] { Security(0, rid: 512), Distribution(1, rid: 1200), User(2, rid: 1104) };
        var edges = new[] { (0, 1), (1, 2) };

        var protectedClosure = Derive(principals, edges);
        var membership = AuthorizationMembershipExpander.ClosureOf(
            GraphOf(principals, edges), ExpansionBudget.Bulk, CancellationToken.None);
        Assert.Equal(ProtectedPrincipalEvaluation.Protected, protectedClosure.EvaluationOf(2));
        Assert.DoesNotContain(2, membership.MembersOf(0).ToArray());
    }

    /// <summary>
    /// Reaching a protected group only by primary group is unknown, never not protected.
    /// </summary>
    /// <remarks>
    /// <c>AC-64</c>. The citation establishes that primary-group membership is real and that
    /// authorization honours it; nothing says the protection process follows it. Answering false
    /// would report a possibly protected account as unprotected.
    /// </remarks>
    [Fact]
    public void Stage2a_PrimaryGroupOnlyPathIsUnknown()
    {
        var closure = Derive(
            [Security(0, rid: 512), User(1, rid: 1104, primaryGroup: 0)],
            edges: []);

        Assert.Equal(ProtectedPrincipalEvaluation.Unknown, closure.EvaluationOf(1));
        Assert.Equal(
            ProtectionUnknownReason.PrimaryGroupTraversalResearchBlocked,
            closure.ReasonsFor(1));
    }

    /// <summary>
    /// An ordinary path settles it even when a gated one also exists.
    /// </summary>
    /// <remarks>
    /// The gated edge only matters to a principal that has nothing else.
    /// </remarks>
    [Fact]
    public void Stage2a_AnOrdinaryPathBeatsAGatedOne()
    {
        var closure = Derive(
            [Security(0, rid: 512), User(1, rid: 1104, primaryGroup: 0)],
            edges: [(0, 1)]);

        Assert.Equal(ProtectedPrincipalEvaluation.Protected, closure.EvaluationOf(1));
    }

    /// <summary>
    /// A gated edge does not turn the rest of the directory into a shrug.
    /// </summary>
    /// <remarks>
    /// The failure §2a names outright. One account behind an unestablished edge must not make
    /// everybody else unknown, or the closure has told a reader nothing while sounding careful.
    /// </remarks>
    [Fact]
    public void Stage2a_AGatedEdgeDoesNotMakeEverybodyUnknown()
    {
        var closure = Derive(
            [Security(0, rid: 512), User(1, rid: 1104, primaryGroup: 0), User(2, rid: 1105)],
            edges: []);

        Assert.Equal(ProtectedPrincipalEvaluation.Unknown, closure.EvaluationOf(1));
        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(2));
    }

    /// <summary>
    /// Partial membership evidence is stated about the derivation, not stamped on every principal.
    /// </summary>
    /// <remarks>
    /// One unresolved member could hide anything beneath it, so there is no bounded set to attach
    /// the doubt to - and attaching it to everyone would be the same shrug in another form. It
    /// travels as a stated limit instead, and a rule reading this closure has to look at it.
    /// </remarks>
    [Fact]
    public void Stage2a_PartialEvidenceIsAStatedLimitRatherThanUniversalDoubt()
    {
        var closure = Derive(
            [Security(0, rid: 512), User(1, rid: 1104)],
            edges: [],
            membershipEvidenceIsPartial: true);

        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(1));
        Assert.True(closure.StatedLimits.HasFlag(ProtectionUnknownReason.PartialMembershipEvidence));
    }

    /// <summary>
    /// Every derivation admits that the protected set itself could have been customised.
    /// </summary>
    /// <remarks>
    /// <c>dSHeuristics</c> can remove groups from the protected set and this product does not
    /// capture it. Removal only shrinks the set, so this over-reports protection rather than
    /// missing it - which is why it is a stated limit and not a universal unknown.
    /// </remarks>
    [Fact]
    public void Stage2a_TheCatalogueAdmitsItCouldHaveBeenCustomised()
    {
        var closure = Derive([Security(0, rid: 512)], edges: []);

        Assert.True(closure.StatedLimits.HasFlag(ProtectionUnknownReason.ProtectedCatalogueIncomplete));
    }

    /// <summary>
    /// The catalogue records what establishes each kind of edge, and they are not the same.
    /// </summary>
    [Fact]
    public void Stage2a_TheCatalogueRecordsWhatEstablishesEachEdge()
    {
        var catalogue = ProtectedGroupCatalogue.Default;

        Assert.Equal(ProtectedEdgeProvenance.Documented, catalogue.DistributionNestingProvenance);
        Assert.True(catalogue.FollowsDistributionNesting);

        Assert.Equal(ProtectedEdgeProvenance.NotEstablished, catalogue.PrimaryGroupProvenance);
        Assert.False(catalogue.FollowsPrimaryGroup);
    }

    private static ProtectedPrincipalClosure Derive(
        IReadOnlyList<Fixture> principals,
        IReadOnlyList<(int Group, int Member)> edges,
        bool membershipEvidenceIsPartial = false) =>
        ProtectedPrincipalDeriver.Derive(
            GraphOf(principals, edges),
            SidsFor(principals),
            ProtectedGroupCatalogue.Default,
            membershipEvidenceIsPartial,
            CancellationToken.None);

    private static NestingGraph GraphOf(
        IReadOnlyList<Fixture> principals,
        IReadOnlyList<(int Group, int Member)> edges) =>
        NestingGraph.Build(new NestingFacts(
            SidsFor(principals),
            Identities: [],
            [.. principals.Select(p => p.Row)],
            [.. edges.Select(e => new NestingEdge(e.Group, e.Member))],
            UnresolvedTrustees: [],
            ObjectsWithoutSid: 0, CollapsedStubs: 0, ForestHeuristics: null));

    private static SidInterner SidsFor(IReadOnlyList<Fixture> principals)
    {
        var sids = new SidInterner();
        foreach (var principal in principals)
            sids.Intern(DomainSid + "-" + principal.Rid, domainFqdn: null);

        return sids;
    }

    /// <summary>
    /// A principal and the relative identifier its SID is built from, kept together so no test
    /// depends on state left behind by another.
    /// </summary>
    private sealed record Fixture(PrincipalRow Row, int Rid);

    private static Fixture Security(int sidId, int rid) =>
        new(
            new PrincipalRow(sidId, Guid.NewGuid(), IsGroup: true, GroupType: unchecked((int)0x80000002), PrimaryGroupSidId: null),
            rid);

    private static Fixture Distribution(int sidId, int rid) =>
        new(
            new PrincipalRow(sidId, Guid.NewGuid(), IsGroup: true, GroupType: 0x00000002, PrimaryGroupSidId: null),
            rid);

    private static Fixture User(int sidId, int rid, int? primaryGroup = null) =>
        new(
            new PrincipalRow(sidId, Guid.NewGuid(), IsGroup: false, GroupType: null, PrimaryGroupSidId: primaryGroup),
            rid);
}
