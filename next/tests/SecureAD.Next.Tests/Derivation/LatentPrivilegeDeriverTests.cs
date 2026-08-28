using SecureAD.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// Privilege that is staged rather than held: what a single conversion would change.
/// </summary>
/// <remarks>
/// <b>Every one of these describes a change that has not happened.</b> The claim is conditional, and
/// the tests that matter most are the ones asserting nothing is reported when the conversion would
/// change nothing - a latent-privilege finding that fires on a harmless mailing list teaches an
/// operator to ignore the ones that matter.
/// </remarks>
public sealed class LatentPrivilegeDeriverTests
{
    /// <summary>
    /// A distribution group under a security group is one conversion from conferring it.
    /// </summary>
    [Fact]
    public void Stage2a_ConvertingADistributionGroupWouldConferTheGroupAboveIt()
    {
        // DomainAdmins contains DistributionGroup contains Alice.
        var paths = Derive(
            [Security(0), Distribution(1), User(2)],
            edges: [(0, 1), (1, 2)]);

        var path = Assert.Single(paths);
        Assert.Equal(1, path.DistributionGroupSidId);
        Assert.Equal(0, path.WouldGainSidId);
        Assert.Equal(new[] { 2 }, path.PrincipalsWhoWouldGain);
    }

    /// <summary>
    /// The people who would gain it are exactly those who do not already hold it.
    /// </summary>
    [Fact]
    public void Stage2a_SomebodyWhoAlreadyHoldsItIsNotReportedAsGaining()
    {
        // Alice is directly in DomainAdmins as well as inside the distribution group.
        var paths = Derive(
            [Security(0), Distribution(1), User(2), User(3)],
            edges: [(0, 1), (1, 2), (1, 3), (0, 3)]);

        var path = Assert.Single(paths);
        Assert.Equal(new[] { 2 }, path.PrincipalsWhoWouldGain);
    }

    /// <summary>
    /// Nothing is reported when the conversion would change nothing for anybody.
    /// </summary>
    [Fact]
    public void Stage2a_APathThatChangesNothingIsNotReported()
    {
        var paths = Derive(
            [Security(0), Distribution(1), User(2)],
            edges: [(0, 1), (1, 2), (0, 2)]);

        Assert.Empty(paths);
    }

    /// <summary>
    /// An empty distribution group confers nothing on nobody.
    /// </summary>
    [Fact]
    public void Stage2a_AnEmptyDistributionGroupIsNotReported()
    {
        var paths = Derive(
            [Security(0), Distribution(1)],
            edges: [(0, 1)]);

        Assert.Empty(paths);
    }

    /// <summary>
    /// A distribution group nested nowhere privileged is not reported.
    /// </summary>
    [Fact]
    public void Stage2a_ADistributionGroupUnderNothingIsNotReported()
    {
        var paths = Derive(
            [Distribution(0), User(1)],
            edges: [(0, 1)]);

        Assert.Empty(paths);
    }

    /// <summary>
    /// A security group is never itself a conversion candidate.
    /// </summary>
    /// <remarks>
    /// It is already security-enabled, so there is no conversion to describe and its members hold
    /// the authority now - which is the authorization closure's business, not this one's.
    /// </remarks>
    [Fact]
    public void Stage2a_ASecurityGroupIsNotAConversionCandidate()
    {
        var paths = Derive(
            [Security(0), Security(1), User(2)],
            edges: [(0, 1), (1, 2)]);

        Assert.Empty(paths);
    }

    /// <summary>
    /// Authority is gained from every security-enabled group above, not only the nearest.
    /// </summary>
    [Fact]
    public void Stage2a_AuthorityIsGainedFromEverySecurityGroupAbove()
    {
        // Outer contains Inner contains Distribution contains Alice, both outer ones security.
        var paths = Derive(
            [Security(0), Security(1), Distribution(2), User(3)],
            edges: [(0, 1), (1, 2), (2, 3)]);

        Assert.Equal(2, paths.Count);
        Assert.Contains(paths, p => p.WouldGainSidId == 0);
        Assert.Contains(paths, p => p.WouldGainSidId == 1);
    }

    /// <summary>
    /// A distribution group above the candidate stops the claim there.
    /// </summary>
    /// <remarks>
    /// Converting the candidate alone would not make the outer group carry authorization either, so
    /// a path through it would need two conversions - a weaker claim, and not the one being made.
    /// </remarks>
    [Fact]
    public void Stage2a_ADistributionGroupAboveStopsTheClaim()
    {
        // Security contains OuterDistribution contains InnerDistribution contains Alice.
        var paths = Derive(
            [Security(0), Distribution(1), Distribution(2), User(3)],
            edges: [(0, 1), (1, 2), (2, 3)]);

        // The outer distribution group is one conversion from conferring the security group.
        // The inner one is not: converting it alone leaves the outer one still a distribution group.
        Assert.All(paths, p => Assert.Equal(1, p.DistributionGroupSidId));
    }

    /// <summary>
    /// The claim is about a change, so a group of unknown type is not reported as convertible.
    /// </summary>
    /// <remarks>
    /// Unlike the membership expansion, there is no safe direction to guess in here. Reporting
    /// "converting this would grant Domain Admins" about a group that is already security-enabled
    /// describes a change that cannot happen, and an operator who checks one and finds it wrong has
    /// learned to discount the rest.
    /// </remarks>
    [Fact]
    public void Stage2a_AGroupOfUnknownTypeIsNotReportedAsConvertible()
    {
        var paths = Derive(
            [Security(0), UnknownType(1), User(2)],
            edges: [(0, 1), (1, 2)]);

        Assert.Empty(paths);
    }

    private static IReadOnlyList<LatentPrivilegePath> Derive(
        IReadOnlyList<PrincipalRow> principals,
        IReadOnlyList<(int Group, int Member)> edges)
    {
        var sids = new SidInterner();
        for (var i = 0; i < principals.Count; i++)
            sids.Intern("S-1-5-21-1-2-3-" + (1000 + i), domainFqdn: null);

        var graph = NestingGraph.Build(new NestingFacts(
            sids,
            Identities: [],
            principals,
            [.. edges.Select(e => new NestingEdge(e.Group, e.Member))],
            UnresolvedTrustees: [],
            ObjectsWithoutSid: 0, CollapsedStubs: 0, ForestHeuristics: null));

        var closure = AuthorizationMembershipExpander.ClosureOf(
            graph, ExpansionBudget.Bulk, CancellationToken.None);

        return LatentPrivilegeDeriver.Derive(graph, closure, CancellationToken.None);
    }

    private static PrincipalRow Security(int sidId) =>
        new(sidId, Guid.NewGuid(), IsGroup: true, GroupType: unchecked((int)0x80000002), PrimaryGroupSidId: null);

    private static PrincipalRow Distribution(int sidId) =>
        new(sidId, Guid.NewGuid(), IsGroup: true, GroupType: 0x00000002, PrimaryGroupSidId: null);

    private static PrincipalRow UnknownType(int sidId) =>
        new(sidId, Guid.NewGuid(), IsGroup: true, GroupType: null, PrimaryGroupSidId: null);

    private static PrincipalRow User(int sidId) =>
        new(sidId, Guid.NewGuid(), IsGroup: false, GroupType: null, PrimaryGroupSidId: null);
}
