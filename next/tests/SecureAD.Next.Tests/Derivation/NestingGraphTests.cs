using SecureAD.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// The in-memory nesting graph: what it answers, and what it deliberately keeps apart.
/// </summary>
/// <remarks>
/// <b>The separation of primary-group membership is the point of most of these.</b> Folding it in
/// with ordinary nesting would make the graph simpler and would make <c>AC-64</c> impossible to
/// honour, because no later phase could tell which edges came from where.
/// </remarks>
public sealed class NestingGraphTests
{
    /// <summary>
    /// A group's direct members come back.
    /// </summary>
    [Fact]
    public void Stage2a_DirectMembersComeBack()
    {
        var graph = Build(
            principals: [Group(0), User(1), User(2)],
            edges: [new NestingEdge(0, 1), new NestingEdge(0, 2)]);

        Assert.Equal(new[] { 1, 2 }, graph.MembersOf(0).ToArray());
    }

    /// <summary>
    /// A group nobody is in comes back empty rather than failing.
    /// </summary>
    [Fact]
    public void Stage2a_AnEmptyGroupComesBackEmpty()
    {
        var graph = Build(principals: [Group(0)], edges: []);

        Assert.Empty(graph.MembersOf(0).ToArray());
    }

    /// <summary>
    /// The last row's members come back, which is what the extra offset slot is for.
    /// </summary>
    /// <remarks>
    /// An off-by-one here reads the wrong group's members or walks off the array, and it would only
    /// show on the highest id in the dictionary.
    /// </remarks>
    [Fact]
    public void Stage2a_TheLastRowsMembersComeBack()
    {
        var graph = Build(
            principals: [User(0), Group(1)],
            edges: [new NestingEdge(1, 0)]);

        Assert.Equal(new[] { 0 }, graph.MembersOf(1).ToArray());
    }

    /// <summary>
    /// Primary-group members are found in the direction the attribute does not point.
    /// </summary>
    [Fact]
    public void Stage2a_PrimaryGroupMembersAreIndexedByGroup()
    {
        var graph = Build(
            principals: [Group(0), User(1, primaryGroup: 0), User(2, primaryGroup: 0)],
            edges: []);

        Assert.Equal(new[] { 1, 2 }, graph.PrimaryMembersOf(0).ToArray());
    }

    /// <summary>
    /// Primary-group membership is not returned as ordinary membership.
    /// </summary>
    /// <remarks>
    /// The separation <c>AC-64</c> depends on. A closure that must not follow primary groups asks
    /// only <c>MembersOf</c>, and it has to be told the truth.
    /// </remarks>
    [Fact]
    public void Stage2a_PrimaryGroupMembershipIsNotOrdinaryMembership()
    {
        var graph = Build(
            principals: [Group(0), User(1, primaryGroup: 0)],
            edges: []);

        Assert.Empty(graph.MembersOf(0).ToArray());
        Assert.Equal(new[] { 1 }, graph.PrimaryMembersOf(0).ToArray());
    }

    /// <summary>
    /// The two kinds of membership coexist without contaminating each other.
    /// </summary>
    [Fact]
    public void Stage2a_TheTwoKindsOfMembershipStaySeparate()
    {
        var graph = Build(
            principals: [Group(0), User(1), User(2, primaryGroup: 0)],
            edges: [new NestingEdge(0, 1)]);

        Assert.Equal(new[] { 1 }, graph.MembersOf(0).ToArray());
        Assert.Equal(new[] { 2 }, graph.PrimaryMembersOf(0).ToArray());
    }

    /// <summary>
    /// A security group says so; a distribution group says so; an uncaptured type says neither.
    /// </summary>
    [Fact]
    public void Stage2a_SecurityEnabledIsThreeAnswers()
    {
        var graph = Build(
            principals:
            [
                new PrincipalRow(0, Guid.NewGuid(), IsGroup: true, GroupType: unchecked((int)0x80000002), PrimaryGroupSidId: null),
                new PrincipalRow(1, Guid.NewGuid(), IsGroup: true, GroupType: 0x00000002, PrimaryGroupSidId: null),
                new PrincipalRow(2, Guid.NewGuid(), IsGroup: true, GroupType: null, PrimaryGroupSidId: null),
            ],
            edges: []);

        Assert.True(graph.IsSecurityEnabled(0));
        Assert.False(graph.IsSecurityEnabled(1));
        Assert.Null(graph.IsSecurityEnabled(2));
    }

    /// <summary>
    /// A SID present only as somebody's history is answerable about, and is nobody's group.
    /// </summary>
    /// <remarks>
    /// The graph is over every SID in the dictionary, not only the captured principals, so a
    /// traversal reaching one of these gets an ordinary empty answer rather than an exception.
    /// </remarks>
    [Fact]
    public void Stage2a_ASidWithNoPrincipalIsAnswerable()
    {
        var facts = new NestingFacts(
            InternerOf("S-1-5-21-1-2-3-1104", "S-1-5-21-9-9-9-1104"),
            Identities: [],
            Principals: [User(0)],
            Edges: [],
            UnresolvedTrustees: [],
            ObjectsWithoutSid: 0, CollapsedStubs: 0, ForestHeuristics: null);

        var graph = NestingGraph.Build(facts);

        Assert.False(graph.IsGroup(1));
        Assert.Null(graph.IsSecurityEnabled(1));
        Assert.Empty(graph.MembersOf(1).ToArray());
        Assert.Empty(graph.PrimaryMembersOf(1).ToArray());
    }

    private static NestingGraph Build(
        IReadOnlyList<PrincipalRow> principals,
        IReadOnlyList<NestingEdge> edges)
    {
        var sids = new SidInterner();
        for (var i = 0; i < principals.Count; i++)
            sids.Intern("S-1-5-21-1-2-3-" + (1000 + i), domainFqdn: null);

        return NestingGraph.Build(new NestingFacts(
            sids, [], principals, edges, [], 0, 0, null));
    }

    private static SidInterner InternerOf(params string[] sids)
    {
        var interner = new SidInterner();
        foreach (var sid in sids)
            interner.Intern(sid, domainFqdn: null);

        return interner;
    }

    private static PrincipalRow Group(int sidId) =>
        new(sidId, Guid.NewGuid(), IsGroup: true, GroupType: unchecked((int)0x80000002), PrimaryGroupSidId: null);

    private static PrincipalRow User(int sidId, int? primaryGroup = null) =>
        new(sidId, Guid.NewGuid(), IsGroup: false, GroupType: null, PrimaryGroupSidId: primaryGroup);
}
