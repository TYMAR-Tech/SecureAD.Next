using SecureAD.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// Expanding membership: what reaches a group, what deliberately does not, and what the expansion
/// admits it could not settle.
/// </summary>
/// <remarks>
/// <b>The distribution-group cases are the ones with a citation behind them.</b> Microsoft's
/// guidance on reducing the Active Directory attack surface states that an account nested through a
/// distribution group does not receive the enclosing protected group's SID in its access token. An
/// expansion that walked through one would report privilege that does not exist.
/// </remarks>
public sealed class AuthorizationMembershipExpanderTests
{
    /// <summary>
    /// A member of a member is a member.
    /// </summary>
    [Fact]
    public void Stage2a_NestingIsTransitive()
    {
        // Outer contains Inner contains Alice.
        var closure = Expand(
            Security(0), Security(1), User(2),
            edges: [(0, 1), (1, 2)]);

        Assert.Equal(new[] { 1, 2 }, closure.MembersOf(0).ToArray());
    }

    /// <summary>
    /// The work is shared: a subtree beneath two groups is expanded once and both get it.
    /// </summary>
    /// <remarks>
    /// The predecessor walked it once per group above it. This asserts the answer, not the cost -
    /// but the answer being right for both is what memoisation has to preserve.
    /// </remarks>
    [Fact]
    public void Stage2a_ASharedSubtreeReachesBothParents()
    {
        // Left and Right both contain Shared, which contains Alice.
        var closure = Expand(
            Security(0), Security(1), Security(2), User(3),
            edges: [(0, 2), (1, 2), (2, 3)]);

        Assert.Equal(new[] { 2, 3 }, closure.MembersOf(0).ToArray());
        Assert.Equal(new[] { 2, 3 }, closure.MembersOf(1).ToArray());
    }

    /// <summary>
    /// A membership loop terminates, and is reported rather than merely survived.
    /// </summary>
    [Fact]
    public void Stage2a_ACycleTerminatesAndIsReported()
    {
        // A contains B, B contains A, and A contains Alice.
        var closure = Expand(
            Security(0), Security(1), User(2),
            edges: [(0, 1), (1, 0), (0, 2)]);

        var cycle = Assert.Single(closure.Cycles);
        Assert.Equal(new[] { 0, 1 }, cycle.Order().ToArray());
        Assert.Contains(2, closure.MembersOf(0).ToArray());
        Assert.Contains(2, closure.MembersOf(1).ToArray());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Sec052DirectSelfLoopIsRecordedAndRetainsCapturedMembers(bool securityEnabled)
    {
        var group = securityEnabled ? Security(0) : Distribution(0);
        var baseline = Expand(group, User(1), edges: [(0, 1)]);
        var loop = Expand(group, User(1), edges: [(0, 0), (0, 1)]);
        Assert.Equal(new[] { 0 }, Assert.Single(loop.Cycles));
        Assert.Equal(new[] { 0, 1 }, loop.MembersOf(0).ToArray());
        Assert.Equal(new[] { 1 }, baseline.MembersOf(0).ToArray());
        Assert.Empty(baseline.Cycles);
    }

    /// <summary>
    /// A distribution hop does not carry authorization.
    /// </summary>
    /// <remarks>
    /// Alice is in a distribution group nested in Domain Admins. She is not a Domain Admin, and
    /// saying she is would be an invented finding against a real person.
    /// </remarks>
    [Fact]
    public void Stage2a_ADistributionHopCarriesNoAuthorization()
    {
        // DomainAdmins contains DistributionGroup contains Alice.
        var closure = Expand(
            Security(0), Distribution(1), User(2),
            edges: [(0, 1), (1, 2)]);

        Assert.Equal(new[] { 1 }, closure.MembersOf(0).ToArray());
        Assert.DoesNotContain(2, closure.MembersOf(0).ToArray());
    }

    /// <summary>
    /// The distribution group's own members are still known.
    /// </summary>
    /// <remarks>
    /// What the latent-privilege product is derived from: converting that group to security-enabled
    /// would give these principals the path, so who they are has to be answerable.
    /// </remarks>
    [Fact]
    public void Stage2a_ADistributionGroupsOwnMembersAreStillKnown()
    {
        var closure = Expand(
            Security(0), Distribution(1), User(2),
            edges: [(0, 1), (1, 2)]);

        Assert.Equal(new[] { 2 }, closure.MembersOf(1).ToArray());
    }

    /// <summary>
    /// Primary-group membership is expanded like any other.
    /// </summary>
    [Fact]
    public void Stage2a_PrimaryGroupMembershipIsExpanded()
    {
        var closure = Expand(
            Security(0), User(1, primaryGroup: 0),
            edges: []);

        Assert.Equal(new[] { 1 }, closure.MembersOf(0).ToArray());
    }

    /// <summary>
    /// A group of unknown type is traversed, and the uncertainty is recorded.
    /// </summary>
    /// <remarks>
    /// Refusing to traverse would report principals as not holding a privilege they may hold, which
    /// is the direction an audit tool must not be wrong in. Traversing can only over-report, and the
    /// group is named so the doubt travels with the answer.
    /// </remarks>
    [Fact]
    public void Stage2a_AGroupOfUnknownTypeIsTraversedAndRecorded()
    {
        var closure = Expand(
            Security(0), UnknownType(1), User(2),
            edges: [(0, 1), (1, 2)]);

        Assert.Contains(2, closure.MembersOf(0).ToArray());
        Assert.Contains(1, closure.GroupsOfUnknownType);
    }

    /// <summary>
    /// Reaching the entry budget stops the expansion and it says so.
    /// </summary>
    /// <remarks>
    /// A partial closure that called itself complete would be read as a clean result by every rule
    /// resting on it.
    /// </remarks>
    [Fact]
    public void Stage2a_ReachingTheBudgetLeavesTheClosureIncomplete()
    {
        var principals = new List<PrincipalRow> { Security(0) };
        var edges = new List<(int, int)>();
        for (var i = 1; i <= 50; i++)
        {
            principals.Add(User(i));
            edges.Add((0, i));
        }

        var closure = Expand(
            principals,
            edges,
            new ExpansionBudget(MaxClosureEntries: 10, TimeSpan.FromMinutes(1)));

        Assert.False(closure.IsComplete);
        Assert.Equal(ExpansionLimit.MaxClosureEntriesReached, closure.Limit);
    }

    /// <summary>
    /// An ordinary expansion is complete and says so.
    /// </summary>
    [Fact]
    public void Stage2a_AnOrdinaryExpansionIsComplete()
    {
        var closure = Expand(Security(0), User(1), edges: [(0, 1)]);

        Assert.True(closure.IsComplete);
        Assert.Equal(ExpansionLimit.None, closure.Limit);
    }

    /// <summary>
    /// A chain deeper than any recursion would survive is walked without failing.
    /// </summary>
    /// <remarks>
    /// The traversal's depth is bounded by the number of principals, not by nesting depth, so a
    /// recursive implementation would exhaust the stack on a forest rather than on anything
    /// contrived. Ten thousand is well past where recursion dies and nothing like a real directory.
    /// The assertion is on a group near the bottom of the chain, because the components are settled
    /// deepest-first - reaching it at all means the walk went all the way down and came back.
    /// </remarks>
    [Fact]
    public void Stage2a_ADeepChainDoesNotExhaustTheStack()
    {
        const int depth = 10_000;

        var closure = Expand(Chain(depth).Principals, Chain(depth).Edges, ExpansionBudget.Bulk);

        Assert.Equal(1, closure.MembersOf(depth - 2).Length);
    }

    /// <summary>
    /// A deep chain runs out of budget, because the answer is quadratic in its depth.
    /// </summary>
    /// <remarks>
    /// <b>This is the limit that does not go away.</b> Interning SIDs and expanding each group once
    /// reduce what it costs to compute a closure; neither reduces how large the closure is. A chain
    /// of ten thousand groups has each group containing everything below it, which is fifty million
    /// pairs before anything is written. The budget is what stands between that and a derivation
    /// that never finishes, and the outermost groups are the ones that go unanswered - so the
    /// result is a floor, and says so.
    /// </remarks>
    [Fact]
    public void Stage2a_ADeepChainExhaustsTheEntryBudget()
    {
        const int depth = 10_000;

        var closure = Expand(Chain(depth).Principals, Chain(depth).Edges, ExpansionBudget.Bulk);

        Assert.False(closure.IsComplete);
        Assert.Equal(ExpansionLimit.MaxClosureEntriesReached, closure.Limit);
        Assert.Empty(closure.MembersOf(0).ToArray());
    }

    private static (List<PrincipalRow> Principals, List<(int, int)> Edges) Chain(int depth)
    {
        var principals = new List<PrincipalRow>();
        var edges = new List<(int, int)>();

        for (var i = 0; i < depth; i++)
        {
            principals.Add(Security(i));
            if (i > 0)
                edges.Add((i - 1, i));
        }

        return (principals, edges);
    }

    private static MembershipClosure Expand(
        params PrincipalRow[] principals) =>
        Expand(principals, [], ExpansionBudget.Bulk);

    private static MembershipClosure Expand(
        PrincipalRow p0, PrincipalRow p1, IReadOnlyList<(int, int)> edges) =>
        Expand([p0, p1], edges, ExpansionBudget.Bulk);

    private static MembershipClosure Expand(
        PrincipalRow p0, PrincipalRow p1, PrincipalRow p2, IReadOnlyList<(int, int)> edges) =>
        Expand([p0, p1, p2], edges, ExpansionBudget.Bulk);

    private static MembershipClosure Expand(
        PrincipalRow p0, PrincipalRow p1, PrincipalRow p2, PrincipalRow p3,
        IReadOnlyList<(int, int)> edges) =>
        Expand([p0, p1, p2, p3], edges, ExpansionBudget.Bulk);

    private static MembershipClosure Expand(
        IReadOnlyList<PrincipalRow> principals,
        IReadOnlyList<(int Group, int Member)> edges,
        ExpansionBudget budget)
    {
        var sids = new SidInterner();
        for (var i = 0; i < principals.Count; i++)
            sids.Intern("S-1-5-21-1-2-3-" + (1000 + i), domainFqdn: null);

        var facts = new NestingFacts(
            sids,
            Identities: [],
            principals,
            [.. edges.Select(e => new NestingEdge(e.Group, e.Member))],
            UnresolvedTrustees: [],
            ObjectsWithoutSid: 0, CollapsedStubs: 0, ForestHeuristics: null);

        return AuthorizationMembershipExpander.ClosureOf(
            NestingGraph.Build(facts), budget, CancellationToken.None);
    }

    private static PrincipalRow Security(int sidId) =>
        new(sidId, Guid.NewGuid(), IsGroup: true, GroupType: unchecked((int)0x80000002), PrimaryGroupSidId: null);

    private static PrincipalRow Distribution(int sidId) =>
        new(sidId, Guid.NewGuid(), IsGroup: true, GroupType: 0x00000002, PrimaryGroupSidId: null);

    private static PrincipalRow UnknownType(int sidId) =>
        new(sidId, Guid.NewGuid(), IsGroup: true, GroupType: null, PrimaryGroupSidId: null);

    private static PrincipalRow User(int sidId, int? primaryGroup = null) =>
        new(sidId, Guid.NewGuid(), IsGroup: false, GroupType: null, PrimaryGroupSidId: primaryGroup);
}

internal static class OrderingExtensions
{
    /// <summary>Sorts a component so an assertion does not depend on discovery order.</summary>
    internal static IEnumerable<int> Order(this int[] values) => values.OrderBy(v => v);
}
