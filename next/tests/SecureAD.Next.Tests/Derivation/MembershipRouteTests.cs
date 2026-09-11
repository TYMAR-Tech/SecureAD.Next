using SecureAD.Derivation;
using SecureAD.Evidence.Findings;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

public sealed class MembershipRouteTests
{
    private const string Domain = "S-1-5-21-11-22-33";

    [Fact]
    public void TwoDirectMembershipsProduceTwoInitialGroups()
    {
        var summary = Derive([512, 519, 1100], [(0, 2), (1, 2)])[2];
        Assert.True(summary.IsComplete);
        Assert.Equal(2, summary.Memberships.Count);
        Assert.All(summary.Memberships, group => Assert.Equal(2, Assert.Single(group.Routes).Steps.Count));
    }

    [Fact]
    public void ALongerIndependentRouteSurvivesAShorterRouteToTheSameRoot()
    {
        var summary = Derive([512, 1200, 1201, 1100], [(0, 3), (0, 1), (1, 2), (2, 3)])[3];
        Assert.Equal(2, summary.Memberships.Count);
        Assert.Equal(new[] { 2, 4 }, summary.Memberships.SelectMany(g => g.Routes).Select(r => r.Steps.Count).Order());
    }

    [Fact]
    public void OuterRootsSharingAnInitialMembershipStayInOneGroup()
    {
        var summary = Derive([512, 519, 1200, 1100], [(0, 1), (1, 2), (2, 3)])[3];
        var membership = Assert.Single(summary.Memberships);
        Assert.Equal(Sid(1200), membership.InitialMembership.Sid);
        Assert.Equal("CN=1200,DC=ad,DC=lab", membership.InitialMembership.DistinguishedName);
        Assert.Equal(2, membership.Routes.Count);
    }

    [Fact]
    public void EqualDistanceIndependentMembershipsAreNotCollapsed()
    {
        var summary = Derive([512, 1200, 1201, 1100], [(0, 1), (0, 2), (1, 3), (2, 3)])[3];
        Assert.Equal(2, summary.Memberships.Count);
        Assert.All(summary.Memberships, g => Assert.Equal(3, Assert.Single(g.Routes).Steps.Count));
    }

    [Fact]
    public void CyclesTerminateWithoutLosingAccountInitialMemberships()
    {
        var summary = Derive([512, 1200, 1201, 1100], [(0, 1), (1, 2), (2, 1), (1, 3), (2, 3)])[3];
        Assert.True(summary.IsComplete);
        Assert.Equal(2, summary.Memberships.Count);
        Assert.All(summary.Memberships.SelectMany(g => g.Routes), r =>
            Assert.Equal(r.Steps.Count, r.Steps.Select(s => s.Principal.Sid).Distinct().Count()));
    }

    [Fact]
    public void DistributionProtectionIsNotAuthorizationAndALongerSecurityPathSurvives()
    {
        var summary = Derive([512, 1200, 1201, 1202, 1203, 1100],
            [(0, 1), (1, 4), (0, 2), (2, 3), (3, 4), (4, 5)], distribution: 1)[5];
        var routes = Assert.Single(summary.Memberships).Routes;
        Assert.Contains(routes, r => r.Authorization == MembershipRouteAuthorization.DistributionGroup && r.EstablishesProtection);
        Assert.Contains(routes, r => r.Authorization == MembershipRouteAuthorization.SecurityEnabled && r.Steps.Count == 5);
    }

    [Fact]
    public void UnknownGroupTypeDoesNotClaimAuthorization()
    {
        var summary = Derive([512, 1200, 1100], [(0, 1), (1, 2)], unknownType: 1)[2];
        Assert.Equal(MembershipRouteAuthorization.UnknownGroupType, Assert.Single(Assert.Single(summary.Memberships).Routes).Authorization);
    }

    [Fact]
    public void PrimaryMembershipIsLabelledAndDoesNotEstablishProtection()
    {
        var summary = Derive([512, 1100], [], primaryGroup: 0)[1];
        var route = Assert.Single(Assert.Single(summary.Memberships).Routes);
        Assert.True(route.Steps[1].IsPrimaryGroup);
        Assert.False(route.EstablishesProtection);
        Assert.Equal(MembershipRouteAuthorization.SecurityEnabled, route.Authorization);
    }

    [Fact]
    public void PartialInputRetainsKnownRoutesButNeverClaimsATotal()
    {
        var summary = Derive([512, 1100], [(0, 1)], partial: true)[1];
        Assert.Single(summary.Memberships);
        Assert.False(summary.IsComplete);
        Assert.Equal(MembershipRouteIncompleteReason.MembershipEvidenceIncomplete, summary.IncompleteReasons);
    }

    [Theory]
    [InlineData(0, 100, 100000, 1000, MembershipRouteIncompleteReason.NodeBudgetReached)]
    [InlineData(100, 0, 100000, 1000, MembershipRouteIncompleteReason.EdgeBudgetReached)]
    [InlineData(100, 100, 0, 1000, MembershipRouteIncompleteReason.StorageBudgetReached)]
    [InlineData(100, 100, 100000, 0, MembershipRouteIncompleteReason.TimeBudgetReached)]
    public void EachBudgetNamesItsStoppingReason(int nodes, int edges, long bytes, int milliseconds, MembershipRouteIncompleteReason reason)
    {
        var summary = Derive([512, 1100], [(0, 1)], budget: new(nodes, edges, bytes, TimeSpan.FromMilliseconds(milliseconds)))[1];
        Assert.False(summary.IsComplete);
        Assert.Equal(reason, summary.IncompleteReasons);
    }

    [Fact]
    public void ReachingABudgetKeepsRoutesAlreadyFound()
    {
        var summary = Derive([512, 519, 1100], [(0, 2), (1, 2)], budget: new(100, 1, 100000, TimeSpan.FromSeconds(10)))[2];
        Assert.Single(summary.Memberships);
        Assert.Equal(MembershipRouteIncompleteReason.EdgeBudgetReached, summary.IncompleteReasons);
    }

    [Fact]
    public void ReorderedEdgesAndInternedIdsProduceTheSameOrderedEvidence()
    {
        var rids = new[] { 512, 519, 1200, 1201, 1100 };
        (int Group, int Member)[] edges = [(0, 1), (0, 2), (1, 3), (2, 4), (3, 4)];
        var first = Derive(rids, edges)[4];
        var reversed = Derive(rids.Reverse().ToArray(), edges.Reverse().Select(e => (4 - e.Group, 4 - e.Member)).ToArray(), account: 0)[0];
        Assert.Equal(Describe(first), Describe(reversed));
    }

    [Fact]
    public void CancellationDoesNotBecomeAPartialSuccess()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => Derive([512, 1100], [(0, 1)], cancellation: cancellation.Token));
    }

    [Fact]
    public void TwoDomainsBuiltinGroupsRemainDistinctInitialMemberships()
    {
        var sids = new SidInterner();
        sids.Intern("S-1-5-32-544", "child.ad.lab");
        sids.Intern("S-1-5-32-544", "ad.lab");
        sids.Intern(Sid(1100), null);
        var graph = NestingGraph.Build(new NestingFacts(sids, [],
            [new(0, Guid.NewGuid(), true, unchecked((int)0x80000002), null),
             new(1, Guid.NewGuid(), true, unchecked((int)0x80000002), null),
             new(2, Guid.NewGuid(), false, null, null)],
            [new(0, 2), new(1, 2)], [], 0, 0, string.Empty));
        var product = ProtectedPrincipalDeriver.Derive(graph, sids, ProtectedGroupCatalogue.NarrowedBy(string.Empty),
            false, CancellationToken.None, Domain,
            new HashSet<string>(StringComparer.Ordinal), []);
        var summary = product.MembershipRoutesBySid[2];
        Assert.Equal(new[] { "ad.lab", "child.ad.lab" }, summary.Memberships.Select(m => m.InitialMembership.Scope));
        Assert.All(summary.Memberships, m => Assert.Equal(m.InitialMembership.Scope,
            Assert.Single(m.Routes).Steps[^1].Principal.Scope));
    }

    [Fact]
    public void OrdinaryAndPrimaryLinksToTheSameInitialGroupAreLabelledWithoutDoublingTheCount()
    {
        var summary = Derive([512, 1100], [(0, 1)], primaryGroup: 0)[1];
        var membership = Assert.Single(summary.Memberships);
        Assert.Equal(2, membership.Routes.Count);
        Assert.Contains(membership.Routes, route => route.Steps[1].IsPrimaryGroup && !route.EstablishesProtection);
        Assert.Contains(membership.Routes, route => !route.Steps[1].IsPrimaryGroup && route.EstablishesProtection);
    }

    internal static IReadOnlyList<MembershipRouteSummary> Derive(int[] rids, (int Group, int Member)[] edges,
        int? distribution = null, int? unknownType = null, int? primaryGroup = null, bool partial = false,
        MembershipRouteBudget? budget = null, int? account = null, CancellationToken cancellation = default)
    {
        var sids = new SidInterner();
        foreach (var rid in rids)
            sids.Intern(Sid(rid), null);
        var principals = rids.Select((rid, id) => new PrincipalRow(id, Guid.NewGuid(), id != (account ?? rids.Length - 1),
            id == unknownType ? null : id == distribution ? 2 : unchecked((int)0x80000002),
            id == (account ?? rids.Length - 1) ? primaryGroup : null)
        { DistinguishedName = $"CN={rid},DC=ad,DC=lab" }).ToArray();
        var graph = NestingGraph.Build(new NestingFacts(sids, [], principals,
            edges.Select(e => new NestingEdge(e.Group, e.Member)).ToArray(), [], 0, 0, string.Empty));
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(string.Empty);
        var roots = rids.Select((rid, id) => (Rid: rid, Id: id)).Where(r => r.Rid is 512 or 519)
            .Select(r => new MembershipRouteRoot(r.Id, catalogue.Entries.Single(e => e.Rid == r.Rid), true)).ToArray();
        return MembershipRouteDeriver.Derive(graph, sids, roots,
            partial ? MembershipRouteIncompleteReason.MembershipEvidenceIncomplete : MembershipRouteIncompleteReason.None,
            budget ?? MembershipRouteBudget.Bulk, cancellation);
    }

    private static string Sid(int rid) => $"{Domain}-{rid}";

    private static string Describe(MembershipRouteSummary summary) => string.Join("|", summary.Memberships.SelectMany(g => g.Routes)
        .Select(r => $"{r.CatalogueEntryId}:{r.Authorization}:{r.EstablishesProtection}:"
            + string.Join(",", r.Steps.Select(s => $"{s.Principal.Sid}:{s.IsPrimaryGroup}"))));
}
