using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// What a derived answer admits it does not cover.
/// </summary>
/// <remarks>
/// <b>Every one of these is about refusing to turn a missing input into an empty set.</b> A closure
/// that could not read half a forest and one that read all of it and found nothing are the same
/// shape once the difference is dropped, and the first reads as a clean result.
/// </remarks>
public sealed class DerivationCompletenessTests
{
    /// <summary>
    /// A derivation over a fully read forest with nothing unresolved is complete.
    /// </summary>
    [Fact]
    public void Stage2a_AnUnobstructedDerivationIsComplete()
    {
        var completeness = Completeness(
            unresolvedTrustees: [],
            domains: [DomainCoverage.Read("corp.example")]);

        Assert.True(completeness.IsComplete);
        Assert.Empty(completeness.MissingPartitions);
        Assert.Equal(ExpansionLimit.None, completeness.Limit);
    }

    /// <summary>
    /// A member nobody could resolve makes the derivation incomplete.
    /// </summary>
    [Fact]
    public void Stage2a_AnUnresolvedTrusteeMakesItIncomplete()
    {
        var completeness = Completeness(
            unresolvedTrustees: ["CN=Ghost,DC=elsewhere"],
            domains: [DomainCoverage.Read("corp.example")]);

        Assert.False(completeness.IsComplete);
        Assert.Equal("CN=Ghost,DC=elsewhere", Assert.Single(completeness.UnresolvedTrustees));
    }

    /// <summary>
    /// A domain that could not be read makes the derivation incomplete.
    /// </summary>
    [Fact]
    public void Stage2a_AnUnreadDomainMakesItIncomplete()
    {
        var completeness = Completeness(
            unresolvedTrustees: [],
            domains:
            [
                DomainCoverage.Read("corp.example"),
                DomainCoverage.NotRead("far.example", "No controller answered."),
            ]);

        Assert.False(completeness.IsComplete);
        Assert.Equal("far.example", Assert.Single(completeness.MissingPartitions).DomainFqdn);
    }

    /// <summary>
    /// A domain left out by choice is still missing from the graph, and still says which it was.
    /// </summary>
    /// <remarks>
    /// Both are holes. Reducing them to a list of names would lose the difference between a
    /// decision somebody made and a domain nobody could reach, which they have to be able to tell
    /// apart without going back to another table.
    /// </remarks>
    [Fact]
    public void Stage2a_ADomainExcludedByChoiceIsStillMissingAndStillSaysSo()
    {
        var completeness = Completeness(
            unresolvedTrustees: [],
            domains:
            [
                DomainCoverage.Read("corp.example"),
                DomainCoverage.Excluded("old.example", ExclusionKind.ByChoice, "Decommissioning."),
            ]);

        Assert.False(completeness.IsComplete);

        var missing = Assert.Single(completeness.MissingPartitions);
        Assert.Equal("old.example", missing.DomainFqdn);
        Assert.Equal(DomainReadOutcome.ExcludedByChoice, missing.Outcome);
    }

    /// <summary>
    /// A group the budget never reached is named, and its empty membership is not read as empty.
    /// </summary>
    [Fact]
    public void Stage2a_AGroupTheBudgetNeverReachedIsNamed()
    {
        var principals = new List<PrincipalRow> { Security(0) };
        var edges = new List<(int, int)>();
        for (var i = 1; i <= 50; i++)
        {
            principals.Add(User(i));
            edges.Add((0, i));
        }

        var (facts, graph) = Build(principals, edges, unresolvedTrustees: []);
        var closure = AuthorizationMembershipExpander.ClosureOf(
            graph, new ExpansionBudget(MaxClosureEntries: 1, TimeSpan.FromMinutes(1)), CancellationToken.None);

        var completeness = DerivationCompleteness.Of(
            facts, closure, ScopeOf([DomainCoverage.Read("corp.example")]), Guid.NewGuid());

        Assert.False(completeness.IsComplete);
        Assert.Equal(ExpansionLimit.MaxClosureEntriesReached, completeness.Limit);
    }

    /// <summary>
    /// The generation identifier travels with the answer.
    /// </summary>
    [Fact]
    public void Stage2a_TheGenerationIdentifierTravelsWithTheAnswer()
    {
        var generation = Guid.NewGuid();

        var completeness = Completeness(
            unresolvedTrustees: [],
            domains: [DomainCoverage.Read("corp.example")],
            generation: generation);

        Assert.Equal(generation, completeness.DerivationGenerationId);
    }

    private static DerivationCompleteness Completeness(
        IReadOnlyList<string> unresolvedTrustees,
        IReadOnlyList<DomainCoverage> domains,
        Guid? generation = null)
    {
        var (facts, graph) = Build(
            [Security(0), User(1)], [(0, 1)], unresolvedTrustees);

        var closure = AuthorizationMembershipExpander.ClosureOf(
            graph, ExpansionBudget.Bulk, CancellationToken.None);

        return DerivationCompleteness.Of(
            facts, closure, ScopeOf(domains), generation ?? Guid.NewGuid());
    }

    private static (NestingFacts Facts, NestingGraph Graph) Build(
        IReadOnlyList<PrincipalRow> principals,
        IReadOnlyList<(int Group, int Member)> edges,
        IReadOnlyList<string> unresolvedTrustees)
    {
        var sids = new SidInterner();
        for (var i = 0; i < principals.Count; i++)
            sids.Intern("S-1-5-21-1-2-3-" + (1000 + i), domainFqdn: null);

        var facts = new NestingFacts(
            sids,
            Identities: [],
            principals,
            [.. edges.Select(e => new NestingEdge(e.Group, e.Member))],
            unresolvedTrustees,
            ObjectsWithoutSid: 0, CollapsedStubs: 0, ForestHeuristics: null);

        return (facts, NestingGraph.Build(facts));
    }

    private static RunScope ScopeOf(IReadOnlyList<DomainCoverage> domains) =>
        RunScope.Of("coverage", domains);

    private static PrincipalRow Security(int sidId) =>
        new(sidId, Guid.NewGuid(), IsGroup: true, GroupType: unchecked((int)0x80000002), PrimaryGroupSidId: null);

    private static PrincipalRow User(int sidId) =>
        new(sidId, Guid.NewGuid(), IsGroup: false, GroupType: null, PrimaryGroupSidId: null);
}
