using SecureAD.Derivation;
using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// Expanding one principal to everything nested inside it.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the foundation SEC-090, SEC-093, the membership cycle rule and the groups screen all
/// rest on</b>, recorded as <c>P-124</c>. They differ only in which principal they start from, so a
/// defect here is a defect in four places at once and the tests are shaped accordingly.
/// </para>
/// <para>
/// <b>The cycle test is the one that would hang rather than fail.</b> Microsoft states that group
/// membership may have loops and that an enumeration should keep a visited list to end the
/// recursion; a walk without one does not return a wrong answer, it does not return.
/// </para>
/// </remarks>
public sealed class PrincipalExpansionTests
{
    private static readonly DateTimeOffset Started = new(2026, 9, 3, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = Started.AddMinutes(1);

    private const string Scope = "ad.lab";

    /// <summary>Readers, Staff, Everyone-ish members - names are for the reader of this file.</summary>
    private const string Readers = "S-1-5-21-9-9-9-1101";
    private const string Staff = "S-1-5-21-9-9-9-1102";
    private const string Alice = "S-1-5-21-9-9-9-1103";
    private const string DomainUsers = "S-1-5-21-9-9-9-513";

    /// <summary>
    /// A chain reaches everything below it, and says how it got there.
    /// </summary>
    /// <remarks>
    /// The path is what makes a finding actionable at depth. An operator told that Domain Users is
    /// inside Readers still has to find the link; told the route, they can cut it.
    /// </remarks>
    [Fact]
    public void AChainIsWalkedToTheBottom()
    {
        var directory = Store(edges: [(0, 1), (1, 2)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope);

        Assert.Equal(PrincipalExpansionOutcome.Expanded, expansion.Outcome);
        Assert.True(expansion.IsComplete);

        var members = expansion.Members!;
        Assert.Equal(2, members.Count);
        Assert.Equal([Readers, Staff], members[0].PathFromRoot);
        Assert.Equal([Readers, Staff, Alice], members[1].PathFromRoot);
    }

    /// <summary>
    /// A cycle terminates, and everything in it is reported once.
    /// </summary>
    /// <remarks>
    /// <b>Removing the visited set does not hang this, and the first version of this comment said
    /// it would.</b> Running the mutation showed the budget catches the loop instead, so the walk
    /// returns a wrong answer rather than never returning - principals reported repeatedly and the
    /// outcome marked as stopped at a budget on a graph of three nodes. That is the worse failure
    /// of the two, because it looks like a result. The assertion on the count is what catches it.
    /// </remarks>
    [Fact]
    public void ACycleTerminatesAndReportsEachPrincipalOnce()
    {
        var directory = Store(edges: [(0, 1), (1, 2), (2, 0)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope);

        Assert.Equal(PrincipalExpansionOutcome.Expanded, expansion.Outcome);

        var members = expansion.Members!;
        Assert.Equal(2, members.Count);
        Assert.Distinct(members.Select(m => m.Sid));

        // The principal being expanded is not reported as being inside itself, even though the
        // cycle leads back to it. A finding saying a group contains itself would be true of the
        // graph and useless to an operator.
        Assert.DoesNotContain(members, m => m.Sid == Readers);
    }

    /// <summary>
    /// A broad principal nested three deep is found, and names itself.
    /// </summary>
    /// <remarks>
    /// <b>This is the whole reason the foundation exists.</b> The delegation names <c>Readers</c>,
    /// which looks scoped. Nothing in the directory tools shows that Domain Users is inside it.
    /// </remarks>
    [Fact]
    public void ABroadPrincipalNestedDeepIsFound()
    {
        var directory = Store(edges: [(0, 1), (1, 3)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope);

        var broad = Assert.Single(expansion.BroadMembers);
        Assert.Equal(DomainUsers, broad.Sid);
        Assert.Equal([Readers, Staff, DomainUsers], broad.PathFromRoot);
    }

    /// <summary>
    /// A group with nothing in it expands to an empty list, which is an answer.
    /// </summary>
    /// <remarks>
    /// Empty and null mean different things here and both are reachable. This is the case that
    /// makes the null meaningful.
    /// </remarks>
    [Fact]
    public void AnEmptyGroupExpandsToNothingRatherThanToNoAnswer()
    {
        var directory = Store(edges: [(1, 2)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope);

        Assert.Equal(PrincipalExpansionOutcome.Expanded, expansion.Outcome);
        Assert.NotNull(expansion.Members);
        Assert.Empty(expansion.Members!);
        Assert.Empty(expansion.BroadMembers);
    }

    /// <summary>
    /// A principal this bundle never captured is not reported as empty.
    /// </summary>
    /// <remarks>
    /// <b>The distinction the product exists to keep.</b> A delegation naming a principal from a
    /// trusted forest resolves to nothing here, and answering <i>nobody is inside it</i> would be a
    /// statement about a directory this run never read.
    /// </remarks>
    [Fact]
    public void APrincipalThatWasNeverCapturedIsNotReportedAsEmpty()
    {
        var directory = Store(edges: [(0, 1)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf("S-1-5-21-8-8-8-1234", Scope);

        Assert.Equal(PrincipalExpansionOutcome.PrincipalNotFound, expansion.Outcome);
        Assert.False(expansion.IsComplete);
        Assert.Null(expansion.Members);
    }

    /// <summary>
    /// A derivation whose nesting pass never ran says so rather than reporting a flat forest.
    /// </summary>
    [Fact]
    public void ADerivationWithNoNestingPassSaysSo()
    {
        var directory = Store(edges: [], nesting: DerivationPhaseOutcome.DidNotRun);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope);

        Assert.Equal(PrincipalExpansionOutcome.NoNestingDerived, expansion.Outcome);
        Assert.Null(expansion.Members);
    }

    /// <summary>
    /// A walk that runs out of budget returns what it found and says the rest is unknown.
    /// </summary>
    /// <remarks>
    /// <b>Both halves matter.</b> Withholding the members would lose true findings; calling the
    /// answer complete would claim the group holds nothing else. The members are also marked
    /// individually, so a reader can see which of them has an unexplored subtree beneath it.
    /// </remarks>
    [Fact]
    public void ABudgetStopReturnsWhatItFoundAndSaysTheRestIsUnknown()
    {
        var directory = Store(edges: [(0, 1), (0, 2), (0, 3)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope, budget: 2);

        Assert.Equal(PrincipalExpansionOutcome.StoppedAtBudget, expansion.Outcome);
        Assert.False(expansion.IsComplete);
        Assert.Equal(2, expansion.Members!.Count);
    }

    /// <summary>
    /// Asking for nothing is refused rather than quietly returning nothing.
    /// </summary>
    [Fact]
    public void ABudgetOfZeroIsRefused()
    {
        var directory = Store(edges: [(0, 1)]);

        using var reader = DerivationReader.Open(directory).Value!;

        Assert.Throws<ArgumentOutOfRangeException>(() => reader.MembersOf(Readers, Scope, budget: 0));
    }

    /// <summary>Builds a store holding four principals and the edges given.</summary>
    /// <param name="edges">Group and member, as indexes into the four SIDs above.</param>
    /// <param name="nesting">What became of the nesting pass.</param>
    private static string Store(
        (int Group, int Member)[] edges,
        DerivationPhaseOutcome nesting = DerivationPhaseOutcome.Succeeded)
    {
        var directory = TempDirectories.Create("expansion-tests");

        Directory.CreateDirectory(directory);
        var evidencePath = BundleLayout.EvidencePath(directory);
        File.WriteAllText(evidencePath, "test evidence");
        BundleSealing.Seal(evidencePath, BundleLayout.SealPath(directory));

        var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash;

        using (var writer = DerivationWriter.Create(directory, seal, Started))
        {
            writer.WriteSids(
                [Readers, Staff, Alice, DomainUsers],
                [Scope, Scope, Scope, Scope]);

            writer.WriteNestingEdges(edges.Select(e => new NestingEdge(e.Group, e.Member)));
            writer.RecordPhase(MembershipNestingPass.PhaseName, nesting, error: null);

            writer.RecordCompleteness(new DerivationCompleteness(
                IsComplete: true,
                PartialGroups: [],
                MissingPartitions: [],
                UnresolvedTrustees: [],
                DerivationGenerationId: writer.GenerationId,
                Limit: ExpansionLimit.None));

            writer.Complete(Finished);
        }

        return directory;
    }
}
