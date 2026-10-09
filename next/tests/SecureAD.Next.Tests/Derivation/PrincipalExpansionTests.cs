using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
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
public sealed partial class PrincipalExpansionTests
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
    /// The SID <c>ba.ad.lab</c>'s principals share, read out of the sealed <c>ad.lab</c> bundle of
    /// 2026-09-04.
    /// </summary>
    /// <remarks>
    /// <b>Taken from the forest rather than made up, and that is the point.</b> <c>F-S44-2</c> is
    /// the finding that a set of tests built entirely from the same assumption as the code proves
    /// only that the two agree. These values were measured in the bundle this work is anchored to:
    /// the domain reports <c>Read</c>, and this identifier is one of four found carrying LAPS read
    /// entries while matching no captured object.
    /// </remarks>
    private const string LabDomainSid = "S-1-5-21-1834058357-2590327168-2246012571";

    /// <summary>An identifier measured in that bundle that no object carries.</summary>
    private const string LabOrphan = LabDomainSid + "-2102";

    /// <summary>The SID Readers carried before it was migrated between domains.</summary>
    private const string ReadersOldSid = "S-1-5-21-7-7-7-1101";

    /// <summary>
    /// A global security group's <c>groupType</c>: global scope with the security-enabled bit.
    /// </summary>
    private const int SecurityGroup = unchecked((int)0x80000002);

    /// <summary>
    /// A global distribution group's <c>groupType</c>: the same scope without the security bit.
    /// </summary>
    private const int DistributionGroup = 0x00000002;

    [Fact]
    public void DifferentWalksReuseTheReadersIdentityRows()
    {
        var directory = Store(edges: [(0, 1), (1, 2)]);
        using var reader = DerivationReader.Open(directory).Value!;
        var first = reader.MembersOf(Readers, Scope).Members!.Single(member => member.Sid == Alice);

        var second = Assert.Single(reader.MembersOf(Staff, Scope).Members!);

        Assert.Same(first.Sid, second.Sid);
    }

    [Fact]
    public void ReusedInputsKeepDifferentRootsIndependent()
    {
        var directory = Store(edges: [(0, 1), (1, 2)]);
        using var reader = DerivationReader.Open(directory).Value!;
        reader.MembersOf(Readers, Scope);

        var expansion = reader.MembersOf(Staff, Scope);

        Assert.Equal(new[] { Alice }, expansion.Members!.Select(member => member.Sid));
    }

    [Fact]
    public void AShortFirstWalkDoesNotLimitTheNextWalk()
    {
        var directory = Store(edges: [(0, 1), (1, 2)]);
        using var reader = DerivationReader.Open(directory).Value!;
        reader.MembersOf(Readers, Scope, budget: 1);

        var expansion = reader.MembersOf(Readers, Scope);

        Assert.Equal(PrincipalExpansionOutcome.Expanded, expansion.Outcome);
    }

    [Fact]
    public void SeparateReadersNeverShareMembershipInputs()
    {
        var firstDirectory = Store(edges: [(0, 1)]);
        var secondDirectory = Store(edges: [(0, 2)]);
        using var first = DerivationReader.Open(firstDirectory).Value!;
        using var second = DerivationReader.Open(secondDirectory).Value!;
        first.MembersOf(Readers, Scope);

        var expansion = second.MembersOf(Readers, Scope);

        Assert.Equal(new[] { Alice }, expansion.Members!.Select(member => member.Sid));
    }

    [Fact]
    public void ReusingInputsKeepsUnidentifiedMembershipExplicit()
    {
        var directory = Store(edges: [(0, 1), (1, 2)], unresolvedMembers: [1]);
        using var reader = DerivationReader.Open(directory).Value!;
        reader.MembersOf(Readers, Scope);

        var expansion = reader.MembersOf(Staff, Scope);

        Assert.Equal(PrincipalExpansionOutcome.ExpandedWithUnidentifiedMember, expansion.Outcome);
    }

    [Fact]
    public void CachedInputsCannotBeReadAfterDisposal()
    {
        var directory = Store(edges: [(0, 1)]);
        var reader = DerivationReader.Open(directory).Value!;
        reader.MembersOf(Readers, Scope);
        reader.Dispose();

        Assert.Throws<ObjectDisposedException>(() => reader.MembersOf(Readers, Scope));
    }


    /// <summary>
    /// A group that claimed a member nobody captured does not report as fully expanded.
    /// </summary>
    /// <remarks>
    /// <b>The fire for P-164, at the level a rule sees.</b> Staff claimed a member the capture
    /// never read, so what Staff holds is not known. Before this the walk found the edges it could
    /// and reported <see cref="PrincipalExpansionOutcome.Expanded"/>, which a rule reads as a
    /// settled answer - and SEC-090 then reported the machine clean.
    /// </remarks>
    [Fact]
    public void AGroupThatClaimedAnUnidentifiableMemberIsNotReportedComplete()
    {
        var directory = Store(edges: [(0, 1), (1, 2)], unresolvedMembers: [1]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope);

        Assert.Equal(PrincipalExpansionOutcome.ExpandedWithUnidentifiedMember, expansion.Outcome);
        Assert.False(expansion.IsComplete);

        // The members that were reached are still real and still returned. The silence is about
        // what else might be there, and only the group that carried it is marked short.
        var members = expansion.Members!;
        Assert.Equal(2, members.Count);
        Assert.False(members.Single(m => m.Sid == Staff).IsComplete);
        Assert.True(members.Single(m => m.Sid == Alice).IsComplete);
    }

    /// <summary>
    /// The same store without the unidentified member expands cleanly.
    /// </summary>
    /// <remarks>
    /// <b>The negative control.</b> Identical edges, one fewer stored fact. Without it the test
    /// above would pass against a walk that called every expansion incomplete, which is the
    /// forest-wide silence P-164 says is worse than the defect.
    /// </remarks>
    [Fact]
    public void TheSameChainWithEveryMemberIdentifiedExpandsCleanly()
    {
        var directory = Store(edges: [(0, 1), (1, 2)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope);

        Assert.Equal(PrincipalExpansionOutcome.Expanded, expansion.Outcome);
        Assert.True(expansion.IsComplete);
        Assert.All(expansion.Members!, m => Assert.True(m.IsComplete));
    }

    /// <summary>
    /// The principal being expanded is itself checked, not only the groups beneath it.
    /// </summary>
    /// <remarks>
    /// The root is never a member of its own answer, so nothing in the loop over members would
    /// reach it. A group that itself claimed an unidentifiable member would otherwise report
    /// everything it holds as everything there is - the original defect, surviving at the one place
    /// every caller starts from.
    /// </remarks>
    [Fact]
    public void TheExpandedPrincipalsOwnUnidentifiableMemberIsCaught()
    {
        var directory = Store(edges: [(0, 1)], unresolvedMembers: [0]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope);

        Assert.Equal(PrincipalExpansionOutcome.ExpandedWithUnidentifiedMember, expansion.Outcome);
        Assert.False(expansion.IsComplete);
    }

    /// <summary>
    /// An unidentifiable <i>containing</i> group does not thin what is inside the principal.
    /// </summary>
    /// <remarks>
    /// <b>The asymmetry P-164 requires, tested from the reading end.</b> Alice naming a group
    /// nobody captured says something about what encloses Alice, which is not the question
    /// <c>MembersOf</c> answers. Consuming it here would mark Readers short on evidence about a
    /// different object, and in a nine-domain forest with cross-forest members that would be most
    /// expansions.
    /// </remarks>
    [Fact]
    public void AnUnidentifiableContainingGroupDoesNotThinTheExpansion()
    {
        var directory = Store(edges: [(0, 1), (1, 2)], unresolvedContainers: [1, 2]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope);

        Assert.Equal(PrincipalExpansionOutcome.Expanded, expansion.Outcome);
        Assert.True(expansion.IsComplete);
    }

    /// <summary>
    /// A distribution group's unidentifiable member does not thin the answer either.
    /// </summary>
    /// <remarks>
    /// The walk deliberately does not enter a distribution group, because Microsoft is explicit
    /// that an account beneath one does not receive the enclosing group's SID in its token. What is
    /// below it is therefore not part of this answer at all, so a member it could not identify
    /// takes nothing away from what was asked. This is the same reasoning the budget case already
    /// uses for a group it chose not to enter.
    /// </remarks>
    [Fact]
    public void AnUnidentifiableMemberBelowADistributionGroupDoesNotThinTheAnswer()
    {
        var directory = Store(
            edges: [(0, 1), (1, 2)],
            groupTypes: [(1, DistributionGroup)],
            unresolvedMembers: [1]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope);

        Assert.Equal(PrincipalExpansionOutcome.Expanded, expansion.Outcome);
        Assert.True(expansion.IsComplete);
    }

    /// <summary>
    /// The count a run reports is null where the nesting was never derived.
    /// </summary>
    /// <remarks>
    /// <b>Zero would be a claim.</b> A store with no rows because nothing was derived and one with
    /// no rows because every member resolved are opposite facts, and the dashboard reading the
    /// second as the first would tell an operator his groups are fully known when nobody looked.
    /// </remarks>
    [Fact]
    public void TheUnidentifiedMemberCountIsUnknownWhereNestingWasNotDerived()
    {
        var derived = Store(edges: [(0, 1)], unresolvedMembers: [0]);
        var notDerived = Store(edges: [], nesting: DerivationPhaseOutcome.DidNotRun);

        using var fromDerived = DerivationReader.Open(derived).Value!;
        using var fromNotDerived = DerivationReader.Open(notDerived).Value!;

        Assert.Equal(1, fromDerived.GroupsWithUnidentifiedMembers());
        Assert.Null(fromNotDerived.GroupsWithUnidentifiedMembers());
    }

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

    [Fact]
    public void QualifiedNestedWalkKeepsUnperformedWorkDistinctFromAnEmptyGroup()
    {
        using var missing = DerivationReader.Open(Store(edges: [], nesting: DerivationPhaseOutcome.DidNotRun)).Value!;
        using var empty = DerivationReader.Open(Store(edges: [])).Value!;
        var unperformed = missing.MembersOf(Readers, Scope, (_, _) => true, CancellationToken.None);
        var performed = empty.MembersOf(Readers, Scope, (_, _) => true, CancellationToken.None);
        Assert.Equal(PrincipalExpansionOutcome.NoNestingDerived, unperformed.Outcome);
        Assert.Null(unperformed.Members);
        Assert.Equal(PrincipalExpansionOutcome.Expanded, performed.Outcome);
        Assert.Empty(performed.Members!);
    }

    [Fact]
    public void QualifiedNestedWalkChecksCancellationAfterTheLastLink()
    {
        using var reader = DerivationReader.Open(Store(edges: [(0, 1)])).Value!;
        using var stopping = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => reader.MembersOf(Readers, Scope, (_, _) =>
        {
            stopping.Cancel();
            return true;
        }, stopping.Token));
    }

    [Fact]
    public void QualifiedNestedWalkDoesNotIntroduceTheOrdinaryExpansionCeiling()
    {
        var count = DerivationReader.DefaultExpansionBudget + 2;
        using var reader = DerivationReader.Open(Store(Enumerable.Range(1, count - 1).Select(index => (0, index)).ToArray(),
            principalCount: count)).Value!;
        var ordinary = reader.MembersOf(Readers, Scope);
        var qualified = reader.MembersOf(Readers, Scope, (_, _) => true, CancellationToken.None);
        Assert.Equal((PrincipalExpansionOutcome.StoppedAtBudget, DerivationReader.DefaultExpansionBudget),
            (ordinary.Outcome, ordinary.Members!.Count));
        Assert.Equal((PrincipalExpansionOutcome.Expanded, count - 1), (qualified.Outcome, qualified.Members!.Count));
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

    /// <summary>
    /// An identifier nothing carries, in a domain read in full, is reported as non-existent.
    /// </summary>
    /// <remarks>
    /// <b>The case <c>P-134</c> was raised for.</b> The values are the ones measured in the sealed
    /// <c>ad.lab</c> bundle of 2026-09-04 rather than invented: <see cref="LabDomainSid"/> is the
    /// SID <c>ba.ad.lab</c>'s principals actually share, and <see cref="LabOrphan"/> is one of the
    /// four identifiers found there carrying LAPS read entries and matching no object. The owner
    /// confirmed they are deleted accounts.
    /// </remarks>
    [Fact]
    public void AnIdentifierNothingCarriesInAFullyReadDomainDoesNotExist()
    {
        var directory = Store(
            edges: [(0, 1)],
            coverage: [(LabDomainSid, "ba.ad.lab", DomainReadOutcome.Read)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(LabOrphan, Scope);

        Assert.Equal(PrincipalExpansionOutcome.PrincipalDoesNotExist, expansion.Outcome);
    }

    /// <summary>
    /// A domain that was not read in full refuses, whatever the reason.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The negative control that matters most, and the one the brief for this work demanded be
    /// written first.</b> Everything except <see cref="DomainReadOutcome.Read"/> leaves a hole of
    /// unknown shape, so "no object carries this identifier" means only "no object we managed to
    /// read carries it". Concluding absence from that would report a live delegation - possibly to
    /// a principal of a domain nobody could reach - as harmless.
    /// </para>
    /// <para>
    /// <b><see cref="DomainReadOutcome.PartiallyRead"/> is the dangerous member of the four</b>,
    /// because most of a domain reads like nearly all of it. It counts as a failure, per
    /// <c>docs/decisions/0027</c>, and must refuse exactly as an unreachable domain does.
    /// </para>
    /// </remarks>
    /// <param name="outcome">A coverage outcome that is not a complete read.</param>
    [Theory]
    [InlineData(DomainReadOutcome.PartiallyRead)]
    [InlineData(DomainReadOutcome.NotRead)]
    [InlineData(DomainReadOutcome.ExcludedByChoice)]
    [InlineData(DomainReadOutcome.ExcludedForWantOfCandidates)]
    public void ADomainThatWasNotReadInFullStillRefuses(DomainReadOutcome outcome)
    {
        var directory = Store(
            edges: [(0, 1)],
            coverage: [(LabDomainSid, "ba.ad.lab", outcome)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(LabOrphan, Scope);

        Assert.Equal(PrincipalExpansionOutcome.PrincipalNotFound, expansion.Outcome);
    }

    /// <summary>
    /// An identifier whose domain the derivation holds no row for refuses.
    /// </summary>
    /// <remarks>
    /// <b>Silence is not permission.</b> A domain gets no row when its captured objects disagreed
    /// about its SID, or when the run never saw an ordinary principal of it. Reading a missing row
    /// as "read in full" would turn every gap in the derivation into a claim about the forest.
    /// </remarks>
    [Fact]
    public void AnIdentifierWhoseDomainHasNoCoverageRowStillRefuses()
    {
        // A row for a different domain entirely, so the table is populated and the lookup still
        // misses. An empty table would pass this test for the wrong reason.
        var directory = Store(
            edges: [(0, 1)],
            coverage: [("S-1-5-21-1-2-3", "elsewhere.lab", DomainReadOutcome.Read)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(LabOrphan, Scope);

        Assert.Equal(PrincipalExpansionOutcome.PrincipalNotFound, expansion.Outcome);
    }

    /// <summary>
    /// A built-in or well-known identifier is never judged non-existent.
    /// </summary>
    /// <remarks>
    /// <b>It names no domain, so there is no coverage that could license the conclusion.</b>
    /// <c>S-1-5-32-544</c> is Administrators in every domain and <c>S-1-1-0</c> is Everyone
    /// everywhere; neither carries a domain SID to look up. Matching them on any weaker test - a
    /// prefix, or merely being unresolvable - is how "not found" would quietly become "does not
    /// exist" for the most powerful identifiers in the directory.
    /// </remarks>
    /// <param name="sid">An identifier that belongs to no single domain.</param>
    [Theory]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-11")]
    [InlineData("S-1-5-18")]
    public void AnIdentifierBelongingToNoDomainStillRefuses(string sid)
    {
        var directory = Store(
            edges: [(0, 1)],
            coverage: [(LabDomainSid, "ba.ad.lab", DomainReadOutcome.Read)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(sid, Scope);

        Assert.Equal(PrincipalExpansionOutcome.PrincipalNotFound, expansion.Outcome);
    }

    /// <summary>
    /// An identifier from a fully-read domain that something DOES carry is expanded as before.
    /// </summary>
    /// <remarks>
    /// <b>The control on the control.</b> Coverage saying a domain was read must not change the
    /// answer for a principal the derivation holds; it decides only what an absence means.
    /// </remarks>
    [Fact]
    public void CoverageDoesNotChangeTheAnswerForAPrincipalThatIsHeld()
    {
        var directory = Store(
            edges: [(0, 1), (1, 2)],
            coverage: [(LabDomainSid, "ba.ad.lab", DomainReadOutcome.Read)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope);

        Assert.Equal(PrincipalExpansionOutcome.Expanded, expansion.Outcome);
        Assert.Equal(2, expansion.Members!.Count);
    }

    /// <summary>
    /// A group nested through a distribution group is listed, and what is under it is not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A distribution group carries no authorization, so a hop through one grants nothing.</b>
    /// Microsoft is explicit that an account nested beneath a distribution group does not receive
    /// the enclosing security group's SID in its access token. Walking through one names principals
    /// who hold nothing at all - a false positive, and the kind a customer would act on by removing
    /// access that was never granted.
    /// </para>
    /// <para>
    /// <b>The group itself is still reported, because it really is a member.</b> Dropping it would
    /// replace one untruth with another: an operator looking at the membership would be shown a
    /// list the directory does not agree with.
    /// </para>
    /// <para>
    /// <b>Its negative control is <see cref="ABroadPrincipalNestedDeepIsFound"/></b>, which is this
    /// fixture with the middle group left as a security group and asserts that Domain Users IS
    /// found. The two together are what separate this fix from a walk that merely stopped
    /// descending. P-166.
    /// </para>
    /// </remarks>
    [Fact]
    public void WhatIsBeneathADistributionGroupIsNotInsideWhatContainsIt()
    {
        var directory = Store(edges: [(0, 1), (1, 3)], groupTypes: [(1, DistributionGroup)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope);

        Assert.Equal(PrincipalExpansionOutcome.Expanded, expansion.Outcome);

        var member = Assert.Single(expansion.Members!);
        Assert.Equal(Staff, member.Sid);

        // Not a place the answer thinned out. What is below a distribution group does not belong in
        // this answer at all, so declining to enter it is a complete answer rather than a partial
        // one - marking it incomplete would push every rule reading this into a needless refusal.
        Assert.True(member.IsComplete);

        Assert.Empty(expansion.BroadMembers);
    }

    /// <summary>
    /// A group whose type was never captured is walked through, and the answer says so.
    /// </summary>
    /// <remarks>
    /// <b>Ignorance is not a distribution group, and treating it as one would hide real access.</b>
    /// The cautious pair is to follow the route and refuse to vouch for it: the members are
    /// returned, so nothing is lost, and the outcome stops a rule turning this into a clean
    /// verdict. The owner decided this on 2026-09-11.
    /// </remarks>
    [Fact]
    public void AGroupWhoseTypeWasNeverCapturedIsWalkedAndTheAnswerIsMarked()
    {
        var directory = Store(edges: [(0, 1), (1, 3)], groupTypes: [(1, null)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Readers, Scope);

        Assert.Equal(
            PrincipalExpansionOutcome.ExpandedThroughUnknownGroupType, expansion.Outcome);

        // The members are real and are returned. What the outcome withholds is the claim that the
        // route carries authorization, not the members themselves.
        Assert.False(expansion.IsComplete);
        Assert.Contains(expansion.BroadMembers, m => m.Sid == DomainUsers);
    }

    /// <summary>
    /// A group asked about by the SID it carried before a migration expands to its members.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>An access control entry naming an old SID reaches the migrated principal</b>, which is
    /// why sIDHistory is stored as a second identity rather than discarded. The membership edges
    /// hang off the principal's current SID alone, so a walk starting at the identity that matched
    /// finds the group, finds nothing beneath it, and reports it as containing nobody.
    /// </para>
    /// <para>
    /// <b>The failure this replaces was worse than losing the members.</b> The outcome was
    /// <c>Expanded</c>: a definite statement that the group is empty, which a rule turns into a
    /// clean verdict and an operator reads as safe. P-165.
    /// </para>
    /// </remarks>
    [Fact]
    public void AGroupReachedByItsOldSidExpandsToItsMembers()
    {
        var directory = Store(edges: [(0, 1)], history: [(ReadersOldSid, 0)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(ReadersOldSid, Scope);

        Assert.Equal(PrincipalExpansionOutcome.Expanded, expansion.Outcome);

        var member = Assert.Single(expansion.Members!);
        Assert.Equal(Staff, member.Sid);

        // The route shown to an operator names the group that holds the membership, not the
        // identifier the entry happened to use. Cutting the link means editing Readers.
        Assert.Equal([Readers, Staff], member.PathFromRoot);
    }

    /// <summary>
    /// A principal that answers to its own SID is not redirected to another one.
    /// </summary>
    /// <remarks>
    /// <b>The negative control on the identity hop.</b> Every identity resolves through the same
    /// lookup, a principal's own included, so a defect there would send ordinary expansions to the
    /// wrong principal - silently, because the answer would still be a well-formed group. Here
    /// Staff holds nothing, and a redirect to Readers would hand back a member.
    /// </remarks>
    [Fact]
    public void APrincipalAnsweringToItsOwnSidIsNotRedirected()
    {
        var directory = Store(edges: [(0, 1)], history: [(ReadersOldSid, 0)]);

        using var reader = DerivationReader.Open(directory).Value!;
        var expansion = reader.MembersOf(Staff, Scope);

        Assert.Equal(PrincipalExpansionOutcome.Expanded, expansion.Outcome);
        Assert.Empty(expansion.Members!);
    }

    /// <summary>Builds a store holding four principals and the edges given.</summary>
    /// <remarks>
    /// <b>Principal rows and identity rows are written because a real derivation writes them.</b>
    /// The nesting pass records a row for every principal it sees and an identity row for every SID
    /// each one answers to, so a fixture without them is a store that cannot occur - and a walk
    /// reading group types would find every group untyped, which is a different test from the one
    /// intended.
    /// </remarks>
    /// <param name="edges">Group and member, as indexes into the four SIDs above.</param>
    /// <param name="nesting">What became of the nesting pass.</param>
    /// <param name="coverage">What the run made of reading each domain.</param>
    /// <param name="groupTypes">
    /// Overrides for the <c>groupType</c> of principals by index. Anything not named is a security
    /// group where the edges make it a group and not a group at all otherwise; an entry whose value
    /// is null is a group whose type the capture never read.
    /// </param>
    /// <param name="history">
    /// Extra SIDs interned as identities carried from a migration, each naming the index of the
    /// principal that answers to it.
    /// </param>
    /// <param name="unresolvedMembers">
    /// Principals, by index, that claimed a member no captured object answers to. Written as the
    /// nesting pass writes them, so the walk sees what a real derivation would hold.
    /// </param>
    /// <param name="unresolvedContainers">
    /// Principals, by index, that named a containing group no captured object answers to. Stored
    /// but never consulted by an expansion, which is the asymmetry P-164 requires.
    /// </param>
    /// <param name="principalCount">The original four identities plus optional ordinary current identities.</param>
    private static string Store(
        (int Group, int Member)[] edges,
        DerivationPhaseOutcome nesting = DerivationPhaseOutcome.Succeeded,
        (string DomainSid, string DomainFqdn, DomainReadOutcome Outcome)[]? coverage = null,
        (int Index, int? GroupType)[]? groupTypes = null,
        (string Sid, int Principal)[]? history = null,
        int[]? unresolvedMembers = null,
        int[]? unresolvedContainers = null,
        int principalCount = 4)
    {
        var directory = TempDirectories.Create("expansion-tests");

        Directory.CreateDirectory(directory);
        var evidencePath = BundleLayout.EvidencePath(directory);
        File.WriteAllText(evidencePath, "test evidence");
        BundleSealing.Seal(evidencePath, BundleLayout.SealPath(directory));

        var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash;

        var carried = history ?? [];
        var overrides = (groupTypes ?? []).ToDictionary(g => g.Index, g => g.GroupType);
        var groupIndexes = edges.Select(e => e.Group).ToHashSet();

        using (var writer = DerivationWriter.Create(directory, seal, Started))
        {
            writer.WriteSids(
                [Readers, Staff, Alice, DomainUsers, .. Enumerable.Range(4, principalCount - 4).Select(index => $"S-1-5-21-9-9-9-{2000 + index}"),
                    .. carried.Select(h => h.Sid)],
                [.. Enumerable.Repeat(Scope, principalCount), .. carried.Select(_ => Scope)]);

            writer.WritePrincipals(Enumerable.Range(0, principalCount).Select(index => new PrincipalRow(
                index,
                Guid.Empty,
                IsGroup: groupIndexes.Contains(index),
                GroupType: overrides.TryGetValue(index, out var type)
                    ? type
                    : groupIndexes.Contains(index) ? SecurityGroup : null,
                PrimaryGroupSidId: null)));

            writer.WriteSidIdentities(
            [
                .. Enumerable.Range(0, principalCount)
                    .Select(index => new SidIdentityRow(index, index, SidIdentityKind.Current)),
                .. carried.Select((h, offset) =>
                    new SidIdentityRow(principalCount + offset, h.Principal, SidIdentityKind.History)),
            ]);

            writer.WriteNestingEdges(edges.Select(e => new NestingEdge(e.Group, e.Member)));

            writer.WriteUnresolvedNestingLinks(
            [
                .. (unresolvedMembers ?? []).Select(index => new UnresolvedNestingLink(
                    index, NestingLinkDirection.Member, $"CN=Gone{index},DC=elsewhere")),
                .. (unresolvedContainers ?? []).Select(index => new UnresolvedNestingLink(
                    index, NestingLinkDirection.ContainingGroup, $"CN=Above{index},DC=elsewhere")),
            ]);

            writer.RecordPhase(MembershipNestingPass.PhaseName, nesting, error: null);

            writer.WriteDomainReadCoverage(
                [.. (coverage ?? []).Select(c =>
                    new DomainReadCoverageRow(c.DomainSid, c.DomainFqdn, c.Outcome))]);

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
