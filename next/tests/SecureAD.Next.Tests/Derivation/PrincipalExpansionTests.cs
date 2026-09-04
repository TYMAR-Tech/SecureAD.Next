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

    /// <summary>Builds a store holding four principals and the edges given.</summary>
    /// <param name="edges">Group and member, as indexes into the four SIDs above.</param>
    /// <param name="nesting">What became of the nesting pass.</param>
    /// <param name="coverage">What the run made of reading each domain.</param>
    private static string Store(
        (int Group, int Member)[] edges,
        DerivationPhaseOutcome nesting = DerivationPhaseOutcome.Succeeded,
        (string DomainSid, string DomainFqdn, DomainReadOutcome Outcome)[]? coverage = null)
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

