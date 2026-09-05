using System.Linq;
using SecureAD.Evidence;
using SecureAD.Evidence.Inventory;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// Holds the one thing the dashboard exists to get right: a domain that could not be read never
/// renders as a domain that was read and found empty.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this suite is shaped around a pair rather than a single assertion.</b> Asserting that an
/// unread domain shows no number passes just as well against a screen that shows no number for
/// anything - which is the failure class 1 shape described in
/// <c>.github/copilot-instructions.md</c>, a check that passes while measuring nothing. Every test
/// below that asserts a silence is paired with one asserting the corresponding sound, so the suite
/// fails if the screen goes quiet everywhere.
/// </para>
/// <para>
/// <b>The read-and-empty case is the control.</b> A domain read in full that holds no
/// organisational units genuinely has none, and <c>0</c> is the honest answer for it. If that
/// assertion is ever relaxed to make the unread case easier to satisfy, the screen has stopped
/// distinguishing the two and this suite has stopped being worth running.
/// </para>
/// </remarks>
public class DashboardViewModelTests
{
    private const string Bundle = @"C:\runs\ad.lab-20260905";

    // -------------------------------------------------------------------------------------------
    // The distinction itself.

    /// <summary>
    /// A domain read in full that held nothing shows zero, because zero is what it held.
    /// </summary>
    [Fact]
    public void ADomainReadAndFoundEmptyShowsZero()
    {
        var dashboard = Showing(AForestOf(
            Counted("empty.ad.lab", ObjectCounts.None)));

        var row = Row(dashboard, "empty.ad.lab");

        Assert.True(row.CountsAreShown);
        Assert.Equal("0", row.Users);
        Assert.Equal("0", row.Computers);
        Assert.Equal("0", row.Groups);
        Assert.Equal("0", row.OrganisationalUnits);
    }

    /// <summary>
    /// A domain that was not read shows no number at all - not a zero, not a dash in the count
    /// columns, nothing a reader could take for a measurement.
    /// </summary>
    /// <remarks>
    /// This is the assertion the whole stage is for. A count of zero against a domain nobody could
    /// read tells an administrator his directory is clean, and he stops looking.
    /// </remarks>
    [Theory]
    [InlineData(DomainReadOutcome.PartiallyRead)]
    [InlineData(DomainReadOutcome.ExcludedByChoice)]
    [InlineData(DomainReadOutcome.ExcludedForWantOfCandidates)]
    public void ADomainThatWasNotReadShowsNoNumber(DomainReadOutcome outcome)
    {
        var dashboard = Showing(AForestOf(NotCounted("dark.ad.lab", outcome)));

        var row = Row(dashboard, "dark.ad.lab");

        Assert.False(row.CountsAreShown);
        Assert.True(row.ExplanationIsShown);
        Assert.Null(row.Users);
        Assert.Null(row.Computers);
        Assert.Null(row.Groups);
        Assert.Null(row.OrganisationalUnits);
    }

    /// <summary>
    /// The two cases do not read alike, stated as one assertion so that making either side quieter
    /// cannot satisfy it.
    /// </summary>
    /// <remarks>
    /// <b>This is the mutation the suite is built to catch.</b> Change
    /// <c>DomainInventory.NotCounted</c> to carry <c>ObjectCounts.None</c> instead of null - the
    /// single most natural way to simplify that type - and the empty domain and the unreadable one
    /// become indistinguishable. Everything else here still passes; this fails.
    /// </remarks>
    [Fact]
    public void AnEmptyDomainAndAnUnreadableOneDoNotReadAlike()
    {
        var dashboard = Showing(AForestOf(
            Counted("empty.ad.lab", ObjectCounts.None),
            NotCounted("dark.ad.lab", DomainReadOutcome.ExcludedForWantOfCandidates)));

        var empty = Row(dashboard, "empty.ad.lab");
        var dark = Row(dashboard, "dark.ad.lab");

        Assert.NotEqual(empty.CountsAreShown, dark.CountsAreShown);
        Assert.NotEqual(empty.Users, dark.Users);
    }

    /// <summary>
    /// A domain with no numbers says what happened to it, in words, rather than leaving a blank
    /// row.
    /// </summary>
    /// <remarks>
    /// A blank row is a third way of saying nothing, and an operator would read it as a domain that
    /// holds nothing - which is the very thing the missing number was meant to avoid claiming.
    /// </remarks>
    [Fact]
    public void ADomainWithNoNumbersSaysWhyInWords()
    {
        var dashboard = Showing(AForestOf(
            NotCounted("dark.ad.lab", DomainReadOutcome.ExcludedForWantOfCandidates)));

        var explanation = Row(dashboard, "dark.ad.lab").Explanation;

        Assert.Contains("no writable domain controller", explanation, StringComparison.Ordinal);
        Assert.Contains(Reason, explanation, StringComparison.Ordinal);
    }

    /// <summary>
    /// A domain left out by choice does not read as one that could not be reached.
    /// </summary>
    /// <remarks>
    /// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c>. Both rows are empty of
    /// numbers, so the words are the only thing keeping them apart.
    /// </remarks>
    [Fact]
    public void AnExcludedDomainDoesNotReadAsAnUnreachableOne()
    {
        var dashboard = Showing(AForestOf(
            NotCounted("chosen.ad.lab", DomainReadOutcome.ExcludedByChoice),
            NotCounted("dark.ad.lab", DomainReadOutcome.ExcludedForWantOfCandidates)));

        var chosen = Row(dashboard, "chosen.ad.lab").Explanation;
        var dark = Row(dashboard, "dark.ad.lab").Explanation;

        Assert.NotEqual(chosen, dark);
        Assert.Contains("You left this domain out", chosen, StringComparison.Ordinal);
        Assert.DoesNotContain("You left this domain out", dark, StringComparison.Ordinal);
    }

    // -------------------------------------------------------------------------------------------
    // Totals, and what they are allowed to claim.

    /// <summary>A total counts the domains that were read and nothing else.</summary>
    [Fact]
    public void TheTotalCountsOnlyTheDomainsThatWereRead()
    {
        var dashboard = Showing(AForestOf(
            Counted("one.ad.lab", new ObjectCounts(100, 10, 5, 2)),
            Counted("two.ad.lab", new ObjectCounts(200, 20, 5, 3)),
            NotCounted("dark.ad.lab", DomainReadOutcome.ExcludedForWantOfCandidates)));

        Assert.Equal("300", dashboard.TotalUsers);
        Assert.Equal("30", dashboard.TotalComputers);
        Assert.Equal("10", dashboard.TotalGroups);
        Assert.Equal("5", dashboard.TotalOrganisationalUnits);
    }

    /// <summary>
    /// A total over part of a forest names the domains it covers, rather than counting them.
    /// </summary>
    /// <remarks>
    /// <i>2 of 3</i> says how many and not which, and which is what decides whether the total
    /// covers the domain the operator is worried about.
    /// </remarks>
    [Fact]
    public void APartialTotalNamesTheDomainsItCovers()
    {
        var dashboard = Showing(AForestOf(
            Counted("one.ad.lab", ObjectCounts.None),
            NotCounted("dark.ad.lab", DomainReadOutcome.ExcludedByChoice)));

        Assert.False(dashboard.EveryDomainCounted);
        Assert.Contains("one.ad.lab", dashboard.TotalsCover, StringComparison.Ordinal);
        Assert.DoesNotContain("dark.ad.lab", dashboard.TotalsCover, StringComparison.Ordinal);
    }

    /// <summary>
    /// A run in which no domain was read in full totals nothing, and shows no zero for it.
    /// </summary>
    [Fact]
    public void AForestWithNothingReadTotalsNoNumber()
    {
        var dashboard = Showing(AForestOf(
            NotCounted("dark.ad.lab", DomainReadOutcome.ExcludedForWantOfCandidates)));

        Assert.False(dashboard.HasTotals);
        Assert.NotEqual("0", dashboard.TotalUsers);
    }

    /// <summary>
    /// The coverage headline states the denominator even when every domain was read.
    /// </summary>
    /// <remarks>
    /// A headline that appeared only on a shortfall would teach an operator to read its absence as
    /// reassurance - and its absence is also what an unbound property looks like.
    /// </remarks>
    [Fact]
    public void TheCoverageHeadlineStatesTheDenominatorEvenWhenNothingWasMissed()
    {
        var dashboard = Showing(AForestOf(
            Counted("one.ad.lab", ObjectCounts.None),
            Counted("two.ad.lab", ObjectCounts.None)));

        Assert.True(dashboard.EveryDomainCounted);
        Assert.Contains("2 domains", dashboard.CoverageHeadline, StringComparison.Ordinal);
    }

    /// <summary>The headline says how many of how many when a domain is missing.</summary>
    [Fact]
    public void TheCoverageHeadlineSaysHowManyOfHowMany()
    {
        var dashboard = Showing(AForestOf(
            Counted("one.ad.lab", ObjectCounts.None),
            NotCounted("dark.ad.lab", DomainReadOutcome.ExcludedByChoice)));

        Assert.Contains("1 of 2 domains", dashboard.CoverageHeadline, StringComparison.Ordinal);
    }

    // -------------------------------------------------------------------------------------------
    // The warning that goes above everything.

    /// <summary>
    /// A domain the forest named no controller for is raised, not merely listed.
    /// </summary>
    [Fact]
    public void ADomainWithNoControllerIsRaisedAsAWarning()
    {
        var dashboard = Showing(AForestOf(
            Counted("one.ad.lab", ObjectCounts.None),
            NotCounted("dark.ad.lab", DomainReadOutcome.ExcludedForWantOfCandidates)));

        Assert.True(dashboard.HasWarning);
        Assert.Contains("dark.ad.lab", dashboard.Warning!.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "one.ad.lab", dashboard.Warning.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A domain the operator excluded raises nothing, because he already knows about it.
    /// </summary>
    /// <remarks>
    /// The negative control for the test above. Without it, a warning raised for every uncounted
    /// domain would satisfy that one while destroying the distinction <c>0063</c> requires.
    /// </remarks>
    [Fact]
    public void ADomainTheOperatorExcludedRaisesNoWarning()
    {
        var dashboard = Showing(AForestOf(
            NotCounted("chosen.ad.lab", DomainReadOutcome.ExcludedByChoice)));

        Assert.False(dashboard.HasWarning);
        Assert.Null(dashboard.Warning);
    }

    /// <summary>A forest read in full raises nothing.</summary>
    [Fact]
    public void AForestReadInFullRaisesNoWarning()
    {
        var dashboard = Showing(AForestOf(Counted("one.ad.lab", ObjectCounts.None)));

        Assert.False(dashboard.HasWarning);
    }

    // -------------------------------------------------------------------------------------------
    // Policies, stated as read of declared.

    /// <summary>A shortfall in SYSVOL is stated as exact numbers, not as a warning.</summary>
    [Fact]
    public void PoliciesAreStatedAsReadOfDeclared()
    {
        var dashboard = Showing(ForestInventory.Of(
            "ad.lab",
            [Counted("one.ad.lab", ObjectCounts.None)],
            policiesDeclared: 50,
            policiesRead: 47));

        Assert.True(dashboard.SomePoliciesWereNotRead);
        Assert.Contains("47 of 50", dashboard.Policies, StringComparison.Ordinal);
        Assert.Contains("3 could not be read", dashboard.Policies, StringComparison.Ordinal);
    }

    /// <summary>Policies all read say so, rather than saying nothing.</summary>
    [Fact]
    public void PoliciesAllReadAreStatedToo()
    {
        var dashboard = Showing(ForestInventory.Of(
            "ad.lab",
            [Counted("one.ad.lab", ObjectCounts.None)],
            policiesDeclared: 12,
            policiesRead: 12));

        Assert.False(dashboard.SomePoliciesWereNotRead);
        Assert.Contains("12 Group Policy objects", dashboard.Policies, StringComparison.Ordinal);
    }

    // -------------------------------------------------------------------------------------------
    // The confidential-attribute caveat.

    /// <summary>
    /// A domain read over an unencrypted connection is caveated, and the caveat says the counts
    /// themselves are unaffected.
    /// </summary>
    /// <remarks>
    /// Wording it as <i>these counts may be wrong</i> would be its own falsehood: every object
    /// still arrived, and it is attribute values a 2025 controller withholds (<c>F-S24-1</c>).
    /// </remarks>
    [Fact]
    public void AnUnencryptedReadIsCaveatedWithoutImpugningTheCounts()
    {
        var dashboard = Showing(AForestOf(
            DomainInventory.Counted(
                DomainCoverage.Read("open.ad.lab"),
                new ObjectCounts(10, 1, 1, 1),
                mayBeMissingConfidentialValues: true)));

        Assert.True(dashboard.HasConfidentialCaveat);
        Assert.Contains(
            "open.ad.lab", dashboard.ConfidentialCaveat!.Detail, StringComparison.Ordinal);
        Assert.Contains(
            "counts here are unaffected",
            dashboard.ConfidentialCaveat.Detail,
            StringComparison.Ordinal);
    }

    /// <summary>An encrypted run carries no caveat, so the caveat means something when it appears.</summary>
    [Fact]
    public void AnEncryptedRunCarriesNoCaveat()
    {
        var dashboard = Showing(AForestOf(Counted("one.ad.lab", ObjectCounts.None)));

        Assert.False(dashboard.HasConfidentialCaveat);
    }

    // -------------------------------------------------------------------------------------------
    // The other silences.

    /// <summary>
    /// A run whose coverage could not be established refuses, rather than drawing an empty forest.
    /// </summary>
    [Fact]
    public void ARunThatCannotBeSummarisedRefusesRatherThanShowingNothing()
    {
        var source = new FakeAssetSource
        {
            InventoryFails = AuditError.Create(
                ErrorCategory.Evidence,
                "CoverageAbsent",
                ErrorSeverity.Failed,
                "This run records no domain at all.",
                Bundle),
        };

        var dashboard = new DashboardViewModel(source);
        dashboard.Show(Bundle);

        Assert.False(dashboard.HasRun);
        Assert.False(dashboard.HasNoRun);
        Assert.NotNull(dashboard.Refusal);
        Assert.Contains(
            "records no domain", dashboard.Refusal!.Detail, StringComparison.Ordinal);
        Assert.Empty(dashboard.Domains);
    }

    /// <summary>
    /// No run chosen is held apart from a run that would not open.
    /// </summary>
    /// <remarks>
    /// The two send an operator to do different things: one is a question he has not answered, the
    /// other is a failure he needs to see.
    /// </remarks>
    [Fact]
    public void NoRunChosenIsNotTheSameAsARunThatWouldNotOpen()
    {
        var dashboard = Showing(AForestOf(Counted("one.ad.lab", ObjectCounts.None)));

        dashboard.Clear();

        Assert.True(dashboard.HasNoRun);
        Assert.False(dashboard.HasRun);
        Assert.Null(dashboard.Refusal);
        Assert.Empty(dashboard.Domains);
    }

    // -------------------------------------------------------------------------------------------
    // The suite's own self-test.

    /// <summary>
    /// Proves the fixtures actually contain the states the assertions above are about.
    /// </summary>
    /// <remarks>
    /// <b>Failure class 1 is a check that passes while measuring nothing</b>
    /// (<c>.github/copilot-instructions.md</c>). Every assertion above about an unread domain would
    /// pass against a helper that silently produced a read one with no objects, because both draw
    /// empty. This asserts the helpers build what they claim to, so the rest of the suite is
    /// anchored to something outside itself.
    /// </remarks>
    [Fact]
    public void TheFixturesReallyHoldTheStatesTheseTestsAssertAbout()
    {
        Assert.True(Counted("a.ad.lab", ObjectCounts.None).WasCounted);
        Assert.Equal(
            DomainReadOutcome.Read, Counted("a.ad.lab", ObjectCounts.None).Coverage.Outcome);

        foreach (var outcome in new[]
        {
            DomainReadOutcome.PartiallyRead,
            DomainReadOutcome.ExcludedByChoice,
            DomainReadOutcome.ExcludedForWantOfCandidates,
        })
        {
            var domain = NotCounted("b.ad.lab", outcome);

            Assert.False(domain.WasCounted);
            Assert.Equal(outcome, domain.Coverage.Outcome);
        }
    }

    /// <summary>
    /// Proves the type refuses the two contradictions rather than trusting callers to avoid them.
    /// </summary>
    [Fact]
    public void TheTypeRefusesToCountAnUnreadDomainOrToSilenceAReadOne()
    {
        Assert.Throws<ArgumentException>(() => DomainInventory.Counted(
            DomainCoverage.Excluded("dark.ad.lab", ExclusionKind.ByChoice, Reason),
            ObjectCounts.None,
            mayBeMissingConfidentialValues: false));

        Assert.Throws<ArgumentException>(() =>
            DomainInventory.NotCounted(DomainCoverage.Read("one.ad.lab")));
    }

    // -------------------------------------------------------------------------------------------

    private const string Reason = "The controller refused the bind.";

    private static DomainInventory Counted(string domain, ObjectCounts counts) =>
        DomainInventory.Counted(
            DomainCoverage.Read(domain), counts, mayBeMissingConfidentialValues: false);

    private static DomainInventory NotCounted(string domain, DomainReadOutcome outcome) =>
        DomainInventory.NotCounted(outcome switch
        {
            DomainReadOutcome.PartiallyRead => DomainCoverage.PartiallyRead(domain, Reason),
            DomainReadOutcome.NotRead => DomainCoverage.NotRead(domain, Reason),
            DomainReadOutcome.ExcludedByChoice =>
                DomainCoverage.Excluded(domain, ExclusionKind.ByChoice, Reason),
            DomainReadOutcome.ExcludedForWantOfCandidates =>
                DomainCoverage.Excluded(domain, ExclusionKind.ForWantOfCandidates, Reason),
            _ => throw new ArgumentOutOfRangeException(nameof(outcome)),
        });

    private static ForestInventory AForestOf(params DomainInventory[] domains) =>
        ForestInventory.Of("ad.lab", domains, policiesDeclared: 0, policiesRead: 0);

    private static DashboardViewModel Showing(ForestInventory inventory)
    {
        var dashboard = new DashboardViewModel(new FakeAssetSource { Inventory = inventory });
        dashboard.Show(Bundle);
        return dashboard;
    }

    private static DomainInventoryRowViewModel Row(DashboardViewModel dashboard, string domain) =>
        dashboard.Domains.Single(r =>
            string.Equals(r.DomainFqdn, domain, StringComparison.OrdinalIgnoreCase));
}
