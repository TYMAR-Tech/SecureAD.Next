using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// Reading findings a page at a time, which is how a grid shows a forest it cannot hold.
/// </summary>
/// <remarks>
/// <para>
/// <b>The boundary cases are the point.</b> A page that returns the right rows on an easy dataset
/// proves very little; what breaks a paged grid is a page boundary landing in the middle of a run
/// of rows that sort equal, and the symptom is a finding shown twice on one screen and another
/// never shown at all. It is silent, it depends on where the boundary falls, and nobody reports it
/// as a paging defect.
/// </para>
/// <para>
/// The approach is taken from the predecessor's <c>KeysetQueryBuilder</c>, read 2026-08-26.
/// </para>
/// </remarks>
public sealed class FindingsPagingTests
{
    private const string ThisCapture = "0f9c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5";

    private static readonly DateTimeOffset Started = new(2026, 8, 25, 9, 0, 0, TimeSpan.Zero);

    private static readonly RuleDefinition Sec010 = new(
        "SEC-010", "Unconstrained delegation on an account", Severity.High, 1,
        ["user", "computer"],
        ["userAccountControl", "objectClass", "primaryGroupID"]);

    private static readonly RuleDefinition Sec011 = new(
        "SEC-011", "Unconstrained delegation on a member computer", Severity.High, 1,
        ["user", "computer"],
        ["userAccountControl", "objectClass", "primaryGroupID"]);

    /// <summary>
    /// A page holds what it was asked for and says there is more.
    /// </summary>
    [Fact]
    public void APageHoldsWhatItWasAskedForAndSaysThereIsMore()
    {
        var directory = ABundleWith(Findings(10));

        var page = Page(directory, Query() with { PageSize = 4 });

        Assert.Equal(4, page.Findings.Count);
        Assert.True(page.HasMore);
    }

    /// <summary>
    /// The last page says there is nothing after it.
    /// </summary>
    [Fact]
    public void TheLastPageSaysThereIsNothingAfterIt()
    {
        var directory = ABundleWith(Findings(3));

        var page = Page(directory, Query() with { PageSize = 4 });

        Assert.Equal(3, page.Findings.Count);
        Assert.False(page.HasMore);
    }

    /// <summary>
    /// A page that exactly empties the findings still says there is nothing after it.
    /// </summary>
    /// <remarks>
    /// The off-by-one every paged grid has: a page of four over exactly four findings must not
    /// offer a fifth that turns out to be empty. Fetching one row more than the page is what
    /// answers this without a second query.
    /// </remarks>
    [Fact]
    public void APageThatExactlyEmptiesTheFindingsHasNothingAfterIt()
    {
        var directory = ABundleWith(Findings(4));

        var page = Page(directory, Query() with { PageSize = 4 });

        Assert.Equal(4, page.Findings.Count);
        Assert.False(page.HasMore);
    }

    /// <summary>
    /// Reading every page shows every finding exactly once.
    /// </summary>
    /// <remarks>
    /// <b>This is the test the tie-breaker exists for.</b> The findings here all share one severity
    /// and one rule, so nothing but the distinguished name orders them - which is exactly the
    /// dataset where a boundary landing inside the group repeats one row and loses another.
    /// </remarks>
    [Fact]
    public void ReadingEveryPageShowsEveryFindingExactlyOnce()
    {
        var directory = ABundleWith(Findings(17));

        var seen = new List<string>();
        var query = Query() with { PageSize = 5 };

        while (true)
        {
            var page = Page(directory, query);
            seen.AddRange(page.Findings.Select(f => f.DistinguishedName));

            if (page.Next is not { } mark)
                break;

            query = query.ResumingAfter(mark);
        }

        Assert.Equal(17, seen.Count);
        Assert.Equal(17, seen.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>
    /// The worst findings are on the first page.
    /// </summary>
    /// <remarks>
    /// Ordering on the stored word would put Low above Medium, so this proves the rank is what
    /// orders the grid.
    /// </remarks>
    [Fact]
    public void TheWorstFindingsAreOnTheFirstPage()
    {
        var directory = ABundleWith(
        [
            AFinding("CN=a,DC=contoso,DC=com") with { Severity = Severity.Low },
            AFinding("CN=b,DC=contoso,DC=com") with { Severity = Severity.Critical },
            AFinding("CN=c,DC=contoso,DC=com") with { Severity = Severity.Medium },
            AFinding("CN=d,DC=contoso,DC=com") with { Severity = Severity.High },
        ]);

        var page = Page(directory, Query() with { PageSize = 2 });

        Assert.Equal(
            [Severity.Critical, Severity.High],
            page.Findings.Select(f => f.Severity));
    }

    /// <summary>
    /// Asking for one severity returns only that severity.
    /// </summary>
    [Fact]
    public void AskingForOneSeverityReturnsOnlyThatSeverity()
    {
        var directory = ABundleWith(
        [
            AFinding("CN=a,DC=contoso,DC=com") with { Severity = Severity.Low },
            AFinding("CN=b,DC=contoso,DC=com") with { Severity = Severity.Critical },
            AFinding("CN=c,DC=contoso,DC=com") with { Severity = Severity.Critical },
        ]);

        var page = Page(directory, Query() with { Severity = Severity.Critical });

        Assert.Equal(2, page.Findings.Count);
        Assert.All(page.Findings, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    /// <summary>
    /// Asking for one container returns what is beneath it and nothing else.
    /// </summary>
    /// <remarks>
    /// This is how the tree selection scopes the grid, which is the shape the predecessor used and
    /// which <c>AssetsViewModel</c> already anticipates in its remarks.
    /// </remarks>
    [Fact]
    public void AskingForOneContainerReturnsWhatIsBeneathIt()
    {
        var directory = ABundleWith(
        [
            AFinding("CN=one,OU=Servers,DC=contoso,DC=com"),
            AFinding("CN=two,OU=Servers,DC=contoso,DC=com"),
            AFinding("CN=three,OU=People,DC=contoso,DC=com"),
        ]);

        var page = Page(
            directory,
            Query() with { Container = "OU=Servers,DC=contoso,DC=com" });

        Assert.Equal(2, page.Findings.Count);
        Assert.All(
            page.Findings,
            f => Assert.Contains("OU=Servers", f.DistinguishedName, StringComparison.Ordinal));
    }

    /// <summary>
    /// A container whose name contains a wildcard does not widen the grid.
    /// </summary>
    /// <remarks>
    /// <b><c>%</c> and <c>_</c> are legal in a distinguished name and mean something to a
    /// <c>LIKE</c>.</b> Left unescaped, selecting a container called <c>Test_1</c> would also show
    /// findings in <c>Test01</c> - a grid quietly showing objects from somewhere the operator did
    /// not select.
    /// </remarks>
    [Fact]
    public void AContainerHoldingAWildcardDoesNotWidenTheGrid()
    {
        var directory = ABundleWith(
        [
            AFinding("CN=one,OU=Test_1,DC=contoso,DC=com"),
            AFinding("CN=two,OU=Test01,DC=contoso,DC=com"),
        ]);

        var page = Page(directory, Query() with { Container = "OU=Test_1,DC=contoso,DC=com" });

        var only = Assert.Single(page.Findings);
        Assert.Equal("CN=one,OU=Test_1,DC=contoso,DC=com", only.DistinguishedName);
    }

    /// <summary>
    /// Asking for one rule returns only that rule's findings.
    /// </summary>
    [Fact]
    public void AskingForOneRuleReturnsOnlyThatRulesFindings()
    {
        var directory = ADirectory();

        using (var writer = JudgementWriter.Create(directory, ThisCapture, derivationGenerationId: null, Started, Started))
        {
            writer.Write(RuleExecution.Judged(Sec010, 1, 0, [AFinding("CN=a,DC=contoso,DC=com")]));
            writer.Write(RuleExecution.Judged(
                Sec011, 1, 0, [AFinding("CN=b,DC=contoso,DC=com") with { RuleId = "SEC-011" }]));
            writer.Complete(Started);
        }

        var page = Page(directory, Query() with { RuleId = "SEC-011" });

        var only = Assert.Single(page.Findings);
        Assert.Equal("SEC-011", only.RuleId);
    }

    /// <summary>
    /// A judging where no rule ran is refused rather than paged as an empty grid.
    /// </summary>
    /// <remarks>
    /// <b>An empty page and a clean forest are the same picture and opposite facts.</b> The whole
    /// read hands findings out beside the rules that ran so a caller cannot confuse them; a page
    /// cannot carry the rules, so it refuses instead.
    /// </remarks>
    [Fact]
    public void AJudgingWhereNoRuleRanIsRefusedRatherThanPagedAsEmpty()
    {
        var directory = ADirectory();

        using (var writer = JudgementWriter.Create(directory, ThisCapture, derivationGenerationId: null, Started, Started))
            writer.Complete(Started);

        using var reader = Opened(directory);
        var page = reader.ReadPage(Query());

        Assert.False(page.IsSuccess);
        Assert.Equal("Evidence.JudgementDidNotRun", page.Error!.Code);
    }

    /// <summary>
    /// A judging that ran and matched nothing gives an empty page rather than a refusal.
    /// </summary>
    /// <remarks>
    /// The other half of the distinction above, and the reason it is drawn: this really is a forest
    /// where the rules found nothing, and saying so is the answer an operator wants.
    /// </remarks>
    [Fact]
    public void AJudgingThatMatchedNothingGivesAnEmptyPage()
    {
        var directory = ADirectory();

        using (var writer = JudgementWriter.Create(directory, ThisCapture, derivationGenerationId: null, Started, Started))
        {
            writer.Write(RuleExecution.Judged(Sec010, 400, 0, []));
            writer.Complete(Started);
        }

        var page = Page(directory, Query());

        Assert.Empty(page.Findings);
        Assert.False(page.HasMore);
    }

    /// <summary>
    /// Asking about one object returns only that object's findings.
    /// </summary>
    /// <remarks>
    /// This is how the object view fills its findings section: an operator who opened one object is
    /// asking what is wrong with it.
    /// </remarks>
    [Fact]
    public void AskingAboutOneObjectReturnsOnlyThatObjectsFindings()
    {
        var directory = ABundleWith(
        [
            AFinding("CN=one,OU=Servers,DC=contoso,DC=com"),
            AFinding("CN=two,OU=Servers,DC=contoso,DC=com"),
        ]);

        var page = Page(
            directory,
            Query() with { Object = "CN=one,OU=Servers,DC=contoso,DC=com" });

        var only = Assert.Single(page.Findings);
        Assert.Equal("CN=one,OU=Servers,DC=contoso,DC=com", only.DistinguishedName);
    }

    /// <summary>
    /// Asking about a container as an object does not return what is inside it.
    /// </summary>
    /// <remarks>
    /// <b>This is why the object filter is not expressed as a container match.</b> A container match
    /// is a suffix, so asking about <c>OU=Servers</c> that way would answer with every finding
    /// beneath it - and an operator who opened the organisational unit itself would be told its
    /// members' problems were its own.
    /// </remarks>
    [Fact]
    public void AskingAboutAContainerDoesNotReturnWhatIsInsideIt()
    {
        var directory = ABundleWith(
        [
            AFinding("OU=Servers,DC=contoso,DC=com"),
            AFinding("CN=one,OU=Servers,DC=contoso,DC=com"),
            AFinding("CN=two,OU=Servers,DC=contoso,DC=com"),
        ]);

        var page = Page(directory, Query() with { Object = "OU=Servers,DC=contoso,DC=com" });

        var only = Assert.Single(page.Findings);
        Assert.Equal("OU=Servers,DC=contoso,DC=com", only.DistinguishedName);
    }

    /// <summary>
    /// An object with nothing found about it gives an empty page rather than a refusal.
    /// </summary>
    /// <remarks>
    /// The rules ran; this object is simply not one of the things they found. That is a statement
    /// about the object, and the findings section on it should say so.
    /// </remarks>
    [Fact]
    public void AnObjectWithNothingFoundAboutItGivesAnEmptyPage()
    {
        var directory = ABundleWith([AFinding("CN=one,OU=Servers,DC=contoso,DC=com")]);

        var page = Page(directory, Query() with { Object = "CN=quiet,OU=People,DC=contoso,DC=com" });

        Assert.Empty(page.Findings);
        Assert.True(page.NothingWasFound);
    }

    /// <summary>
    /// The shorthand for asking about one object asks about that object.
    /// </summary>
    [Fact]
    public void TheShorthandForOneObjectAsksAboutThatObject()
    {
        var query = FindingsQuery.About("CN=one,OU=Servers,DC=contoso,DC=com");

        Assert.Equal("CN=one,OU=Servers,DC=contoso,DC=com", query.Object);
        Assert.Null(query.Container);
    }

    /// <summary>
    /// The filter values are the severities and rules some finding actually has.
    /// </summary>
    /// <remarks>
    /// <b>Why they are read rather than listed.</b> A screen that offers every severity offers
    /// Critical whether or not anything is critical, and an operator who picks it and gets an empty
    /// grid has learned only to distrust the control.
    /// </remarks>
    [Fact]
    public void TheFilterValuesAreOnlyWhatTheFindingsHave()
    {
        var directory = ABundleWith(
        [
            AFinding("CN=a,DC=contoso,DC=com") with { Severity = Severity.Low },
            AFinding("CN=b,DC=contoso,DC=com") with { Severity = Severity.Low },
        ]);

        var values = FilterValues(directory);

        Assert.Equal([Severity.Low], values.Severities);
        Assert.Equal(["SEC-010"], values.Rules);
    }

    /// <summary>
    /// The severities come back worst first rather than alphabetically.
    /// </summary>
    /// <remarks>
    /// The same trap as the grid: the stored severity is the enum's name, so ordering on it puts
    /// Low above Medium - which on a filter list reads as a mistake rather than as a sort.
    /// </remarks>
    [Fact]
    public void TheFilterSeveritiesComeBackWorstFirst()
    {
        var directory = ABundleWith(
        [
            AFinding("CN=a,DC=contoso,DC=com") with { Severity = Severity.Low },
            AFinding("CN=b,DC=contoso,DC=com") with { Severity = Severity.Critical },
            AFinding("CN=c,DC=contoso,DC=com") with { Severity = Severity.Medium },
        ]);

        var values = FilterValues(directory);

        Assert.Equal([Severity.Critical, Severity.Medium, Severity.Low], values.Severities);
    }

    /// <summary>
    /// A bundle nobody judged says so rather than offering two empty lists.
    /// </summary>
    /// <remarks>
    /// <b>Empty filters have two causes and they are not alike.</b> A judged bundle whose rules
    /// found nothing genuinely offers nothing to filter by; a bundle nobody judged offers nothing
    /// either. A screen that could not tell them apart would show the same picture for
    /// <i>your forest is quiet</i> and <i>nobody has looked</i>.
    /// </remarks>
    [Fact]
    public void FilterValuesFromABundleNobodyJudgedSaySoRatherThanLookingEmpty()
    {
        var directory = ADirectory();

        using (var writer = JudgementWriter.Create(directory, ThisCapture, derivationGenerationId: null, Started, Started))
            writer.Complete(Started);

        var values = FilterValues(directory);

        Assert.True(values.DidNotRun);
        Assert.Empty(values.Severities);
    }

    /// <summary>
    /// A judging that ran and matched nothing is not mistaken for one that never ran.
    /// </summary>
    [Fact]
    public void FilterValuesFromAJudgingThatMatchedNothingSayTheRulesRan()
    {
        var directory = ABundleWith([]);

        var values = FilterValues(directory);

        Assert.False(values.DidNotRun);
        Assert.Empty(values.Severities);
    }

    private static FindingsQuery Query() => FindingsQuery.Everything();

    private static FindingsFilterValues FilterValues(string directory)
    {
        using var reader = Opened(directory);
        return reader.ReadFilterValues();
    }

    private static FindingsPage Page(string directory, FindingsQuery query)
    {
        using var reader = Opened(directory);
        var page = reader.ReadPage(query);

        Assert.True(page.IsSuccess, page.Error?.Description);
        return page.Value!;
    }

    private static JudgementReader Opened(string directory)
    {
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return opened.Value!;
    }

    /// <summary>
    /// Findings that differ only by distinguished name, so nothing but the tie-breaker orders them.
    /// </summary>
    /// <remarks>
    /// <b>Stored in an order that disagrees with the sort, deliberately.</b> Written in ascending
    /// name order, SQLite returns them in insertion order for free, and a query with no tie-breaker
    /// pages perfectly - so the test would pass against the very defect it exists to catch.
    /// <para>
    /// <b>Verified by mutation on 2026-08-26, and the first attempt proved nothing.</b> Removing
    /// the distinguished name from the <c>ORDER BY</c> alone left it in the keyset comparison, so
    /// the two halves still agreed and every test stayed green. Only removing it from both - which
    /// is what a missing tie-breaker actually is - made
    /// <see cref="ReadingEveryPageShowsEveryFindingExactlyOnce"/> fail.
    /// </para>
    /// </remarks>
    private static Finding[] Findings(int count) =>
        [.. Enumerable
            .Range(0, count)
            .Select(i => AFinding($"CN=svc-{i:D3},OU=Service Accounts,DC=contoso,DC=com"))
            .Reverse()];

    private static Finding AFinding(string distinguishedName) =>
        new(
            "SEC-010",
            1,
            Severity.High,
            new FindingSubject(FindingSubjectKind.Account, distinguishedName),
            Guid.NewGuid(),
            distinguishedName,
            "contoso.com",
            "user",
            "Trusted for unconstrained delegation.",
            EvidenceCompleteness.Complete,
            new UnconstrainedDelegationEvidence(
                0x80000, false, new DomainControllerSignals(false, false, false)));

    private static string ABundleWith(IReadOnlyList<Finding> findings)
    {
        var directory = ADirectory();

        using (var writer = JudgementWriter.Create(directory, ThisCapture, derivationGenerationId: null, Started, Started))
        {
            writer.Write(RuleExecution.Judged(Sec010, findings.Count, 0, findings));
            writer.Complete(Started);
        }

        return directory;
    }

    private static string ADirectory()
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "securead-findings-paging", Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);

        // Written before the writer opens, because a judgement records the seal of the evidence it
        // was made against and refuses to open beside one that does not match.
        File.WriteAllText(
            BundleLayout.SealPath(directory),
            JsonSerializer.Serialize(new BundleSealContents(BundleSealing.Algorithm, ThisCapture)));

        return directory;
    }
}
