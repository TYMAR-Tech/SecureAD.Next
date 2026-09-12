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
        ["userAccountControl", "objectClass", "primaryGroupID"],
        RequiredDerivedFacts: []);

    private static readonly RuleDefinition Sec011 = new(
        "SEC-011", "Unconstrained delegation on a member computer", Severity.High, 1,
        ["user", "computer"],
        ["userAccountControl", "objectClass", "primaryGroupID"],
        RequiredDerivedFacts: []);

    private static readonly RuleDefinition Sec030 = new(
        "SEC-030", "AdminCount without protection", Severity.High, 1,
        ["user", "computer", "group"],
        ["adminCount", "nTSecurityDescriptor", "objectSid"],
        RequiredDerivedFacts: [nameof(DerivedFactKind.ProtectedPrincipals)]);

    private static readonly RuleDefinition Sec022 = new(
        "SEC-022", "Kerberos pre-authentication not required", Severity.High, 1,
        ["user", "computer"],
        ["userAccountControl", "objectClass"],
        RequiredDerivedFacts: []);

    private static Finding AMarkerFinding() =>
        new(
            "SEC-030",
            1,
            Severity.High,
            new FindingSubject(FindingSubjectKind.Account, "svc-legacy"),
            Guid.NewGuid(),
            "CN=svc-legacy,OU=Service Accounts,DC=contoso,DC=com",
            "contoso.com",
            "user",
            "Carries the AdminSDHolder marker with nothing establishing protection.",
            EvidenceCompleteness.Complete,
            new AdminCountWithoutProtectionEvidence("S-1-5-21-1-2-3-1104"));

    private static Finding APreauthFinding() =>
        new(
            "SEC-022",
            1,
            Severity.High,
            new FindingSubject(FindingSubjectKind.Account, "svc-nopreauth"),
            Guid.NewGuid(),
            "CN=svc-nopreauth,OU=Service Accounts,DC=contoso,DC=com",
            "contoso.com",
            "user",
            "Does not require Kerberos pre-authentication.",
            EvidenceCompleteness.Complete,
            new UserAccountControlEvidence(0x400202));

    private static readonly RuleDefinition Sec027 = new(
        "SEC-027", "Privileged identifier carried in SID history", Severity.High, 1,
        ["user", "computer", "group"],
        ["sIDHistory", "objectSid", "objectClass"],
        RequiredDerivedFacts: []);

    /// <summary>
    /// A SEC-027 finding, whose evidence is the first kind stored across two tables.
    /// </summary>
    /// <remarks>
    /// <b>It carries an unranked value and an unreadable one on purpose.</b> A finding whose history
    /// held only its single match would round-trip correctly even if the reader dropped every row
    /// but the first, and would say nothing about whether the unreadable count survived storage. The
    /// two are what the child table and its column exist for.
    /// </remarks>
    private static Finding ASidHistoryFinding() =>
        new(
            "SEC-027",
            1,
            Severity.High,
            new FindingSubject(FindingSubjectKind.Account, "svc-migrated"),
            Guid.NewGuid(),
            "CN=svc-migrated,OU=Service Accounts,DC=contoso,DC=com",
            "contoso.com",
            "user",
            "Carries Enterprise Admins of another domain in its SID history.",
            EvidenceCompleteness.Complete,
            new PrivilegedSidHistoryEvidence(
                "S-1-5-21-9-9-9-1105",
                ["S-1-5-21-1-2-3-519", "S-1-5-21-1-2-3-1157"],
                [new PrivilegedSidHistoryMatch("S-1-5-21-1-2-3-519", 519, "Enterprise Admins")],
                UnreadableValues: 1));

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
    /// Findings that tie on severity, rule and object are all returned.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The cursor's stated premise is false, and this is the dataset that shows it.</b>
    /// <see cref="FindingsPageMark"/> documented that "a distinguished name is unique within a
    /// forest, so no two findings can tie on all three". A distinguished name is unique per
    /// <i>object</i>, but <c>finding</c> is unique on rule, subject kind, subject key and object
    /// GUID - so one rule may report the same object more than once, and those rows tie on every
    /// value the cursor carries.
    /// </para>
    /// <para>
    /// <b>This is not hypothetical.</b> Judging <c>ad.lab-20260910-074140</c> produced two SEC-090
    /// findings for <c>CN=BAWK1,OU=Workstations,OU=BA Lab,DC=ba,DC=ad,DC=lab</c>, identical in
    /// severity, rule and distinguished name - one per broad principal able to read its LAPS
    /// password. P-157 records the same shape for LAPS decryptors.
    /// </para>
    /// <para>
    /// <b>Why <see cref="ReadingEveryPageShowsEveryFindingExactlyOnce"/> did not catch it.</b> That
    /// test says nothing but the distinguished name orders its rows, and it is right - but its
    /// dataset gives every finding a different one, so nothing ever ties and the tie-breaker it
    /// exists for is never reached. A page size of one here puts a boundary inside a tied group on
    /// every page, which is the only arrangement that exercises it.
    /// </para>
    /// </remarks>
    [Fact]
    public void FindingsThatTieOnSeverityRuleAndObjectAreAllReturned()
    {
        const string Shared = "CN=BAWK1,OU=Workstations,DC=contoso,DC=com";
        var directory = ABundleWith([AFinding(Shared), AFinding(Shared), AFinding(Shared), AFinding(Shared)]);

        var seen = 0;
        var query = Query() with { PageSize = 1 };

        while (true)
        {
            var page = Page(directory, query);
            seen += page.Findings.Count;

            if (page.Next is not { } mark)
                break;

            query = query.ResumingAfter(mark);
        }

        Assert.Equal(4, seen);
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

    /// <summary>
    /// A page carries the evidence of every kind of finding, not only the first kind written.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Every other test in this file writes SEC-010 findings</b>, whose evidence is the
    /// unconstrained-delegation kind, so the whole suite could pass while a page mangled every other
    /// kind - which is what it did. The paged query and the whole read share one mapper and did not
    /// share one column list, so column 16 was <c>a.sid</c> in one and <c>f.severity_rank</c> in the
    /// other. A severity rank is never null, so a non-delegation finding took the SID branch and a
    /// number was read as a security identifier.
    /// </para>
    /// <para>
    /// <b>Observed failing before it was fixed</b>, on the findings grid path an operator uses.
    /// </para>
    /// </remarks>
    [Fact]
    public void APageCarriesTheEvidenceOfEveryKindOfFinding()
    {
        var directory = ADirectory();

        using (var writer = JudgementWriter.Create(
            directory, ThisCapture, derivationGenerationId: null, Started, Started))
        {
            writer.Write(RuleExecution.Judged(Sec030, 1, 0, [AMarkerFinding()]));
            writer.Write(RuleExecution.Judged(Sec022, 1, 0, [APreauthFinding()]));
            writer.Write(RuleExecution.Judged(Sec027, 1, 0, [ASidHistoryFinding()]));
            writer.Complete(Started);
        }

        var page = Page(directory, Query());

        var marker = Assert.Single(page.Findings, f => f.RuleId == "SEC-030");
        Assert.Equal("S-1-5-21-1-2-3-1104", Assert.IsType<AdminCountWithoutProtectionEvidence>(
            marker.Evidence).Sid);

        var preauth = Assert.Single(page.Findings, f => f.RuleId == "SEC-022");
        Assert.Equal(0x400202u, Assert.IsType<UserAccountControlEvidence>(
            preauth.Evidence).UserAccountControl);

        // SEC-027 is the first evidence kind stored across two tables, so a page must reassemble it
        // rather than merely find a row. Every value is checked, not only the match: the child rows
        // are what carry the account's whole history, and a reader that returned only the first of
        // them would satisfy a weaker assertion while losing what section 6 of the rule document
        // says must never be lost.
        var history = Assert.Single(page.Findings, f => f.RuleId == "SEC-027");
        var evidence = Assert.IsType<PrivilegedSidHistoryEvidence>(history.Evidence);

        Assert.Equal("S-1-5-21-9-9-9-1105", evidence.ObjectSid);
        Assert.Equal(
            ["S-1-5-21-1-2-3-519", "S-1-5-21-1-2-3-1157"],
            evidence.HistoryValues);
        Assert.Equal("Enterprise Admins", Assert.Single(evidence.Matches).Name);
        Assert.Equal(["S-1-5-21-1-2-3-1157"], evidence.UnrankedValues);
        Assert.Equal(1, evidence.UnreadableValues);
        Assert.False(evidence.IsComplete);
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
        var directory = TempDirectories.Create("findings-paging");

        Directory.CreateDirectory(directory);

        // Written before the writer opens, because a judgement records the seal of the evidence it
        // was made against and refuses to open beside one that does not match.
        File.WriteAllText(
            BundleLayout.SealPath(directory),
            JsonSerializer.Serialize(new BundleSealContents(BundleSealing.Algorithm, ThisCapture)));

        return directory;
    }
}
