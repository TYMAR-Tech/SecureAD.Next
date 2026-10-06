using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class SavedTier0PathSectionTests
{
    [Fact]
    public void Sec071GroupsLeadWithRiskAndReadOtherEvidenceOnlyWhenOpened()
    {
        var saved = Saved();
        var counts = new PathRiskQuestionCounts(1, 1, 1, 1);
        saved = saved with
        {
            Summary = saved.Summary! with { Outcome = RuleExecutionOutcome.Indeterminate, UnresolvedAccessChecks = 1 },
            Page = saved.Page with { Counts = counts },
        };
        var requests = new List<PathRiskVerdict>();
        var section = Section();
        section.ConfigureAsync(UserDn, (group, _, _) =>
        {
            requests.Add(group);
            var original = saved.Page.Questions[0];
            var risk = original.Risk with
            {
                Verdict = group,
                Expectedness = group == PathRiskVerdict.ExpectedRoute ? ControlExpectedness.Expected
                    : group == PathRiskVerdict.UnexpectedRoute ? ControlExpectedness.Unexpected : null,
                ExpectednessReason = group == PathRiskVerdict.ExpectedRoute ? ControlExpectednessReason.ExpectedSameDomainControlPlane
                    : group == PathRiskVerdict.UnexpectedRoute ? ControlExpectednessReason.UnexpectedNotControlPlane : null,
                Issue = group == PathRiskVerdict.Unknown ? PathRiskIssue.AuthorizationUnknown
                    : group == PathRiskVerdict.NotEstablished ? PathRiskIssue.AuthorizationNotEstablished : null,
                Authorization = group == PathRiskVerdict.Unknown ? ControlEvaluationState.Unknown
                    : group == PathRiskVerdict.NotEstablished ? ControlEvaluationState.NotEstablished : ControlEvaluationState.Established,
            };
            var question = original with { Risk = risk, Requester = original.Requester! with { Authorization = risk.Authorization } };
            return Task.FromResult(Result<SavedTier0Path?>.Success(saved with
            { Page = saved.Page with { Group = group, Questions = [question] } }));
        });
        section.Read();

        Assert.Equal(new[] { "Unexpected routes", "Unresolved access checks", "Expected administration — not findings",
            "Other completed checks — no route established" }, section.Groups.Select(group => group.Heading));
        Assert.Equal(new[] { true, false, false, false }, section.Groups.Select(group => group.IsExpanded));
        Assert.Equal(new[] { 1, 0, 0, 0 }, section.Groups.Select(group => group.Questions.Count));
        Assert.Equal([PathRiskVerdict.UnexpectedRoute], requests);
        Assert.Contains("Unresolved access checks: 1", section.Limitations);

        section.Groups[2].IsExpanded = true;
        Assert.Equal([PathRiskVerdict.UnexpectedRoute, PathRiskVerdict.ExpectedRoute], requests);
        Assert.Contains("captured domain administrative authority", Assert.Single(section.Groups[2].Questions).Explanation);
        section.Groups[1].IsExpanded = true;
        var unresolved = Assert.Single(section.Groups[1].Questions);
        Assert.Equal("Unresolved access checks", unresolved.Heading);
        Assert.Empty(unresolved.Steps);
        Assert.Equal("SEC-071 — Unexpected route to Tier 0", section.Result);
    }

    [Fact]
    public void Sec071FindingsSummaryDoesNotCountTheFilteredPage()
    {
        var source = Source();
        source.Tier0Summary = Result<Tier0FindingSummary?>.Success(Saved().Summary! with
        { AssessedAccounts = 12, AccountsWithFindings = 7, UnresolvedAccessChecks = 3, Outcome = RuleExecutionOutcome.Indeterminate });
        source.FindingsPage = new([], null, 18);
        var screen = new AssetsViewModel(source);
        screen.Show(Bundle, false);
        screen.Pane = AssetsPane.Findings;
        screen.RuleFilter = "SEC-071";

        Assert.Empty(screen.Findings);
        Assert.Equal(string.Join(Environment.NewLine, "Accounts with SEC-071 findings: 7", "Unresolved access checks: 3",
            "Supported checks only; other routes may exist."),
            screen.Tier0SummaryText);
        Assert.Equal("Whole-run Tier 0 summary", screen.Tier0SummaryHeading);
    }

    [Theory]
    [InlineData(PathRiskAvailability.NotRequested, "Not requested")]
    [InlineData(PathRiskAvailability.InputsUnavailable, "Required inputs unavailable")]
    public void Sec071UnavailableSummaryDoesNotPrintZeroFindings(PathRiskAvailability availability, string expected)
    {
        var source = Source();
        source.Tier0Summary = Result<Tier0FindingSummary?>.Success(Availability(Saved(), availability).Summary);
        var screen = new AssetsViewModel(source);
        screen.Show(Bundle, false);
        screen.Pane = AssetsPane.Findings;

        Assert.Equal(expected, screen.Tier0SummaryText);
        Assert.DoesNotContain("Accounts with SEC-071 findings:", screen.Tier0SummaryText);
    }

    [Fact]
    public void Sec071SummaryReadFailureClearsThePreviousCounts()
    {
        var source = Source();
        source.Tier0Summary = Result<Tier0FindingSummary?>.Success(Saved().Summary);
        var screen = new AssetsViewModel(source);
        screen.Show(Bundle, false);
        screen.Pane = AssetsPane.Findings;
        Assert.True(screen.HasTier0Summary);
        source.Tier0Summary = Result<Tier0FindingSummary?>.Failure(Failure());
        screen.RuleFilter = "SEC-071";

        Assert.False(screen.HasTier0Summary);
        Assert.NotNull(screen.ViewRefusal);
    }

    [Fact]
    public void Sec071FindingLinksToTheSameAccountRiskSectionWithACapturedName()
    {
        var source = Source();
        var screen = new AssetsViewModel(source);
        screen.Show(Bundle, false);
        var row = new FindingRowViewModel(Saved().Finding!);
        Assert.Equal("User", row.Principal);
        Assert.True(row.HasTier0Routes);

        screen.OpenSavedRoutesCommand.Execute(row);

        Assert.Equal((Bundle, UserDn), Assert.Single(source.PathQueries));
        Assert.IsType<SavedTier0PathSectionViewModel>(screen.Opened!.Selected);
    }

    [Fact]
    public void Sec071NoRecordedQuestionsAreNotAClaimAboutIncomingRisk()
    {
        var saved = NoFinding(Saved());
        var section = Read(saved with { Page = saved.Page with { Counts = new(0, 0, 0, 0) } });
        Assert.Equal("No saved access checks for this object. This does not assess accounts that may reach it.", section.Result);
        Assert.Empty(section.Groups);
    }

    [Fact]
    public void Sec071ChangingGenerationWhileOpeningAGroupWithholdsTheResult()
    {
        var first = NoFinding(Saved(), unresolved: true);
        var second = NoFinding(Saved(), unresolved: true);
        var section = Section();
        section.ConfigureAsync(UserDn, (group, _, _) => Task.FromResult(Result<SavedTier0Path?>.Success(
            group == PathRiskVerdict.UnexpectedRoute ? first : second with { Page = second.Page with { Group = group } })));
        section.Read();
        Assert.Single(section.Groups).IsExpanded = true;
        Assert.Equal("Saved result unavailable", section.Result);
        Assert.Empty(section.Groups);
    }
}
