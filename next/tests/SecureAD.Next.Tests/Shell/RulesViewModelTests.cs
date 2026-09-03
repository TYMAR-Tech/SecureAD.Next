using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// The rule listing on the assets screen: what it says was checked, and how it keeps apart the
/// several ways a rule can report nothing.
/// </summary>
/// <remarks>
/// <b>This screen exists because four different things draw an empty findings grid.</b> A rule that
/// judged every object it was about and found nothing, one that could not read what it declared,
/// one that threw, and one that was never scheduled all produce no findings - and only the first is
/// a statement about the forest. The tests here are about the words, because the words are the
/// whole product of the screen.
/// </remarks>
public sealed class RulesViewModelTests
{
    private const string BundlePath = @"C:\runs\contoso-2026-09-03";
    private const string DomainDn = "DC=contoso,DC=com";

    /// <summary>
    /// What the rules did is not read while another view is showing.
    /// </summary>
    [Fact]
    public void TheRulesAreNotReadWhileTheObjectsAreShowing()
    {
        var assets = ASource();
        var screen = Showing(assets);

        Assert.Equal(0, assets.RuleExecutionReads);
        Assert.Empty(screen.RuleRows);
    }

    [Fact]
    public void ChoosingTheRulesReadsWhatTheyDid()
    {
        var assets = ASource();
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Rules;

        Assert.Equal(1, assets.RuleExecutionReads);
        Assert.True(screen.ShowsRules);
        Assert.True(screen.ShowsRulesListing);
        Assert.False(screen.ShowsObjects);
        Assert.False(screen.ShowsLaps);
    }

    /// <summary>
    /// Every rule this build ships gets a row, whether or not the judging ran it.
    /// </summary>
    /// <remarks>
    /// <b>The catalogue is the list.</b> Built from the judgement instead, a rule the run never
    /// scheduled would be absent from a screen of rules - and a rule missing from a list of rules
    /// reads as a rule that does not exist, which is the opposite of what an operator needs to
    /// know.
    /// </remarks>
    [Fact]
    public void EveryRuleThisBuildShipsIsListedWhateverTheJudgingDid()
    {
        var assets = ASource();
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Rules;

        Assert.Equal(
            RuleCatalogue.All.Select(rule => rule.Definition.Id).OrderBy(id => id),
            screen.RuleRows.Select(row => row.Rule).OrderBy(id => id));
    }

    /// <summary>
    /// A rule that ran and found nothing says so, and is not mistaken for one that could not run.
    /// </summary>
    [Fact]
    public void ARuleThatJudgedEverythingAndFoundNothingSaysWhatItJudged()
    {
        var assets = ASource(Judged(FirstRule, judged: 2082, findings: 0));
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Rules;

        var row = RowFor(screen, FirstRule);

        Assert.Equal("Judged 2,082 objects and reported nothing.", row.Outcome);
        Assert.Equal(FactState.EstablishedGood, row.State);
        Assert.Equal(0, row.Findings);
    }

    [Fact]
    public void ARuleThatFoundSomethingReportsHowMuchAndIsNotAFault()
    {
        var assets = ASource(Judged(FirstRule, judged: 2082, findings: 3));
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Rules;

        var row = RowFor(screen, FirstRule);

        Assert.Equal("Judged 2,082 objects and reported 3.", row.Outcome);

        // The rule did its job. The forest is what is wrong, so this is not a fault of the product.
        Assert.Equal(FactState.EstablishedBad, row.State);
        Assert.Equal(3, row.Findings);
    }

    /// <summary>
    /// A rule that could not read what it declared says which attribute, and says its result is a
    /// floor.
    /// </summary>
    /// <remarks>
    /// <b>This is the row that must never read as an ordinary zero.</b> Nothing has been
    /// established about the objects it could not reach, and a customer making a security decision
    /// on the strength of a blank cell would be making it on nothing.
    /// </remarks>
    [Fact]
    public void ARuleThatCouldNotJudgeNamesWhatItCouldNotReadAndSaysTheResultIsAFloor()
    {
        var assets = ASource(new StoredRuleExecution(
            FirstRule,
            1,
            RuleExecutionOutcome.Indeterminate,
            ObjectsJudged: 12,
            ObjectsNotApplicable: 0,
            ObjectsNotJudged: 40,
            [new MissingInput("primaryGroupID", 40)],
            FindingsProduced: 0,
            Error: null));

        var screen = Showing(assets);
        screen.Pane = AssetsPane.Rules;

        var row = RowFor(screen, FirstRule);

        Assert.Contains("40", row.Outcome);
        Assert.Contains("primaryGroupID", row.Outcome);
        Assert.Contains("floor", row.Outcome);
        Assert.NotEqual(FactState.EstablishedGood, row.State);
    }

    /// <summary>
    /// A rule the judging never scheduled says nothing has been checked against it.
    /// </summary>
    [Fact]
    public void ARuleTheJudgingNeverRanSaysNothingHasBeenCheckedAgainstIt()
    {
        var assets = ASource();
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Rules;

        var row = RowFor(screen, FirstRule);

        Assert.Contains("Not run", row.Outcome);
        Assert.Contains("nothing here has been checked", row.Outcome);
        Assert.Equal(FactState.NotEstablished, row.State);
    }

    /// <summary>
    /// A rule that threw is a fault of the product, not a statement about the forest.
    /// </summary>
    [Fact]
    public void ARuleThatFailedWhileRunningIsMarkedAFault()
    {
        var assets = ASource(new StoredRuleExecution(
            FirstRule,
            1,
            RuleExecutionOutcome.Error,
            0,
            0,
            0,
            [],
            FindingsProduced: 0,
            Error: "The store closed mid-read."));

        var screen = Showing(assets);
        screen.Pane = AssetsPane.Rules;

        var row = RowFor(screen, FirstRule);

        Assert.Contains("failed while running", row.Outcome);
        Assert.Contains("The store closed mid-read.", row.Outcome);
        Assert.Equal(FactState.Fault, row.State);
    }

    /// <summary>
    /// An execution naming a rule this build no longer ships is still listed.
    /// </summary>
    /// <remarks>
    /// <b>A judgement outlives the build that wrote it.</b> Dropping the row would quietly shrink
    /// the account of what was actually done to the bundle, which is the one thing this screen is
    /// for.
    /// </remarks>
    [Fact]
    public void AnExecutionForARuleThisBuildNoLongerShipsIsStillListed()
    {
        var assets = ASource(Judged("SEC-999", judged: 7, findings: 0));
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Rules;

        var row = RowFor(screen, "SEC-999");

        Assert.Equal("SEC-999", row.Name);
        Assert.Equal(string.Empty, row.Severity);
        Assert.Contains("No description is recorded", row.About);
        Assert.Equal("Judged 7 objects and reported nothing.", row.Outcome);
    }

    /// <summary>
    /// What every rule looks for is readable without a finding to hang it on.
    /// </summary>
    /// <remarks>
    /// <b>This is what closes <c>P-118</c>.</b> The same words were reachable only by selecting a
    /// finding, so on a forest with nothing wrong with it the description of what had been checked
    /// was on no screen at all.
    /// </remarks>
    [Fact]
    public void WhatEachRuleLooksForIsReadableWithoutSelectingAFinding()
    {
        var assets = ASource();
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Rules;

        Assert.All(screen.RuleRows, row =>
        {
            Assert.NotEmpty(row.About);
            Assert.DoesNotContain("No description is recorded", row.About);
            Assert.NotEmpty(row.Name);
            Assert.NotEmpty(row.Severity);
        });
    }

    /// <summary>
    /// A judgement that will not open says so, rather than drawing eleven rules that never ran.
    /// </summary>
    /// <remarks>
    /// <b>Those are opposite facts.</b> "Nobody judged this bundle" and "this bundle's judgement is
    /// unreadable" call for different actions, and a silent list of not-run rules states the first
    /// while the second is true.
    /// </remarks>
    [Fact]
    public void AJudgementThatWillNotOpenIsSaidInWords()
    {
        var assets = ASource();
        assets.RuleExecutionsFail = AuditError.Create(
            ErrorCategory.Shell,
            "JudgementCannotBeRead",
            ErrorSeverity.Failed,
            "The judgement's seal did not verify.",
            BundlePath);

        var screen = Showing(assets);
        screen.Pane = AssetsPane.Rules;

        Assert.True(screen.HasRulesRefusal);
        Assert.Contains("seal did not verify", screen.RulesRefusal!.Detail);
    }

    /// <summary>
    /// Moving about the tree does not re-read the rules.
    /// </summary>
    /// <remarks>
    /// <b>A rule is a question asked of the whole forest.</b> Narrowing it to one organisational
    /// unit would show "judged 2,082 objects" beside a container the judging never counted
    /// separately, which is a number about nothing.
    /// </remarks>
    [Fact]
    public void NarrowingTheTreeDoesNotChangeWhatTheRulesDid()
    {
        var assets = ASource(Judged(FirstRule, judged: 2082, findings: 0));
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Rules;
        screen.Roots[0].Children[0].IsSelected = true;

        Assert.Equal(1, assets.RuleExecutionReads);
        Assert.Equal("Judged 2,082 objects and reported nothing.", RowFor(screen, FirstRule).Outcome);
    }

    private static string FirstRule => RuleCatalogue.All[0].Definition.Id;

    private static RuleRowViewModel RowFor(AssetsViewModel screen, string ruleId) =>
        screen.RuleRows.Single(row => row.Rule == ruleId);

    private static StoredRuleExecution Judged(string ruleId, int judged, int findings) =>
        new(ruleId, 1, RuleExecutionOutcome.Succeeded, judged, 0, 0, [], findings, null);

    private static AssetsViewModel Showing(FakeAssetSource assets)
    {
        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);

        return screen;
    }

    private static FakeAssetSource ASource(params StoredRuleExecution[] executions) => new()
    {
        Tree = TreeOfOneDomain(),
        Page = new ObjectPage(
            [new ListedObject(DomainDn, "contoso", Guid.NewGuid(), "domainDNS", null)],
            1,
            true,
            null),
        RuleExecutions = new StoredRuleExecutions(executions, JudgementRunState.Completed),
    };

    private static DirectoryTree TreeOfOneDomain() => new(
        [
            new TreeNode(
                DomainDn,
                "contoso",
                Guid.Parse("11111111-2222-3333-4444-555555555555"),
                TreeNodeOrigin.Partition,
                [
                    new TreeNode(
                        "OU=Servers," + DomainDn,
                        "Servers",
                        null,
                        TreeNodeOrigin.Captured,
                        []),
                ]),
        ],
        []);
}
