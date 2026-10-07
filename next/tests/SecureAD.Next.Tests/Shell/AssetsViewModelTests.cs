using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// The assets screen's state: what it shows, what it refuses to claim, and how it tells four
/// different silences apart.
/// </summary>
public sealed class AssetsViewModelTests
{
    private const string BundlePath = @"C:\runs\contoso-2026-08-12";
    private const string DomainDn = "DC=contoso,DC=com";
    private const string PeopleDn = "OU=People," + DomainDn;

    // ---------------------------------------------------------------------------------------
    // Four silences, kept apart
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void WithNoRunChosenTheScreenDoesNotClaimThereIsNothingHere()
    {
        var screen = new AssetsViewModel(new FakeAssetSource());

        Assert.False(screen.IsEmpty);
    }

    /// <summary>
    /// A bundle that would not open must not render as a run that captured nothing. This is the
    /// distinction <c>0002</c> exists for, on this screen.
    /// </summary>
    [Fact]
    public void ARefusedBundleDoesNotLookLikeARunThatCapturedNothing()
    {
        var screen = ShowingARefusal();

        Assert.False(screen.IsEmpty);
    }

    [Fact]
    public void AContainerReadAndHoldingNothingSaysSoOnlyBecauseItWasRead()
    {
        var screen = Showing(TreeOfOneDomain(), new ObjectPage([], 0, true, null));

        Assert.True(screen.IsEmpty);
    }

    /// <summary>
    /// A listing short by an unknown number of objects is not an empty container, and must never
    /// render as one.
    /// </summary>
    [Fact]
    public void AShortListingIsNotReportedAsAnEmptyContainer()
    {
        var screen = Showing(
            TreeOfOneDomain(),
            new ObjectPage([], 0, false, "A domain was not read."));

        Assert.False(screen.IsEmpty);
    }

    [Fact]
    public void AShortListingSaysWhatWasNotRead()
    {
        var screen = Showing(
            TreeOfOneDomain(),
            new ObjectPage([], 0, false, "A domain was not read."));

        Assert.True(screen.IsShort);
    }

    // ---------------------------------------------------------------------------------------
    // A capture running
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// <c>docs/decisions/0072</c>: analysis does not run while a capture does, and the product says
    /// so in words rather than by disabling a control.
    /// </summary>
    [Fact]
    public void WhileACaptureIsRunningTheBundleIsNotRead()
    {
        var assets = new FakeAssetSource();
        var screen = new AssetsViewModel(assets);

        screen.Show(BundlePath, aCaptureIsRunning: true);

        Assert.Null(assets.AskedFor);
    }

    [Fact]
    public void WhileACaptureIsRunningTheScreenSaysWhyAndWhatToDo()
    {
        var assets = new FakeAssetSource();
        var screen = new AssetsViewModel(assets);

        screen.Show(BundlePath, aCaptureIsRunning: true);

        Assert.Contains(
            "once the capture has finished", screen.Refusal!.Detail, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------
    // A refusal
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The evidence layer distinguishes a damaged seal from a mismatched one because the remedies
    /// differ. A shell that reworded both into one apology would throw that away.
    /// </summary>
    [Fact]
    public void ARefusalIsShownInTheWordsTheEvidenceLayerUsed()
    {
        var screen = ShowingARefusal();

        Assert.Contains(
            "no longer the evidence", screen.Refusal!.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void ARefusedBundleShowsNoTree()
    {
        var screen = ShowingARefusal();

        Assert.Empty(screen.Roots);
    }

    // ---------------------------------------------------------------------------------------
    // The tree and the selection
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The screen arrives rooted at the forest, showing something, rather than as an empty half
    /// with an instruction to click.
    /// </summary>
    [Fact]
    public void ARunOpensRootedAtTheForest()
    {
        var screen = Showing(TreeOfOneDomain(), APageOfOne());

        Assert.Equal(DomainDn, screen.Selected!.DistinguishedName);
    }

    [Fact]
    public void OpeningARunListsTheObjectsOfTheRoot()
    {
        var assets = ShowingSource(TreeOfOneDomain(), APageOfOne());

        Assert.Equal(DomainDn, assets.ListedContainer);
    }

    [Fact]
    public void ReturningToTheSameCurrentRunDoesNotRebuildItsTree()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);
        screen.Selected = screen.Roots[0].Children[0];

        screen.Suspend();
        screen.Show(BundlePath, aCaptureIsRunning: false);

        Assert.Equal((1, DomainDn, 1), (assets.TreeReads, screen.Selected!.DistinguishedName, screen.PageNumber));
    }

    [Fact]
    public void ReturningAfterTheSelectedRunGenerationChangesRebuildsItsTree()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);
        screen.Suspend();
        assets.IsCurrent = false;

        screen.Show(BundlePath, aCaptureIsRunning: false);

        Assert.Equal(2, assets.TreeReads);
    }

    [Fact]
    public void ReturningAfterTheSamePathWasReopenedRebuildsItsTree()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);
        screen.Suspend();
        assets.CloseRun();

        screen.Show(BundlePath, aCaptureIsRunning: false);

        Assert.Equal(2, assets.TreeReads);
    }

    [Fact]
    public void SelectingAnotherRunRebuildsItsTree()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);
        screen.Suspend();

        screen.Show(@"C:\runs\fabrikam-2026-10-06", aCaptureIsRunning: false);

        Assert.Equal(2, assets.TreeReads);
    }

    [Fact]
    public void ARefusedTreeIsNotRetainedForTheNextEntry()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);
        assets.Fails = AuditError.Create(ErrorCategory.Evidence, "TestRefusal", ErrorSeverity.Failed,
            "The evidence was refused.", BundlePath);
        screen.Read();
        screen.Suspend();
        assets.Fails = null;

        screen.Show(BundlePath, aCaptureIsRunning: false);

        Assert.Equal((3, true), (assets.TreeReads, screen.HasTree));
    }

    [Fact]
    public async Task ACancelledTreeIsNotRetainedForTheNextEntry()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);
        assets.CompleteRead = async (value, token) =>
        {
            await release.Task.WaitAsync(token);
            return value;
        };
        screen.Read();

        screen.Suspend();
        await screen.ReadCompletion;
        assets.CompleteRead = null;
        screen.Show(BundlePath, aCaptureIsRunning: false);

        Assert.Equal(3, assets.TreeReads);
    }

    [Fact]
    public void EnteringDuringCaptureDiscardsTheRetainedTree()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);
        screen.Suspend();
        screen.Show(BundlePath, aCaptureIsRunning: true);
        screen.Suspend();

        screen.Show(BundlePath, aCaptureIsRunning: false);

        Assert.Equal(2, assets.TreeReads);
    }

    [Fact]
    public void SelectingAContainerListsThatContainersObjects()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);

        screen.Selected = screen.Roots[0].Children[0];

        Assert.Equal(PeopleDn, assets.ListedContainer);
    }

    // ---------------------------------------------------------------------------------------
    // The level
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Subtree is the owner-selected initial browsing scope.
    /// </summary>
    [Fact]
    public void AScreenOpensAtSubtree()
    {
        var screen = new AssetsViewModel(new FakeAssetSource());

        Assert.Equal(ListingScope.Subtree, screen.Scope);
    }

    [Fact]
    public void ChangingTheLevelListsAgainAtThatLevel()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);

        screen.Scope = ListingScope.OneLevel;

        Assert.Equal(ListingScope.OneLevel, assets.ListedScope);
    }

    /// <summary>
    /// At the narrow levels every row shares the container the operator just selected, so a Parent
    /// column would repeat the question rather than answer anything - which is what the
    /// predecessor's grid did on all 28 rows.
    /// </summary>
    [Fact]
    public void TheParentColumnIsHiddenWhileEveryRowSharesTheSameParent()
    {
        var screen = Showing(TreeOfOneDomain(), APageOfOne());
        screen.Scope = ListingScope.OneLevel;

        Assert.False(screen.ParentIsWorthShowing);
    }

    [Fact]
    public void TheParentColumnAppearsWhenTheLevelReachesAcrossContainers()
    {
        var screen = Showing(TreeOfOneDomain(), APageOfOne());
        screen.Scope = ListingScope.OneLevel;
        screen.Scope = ListingScope.Subtree;

        Assert.True(screen.ParentIsWorthShowing);
    }

    // ---------------------------------------------------------------------------------------
    // Paging
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void ARunOpensOnTheFirstPage()
    {
        var screen = Showing(TreeOfOneDomain(), APageOfOne());

        Assert.Equal(1, screen.PageNumber);
    }

    [Fact]
    public void ThereIsNoPageBeforeTheFirst()
    {
        var screen = Showing(TreeOfOneDomain(), APageOfOne());

        Assert.False(screen.HasPreviousPage);
    }

    [Fact]
    public void ThereIsNoPageAfterTheLast()
    {
        var screen = Showing(TreeOfOneDomain(), APageOfOne());

        Assert.False(screen.HasNextPage);
    }

    [Fact]
    public void AListingLongerThanAPageOffersTheNextOne()
    {
        var screen = Showing(TreeOfOneDomain(), new ObjectPage([Listed("CN=A")], 250, true, null));

        Assert.True(screen.HasNextPage);
    }

    [Fact]
    public void GoingToTheNextPageAsksForIt()
    {
        var assets = new FakeAssetSource
        {
            Tree = TreeOfOneDomain(),
            Page = new ObjectPage([Listed("CN=A")], 250, true, null),
        };

        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);

        screen.NextPageCommand.Execute(null);

        Assert.Equal(2, assets.ListedPage);
    }

    /// <summary>
    /// A different container is a different listing. Keeping the page number would open a
    /// container at page seven of a listing that has two, and show nothing.
    /// </summary>
    [Fact]
    public void SelectingAnotherContainerStartsAtItsFirstPage()
    {
        var assets = new FakeAssetSource
        {
            Tree = TreeOfOneDomain(),
            Page = new ObjectPage([Listed("CN=A")], 250, true, null),
        };

        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);
        screen.NextPageCommand.Execute(null);

        screen.Selected = screen.Roots[0].Children[0];

        Assert.Equal(1, screen.PageNumber);
    }

    [Fact]
    public void ThePagerSaysWhichObjectsOfHowManyAreShowing()
    {
        var screen = Showing(TreeOfOneDomain(), new ObjectPage([Listed("CN=A")], 250, true, null));

        Assert.Equal("1-1 of 250", screen.PageDescription);
    }

    /// <summary>
    /// Nothing to page through says nothing at all, rather than "0-0 of 0".
    /// </summary>
    [Fact]
    public void ThePagerSaysNothingWhenThereIsNothingToPageThrough()
    {
        var screen = Showing(TreeOfOneDomain(), new ObjectPage([], 0, true, null));

        Assert.Equal(string.Empty, screen.PageDescription);
    }

    // ---------------------------------------------------------------------------------------
    // What a row says
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AnObjectIsShownWithItsType()
    {
        var screen = Showing(TreeOfOneDomain(), APageOfOne());

        Assert.Equal("user", screen.Objects[0].ObjectType);
    }

    /// <summary>
    /// A blank cell reads as though the object had no class. It says plainly that nothing was
    /// recorded instead.
    /// </summary>
    [Fact]
    public void AnObjectWhoseClassDidNotArriveSaysSoRatherThanShowingABlank()
    {
        var screen = Showing(
            TreeOfOneDomain(),
            new ObjectPage(
                [new ListedObject("CN=A," + DomainDn, "A", null, null, DomainDn)],
                1,
                true,
                null));

        Assert.Equal("not recorded", screen.Objects[0].ObjectType);
    }

    // ---------------------------------------------------------------------------------------
    // Findings
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Opening a run shows what the judging found.
    /// </summary>
    [Fact]
    public void OpeningARunShowsWhatTheJudgingFound()
    {
        var screen = ShowingFindings(new FindingsPage([AFinding()], null, RulesRan: 2));

        var only = Assert.Single(screen.Findings);
        Assert.Equal("SEC-010", only.Rule);
        Assert.Equal("High", only.Severity);
    }

    /// <summary>
    /// The findings are scoped by the container selected in the tree.
    /// </summary>
    /// <remarks>
    /// An operator who selected <c>OU=People</c> and switched to findings is still asking about
    /// that container, and a grid that widened to the forest would answer a question he did not
    /// ask.
    /// </remarks>
    [Fact]
    public void TheFindingsAreScopedByTheContainerSelected()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Pane = AssetsPane.Findings;
        screen.Show(BundlePath, aCaptureIsRunning: false);

        screen.Selected = screen.Roots[0].Children[0];

        Assert.Equal("OU=People," + DomainDn, assets.FindingsAsked!.Container);
    }

    /// <summary>
    /// A bundle nobody judged is not shown as a forest with nothing wrong with it.
    /// </summary>
    /// <remarks>
    /// <b>The distinction this product exists for, on this screen.</b> An empty grid and a clean
    /// forest are the same picture, so the screen says which it is in words rather than leaving an
    /// operator to read a blank table as reassurance.
    /// </remarks>
    [Fact]
    public void ABundleNobodyJudgedIsNotShownAsAForestWithNothingWrong()
    {
        var assets = new FakeAssetSource
        {
            Tree = TreeOfOneDomain(),
            Page = APageOfOne(),
            FindingsFail = AuditError.Create(
                ErrorCategory.Evidence,
                "JudgementDidNotRun",
                ErrorSeverity.Failed,
                "No rule was run over this bundle.",
                BundlePath),
        };

        var screen = new AssetsViewModel(assets);
        screen.Pane = AssetsPane.Findings;
        screen.Show(BundlePath, aCaptureIsRunning: false);

        Assert.True(screen.HasFindingsRefusal);
        Assert.False(screen.NothingWasFound);
        Assert.Empty(screen.Findings);
    }

    /// <summary>
    /// A judging that ran and matched nothing says so, which is a different fact.
    /// </summary>
    [Fact]
    public void AJudgingThatMatchedNothingSaysSoRatherThanRefusing()
    {
        var screen = ShowingFindings(new FindingsPage([], null, RulesRan: 2));

        Assert.True(screen.NothingWasFound);
        Assert.False(screen.HasFindingsRefusal);
    }

    /// <summary>
    /// A judgement that could not be read does not make the evidence look unreadable.
    /// </summary>
    /// <remarks>
    /// They are separate files and separate remedies. Telling an operator his evidence could not be
    /// opened, when the truth is that the judgement beside it could not, sends him to re-capture a
    /// forest for nothing.
    /// </remarks>
    [Fact]
    public void AJudgementThatCouldNotBeReadDoesNotRefuseTheEvidence()
    {
        var assets = new FakeAssetSource
        {
            Tree = TreeOfOneDomain(),
            Page = APageOfOne(),
            FindingsFail = AuditError.Create(
                ErrorCategory.Evidence,
                "JudgementSealMismatch",
                ErrorSeverity.Failed,
                "The judgement changed after it was sealed.",
                BundlePath),
        };

        var screen = new AssetsViewModel(assets);
        screen.Pane = AssetsPane.Findings;
        screen.Show(BundlePath, aCaptureIsRunning: false);

        Assert.True(screen.HasFindingsRefusal);
        Assert.False(screen.HasRefusal);
        Assert.True(screen.HasTree);
    }

    /// <summary>
    /// There is no next page when the judging fitted on one.
    /// </summary>
    [Fact]
    public void ThereIsNoNextPageWhenTheFindingsFittedOnOne()
    {
        var screen = ShowingFindings(new FindingsPage([AFinding()], null, RulesRan: 2));

        Assert.False(screen.HasMoreFindings);
        Assert.False(screen.HasEarlierFindings);
    }

    /// <summary>
    /// Going on and coming back returns to the page the operator was on.
    /// </summary>
    /// <remarks>
    /// Keyset paging only goes forward - a page knows where it ended, not where the one before it
    /// began - so stepping back means remembering, and this proves the remembering happens.
    /// </remarks>
    [Fact]
    public void GoingOnAndComingBackReturnsToTheFirstPage()
    {
        var screen = ShowingFindings(
            new FindingsPage(
                [AFinding()],
                new FindingsPageMark(3, "SEC-010", "CN=svc,DC=contoso,DC=com", 1),
                RulesRan: 2));

        Assert.Equal(1, screen.FindingsPageNumber);

        screen.NextFindings();
        Assert.Equal(2, screen.FindingsPageNumber);
        Assert.True(screen.HasEarlierFindings);

        screen.PreviousFindings();
        Assert.Equal(1, screen.FindingsPageNumber);
        Assert.False(screen.HasEarlierFindings);
    }

    /// <summary>
    /// Choosing a different container starts its findings at the first page.
    /// </summary>
    /// <remarks>
    /// A mark from the previous container points into a list that no longer exists, so carrying it
    /// over would open a container part way down somebody else's findings.
    /// </remarks>
    [Fact]
    public void ChoosingADifferentContainerStartsItsFindingsAtTheFirstPage()
    {
        var screen = ShowingFindings(
            new FindingsPage(
                [AFinding()],
                new FindingsPageMark(3, "SEC-010", "CN=svc,DC=contoso,DC=com", 1),
                RulesRan: 2));

        screen.NextFindings();
        Assert.Equal(2, screen.FindingsPageNumber);

        screen.Selected = screen.Roots[0].Children[0];

        Assert.Equal(1, screen.FindingsPageNumber);
    }

    /// <summary>
    /// No findings are read while a capture is running.
    /// </summary>
    /// <remarks>
    /// <c>docs/decisions/0072</c>: analysis does not run while a capture does, and reading a
    /// judgement is analysis.
    /// </remarks>
    [Fact]
    public void NoFindingsAreReadWhileACaptureIsRunning()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);

        screen.Show(BundlePath, aCaptureIsRunning: true);

        Assert.Equal(0, assets.FindingsReads);
        Assert.Empty(screen.Findings);
    }

    /// <summary>
    /// Opening an object takes the findings grid off the screen with the object listing.
    /// </summary>
    /// <remarks>
    /// <b>Both halves derive from whether a listing is showing at all</b>, so opening an object
    /// changes them without either being assigned. Written after finding that the change
    /// notification for exactly this had been left out - the grid would have drawn once and never
    /// moved, which reads as a tab that does nothing.
    /// </remarks>
    [Fact]
    public void OpeningAnObjectTakesTheFindingsGridOffTheScreen()
    {
        var assets = new FakeAssetSource
        {
            Tree = TreeOfOneDomain(),
            Page = APageOfOne(),
            FindingsPage = new FindingsPage([AFinding()], null, RulesRan: 2),
            Permissions = SomePermissions(),
            Attributes = FakeAssetSource.CapturedObject("CN=Alice," + DomainDn, "user"),
        };

        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);
        screen.Pane = AssetsPane.Findings;

        var announced = new List<string>();
        screen.PropertyChanged += (_, e) => announced.Add(e.PropertyName!);

        screen.OpenObject(screen.Objects[0]);

        Assert.True(screen.HasOpenObject);
        Assert.False(screen.ShowsFindingsListing);
        Assert.Contains(nameof(screen.ShowsFindingsListing), announced);
    }

    private static ObjectPermissions SomePermissions() => new(
        "CN=Alice," + DomainDn,
        DescriptorAvailability.Read,
        UnreadableReason: null,
        Owner: null,
        DaclState.Present,
        DaclCompleteness.Complete,
        DaclWasCanonical: true,
        IsDaclProtected: false,
        [],
        []);

    /// <summary>
    /// Opening a finding and closing the object returns to the page it was opened from.
    /// </summary>
    /// <remarks>
    /// <b>The owner's shape: same page, same position.</b> An operator who read down to page four
    /// of a large forest's findings, opened one, and was returned to page one would stop opening
    /// them. Keyset paging only goes forward, so this works by the mark stack surviving the round
    /// trip rather than by rebuilding it.
    /// </remarks>
    [Fact]
    public void OpeningAFindingAndClosingItReturnsToThePageItWasOpenedFrom()
    {
        var screen = ShowingFindings(
            new FindingsPage(
                [AFinding()],
                new FindingsPageMark(3, "SEC-010", "CN=svc,DC=contoso,DC=com", 1),
                RulesRan: 2));

        screen.NextFindings();
        screen.NextFindings();
        Assert.Equal(3, screen.FindingsPageNumber);

        screen.OpenFindingCommand.Execute(screen.Findings[0]);
        screen.CloseObject();

        Assert.Equal(3, screen.FindingsPageNumber);
        Assert.NotEmpty(screen.Findings);
    }

    /// <summary>
    /// The findings are not re-read when an object is closed.
    /// </summary>
    /// <remarks>
    /// Closing an object is a return to what was already on screen, not a new question. Re-reading
    /// would cost a query per close, and on a forest that takes hours to judge an operator opens
    /// and closes a great many findings.
    /// </remarks>
    [Fact]
    public void ClosingAnObjectDoesNotReReadTheFindings()
    {
        var assets = new FakeAssetSource
        {
            Tree = TreeOfOneDomain(),
            Page = APageOfOne(),
            Permissions = SomePermissions(),
            Attributes = FakeAssetSource.CapturedObject(AFinding().DistinguishedName, "user"),
            FindingsPage = new FindingsPage([AFinding()], null, RulesRan: 2),
        };

        var screen = new AssetsViewModel(assets);
        screen.Pane = AssetsPane.Findings;
        screen.Show(BundlePath, aCaptureIsRunning: false);

        screen.OpenFindingCommand.Execute(screen.Findings[0]);
        var afterOpening = assets.FindingsReads;

        screen.CloseObject();

        Assert.Equal(afterOpening, assets.FindingsReads);
    }

    // ---------------------------------------------------------------------------------------
    // Findings filters
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// What the filters offer comes from the findings that exist.
    /// </summary>
    /// <remarks>
    /// <b>The reason the values are read rather than written into the screen.</b> A fixed list
    /// offers Critical whether or not anything is critical, and an operator who picks it and gets an
    /// empty grid has learned only to distrust the control.
    /// </remarks>
    [Fact]
    public void TheFiltersOfferOnlyWhatTheFindingsHave()
    {
        var screen = ShowingFindings(
            APageOfFindings(),
            new FindingsFilterValues([Severity.High, Severity.Low], ["SEC-010"], RulesRan: 2));

        Assert.Equal([AssetsViewModel.Any, "High", "Low"], screen.Severities);
        Assert.Equal([AssetsViewModel.Any, "SEC-010"], screen.Rules);
    }

    /// <summary>
    /// The filter values are read once for the run rather than on every selection.
    /// </summary>
    /// <remarks>
    /// They describe the whole judgement, so re-reading them as the operator moves about the tree
    /// would be the same query for the same answer - and worse, if they were scoped to the
    /// selection instead, a chosen filter would vanish from its own list on the next click.
    /// </remarks>
    [Fact]
    public void TheFilterValuesAreReadOnceForTheRun()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Pane = AssetsPane.Findings;
        screen.Show(BundlePath, aCaptureIsRunning: false);

        screen.Selected = screen.Roots[0].Children[0];
        screen.Selected = screen.Roots[0];

        Assert.Equal(1, assets.FilterValueReads);
    }

    /// <summary>
    /// Choosing a severity asks for that severity.
    /// </summary>
    [Fact]
    public void ChoosingASeverityNarrowsWhatIsAskedFor()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Pane = AssetsPane.Findings;
        screen.Show(BundlePath, aCaptureIsRunning: false);

        screen.SeverityFilter = "High";

        Assert.Equal(Severity.High, assets.FindingsAsked!.Severity);
    }

    /// <summary>
    /// Choosing a rule asks for that rule.
    /// </summary>
    [Fact]
    public void ChoosingARuleNarrowsWhatIsAskedFor()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Pane = AssetsPane.Findings;
        screen.Show(BundlePath, aCaptureIsRunning: false);

        screen.RuleFilter = "SEC-010";

        Assert.Equal("SEC-010", assets.FindingsAsked!.RuleId);
    }

    /// <summary>
    /// Clearing a filter stops narrowing rather than asking for a rule called "Any".
    /// </summary>
    [Fact]
    public void ClearingTheFiltersStopsNarrowing()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Pane = AssetsPane.Findings;
        screen.Show(BundlePath, aCaptureIsRunning: false);
        screen.SeverityFilter = "High";
        screen.RuleFilter = "SEC-010";

        screen.ClearFindingsFilters();

        Assert.Null(assets.FindingsAsked!.Severity);
        Assert.Null(assets.FindingsAsked.RuleId);
        Assert.False(screen.IsFiltered);
    }

    /// <summary>
    /// A different filter is a different list, so the grid returns to its first page.
    /// </summary>
    /// <remarks>
    /// <b>Keyset paging only goes forward.</b> The mark from the previous list points into rows the
    /// new one may not contain, so carrying it over would open the grid part way down a list that no
    /// longer exists - and the operator has no way back to the top.
    /// </remarks>
    [Fact]
    public void ChangingAFilterStartsTheGridAgainAtItsFirstPage()
    {
        var assets = new FakeAssetSource
        {
            Tree = TreeOfOneDomain(),
            Page = APageOfOne(),
            FindingsPage = new FindingsPage(
                [AFinding()], new FindingsPageMark(1, "SEC-010", "CN=svc-web", 1), RulesRan: 2),
        };

        var screen = new AssetsViewModel(assets);
        screen.Pane = AssetsPane.Findings;
        screen.Show(BundlePath, aCaptureIsRunning: false);
        screen.NextFindingsCommand.Execute(null);
        Assert.NotNull(assets.FindingsAsked!.After);

        screen.SeverityFilter = "High";

        Assert.Null(assets.FindingsAsked.After);
    }

    /// <summary>
    /// An empty filtered grid does not claim the container is clean.
    /// </summary>
    /// <remarks>
    /// <b>Two different facts wear the same empty table.</b> Nothing found says the rules ran over
    /// this container and matched nothing, which is about the directory. Nothing matching says what
    /// they found lies outside what was asked for, which is about the question - and stating the
    /// first while the second is true tells an operator his container is clean when he has narrowed
    /// to one severity that happens to be absent.
    /// </remarks>
    [Fact]
    public void AnEmptyFilteredGridDoesNotSayTheContainerIsClean()
    {
        var screen = ShowingFindings(new FindingsPage([], null, RulesRan: 2));
        var unfiltered = screen.NothingFoundReason;

        screen.SeverityFilter = "High";

        Assert.True(screen.NothingWasFound);
        Assert.NotEqual(unfiltered, screen.NothingFoundReason);
        Assert.Contains("filters", screen.NothingFoundReason);
    }

    /// <summary>
    /// A judgement that will not open leaves the filters empty rather than refusing twice.
    /// </summary>
    /// <remarks>
    /// The grid itself says why in words. A second refusal from the filters would state the same
    /// failure twice, and the operator can act on neither until the judgement is fixed.
    /// </remarks>
    [Fact]
    public void AJudgementThatWillNotOpenLeavesTheFiltersEmpty()
    {
        var assets = new FakeAssetSource
        {
            Tree = TreeOfOneDomain(),
            Page = APageOfOne(),
            FindingsFail = AuditError.Create(
                ErrorCategory.Evidence,
                "JudgementUnreadable",
                ErrorSeverity.Failed,
                "The judgement could not be opened.",
                BundlePath),
        };

        var screen = new AssetsViewModel(assets);
        screen.Pane = AssetsPane.Findings;
        screen.Show(BundlePath, aCaptureIsRunning: false);

        Assert.Empty(screen.Severities);
        Assert.Empty(screen.Rules);
        Assert.True(screen.HasFindingsRefusal);
    }

    // ---------------------------------------------------------------------------------------

    private static AssetsViewModel ShowingFindings(FindingsPage findings)
    {
        var screen = new AssetsViewModel(new FakeAssetSource
        {
            Tree = TreeOfOneDomain(),
            Page = APageOfOne(),
            Permissions = SomePermissions(),
            Attributes = FakeAssetSource.CapturedObject(AFinding().DistinguishedName, "user"),
            FindingsPage = findings,
        });

        screen.Pane = AssetsPane.Findings;
        screen.Show(BundlePath, aCaptureIsRunning: false);
        return screen;
    }

    private static AssetsViewModel ShowingFindings(
        FindingsPage findings, FindingsFilterValues values)
    {
        var screen = new AssetsViewModel(new FakeAssetSource
        {
            Tree = TreeOfOneDomain(),
            Page = APageOfOne(),
            Permissions = SomePermissions(),
            Attributes = FakeAssetSource.CapturedObject(AFinding().DistinguishedName, "user"),
            FindingsPage = findings,
            FilterValues = values,
        });

        screen.Pane = AssetsPane.Findings;
        screen.Show(BundlePath, aCaptureIsRunning: false);
        return screen;
    }

    private static FindingsPage APageOfFindings() =>
        new([AFinding()], null, RulesRan: 2);

    /// <summary>
    /// A selected finding carries the guidance written for its rule.
    /// </summary>
    /// <remarks>
    /// <b>The screen is a working surface, not a list.</b> A grid that says what is wrong and
    /// leaves an operator to work out what to do is half a product, and this is the half that was
    /// missing. Bound to a real property rather than the collection's current item, so
    /// <c>ViewBindingGateTests</c> can hold it.
    /// </remarks>
    [Fact]
    public void ASelectedFindingCarriesTheGuidanceForItsRule()
    {
        var screen = ShowingFindings(APageOfFindings());

        Assert.False(screen.HasSelectedFinding);

        screen.SelectedFinding = screen.Findings[0];

        Assert.True(screen.HasSelectedFinding);
        Assert.Equal("SEC-010", screen.SelectedFinding!.Rule);
        Assert.True(screen.SelectedFinding.HasGuidance);
        Assert.Contains("impersonate", screen.SelectedFinding.WhyItMatters, StringComparison.Ordinal);
        Assert.Contains(
            "resource-based constrained delegation",
            screen.SelectedFinding.WhatToDo,
            StringComparison.Ordinal);
        Assert.True(screen.SelectedFinding.HasMicrosoftReference);
    }

    /// <summary>
    /// A finding from a rule this build no longer carries says so, rather than showing nothing.
    /// </summary>
    /// <remarks>
    /// <b>A stored judgement outlives the build that made it.</b> An empty explanation would read as
    /// "there is nothing to say about this", which is a different claim from "this build has no
    /// guidance for that rule" - and <c>docs/decisions/0002</c> forbids rendering the second as the
    /// first.
    /// </remarks>
    [Fact]
    public void AFindingWhoseRuleHasNoGuidanceSaysSoRatherThanShowingNothing()
    {
        var screen = ShowingFindings(new FindingsPage([AFindingFrom("SEC-999")], null, RulesRan: 1));

        screen.SelectedFinding = screen.Findings[0];

        Assert.False(screen.SelectedFinding!.HasGuidance);
        Assert.False(string.IsNullOrWhiteSpace(screen.SelectedFinding.WhyItMatters));
        Assert.Contains("SEC-999", screen.SelectedFinding.WhyItMatters, StringComparison.Ordinal);
        Assert.False(screen.SelectedFinding.HasMicrosoftReference);
    }

    private static Finding AFinding() => AFindingFrom("SEC-010");

    private static Finding AFindingFrom(string ruleId) =>
        new(
            ruleId,
            1,
            Severity.High,
            new FindingSubject(FindingSubjectKind.Account, "svc-web"),
            Guid.NewGuid(),
            "CN=svc-web,OU=People," + DomainDn,
            "contoso.com",
            "user",
            "svc-web is trusted for unconstrained delegation.",
            EvidenceCompleteness.Complete,
            new UnconstrainedDelegationEvidence(
                0x80000, false, new DomainControllerSignals(false, false, false)));

    // ---------------------------------------------------------------------------------------

    private static AssetsViewModel Showing(DirectoryTree tree, ObjectPage page)
    {
        var screen = new AssetsViewModel(new FakeAssetSource { Tree = tree, Page = page });
        screen.Show(BundlePath, aCaptureIsRunning: false);
        return screen;
    }

    private static FakeAssetSource ShowingSource(DirectoryTree tree, ObjectPage page)
    {
        var assets = new FakeAssetSource { Tree = tree, Page = page };
        new AssetsViewModel(assets).Show(BundlePath, aCaptureIsRunning: false);
        return assets;
    }

    private static AssetsViewModel ShowingARefusal()
    {
        var assets = new FakeAssetSource
        {
            Fails = AuditError.Create(
                ErrorCategory.Evidence,
                "SealMismatch",
                ErrorSeverity.Failed,
                "The evidence changed after the run declared itself finished. This is no longer "
                + "the evidence that run captured.",
                BundlePath),
        };

        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);
        return screen;
    }

    private static ObjectPage APageOfOne() => new([Listed("CN=Alice," + DomainDn)], 1, true, null);

    private static ListedObject Listed(string dn) =>
        new(dn, "Alice", Guid.NewGuid(), "user", DomainDn);

    private static DirectoryTree TreeOfOneDomain() => new(
        [
            new TreeNode(
                DomainDn,
                "contoso",
                Guid.Parse("11111111-2222-3333-4444-555555555555"),
                TreeNodeOrigin.Partition,
                [new TreeNode("OU=People," + DomainDn, "People", null, TreeNodeOrigin.Captured, [])]),
        ],
        []);
}
