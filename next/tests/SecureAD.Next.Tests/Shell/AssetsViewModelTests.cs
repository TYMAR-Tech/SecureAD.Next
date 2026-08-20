using SecureAD.Evidence;
using SecureAD.Kernel;
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
    /// One level is how a directory is browsed, and what the predecessor showed on arrival.
    /// </summary>
    [Fact]
    public void AScreenOpensAtOneLevel()
    {
        var screen = new AssetsViewModel(new FakeAssetSource());

        Assert.Equal(ListingScope.OneLevel, screen.Scope);
    }

    [Fact]
    public void ChangingTheLevelListsAgainAtThatLevel()
    {
        var assets = new FakeAssetSource { Tree = TreeOfOneDomain(), Page = APageOfOne() };
        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);

        screen.Scope = ListingScope.Subtree;

        Assert.Equal(ListingScope.Subtree, assets.ListedScope);
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

        Assert.False(screen.ParentIsWorthShowing);
    }

    [Fact]
    public void TheParentColumnAppearsWhenTheLevelReachesAcrossContainers()
    {
        var screen = Showing(TreeOfOneDomain(), APageOfOne());

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
