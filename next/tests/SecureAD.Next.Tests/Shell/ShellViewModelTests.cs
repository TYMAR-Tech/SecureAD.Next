using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// The window's navigation: two tiers of tabs, and what stands behind a tab that has nothing
/// built behind it.
/// </summary>
public sealed class ShellViewModelTests
{
    // ---------------------------------------------------------------------------------------
    // The second tier
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A section with one view carries no second row, rather than a single tab that switches to
    /// where the operator already is.
    /// </summary>
    [Fact]
    public void ASectionWithOneViewShowsNoSecondRow()
    {
        var shell = AShell();

        shell.Show(ShellSection.Home);

        Assert.False(shell.HasViews);
    }

    [Fact]
    public void AssetsOffersItsViewsOnTheSecondRow()
    {
        var shell = AShell();

        shell.Show(ShellSection.Assets);

        Assert.Equal(["Objects", "Findings", "LAPS"], shell.Views.Select(v => v.Name));
    }

    /// <summary>
    /// Landing on a tab that says "not built" would make a section look unfinished when its real
    /// view is one click away.
    /// </summary>
    [Fact]
    public void ArrivingAtASectionSelectsTheFirstViewThatWorks()
    {
        var shell = AShell();

        shell.Show(ShellSection.Assets);

        Assert.Equal("Objects", shell.SelectedView!.Name);
    }

    [Fact]
    public void ASelectedViewThatWorksShowsItsScreen()
    {
        var shell = AShell();

        shell.Show(ShellSection.Assets);

        Assert.IsType<AssetsViewModel>(shell.Current);
    }

    // ---------------------------------------------------------------------------------------
    // What stands behind a tab with nothing built
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The tab exists so the shape of the navigation can be judged. What it shows says plainly
    /// that it is not built.
    /// </summary>
    [Fact]
    public void ASectionThatIsNotBuiltShowsSomethingSayingSo()
    {
        var shell = AShell();

        shell.Show(ShellSection.Dashboard);

        Assert.IsType<SectionView>(shell.Current);
    }

    /// <summary>
    /// This is the whole safeguard. <c>docs/decisions/0045</c> left these screens out because a
    /// screen that appears to report and reports nothing is what a customer believes. The tab is
    /// now built anyway, on the owner's instruction, so what stands behind it must say outright
    /// that it states nothing about the directory - an empty dashboard reads as a clean forest.
    /// </summary>
    [Fact]
    public void ASectionThatIsNotBuiltSaysItReportsNothingAboutTheDirectory()
    {
        var shell = AShell();

        shell.Show(ShellSection.Dashboard);

        Assert.Contains(
            "reports nothing about your directory",
            ((SectionView)shell.Current).Absent,
            StringComparison.Ordinal);
    }

    [Fact]
    public void AViewThatIsNotBuiltShowsSomethingSayingSoRatherThanTheScreenBesideIt()
    {
        var shell = AShell();
        shell.Show(ShellSection.Assets);

        shell.Views.Single(v => v.Name == "LAPS").IsSelected = true;

        Assert.IsType<SectionView>(shell.Current);
    }

    /// <summary>
    /// Choosing the findings tab shows the findings rather than the objects.
    /// </summary>
    /// <remarks>
    /// <b>Both tabs are one screen, so the tabs cannot choose between two view models</b> the way
    /// the rail does. The screen is told which of its halves is showing, and this is what proves
    /// the telling happens.
    /// <para>
    /// This replaced <c>AFindingsTabWithNoFindingsEngineSaysNothingHasLooked</c>, which held that
    /// the tab must say nothing had looked while no engine existed. One exists now. What that test
    /// was protecting - that an empty findings table must never read as a clean directory - moved
    /// to <c>AssetsViewModelTests.ABundleNobodyJudgedIsNotShownAsAForestWithNothingWrong</c>, where
    /// the findings actually are.
    /// </para>
    /// </remarks>
    [Fact]
    public void ChoosingTheFindingsTabShowsTheFindings()
    {
        var shell = AShell();
        shell.Show(ShellSection.Assets);

        shell.Views.Single(v => v.Name == "Findings").IsSelected = true;

        Assert.True(shell.Assets.ShowsFindingsListing);
        Assert.False(shell.Assets.ShowsObjectListing);
    }

    /// <summary>
    /// Going back to the objects tab shows the objects again.
    /// </summary>
    [Fact]
    public void GoingBackToTheObjectsTabShowsTheObjects()
    {
        var shell = AShell();
        shell.Show(ShellSection.Assets);

        shell.Views.Single(v => v.Name == "Findings").IsSelected = true;
        shell.Views.Single(v => v.Name == "Objects").IsSelected = true;

        Assert.True(shell.Assets.ShowsObjectListing);
        Assert.False(shell.Assets.ShowsFindingsListing);
    }

    [Fact]
    public void GoingBackToAViewThatWorksShowsItsScreenAgain()
    {
        var shell = AShell();
        shell.Show(ShellSection.Assets);
        shell.Views.Single(v => v.Name == "Findings").IsSelected = true;

        shell.Views.Single(v => v.Name == "Objects").IsSelected = true;

        Assert.IsType<AssetsViewModel>(shell.Current);
    }

    // ---------------------------------------------------------------------------------------
    // The sections that were already there
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void HomeIsTheSectionAWindowOpensOn()
    {
        var shell = AShell();

        Assert.True(shell.IsHome);
    }

    /// <summary>
    /// The library is reached through Home, which is the only screen showing it.
    ///
    /// <para>
    /// This test read <c>Show(ShellSection.Runs)</c> until 2026-08-21, when the Runs section was
    /// retired. It showed the same library object Home does, so the two could not disagree - but
    /// every capability the library gained had to be built twice, and the name and notes editor
    /// was built on only one of them.
    /// </para>
    /// </summary>
    [Fact]
    public void TheLibraryIsReachedThroughHome()
    {
        var shell = AShell();

        Assert.Same(shell.Home.Library, shell.Library);
    }

    // ---------------------------------------------------------------------------------------

    private static ShellViewModel AShell()
    {
        var settings = new FakeSettingsStore();
        var location = new RunLibraryLocation(settings);
        var library = new RunLibraryViewModel(
            location, new FakeRunCatalog(), new FakeConfirmation(), new FakeRunOpener());

        return new ShellViewModel(
            new HomeViewModel(location, new FakeFolderPicker(), new FakeNewAuditDialog(), library),
            new AssetsViewModel(new FakeAssetSource()));
    }
}
