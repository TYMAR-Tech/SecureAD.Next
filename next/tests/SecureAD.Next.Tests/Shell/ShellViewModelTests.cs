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

        Assert.Equal(["Objects", "Findings", "LAPS", "Rules"], shell.Views.Select(v => v.Name));
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
    // Settings, which stood in for something unbuilt until 2026-09-13
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The settings section shows the settings screen.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This asserted the opposite until 2026-09-13</b>, and the history is the point. It read
    /// <c>ShellSection.Dashboard</c> until 2026-09-05, was retargeted to Settings when the dashboard
    /// was built, and was retargeted again - to the truth - when the settings screen was built. The
    /// rule it used to hold is that a section with nothing behind it says so rather than drawing an
    /// empty result. <b>That rule now has no subject: every section is built</b>, so
    /// <c>SectionView.NotBuilt</c> has no production caller at all. Recorded as a finding rather
    /// than answered by deleting a safeguard the owner asked for on 2026-08-20.
    /// </para>
    /// <para>
    /// What replaces it here is not a weaker version of the same check. It is the check that the
    /// operator reaches the screen, which is what the section is now for.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheSettingsSectionShowsTheSettingsScreen()
    {
        var shell = AShell();

        shell.Show(ShellSection.Settings);

        Assert.Same(shell.Settings, shell.Current);
    }

    /// <summary>
    /// Settings shows a real screen rather than a panel saying it does not exist.
    /// </summary>
    /// <remarks>
    /// <b>The negative half, kept deliberately.</b> Asserting only that <c>Current</c> is the
    /// settings screen would still pass if a placeholder were reintroduced beside it, because the
    /// placeholder is reached through a different property. This names the thing that must not come
    /// back.
    /// </remarks>
    [Fact]
    public void TheSettingsSectionIsNoLongerAPlaceholder()
    {
        var shell = AShell();

        shell.Show(ShellSection.Settings);

        Assert.IsNotType<SectionView>(shell.Current);
    }

    /// <summary>
    /// The dashboard is built, so its section shows the screen rather than a placeholder.
    /// </summary>
    [Fact]
    public void TheDashboardSectionShowsTheDashboard()
    {
        var shell = AShell();

        shell.Show(ShellSection.Dashboard);

        Assert.Same(shell.Dashboard, shell.Current);
    }

    /// <summary>
    /// With no run chosen the dashboard reports no run, rather than an empty forest.
    /// </summary>
    /// <remarks>
    /// <b>The reason the dashboard was left unbuilt for so long.</b> An empty dashboard tells an
    /// administrator his directory is clean, and the danger did not go away when the screen was
    /// built - it moved into it. This is where that is held now.
    /// </remarks>
    [Fact]
    public void TheDashboardWithNoRunChosenDoesNotDrawAnEmptyForest()
    {
        var shell = AShell();

        shell.Show(ShellSection.Dashboard);

        Assert.True(shell.Dashboard.HasNoRun);
        Assert.False(shell.Dashboard.HasRun);
        Assert.Empty(shell.Dashboard.Domains);
    }

    /// <summary>
    /// Opening a run from the library lands on the dashboard.
    /// </summary>
    /// <remarks>
    /// The owner's decision of 2026-09-05, and the reason <c>ShowOpenedRun</c> is a named member
    /// rather than a line in the composition root: this is the only way the decision can be held
    /// by anything.
    /// </remarks>
    [Fact]
    public void OpeningARunLandsOnTheDashboard()
    {
        var shell = AShell();

        shell.ShowOpenedRun();

        Assert.Equal(ShellSection.Dashboard, shell.Section);
        Assert.True(shell.IsDashboard);
    }

    /// <summary>
    /// Choosing the LAPS tab shows the assets screen rather than a placeholder.
    /// </summary>
    /// <remarks>
    /// <b>This test used to assert the opposite.</b> The LAPS tab was added on 2026-08-18 as a
    /// <c>NotBuilt</c> placeholder, so the shape of the navigation could be judged before the screen
    /// behind it existed, and this asserted that selecting it showed something saying so. The
    /// inventory was built on 2026-09-03 and the placeholder is gone, so the assertion is inverted
    /// rather than deleted: what matters either way is that the tab and the screen agree.
    /// <c>ASectionThatIsNotBuiltSaysItReportsNothingAboutTheDirectory</c> still covers the
    /// placeholder wording, at the section level where a placeholder still exists.
    /// </remarks>
    [Fact]
    public void ChoosingTheLapsTabShowsTheAssetsScreen()
    {
        var shell = AShell();
        shell.Show(ShellSection.Assets);

        shell.Views.Single(v => v.Name == "LAPS").IsSelected = true;

        var assets = Assert.IsType<AssetsViewModel>(shell.Current);
        Assert.True(assets.ShowsLaps);
        Assert.False(assets.ShowsObjects);
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

        Assert.True(shell.Assets.ShowsFindings);
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

        Assert.True(shell.Assets.ShowsObjects);
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

    [Fact]
    public void ClearingForDiscardRemovesBothScreensOldRun()
    {
        var shell = AShell();
        shell.Assets.Show(@"C:\runs\discard-test", aCaptureIsRunning: false);
        shell.Dashboard.Show(@"C:\runs\discard-test");

        shell.ClearOpenedRun();

        Assert.Null(shell.Assets.BundlePath);
        Assert.Null(shell.Assets.Opened);
        Assert.Null(shell.Dashboard.BundlePath);
        Assert.False(shell.Dashboard.HasRun);
    }

    private static ShellViewModel AShell()
    {
        var settings = new FakeSettingsStore();
        var location = new RunLibraryLocation(settings);
        var library = new RunLibraryViewModel(
            location, new FakeRunCatalog(), new FakeConfirmation(), new FakeRunOpener(),
            new FakeDerivationLauncher(), new FakeJudgingLauncher());

        return new ShellViewModel(
            new HomeViewModel(location, new FakeFolderPicker(), new FakeNewAuditDialog(), library),
            new AssetsViewModel(new FakeAssetSource()),
            new DashboardViewModel(new FakeAssetSource()),
            new SettingsViewModel(new DomainConcurrency(settings)));
    }
}
