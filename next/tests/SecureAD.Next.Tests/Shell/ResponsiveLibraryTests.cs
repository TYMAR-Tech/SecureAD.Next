using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class ResponsiveLibraryTests
{
    [Fact]
    public void LoadingRunsOffTheInteractionThreadAndDoesNotClaimAnEmptyLibrary() => OneThread.Run(async () =>
    {
        var (library, _, catalog) = Model();
        await library.RefreshAsync();
        Assert.True(library.IsEmpty);
        using var pending = new PendingListing();
        catalog.WhenListing = pending.List;
        var interactionThread = Environment.CurrentManagedThreadId;

        var loading = library.RefreshAsync();
        await pending.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Same(loading, library.ReadCompletion);
        Assert.False(loading.IsCompleted);
        Assert.NotEqual(interactionThread, pending.Thread);
        Assert.True(library.IsRefreshing);
        Assert.False(library.HasLooked);
        Assert.False(library.IsEmpty);
        pending.Release();
        await loading;
        Assert.True(library.HasLooked);
        Assert.False(library.IsRefreshing);
        Assert.Equal(1025, library.Runs.Count);
    });

    [Fact]
    public void RefreshRetainsSelectionWhileLoadingAndHonoursANewerChoice() => OneThread.Run(async () =>
    {
        var (library, _, catalog) = Model();
        catalog.Runs.AddRange([Run("first"), Run("second")]);
        await library.RefreshAsync();
        library.Selected = library.Runs[0];
        using var pending = new PendingListing([Run("first"), Run("second")]);
        catalog.WhenListing = pending.List;

        var loading = library.RefreshAsync();
        await pending.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(Run("first").Path, library.Selected?.Path);
        Assert.Equal(2, library.Runs.Count);
        library.Selected = library.Runs[1];
        var previous = library.Selected;
        pending.Release();
        await loading;

        Assert.Equal(Run("second").Path, library.Selected?.Path);
        Assert.NotSame(previous, library.Selected);
        Assert.Contains(library.Selected, library.Runs);
    });

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void SupersededSuccessOrFailureCannotReplaceTheCurrentLibrary(bool differentLibrary, bool oldFailure) =>
        OneThread.Run(async () =>
        {
            var (library, location, catalog) = Model();
            using var pending = new PendingListing([Run("old")], oldFailure);
            catalog.WhenListing = pending.List;
            var older = library.RefreshAsync();
            await pending.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            if (differentLibrary) location.Choose(@"C:\responsive-other");
            var current = Run("current") with { Path = location.Path + @"\current" };
            catalog.WhenListing = (_, _) => Result<IReadOnlyList<RunListing>>.Success([current]);

            await library.RefreshAsync();
            library.Selected = Assert.Single(library.Runs);
            Assert.True(pending.Token.IsCancellationRequested);
            pending.Release();
            await older;

            Assert.Equal(current.Path, Assert.Single(library.Runs).Path);
            Assert.Equal(current.Path, library.Selected?.Path);
            Assert.True(library.HasLooked);
            Assert.Null(library.Problem);
            Assert.False(library.IsRefreshing);
        });

    [Fact]
    public void CancellationRejectsEvenACatalogThatReturnsAfterCancellationAndAllowsRetry() => OneThread.Run(async () =>
    {
        var (library, _, catalog) = Model();
        using var pending = new PendingListing();
        catalog.WhenListing = pending.List;
        var loading = library.RefreshAsync();
        await pending.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));

        library.CancelRefresh();
        Assert.True(pending.Token.IsCancellationRequested);
        pending.Release();
        await loading;

        Assert.Empty(library.Runs);
        Assert.False(library.HasLooked);
        Assert.False(library.IsEmpty);
        Assert.False(library.IsRefreshing);
        catalog.WhenListing = null;
        await library.RefreshAsync();
        Assert.True(library.IsEmpty);
    });

    [Fact]
    public void ChangingLibrariesRemovesThePreviousLibraryBeforeTheNewReadFinishes() => OneThread.Run(async () =>
    {
        var (library, location, catalog) = Model();
        catalog.Runs.Add(Run("previous"));
        await library.RefreshAsync();
        library.Selected = library.Runs[0];
        location.Choose(@"C:\responsive-other");
        using var pending = new PendingListing([]);
        catalog.WhenListing = pending.List;

        var loading = library.RefreshAsync();
        await pending.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Empty(library.Runs);
        Assert.Null(library.Selected);
        Assert.False(library.IsEmpty);
        pending.Release();
        await loading;
        Assert.True(library.IsEmpty);
    });

    [Fact]
    public void AnotherLibraryCanBeChosenWhileThePreviousDriveIsStillLoading() => OneThread.Run(async () =>
    {
        var (library, location, catalog) = Model();
        using var pending = new PendingListing([]);
        catalog.WhenListing = pending.List;
        var picker = new FakeFolderPicker { Answer = @"C:\responsive-slow" };
        var home = new HomeViewModel(location, picker, new FakeNewAuditDialog(), library);
        var choosing = home.ChooseLibraryCommand.ExecuteAsync(null);
        await pending.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try
        {
            Assert.True(home.ChooseLibraryCommand.CanExecute(null));
            picker.Answer = @"C:\responsive-other";
            catalog.WhenListing = (_, _) => Result<IReadOnlyList<RunListing>>.Success([]);
            await home.ChooseLibraryCommand.ExecuteAsync(null);
        }
        finally
        {
            pending.Release();
            await choosing;
        }
        Assert.Equal(@"C:\responsive-other", location.Path);
        Assert.True(library.IsEmpty);
        Assert.Null(library.Problem);
    });

    [Fact]
    public void AdoptionPreservesTheActualReadFailureRatherThanReportingAMissingRun() => OneThread.Run(async () =>
    {
        var (library, _, catalog) = Model();
        catalog.Fails = Failures.Any("Library disk is unavailable.");

        Assert.False(await library.AdoptAsync(Run("new").Path));

        Assert.Equal("Library disk is unavailable.", library.Problem);
        Assert.False(library.IsEmpty);
        Assert.Null(library.Selected);
    });

    [Fact]
    public void StorageExceptionsUseTheExistingProblemPresentationInsteadOfAnEmptyLibrary() => OneThread.Run(async () =>
    {
        var (library, _, catalog) = Model();
        catalog.WhenListing = (_, _) => throw new IOException("Storage disappeared during the read.");

        await library.RefreshAsync();

        Assert.Equal("Storage disappeared during the read.", library.Problem);
        Assert.False(library.IsEmpty);
        Assert.False(library.HasLooked);
        Assert.False(library.IsRefreshing);
    });

    [Fact]
    public void AnOlderBaselineFailureCannotReplaceTheNewLibrarysStatus() => OneThread.Run(async () =>
    {
        var (library, location, catalog) = Model();
        var run = Run("baseline") with { Scope = RunScope.Of("scope", [DomainCoverage.Read("contoso.com")]) };
        catalog.Runs.Add(run);
        await library.RefreshAsync();
        library.Selected = library.Runs[0];
        catalog.AnnotationFails = Failures.Any("The old library is read-only.");
        using var pending = new PendingListing([run]);
        catalog.WhenListing = pending.List;

        var marking = library.MarkAsBaselineAsync();
        await pending.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        location.Choose(@"C:\responsive-other");
        catalog.WhenListing = (_, _) => Result<IReadOnlyList<RunListing>>.Success([]);
        await library.RefreshAsync();
        pending.Release();
        await marking;

        Assert.Null(library.Problem);
        Assert.True(library.IsEmpty);
    });

    [Fact]
    public void DeletionWaitsForProtectedReadersToCloseBeforeRemovingAnyFile() => OneThread.Run(async () =>
    {
        var settings = new FakeSettingsStore { Stored = new(@"C:\responsive-library", null) };
        var location = new RunLibraryLocation(settings);
        location.Load();
        var catalog = new FakeRunCatalog();
        catalog.Runs.Add(Run("deleting"));
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var opener = new FakeRunOpener { WhenClosing = () => closed.Task };
        var library = new RunLibraryViewModel(location, catalog, new FakeConfirmation { Answer = true }, opener,
            new FakeDerivationLauncher(), new FakeJudgingLauncher());
        await library.RefreshAsync();
        library.Selected = library.Runs[0];

        var deleting = library.DeleteRunAsync();
        Assert.Equal(1, opener.CloseCalls);
        Assert.Null(catalog.Deleted);
        Assert.False(deleting.IsCompleted);
        closed.SetResult();
        await deleting;

        Assert.Equal(Run("deleting").Path, catalog.Deleted);
        Assert.True(library.IsEmpty);
    });

    [Fact]
    public void AFailedProtectionHandoffIsReportedAndCannotDeleteTheRun() => OneThread.Run(async () =>
    {
        var store = new FakeSettingsStore { Stored = new(@"C:\responsive-library", null) };
        var location = new RunLibraryLocation(store);
        location.Load();
        var catalog = new FakeRunCatalog();
        catalog.Runs.Add(Run("protected"));
        var opener = new FakeRunOpener { WhenClosing = () => Task.FromException(new IOException("The protected readers did not close.")) };
        var library = new RunLibraryViewModel(location, catalog, new FakeConfirmation { Answer = true }, opener,
            new FakeDerivationLauncher(), new FakeJudgingLauncher());
        await library.RefreshAsync();
        library.Selected = library.Runs[0];

        await library.DeleteRunAsync();

        Assert.Equal("The protected readers did not close.", library.Problem);
        Assert.Null(catalog.Deleted);
        Assert.Single(library.Runs);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SavedAndNewCompletedRunsBothOpenTheExistingDashboard(bool newlyCompleted) => OneThread.Run(async () =>
    {
        var (library, location, catalog) = Model();
        catalog.Runs.Add(Run("completed"));
        var shell = Shell(library, location);
        if (newlyCompleted)
            await shell.OpenCompletedRunAsync(Run("completed").Path);
        else
        {
            await library.RefreshAsync();
            library.Selected = library.Runs[0];
            shell.ShowOpenedRun();
        }

        Assert.Equal(ShellSection.Dashboard, shell.Section);
        Assert.Equal(Run("completed").Path, shell.Dashboard.BundlePath);
        Assert.Equal(Run("completed").Path, library.Selected?.Path);
        Assert.Same(shell.Dashboard, shell.Current);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ACompletedRunCannotPullTheOperatorBackAfterANewerNavigationOrSelection(bool changeSelection) =>
        OneThread.Run(async () =>
        {
            var (library, location, catalog) = Model();
            catalog.Runs.Add(Run("previous"));
            await library.RefreshAsync();
            using var pending = new PendingListing([Run("previous"), Run("completed")]);
            catalog.WhenListing = pending.List;
            var shell = Shell(library, location);

            var opening = shell.OpenCompletedRunAsync(Run("completed").Path);
            await pending.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            if (changeSelection) library.Selected = library.Runs[0];
            else shell.Show(ShellSection.Settings);
            pending.Release();
            await opening;

            Assert.NotEqual(ShellSection.Dashboard, shell.Section);
            if (changeSelection) Assert.Equal(Run("previous").Path, library.Selected?.Path);
        });

    private static (RunLibraryViewModel Library, RunLibraryLocation Location, FakeRunCatalog Catalog) Model()
    {
        var store = new FakeSettingsStore { Stored = new(@"C:\responsive-library", null) };
        var location = new RunLibraryLocation(store);
        location.Load();
        var catalog = new FakeRunCatalog();
        return (new(location, catalog, new FakeConfirmation(), new FakeRunOpener(),
            new FakeDerivationLauncher(), new FakeJudgingLauncher()), location, catalog);
    }

    private static ShellViewModel Shell(RunLibraryViewModel library, RunLibraryLocation location) =>
        new(new HomeViewModel(location, new FakeFolderPicker(), new FakeNewAuditDialog(), library),
            new AssetsViewModel(new FakeAssetSource()), new DashboardViewModel(new FakeAssetSource()),
            new SettingsViewModel(new DomainConcurrency(new FakeSettingsStore())), new RulesViewModel(new FakeAssetSource()));

    private static RunListing Run(string name) => new(name, @"C:\responsive-library\" + name, RunState.Sealed,
        null, new(DateTimeOffset.UnixEpoch, true), RunAnnotation.None, null, new(true, true));

    private sealed class PendingListing : IDisposable
    {
        private readonly IReadOnlyList<RunListing> _runs;
        private readonly bool _fail;
        private readonly ManualResetEventSlim _released = new();
        internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal CancellationToken Token { get; private set; }
        internal int Thread { get; private set; }

        internal PendingListing() : this(Enumerable.Range(0, 1025).Select(index => Run("run-" + index)).ToArray()) { }
        internal PendingListing(IReadOnlyList<RunListing> runs, bool fail = false) { _runs = runs; _fail = fail; }
        internal Result<IReadOnlyList<RunListing>> List(string root, CancellationToken token)
        {
            Token = token;
            Thread = Environment.CurrentManagedThreadId;
            Started.TrySetResult();
            if (!_released.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("The library did not yield to the interaction thread.");
            return _fail ? Result<IReadOnlyList<RunListing>>.Failure(Failures.Any("Superseded failure."))
                : Result<IReadOnlyList<RunListing>>.Success(_runs);
        }
        internal void Release() => _released.Set();
        public void Dispose() { _released.Set(); _released.Dispose(); }
    }
}
