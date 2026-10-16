using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Measure;
using SecureAD.Shell;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;
using SecureAD.Next.Tests.Shell;
using Xunit;
using Xunit.Sdk;

namespace SecureAD.Next.Tests.Measurements;

/// <summary>Fresh-process control of the real application composition root and compiled ShellWindow.</summary>
public static class ApplicationStartupMeasurement
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };
    private static readonly int[] Widths = [900, 1300];

    public static int Run(string[] args, long hostEntry)
    {
        if (args.Length != 3)
            throw new ArgumentException("CASE_JSON NEW_OUTPUT BUILD_RECORD are required; no measurement starts by default.");
        var settings = JsonSerializer.Deserialize<StartupCase>(File.ReadAllText(args[0]))
            ?? throw new InvalidDataException("The startup case is empty.");
        var build = JsonSerializer.Deserialize<EnterpriseBuildRecord>(File.ReadAllText(args[2]))
            ?? throw new InvalidDataException("The startup build record is empty.");
        EnterpriseBaseline.VerifyBuild(build);
        Assert.Contains(settings.Width, Widths);
        Assert.InRange(settings.ExpectedRuns, 0, 1);
        Assert.False(settings.LibraryPath.StartsWith(@"\\", StringComparison.Ordinal));
        var output = EnterpriseBaseline.CreateOutput(args[1]);
        var store = new ObservedSettingsStore(Path.Combine(output, "isolated-settings.json"));
        Assert.True(store.Write(new(settings.LibraryPath, null)).IsSuccess);
        using var stopping = new CancellationTokenSource();
        using var observation = new EnterpriseBaselineObservation(output, build.PhysicalMemoryBytes, stopping);
        using var catalog = new FirstPaintCatalog();
        var capture = new FakeCaptureLauncher();
        if (settings.NewRunTemplate is { } template)
        {
            Assert.False(template.StartsWith(@"\\", StringComparison.Ordinal));
            var destination = Path.Combine(settings.LibraryPath, "offline-completed-run");
            capture.Outcome = new(true, destination);
            capture.WhenCapturing = () => CopyCapturedControl(template, destination);
        }
        var controller = new StartupControl(settings, output, build, observation, hostEntry, store, catalog, capture);
        var app = new App(controller.Settings, controller.Reached, controller.Prepared, catalog, capture);
        app.DispatcherUnhandledException += (_, error) =>
        {
            File.WriteAllText(Path.Combine(output, "failure.txt"), error.Exception.ToString());
            Console.Error.WriteLine(error.Exception);
            error.Handled = true;
            app.Shutdown(1);
        };
        app.InitializeComponent();
        using var watchdog = new Timer(_ => app.Dispatcher.BeginInvoke(() =>
        {
            File.WriteAllText(Path.Combine(output, "failure.txt"), "The application control exceeded its 60-second watchdog; no latency acceptance is implied.");
            app.Shutdown(1);
        }), null, TimeSpan.FromSeconds(60), Timeout.InfiniteTimeSpan);
        return app.Run();
    }

    internal sealed record StartupCase(string LibraryPath, int ExpectedRuns, bool Unavailable,
        bool OpenSavedRun, int Width, int Height)
    {
        public string? NewRunTemplate { get; init; }
    }
    internal sealed record StartupMark(AppStartupPoint Point, double ElapsedMs);

    internal static void RequireCompleteMarks(IReadOnlyList<StartupMark> marks)
    {
        foreach (var point in Enum.GetValues<AppStartupPoint>())
            if (marks.Count(mark => mark.Point == point) != 1)
                throw new InvalidDataException("Startup observation is missing or duplicates " + point + ".");
    }

    private sealed class StartupControl(StartupCase settings, string output, EnterpriseBuildRecord build,
        EnterpriseBaselineObservation observation, long hostEntry, ObservedSettingsStore store,
        FirstPaintCatalog catalog, FakeCaptureLauncher capture)
    {
        private readonly List<StartupMark> _marks = [];
        private readonly List<WindowResult> _results = [];
        private bool _driving;
        private int _settingsFactories;
        private readonly TaskCompletionSource _libraryReady = new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal ObservedSettingsStore Settings()
        {
            _settingsFactories++;
            return store;
        }

        internal void Reached(AppStartupPoint point)
        {
            _marks.Add(new(point, Stopwatch.GetElapsedTime(hostEntry).TotalMilliseconds));
            if (point == AppStartupPoint.LibraryRefreshCompleted) _libraryReady.TrySetResult();
        }

        internal void Prepared(ShellWindow window, ShellViewModel shell)
        {
            window.WindowState = WindowState.Normal;
            window.Width = settings.Width;
            window.Height = settings.Height;
            window.Left = -10000;
            window.Top = -10000;
            window.ShowActivated = false;
            window.ShowInTaskbar = false;
            window.ContentRendered += async (_, _) =>
            {
                if (_driving) return;
                _driving = true;
                var firstPaint = Stopwatch.GetElapsedTime(hostEntry).TotalMilliseconds;
                try
                {
                    await Drive(window, shell, firstPaint);
                    Application.Current.Shutdown(0);
                }
                catch (Exception error) when (error is XunitException or IOException or InvalidOperationException
                    or ArgumentException or OperationCanceledException)
                {
                    File.WriteAllText(Path.Combine(output, "failure.txt"), error.ToString());
                    Console.Error.WriteLine(error);
                    Application.Current.Shutdown(1);
                }
            };
        }

        private async Task Drive(ShellWindow window, ShellViewModel shell, double firstPaint)
        {
            Assert.True(shell.IsHome);
            Assert.True(shell.Library.IsRefreshing);
            Assert.False(shell.Library.HasLooked);
            Assert.False(shell.Library.IsEmpty);
            Assert.Empty(shell.Library.Runs);
            Draw(window);
            catalog.Release();
            await _libraryReady.Task;
            await shell.Library.ReadCompletion;
            RequireCompleteMarks(_marks);
            Assert.True(_marks.Single(mark => mark.Point == AppStartupPoint.WindowShown).ElapsedMs
                <= _marks.Single(mark => mark.Point == AppStartupPoint.LibraryRefreshStarting).ElapsedMs);
            Assert.True(firstPaint < _marks.Single(mark => mark.Point == AppStartupPoint.LibraryRefreshCompleted).ElapsedMs);
            await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ContextIdle);
            Assert.True(shell.IsHome);
            Assert.Equal(settings.ExpectedRuns, shell.Library.Runs.Count);
            if (settings.Unavailable)
            {
                Assert.False(shell.Library.HasLooked);
                Assert.True(shell.Library.HasProblem);
                RequireVisibleText(window, shell.Library.Problem!);
            }
            else
            {
                Assert.True(shell.Library.HasLooked);
                Assert.False(shell.Library.HasProblem);
                if (settings.ExpectedRuns == 0)
                {
                    Assert.True(shell.Library.IsEmpty);
                    RequireVisibleText(window, "This run library holds no runs yet.");
                }
                else
                {
                    Assert.False(shell.Library.IsEmpty);
                    RequireVisibleText(window, Assert.Single(shell.Library.Runs).Name);
                }
            }
            Draw(window);
            _results.Add(new("Home", Stopwatch.GetElapsedTime(hostEntry).TotalMilliseconds,
                settings.ExpectedRuns, shell.Library.Problem));
            if (settings.NewRunTemplate is not null)
            {
                shell.Home.NewAuditCommand.Execute(null);
                var audit = Assert.IsType<NewAuditViewModel>(shell.Audit);
                await audit.OpenCommand.ExecutionTask!;
                await audit.ReviewAsync();
                await audit.StartAsync();
                Assert.True(capture.WasRun);
                Assert.True(audit.HasFinished);
                var path = Assert.IsType<string>(audit.BundleDirectory);
                Assert.True(AnalysisStoreLifecycle.ResolveRoot(path, AnalysisStoreKind.Judgement).IsSuccess);
                await OpenDashboard("new-run", window, shell, path, audit.LeaveAsync);
            }
            else Assert.False(capture.WasRun);
            if (settings.OpenSavedRun || settings.NewRunTemplate is not null)
            {
                var run = Assert.Single(shell.Library.Runs);
                Assert.True(run.FinishedCleanly);
                Assert.True(run.HasResults);
                if (settings.OpenSavedRun)
                {
                    shell.Library.Selected = run;
                    await Open("saved-run", window, shell, run.Path);
                }
                var home = Stopwatch.GetTimestamp();
                shell.Show(ShellSection.Home);
                await shell.Library.ReadCompletion;
                await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ContextIdle);
                Assert.True(shell.Library.HasLooked);
                Assert.Equal(run.Path, shell.Library.Selected?.Path);
                RequireVisibleText(window, run.Name);
                Draw(window);
                _results.Add(new("Home-return", Stopwatch.GetElapsedTime(home).TotalMilliseconds, 1, null));
                await Open("saved-run-reopen", window, shell, run.Path);
            }
            EnterpriseBaseline.VerifyBuild(build);
            Assert.Equal(1, _settingsFactories);
            Assert.True(store.Reads >= 3);
            observation.Dispose();
            File.WriteAllText(Path.Combine(output, "startup-control-result.json"), JsonSerializer.Serialize(new
            {
                State = "RealApplicationStartupControlCompleted", Case = settings,
                StartupMarks = _marks, FirstContentRenderedMs = firstPaint, Results = _results,
                TimingOrigin = "Fresh measurement-host entry before real App.InitializeComponent and App.Run; native product-executable loader cost not measured",
                ActualCompositionRoot = typeof(App).Assembly.Location,
                ActualShellWindow = typeof(ShellWindow).FullName,
                IsolatedSettingsPath = store.Path, SettingsFactoryCalls = _settingsFactories,
                SettingsReads = store.Reads, SettingsWrites = store.Writes,
                ShellSha256 = BundleSealing.HashFile(typeof(App).Assembly.Location),
                InformationalVersion = typeof(App).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
                Build = build, Observation = observation.Stages, VerificationAttempts = observation.Verifications,
                ResourceSamples = observation.ResourceSamples,
                UiWordsOrLayoutChanged = false, FreshProcess = true, DiskCacheCold = false,
                LibraryHeldUntilFirstPaint = true,
                EnterpriseBaselineComplete = false, WholeOperatorJourneyMeasured = false,
                NewRunHandoffMeasured = settings.NewRunTemplate is not null, ResponseBudgetsEstablished = false,
                CaptureBoundary = "Synthetic capture seam only; actual composed derivation, judging, completion and viewing; no live directory",
            }, Json));
        }

        private Task Open(string name, ShellWindow window, ShellViewModel shell, string path) =>
            OpenDashboard(name, window, shell, path, () => shell.Library.OpenRunCommand.ExecuteAsync(null));

        private async Task OpenDashboard(string name, ShellWindow window, ShellViewModel shell, string path, Func<Task> open)
        {
            await observation.MeasureAsync(name, async () =>
            {
                var start = Stopwatch.GetTimestamp();
                await open();
                Assert.True(shell.IsDashboard);
                await WaitFor(() => !shell.Dashboard.IsLoading && (shell.Dashboard.HasRun || shell.Dashboard.HasRefusal),
                    observation.Token, shell.Dashboard);
                await shell.Dashboard.ReadCompletion;
                Assert.Null(shell.Dashboard.Refusal);
                Assert.Equal(path, shell.Dashboard.BundlePath);
                Assert.Equal(path, shell.Library.Selected?.Path);
                Assert.Equal("159", shell.Dashboard.TotalComputers);
                await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ContextIdle);
                var value = Descendants<TextBlock>(window).Single(text =>
                    System.Windows.Data.BindingOperations.GetBinding(text, TextBlock.TextProperty)?.Path.Path == "TotalComputers");
                Assert.Equal("159", value.Text);
                RequireVisible(value);
                Draw(window);
                _results.Add(new(name, Stopwatch.GetElapsedTime(start).TotalMilliseconds, 159, null));
                return true;
            });
        }
    }

    private static async Task WaitFor(Func<bool> condition, CancellationToken token,
        params INotifyPropertyChanged[] models)
    {
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        PropertyChangedEventHandler changed = (_, _) => { if (condition()) ready.TrySetResult(); };
        foreach (var model in models) model.PropertyChanged += changed;
        using var stopping = token.Register(() => ready.TrySetCanceled(token));
        try
        {
            if (condition()) ready.TrySetResult();
            await ready.Task;
        }
        finally { foreach (var model in models) model.PropertyChanged -= changed; }
    }

    private static void RequireVisibleText(DependencyObject root, string expected)
    {
        var text = Descendants<TextBlock>(root).FirstOrDefault(value => value.Text == expected && value.IsVisible);
        if (text is not null) { RequireVisible(text); return; }
        var box = Descendants<TextBox>(root).First(value => value.Text == expected && value.IsVisible);
        RequireVisible(box);
    }

    private static void RequireVisible(FrameworkElement element)
    {
        Assert.True(element.IsVisible);
        Assert.True(element.ActualHeight > 0 && element.ActualWidth > 0);
        for (DependencyObject? parent = element; parent is not null; parent = VisualTreeHelper.GetParent(parent))
            if (parent is UIElement visual) Assert.True(visual.Opacity > 0);
    }

    private static void Draw(Window window)
    {
        window.UpdateLayout();
        var width = checked((int)Math.Ceiling(window.ActualWidth));
        var height = checked((int)Math.Ceiling(window.ActualHeight));
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(window);
        var pixels = new byte[width * height * 4];
        bitmap.CopyPixels(pixels, width * 4, 0);
        Assert.Contains(pixels, value => value != 0);
    }

    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T value) yield return value;
            foreach (var descendant in Descendants<T>(child)) yield return descendant;
        }
    }

    private sealed record WindowResult(string Journey, double CompleteDrawingMs, int ObservedCount, string? Refusal);

    private static void CopyCapturedControl(string template, string destination)
    {
        if (Directory.Exists(destination)) throw new IOException("The offline capture destination already exists.");
        var captured = AnalysisStoreLifecycle.ResolveCapture(template);
        if (!captured.IsSuccess) throw new InvalidDataException(captured.Error.Description);
        Directory.CreateDirectory(destination);
        foreach (var segment in captured.Value.Segments)
        {
            File.Copy(Path.Combine(template, segment.FileName), Path.Combine(destination, segment.FileName));
            File.Copy(Path.Combine(template, segment.FileName + ".seal"), Path.Combine(destination, segment.FileName + ".seal"));
        }
        File.Copy(BundleLayout.CaptureManifestPath(template), BundleLayout.CaptureManifestPath(destination));
    }

    private sealed class FirstPaintCatalog : IRunCatalog, IDisposable
    {
        private readonly ManualResetEventSlim _painted = new();
        private readonly RunCatalog _catalog = new();
        public void Release() => _painted.Set();
        public void Dispose() => _painted.Dispose();
        public Result<IReadOnlyList<RunListing>> List(string root, CancellationToken token)
        {
            if (!_painted.Wait(TimeSpan.FromSeconds(10), token))
                throw new TimeoutException("Home did not draw while the library read was pending.");
            return _catalog.List(root, token);
        }
        public Result<RunAnnotation> Annotate(string path, RunAnnotation annotation) => _catalog.Annotate(path, annotation);
        public Result<string> Delete(string path) => _catalog.Delete(path);
        public Result<string> DiscardJudgement(string path) => _catalog.DiscardJudgement(path);
    }

    private sealed class ObservedSettingsStore(string path) : IShellSettingsStore
    {
        private readonly JsonShellSettingsStore _store = new(path);
        internal string Path => path;
        internal int Reads { get; private set; }
        internal int Writes { get; private set; }
        public SecureAD.Kernel.Result<ShellSettings> Read() { Reads++; return _store.Read(); }
        public SecureAD.Kernel.Result<bool> Write(ShellSettings settings) { Writes++; return _store.Write(settings); }
    }
}
