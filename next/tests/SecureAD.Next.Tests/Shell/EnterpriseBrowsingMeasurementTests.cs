using System.Collections;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Measure;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Shell;

public sealed class EnterpriseBrowsingMeasurementTests(
    EnterpriseBrowsingMeasurementTests.Workload workload, ITestOutputHelper output)
    : IClassFixture<EnterpriseBrowsingMeasurementTests.Workload>
{
    private static readonly string[] Modes = ["first-protected-open", "warm", "close-reopen"];
    private const int Height = 700;
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    [Theory]
    [InlineData(900)]
    [InlineData(1300)]
    public void OrdinaryViewsRecordCompleteDrawingAndExplicitReturnFailures(int width) =>
        OnDispatcher(async () =>
        {
            var directory = EnterpriseBaseline.CreateOutput(Path.Combine(Path.GetTempPath(),
                "uv-" + width + "-" + Guid.NewGuid().ToString("N")[..8]));
            output.WriteLine("Retained browsing-control records: " + directory);
            var run = Path.Combine(directory, "run");
            Directory.CreateDirectory(run);
            foreach (var file in workload.Files)
            {
                var destination = Path.Combine(run, file.Path);
                File.Copy(Path.Combine(workload.Directory, file.Path), destination);
                Assert.Equal(file.Sha256, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(destination))));
            }
            var captured = AnalysisStoreLifecycle.ResolveCapture(run);
            var derived = AnalysisStoreLifecycle.Resolve(run, AnalysisStoreKind.Derivation);
            var judged = AnalysisStoreLifecycle.Resolve(run, AnalysisStoreKind.Judgement);
            Assert.True(captured.IsSuccess, captured.Error?.Description);
            Assert.True(derived.IsSuccess, derived.Error?.Description);
            Assert.True(judged.IsSuccess, judged.Error?.Description);
            Save(directory, "provenance.json", new
            {
                SourceTree = Architecture.RebuildTree.Root(), InputFiles = workload.Files,
                Width = width, Height, Dpi = 96,
                Culture = CultureInfo.CurrentCulture.Name,
                CaptureGeneration = captured.Value.GenerationId,
                DerivationGeneration = derived.Value.GenerationId,
                JudgementGeneration = judged.Value.GenerationId,
                TestAssembly = typeof(EnterpriseBrowsingMeasurementTests).Assembly.Location,
                TestAssemblySha256 = BundleSealing.HashFile(typeof(EnterpriseBrowsingMeasurementTests).Assembly.Location),
                ShellAssemblySha256 = BundleSealing.HashFile(typeof(AssetsViewModel).Assembly.Location),
                InformationalVersion = typeof(AssetsViewModel).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
                Scope = "Offscreen production-view controls through real models and shared selected-run source; not ShellWindow or process startup",
                ViewConstruction = "Existing production-XAML render adapters; view reconstructed per visit",
                ObjectPresentation = "Separate owned offscreen window; ordinary parent view remains mounted",
                FreshProcess = false, DiskCacheCold = false, PhysicalDisplayChecked = false,
                EnterpriseBaselineComplete = false, ResponseBudgetsEstablished = false,
            });
            using var stopping = new CancellationTokenSource();
            using var observation = new EnterpriseBaselineObservation(directory,
                GC.GetGCMemoryInfo().TotalAvailableMemoryBytes, stopping);
            using var source = new BundleAssetSource();
            var assets = new AssetsViewModel(source);
            assets.Suspend();
            var dashboard = new DashboardViewModel(source);
            var rules = new RulesViewModel(source);
            var window = new Window
            {
                Width = width, Height = Height, WindowStyle = WindowStyle.None,
                ShowInTaskbar = false, ShowActivated = false, Left = -10000, Top = -10000,
            };
            var measurements = new List<ViewObservation>();
            var behaviourFailures = new List<BehaviourFailure>();
            window.Show();
            var popup = new Window
            {
                Owner = window, Width = width, Height = Height, WindowStyle = WindowStyle.None,
                ShowInTaskbar = false, ShowActivated = false, Left = -10000, Top = -10000,
            };
            try
            {
                foreach (var mode in Modes)
                {
                    assets.Suspend();
                    rules.Suspend();
                    dashboard.Clear();
                    if (mode == "close-reopen") source.CloseRun();
                    await Measure(mode, "Dashboard", async () =>
                    {
                        dashboard.Show(run);
                        await dashboard.ReadCompletion;
                        Assert.Null(dashboard.Refusal);
                        Assert.True(dashboard.HasRun);
                        Assert.Equal("159", dashboard.TotalComputers);
                        Assert.Equal("159", dashboard.TotalGroups);
                    }, () => DashboardRedesignTests.View(dashboard), view =>
                    {
                        var value = Assert.Single(ObjectNavigationViewTests.Descendants<TextBlock>(view),
                            text => BindingOperations.GetBinding(text, TextBlock.TextProperty)?.Path.Path == nameof(dashboard.TotalComputers));
                        Assert.Equal("159", value.Text);
                        RequireVisible(value, view);
                        return new Probe(dashboard.Domains.Count, 3, value.Text);
                    });
                    await Measure(mode, "Rules", async () =>
                    {
                        rules.Show(run);
                        await rules.ReadCompletion;
                        Assert.Null(rules.RulesRefusal);
                        Assert.Equal(32, rules.VisibleRuleRows.Count);
                    }, () => ProductionViewThemeTests.View("RulesView.xaml", rules),
                        view => GridProbe(view, rules.VisibleRuleRows, 32));
                    await Measure(mode, "Objects", async () =>
                    {
                        assets.Pane = AssetsPane.Objects;
                        assets.Show(run, false);
                        await assets.ReadCompletion;
                        assets.Selected = Assert.Single(assets.Roots,
                            node => node.DistinguishedName == EnterpriseControlWorkload.Domain(0));
                        await assets.ReadCompletion;
                        RequireAssets();
                    }, () => ObjectNavigationViewTests.View(assets), view => GridProbe(view, assets.Objects, assets.Total));
                    await Pane(mode, AssetsPane.Findings, () => FindingsViewTests.View(assets),
                        view => GridProbe(view, assets.Findings, null));
                    await Measure(mode, "Groups", async () =>
                    {
                        assets.Pane = AssetsPane.Groups;
                        assets.GroupsWholeCapture = true;
                        await assets.ReadCompletion;
                        RequireAssets();
                        Assert.Equal(159, assets.GroupTotal);
                    }, () => GroupsViewTests.View(assets), view => GridProbe(view, assets.Groups, assets.GroupTotal));

                    var group = Assert.Single(assets.Groups,
                        row => row.DistinguishedName == EnterpriseControlWorkload.Group(0, 3));
                    Assert.True(group.HasCycle);
                    assets.SelectedGroup = group;
                    var groupPage = assets.Groups.Select(row => row.DistinguishedName).ToArray();
                    await Measure(mode, "Group/object-findings", async () =>
                    {
                        assets.OpenGroupFindingsCommand.Execute(group);
                        await assets.ObjectReadCompletion;
                        Assert.Null(assets.ObjectRefusal);
                        Assert.NotNull(assets.Opened);
                        Assert.Null(assets.Opened.Refusal);
                        Assert.Equal(ObjectSectionCatalog.Findings, assets.Opened.SelectedKey);
                    }, () => ObjectNavigationViewTests.ObjectView(assets), ObjectProbe);
                    await Measure(mode, "Group/original-members", async () =>
                    {
                        assets.Opened!.Show(ObjectSectionCatalog.Membership);
                        await assets.Opened.ReadCompletion;
                        Assert.Null(assets.Opened.Refusal);
                        Assert.NotEmpty(Assert.IsType<GroupMembershipSectionViewModel>(assets.Opened.Content).Members);
                    }, () => ObjectNavigationViewTests.ObjectView(assets), ObjectProbe);
                    await Measure(mode, "Group/return", async () =>
                    {
                        popup.Hide();
                        popup.Content = null;
                        assets.CloseObject();
                        await assets.ReadCompletion;
                        RequireAssets();
                        var failure = AssessSelection(mode, JsonSerializer.Serialize(group.Value),
                            assets.SelectedGroup is { } selected ? JsonSerializer.Serialize(selected.Value) : "No selected group");
                        if (failure is not null)
                        {
                            behaviourFailures.Add(failure);
                            observation.Record("Group/return", AuditError.Create(ErrorCategory.Shell,
                                "ControlObservedGroupSelectionChange", ErrorSeverity.Degraded,
                                "The rendered group-return control did not retain the selected group.", run), []);
                        }
                        Assert.Equal(groupPage, assets.Groups.Select(row => row.DistinguishedName));
                    }, () => GroupsViewTests.View(assets), view => GridProbe(view, assets.Groups, assets.GroupTotal));

                    await Pane(mode, AssetsPane.Tier0,
                        () => ProductionViewThemeTests.View("Tier0OverviewView.xaml", assets),
                        view => GridProbe(view, assets.Tier0Objects, null));
                    await Pane(mode, AssetsPane.Laps,
                        () => ProductionViewThemeTests.View("LapsInventoryView.xaml", assets),
                        view => GridProbe(view, assets.LapsComputers, assets.LapsTotal));
                    await Delegations(mode, "direct", "S-1-5-11", false);
                    await Delegations(mode, "group-held", EnterpriseControlWorkload.DomainSid(0) + "-1100", true);
                }
                assets.Suspend();
                rules.Suspend();
                dashboard.Clear();
                source.CloseRun();
                observation.Dispose();
                Assert.Equal(36, measurements.Count);
                foreach (var file in workload.Files)
                    Assert.Equal(file.Sha256, BundleSealing.HashFile(Path.Combine(run, file.Path)).ToUpperInvariant());
                Save(directory, "view-control-result.json", new
                {
                    State = behaviourFailures.Count == 0 ? "OrdinaryViewControlsReadAndDrawn" : "CompletedWithObservedBehaviourFailures",
                    BehaviourChecksPassed = behaviourFailures.Count == 0, BehaviourFailures = behaviourFailures,
                    EnterpriseBaselineComplete = false,
                    WholeOperatorJourneyMeasured = false, ResponseBudgetsEstablished = false,
                    Width = width, Height, Modes, Measurements = measurements,
                    Stages = observation.Stages, VerificationAttempts = observation.Verifications,
                    ResourceSamples = observation.ResourceSamples,
                    Unmeasured = "Process startup/Home/new-run handoff, full ShellWindow layout, remaining requested proof/value families, off/on overhead and enterprise workload",
                });
            }
            finally
            {
                popup.Close();
                window.Close();
                assets.Suspend();
                rules.Suspend();
                dashboard.Clear();
            }

            async Task Measure(string mode, string surface, Func<Task> load,
                Func<FrameworkElement> createView, Func<FrameworkElement, Probe> inspect)
            {
                var result = await observation.MeasureAsync(mode + "/" + surface, async () =>
                {
                    var started = Stopwatch.GetTimestamp();
                    await load();
                    var dataReady = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                    var view = createView();
                    var host = surface is "Group/object-findings" or "Group/original-members" ? popup : window;
                    host.Content = view;
                    if (ReferenceEquals(host, popup)) popup.Show();
                    ObjectNavigationViewTests.Layout(view, width, Height);
                    var probe = inspect(view);
                    var bitmap = new RenderTargetBitmap(width, Height, 96, 96, PixelFormats.Pbgra32);
                    bitmap.Render(view);
                    var pixels = new byte[width * Height * 4];
                    bitmap.CopyPixels(pixels, width * 4, 0);
                    Assert.Contains(pixels, value => value != 0);
                    var drawn = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                    await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ContextIdle);
                    return new ViewObservation(mode, surface, dataReady, drawn,
                        Stopwatch.GetElapsedTime(started).TotalMilliseconds,
                        probe.LoadedRows, probe.AuthoritativeTotal, probe.VisiblePayload,
                        surface is "Dashboard" or "Rules" ? null : new(
                            assets.Selected?.DistinguishedName, assets.Scope.ToString(),
                            assets.GroupsWholeCapture, assets.Opened is null ? null : assets.SelectedGroup?.DistinguishedName,
                            assets.Opened?.SelectedKey, assets.SelectedDelegationPrincipal?.Principal.Sid,
                            assets.IncludeGroupHeldPermissions));
                });
                measurements.Add(result);
            }

            async Task Pane(string mode, AssetsPane pane, Func<FrameworkElement> createView,
                Func<FrameworkElement, Probe> inspect) => await Measure(mode, pane.ToString(), async () =>
            {
                assets.Pane = pane;
                await assets.ReadCompletion;
                RequireAssets();
            }, createView, inspect);

            async Task Delegations(string mode, string kind, string sid, bool groupHeld) =>
                await Measure(mode, "Delegations/" + kind, async () =>
                {
                    assets.Pane = AssetsPane.Delegations;
                    await assets.ReadCompletion;
                    assets.DelegationPrincipalSearch = sid;
                    Assert.True(assets.FindDelegationPrincipalCommand.CanExecute(null));
                    assets.FindDelegationPrincipalCommand.Execute(null);
                    await assets.ReadCompletion;
                    assets.IncludeGroupHeldPermissions = groupHeld;
                    Assert.True(assets.FindDelegationsCommand.CanExecute(null));
                    assets.FindDelegationsCommand.Execute(null);
                    await assets.ReadCompletion;
                    RequireAssets();
                    Assert.True(assets.HasDelegationAnswer);
                }, () => DelegationsViewTests.View(assets), view => GridProbe(view, assets.Delegations, null));

            void RequireAssets()
            {
                Assert.Null(assets.Refusal);
                Assert.Null(assets.ViewRefusal);
                Assert.False(assets.IsLoading);
            }

            Probe ObjectProbe(FrameworkElement view)
            {
                Assert.NotNull(assets.Opened);
                var heading = Assert.Single(ObjectNavigationViewTests.Descendants<TextBlock>(view),
                    text => text.Text == assets.Opened.Heading);
                RequireVisible(heading, view);
                var rows = assets.Opened.SelectedKey == ObjectSectionCatalog.Membership
                    ? (IEnumerable)Assert.IsType<GroupMembershipSectionViewModel>(assets.Opened.Content).Members
                    : Assert.IsType<FindingsSectionViewModel>(assets.Opened.Content).Findings;
                var expected = rows.Cast<object>().ToArray();
                Assert.NotEmpty(expected);
                var items = Assert.Single(ObjectNavigationViewTests.Descendants<ItemsControl>(view),
                    candidate => candidate.Items.Cast<object>().SequenceEqual(expected));
                return ItemsProbe(items, expected, view, null);
            }
        });

    [Theory]
    [InlineData("same", false)]
    [InlineData("different", true)]
    public void SelectionMismatchRemainsAnExplicitUnacceptedOutcome(string actual, bool expectedFailure)
    {
        var result = AssessSelection("control", "same", actual);
        Assert.Equal(expectedFailure, result is not null);
        if (expectedFailure)
        {
            Assert.NotNull(result);
            Assert.Equal("same", result.Expected);
            Assert.Equal(actual, result.Actual);
        }
    }

    private static BehaviourFailure? AssessSelection(string mode, string expected, string actual) =>
        string.Equals(expected, actual, StringComparison.Ordinal) ? null
            : new(mode, "Group selection retained after original membership and return", expected, actual);

    private static void OnDispatcher(Func<Task> body)
    {
        var scheduled = new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            var running = dispatcher.InvokeAsync(body).Task.Unwrap();
            scheduled.SetResult(running);
            _ = running.ContinueWith(_ => dispatcher.BeginInvokeShutdown(DispatcherPriority.Background),
                CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            Dispatcher.Run();
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "The browsing control did not complete its dispatcher work.");
        scheduled.Task.Unwrap().GetAwaiter().GetResult();
    }

    private static Probe GridProbe(FrameworkElement view, IEnumerable rows, int? total)
    {
        var expected = rows.Cast<object>().ToArray();
        Assert.NotEmpty(expected);
        var grid = Assert.Single(ObjectNavigationViewTests.Descendants<DataGrid>(view),
            candidate => candidate.Items.Cast<object>().SequenceEqual(expected));
        RequireVisible(grid, view);
        Assert.True(grid.ActualHeight >= 50);
        grid.ScrollIntoView(expected[0]);
        grid.UpdateLayout();
        return ItemsProbe(grid, expected, view, total);
    }

    private static Probe ItemsProbe(ItemsControl items, object[] expected, FrameworkElement view, int? total)
    {
        RequireVisible(items, view);
        var first = Assert.IsAssignableFrom<FrameworkElement>(items.ItemContainerGenerator.ContainerFromIndex(0));
        Assert.Same(expected[0], first.DataContext);
        RequireVisible(first, view);
        var payload = ObjectNavigationViewTests.Descendants<TextBlock>(first)
            .First(text => text.IsVisible && !string.IsNullOrWhiteSpace(text.Text));
        RequireVisible(payload, view);
        return new(expected.Length, total, payload.Text);
    }

    private static void RequireVisible(FrameworkElement element, FrameworkElement view)
    {
        Assert.True(element.IsVisible);
        Assert.True(element.ActualWidth > 0 && element.ActualHeight > 0);
        for (DependencyObject? ancestor = element; ancestor is not null; ancestor = VisualTreeHelper.GetParent(ancestor))
            if (ancestor is UIElement visual) Assert.True(visual.Opacity > 0);
        var bounds = element.TransformToAncestor(view).TransformBounds(new Rect(element.RenderSize));
        Assert.True(bounds.IntersectsWith(new Rect(0, 0, view.ActualWidth, view.ActualHeight)));
    }

    private static void Save(string directory, string name, object value) =>
        File.WriteAllText(Path.Combine(directory, name), JsonSerializer.Serialize(value, Json));

    private sealed record Probe(int LoadedRows, int? AuthoritativeTotal, string VisiblePayload);
    private sealed record BehaviourFailure(string Mode, string Check, string Expected, string Actual);
    private sealed record ViewObservation(string Mode, string Surface, double DataReadyMs,
        double CompleteControlDrawingMs, double DispatcherRoundTripMs, int LoadedRows,
        int? AuthoritativeTotal, string VisiblePayload, ViewQuestion? DirectoryQuestion);
    private sealed record ViewQuestion(string? Container, string Scope, bool GroupsWholeCapture,
        string? OpenedGroup, string? ObjectSection, string? DelegationSid, bool IncludeGroupHeldPermissions);

    public sealed class Workload
    {
        internal string Directory { get; }
        internal IReadOnlyList<EnterpriseProductFingerprint> Files { get; }

        public Workload()
        {
            Directory = EnterpriseBaseline.CreateOutput(Path.Combine(Path.GetTempPath(),
                "uf-" + Guid.NewGuid().ToString("N")[..8]));
            EnterpriseControlWorkload.Write(Directory, CancellationToken.None);
            var derived = Stage2aRun.Derive(Directory, ExpansionBudget.Bulk, EnterpriseControlWorkload.When,
                Stage2aRun.Unwatched, RunLog.Discarded, CancellationToken.None);
            Assert.True(derived.IsSuccess, derived.Error?.Description);
            var judged = JudgingRun.JudgeAudit(Directory, RuleCatalogue.All, JudgingRun.ProductionPathRequesterPolicy,
                EnterpriseControlWorkload.When, EnterpriseControlWorkload.When, JudgingRun.NobodyIsWatching,
                RunLog.Discarded, CancellationToken.None, null);
            Assert.True(judged.IsSuccess, judged.Error?.Description);
            Files = EnterpriseBaseline.FingerprintProducts(Directory);
        }
    }
}
