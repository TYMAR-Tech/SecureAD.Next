using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Xml.Linq;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Shell;

[CollectionDefinition("Finding window resources", DisableParallelization = true)]
public sealed class FindingWindowResourcesCollection { }

[Collection("Finding window resources")]
public sealed class FindingWindowOwnershipTests(ITestOutputHelper output)
{
    private const string ChildHost = "SECUREAD_NATIVE_FINDING_WINDOW_TEST";
    private const string NativeWitness = "Native finding-window assertions completed at widths 900 and 1300.";

    [Fact]
    public async Task NativeFindingWindowShowsTheSelectedAnswerAndClosesWithItsOwner()
    {
        // Application.Shutdown is process-wide, so the native application belongs to a child test host.
        if (Environment.GetEnvironmentVariable(ChildHost) == "1")
        {
            ShowNativeWindow();
            return;
        }

        VerifyParentResources();
        await VerifyIsolatedChildAsync();
        VerifyParentResources();
    }

    private async Task VerifyIsolatedChildAsync()
    {
        var temporary = Path.Combine(Path.GetTempPath(), "fw-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(temporary);
        var assembly = typeof(FindingWindowOwnershipTests).Assembly.Location;
        var test = typeof(FindingWindowOwnershipTests).FullName + "."
            + nameof(NativeFindingWindowShowsTheSelectedAnswerAndClosesWithItsOwner);
        var start = new ProcessStartInfo("dotnet")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        start.ArgumentList.Add("vstest");
        start.ArgumentList.Add(assembly);
        start.ArgumentList.Add("/TestCaseFilter:FullyQualifiedName=" + test);
        start.ArgumentList.Add("/Logger:trx;LogFileName=native-window.trx");
        start.ArgumentList.Add("/ResultsDirectory:" + temporary);
        start.ArgumentList.Add("/Platform:x64");
        start.Environment[ChildHost] = "1";
        start.Environment["TEMP"] = temporary;
        start.Environment["TMP"] = temporary;
        output.WriteLine($"Native window child: assembly={assembly}; results={temporary}; test={test}");

        using var process = Process.Start(start);
        Assert.NotNull(process);
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        var finished = process.WaitForExit(60_000);
        if (!finished)
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
        }
        output.WriteLine(await standardOutput);
        output.WriteLine(await standardError);
        Assert.True(finished, "The isolated native-window check exceeded sixty seconds.");
        Assert.Equal(0, process.ExitCode);

        var resultPath = Path.Combine(temporary, "native-window.trx");
        Assert.True(File.Exists(resultPath), "The child produced no test result.");
        var result = XDocument.Load(resultPath);
        Assert.NotNull(result.Root);
        var ns = result.Root.Name.Namespace;
        var counters = Assert.Single(result.Descendants(ns + "Counters"));
        Assert.Equal("1", (string?)counters.Attribute("executed"));
        Assert.Equal("1", (string?)counters.Attribute("passed"));
        Assert.Equal("0", (string?)counters.Attribute("failed"));
        var observed = Assert.Single(result.Descendants(ns + "UnitTestResult"));
        Assert.Equal(test, (string?)observed.Attribute("testName"));
        Assert.Equal("Passed", (string?)observed.Attribute("outcome"));
        var capturedOutput = Assert.Single(observed.Descendants(ns + "StdOut"));
        Assert.Contains(NativeWitness, capturedOutput.Value, StringComparison.Ordinal);
    }

    private static void VerifyParentResources() => ObjectNavigationViewTests.OnSta(() =>
    {
        Assert.Null(Application.Current);
        var source = new FakeAssetSource
        {
            FindingsPage = new([ObjectFindingsPagingTests.Finding(1)], null, 1),
        };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\native-finding-resources", false);
        Assert.Single(model.Findings);
        FrameworkElement? view = null;
        var error = Record.Exception(() => view = FindingsViewTests.View(model));
        Assert.Null(error);
        var loaded = Assert.IsAssignableFrom<FrameworkElement>(view);
        Assert.True(loaded.ActualWidth > 0 && loaded.ActualHeight > 0);
        Assert.NotEmpty(loaded.Resources.MergedDictionaries);
    });

    private void ShowNativeWindow() => ObjectNavigationViewTests.OnSta(() =>
    {
        var application = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        try
        {
            XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
            var root = Architecture.RebuildTree.Root();
            var sources = XDocument.Load(Path.Combine(root, "src", "SecureAD.Shell", "App.xaml"))
                .Descendants(wpf + "ResourceDictionary").Attributes("Source").Select(attribute => attribute.Value);
            foreach (var source in sources)
                application.Resources.MergedDictionaries.Add(new ResourceDictionary
                {
                    Source = new Uri(source.StartsWith("pack:", StringComparison.Ordinal)
                        ? source : "pack://application:,,,/SecureAD;component/" + source, UriKind.Absolute),
                });
            foreach (var width in new[] { 900, 1300 })
            {
                var source = new FakeAssetSource
                {
                    FindingsPage = new([ObjectFindingsPagingTests.Finding(1)], null, 1),
                };
                var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
                model.Show(@"C:\offline-fixture\native-finding", false);
                var selected = Assert.Single(model.Findings);
                model.SelectedFinding = selected;
                var owner = new Window
                {
                    Width = width, Height = 650, Left = -20000, Top = -20000,
                    ShowActivated = false, ShowInTaskbar = false,
                };
                using var presenter = new FindingDetailPresenter(model, owner);
                try
                {
                    owner.Show();
                    model.OpenFinding(selected);
                    var window = Assert.IsType<FindingDetailWindow>(Assert.Single(owner.OwnedWindows.Cast<Window>()));
                    window.ShowInTaskbar = false;
                    window.Width = width;
                    window.UpdateLayout();
                    window.Dispatcher.Invoke(() => { }, DispatcherPriority.Render);
                    Assert.True(window.IsVisible);
                    Assert.Same(model, window.DataContext);
                    var view = Assert.IsType<FindingDetailView>(window.Content);
                    var observed = Assert.Single(ObjectNavigationViewTests.Descendants<TextBlock>(view),
                        text => text.Text == "Do not require Kerberos preauthentication: Enabled");
                    Assert.True(observed.IsVisible && observed.ActualWidth > 0 && observed.ActualHeight > 0);
                    Assert.DoesNotContain(ObjectNavigationViewTests.Descendants<TextBox>(view),
                        text => text.IsVisible && text.Text == selected.Detail);
                    window.Close();
                    Assert.False(model.HasFindingPresentation);
                    Assert.Same(selected, model.SelectedFinding);
                    model.OpenFinding(selected);
                    Assert.Single(owner.OwnedWindows.Cast<Window>());
                    owner.Close();
                    Assert.False(model.HasFindingPresentation);
                    Assert.Empty(owner.OwnedWindows.Cast<Window>());
                }
                finally
                {
                    owner.Close();
                    model.CloseFindingDetails();
                }
            }
            output.WriteLine(NativeWitness);
        }
        finally
        {
            application.Shutdown();
        }
    });
}
