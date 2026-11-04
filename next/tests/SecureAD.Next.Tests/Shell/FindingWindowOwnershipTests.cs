using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Xml.Linq;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

[CollectionDefinition("Finding window resources", DisableParallelization = true)]
public sealed class FindingWindowResourcesCollection { }

[Collection("Finding window resources")]
public sealed class FindingWindowOwnershipTests
{
    [Fact]
    public void NativeFindingWindowShowsTheSelectedAnswerAndClosesWithItsOwner() => ObjectNavigationViewTests.OnSta(() =>
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
        }
        finally
        {
            application.Shutdown();
        }
    });
}
