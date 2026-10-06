using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using SecureAD.Evidence;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class CoverageFooterViewTests
{
    [Theory]
    [InlineData(1280, 800, false)]
    [InlineData(1280, 800, true)]
    [InlineData(900, 470, true)]
    public void CoverageSharesThePagerFooterAndReclaimsTheTopStrip(int width, int height, bool incomplete) => OnSta(() =>
    {
        var (model, source) = Model(incomplete);
        var view = View(model);
        var window = WindowFor(view, width, height);
        window.Show();
        try
        {
            Layout(view, width, height);
            var footer = Assert.IsType<Grid>(view.FindName("AssetsFooter"));
            var summary = Assert.IsType<WrapPanel>(view.FindName("CaptureCoverageSummary"));
            var action = CoverageAction(view, model);
            var previous = Assert.Single(Descendants<Button>(view), button => ReferenceEquals(button.Command, model.PreviousPageCommand));
            var next = Assert.Single(Descendants<Button>(view), button => ReferenceEquals(button.Command, model.NextPageCommand));
            var objects = Assert.Single(Descendants<DataGrid>(view), grid => ReferenceEquals(grid.ItemsSource, model.Objects));
            var tree = Assert.Single(Descendants<TreeView>(view));
            var navigation = Assert.IsType<Border>(Assert.IsType<Grid>(tree.Parent).Parent);
            var padding = Assert.IsType<Thickness>(view.FindResource("ScreenPadding"));
            Assert.Equal(padding.Top, At(navigation, view).Y, 3);
            Assert.True(At(objects, view).Y < 60);
            Assert.True(At(action, view).Y >= At(objects, view).Y + objects.ActualHeight);
            Assert.Equal(At(footer, view).X + footer.ActualWidth, At(summary, view).X + summary.ActualWidth, 3);
            Assert.True(At(action, view).X + action.ActualWidth <= At(footer, view).X + footer.ActualWidth + .1);
            Assert.True(objects.ActualHeight >= 100);
            var warning = Assert.Single(Descendants<TextBlock>(summary), text => text.Text == ObjectNavigationText.CaptureIncomplete);
            Assert.Equal(incomplete, warning.IsVisible);

            var columns = Assert.Single(Descendants<FieldGrid>(footer));
            var pagerSlot = LayoutInformation.GetLayoutSlot((FrameworkElement)columns.Children[0]);
            var coverageSlot = LayoutInformation.GetLayoutSlot((FrameworkElement)columns.Children[1]);
            if (width >= 1200)
            {
                Assert.Equal(pagerSlot.Y, coverageSlot.Y, 3);
                Assert.True(At(action, view).X > At(next, view).X + next.ActualWidth);
            }
            else
                Assert.True(coverageSlot.Y >= pagerSlot.Bottom);

            Invoke(next);
            Layout(view, width, height);
            Assert.Equal(2, model.PageNumber);
            Invoke(previous);
            Layout(view, width, height);
            Assert.Equal(1, model.PageNumber);
            Assert.True(source.ObjectListings >= 3);
        }
        finally { window.Close(); }
    });

    [Fact]
    public void CoverageDetailsOpenAboveTheFooterAndStayAvailableAcrossAssetsViews() => OnSta(() =>
    {
        var (model, source) = Model(incomplete: true);
        source.Tree = source.Tree with { Gaps = [
            .. Enumerable.Range(0, 20).Select(index => new TreeGap(
                $"missing-{index}.example", TreeGapReason.DomainNotFullyRead, "The domain could not be read.")),
            new("DC=DomainDnsZones,DC=contoso,DC=com", TreeGapReason.PartitionNotRead, "Outside product scope."),
        ] };
        model.Read();
        var view = View(model, includeObject: true);
        var window = WindowFor(view, 1280, 800);
        window.Show();
        try
        {
            Layout(view, 1280, 800);
            var action = CoverageAction(view, model);
            var closedY = At(action, view).Y;
            Invoke(action);
            Layout(view, 1280, 800);
            Assert.True(model.ShowsCaptureCoverageDetails);
            Assert.Equal(closedY, At(action, view).Y, 3);
            var scroll = Assert.Single(Descendants<ScrollViewer>(view), item => item.Content is StackPanel panel &&
                Descendants<TextBlock>(panel).Any(text => text.Text == ObjectNavigationText.CoverageBoundary));
            Assert.True(scroll.IsVisible && scroll.ExtentHeight > scroll.ViewportHeight);
            Assert.True(At(scroll, view).Y + scroll.ActualHeight <= At(action, view).Y);
            Assert.Equal(ScrollBarVisibility.Disabled, scroll.HorizontalScrollBarVisibility);
            scroll.ScrollToEnd();
            Layout(view, 1280, 800);
            Assert.True(scroll.VerticalOffset > 0);
            Assert.Contains(Descendants<TextBlock>(scroll), text => text.Text == ObjectNavigationText.ScopeNotes && text.IsVisible);
            Assert.Contains(Descendants<TextBlock>(scroll), text => text.Text == ObjectNavigationText.RunGaps);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == ObjectNavigationText.CaptureIncomplete && text.IsVisible);
            Invoke(action);
            Layout(view, 1280, 800);
            Assert.False(scroll.IsVisible);
            foreach (var pane in Enum.GetValues<AssetsPane>())
            {
                model.Pane = pane;
                Layout(view, 1280, 800);
                Assert.True(action.IsVisible && action.IsEnabled);
                Assert.Contains(Descendants<TextBlock>(view), text => text.Text == ObjectNavigationText.CaptureIncomplete && text.IsVisible);
            }
            model.Pane = AssetsPane.Objects;
            source.Attributes = FakeAssetSource.CapturedObject("DC=contoso,DC=com", "user");
            model.OpenObject(model.Objects[0]);
            Layout(view, 1280, 800);
            Assert.True(model.HasOpenObject && action.IsVisible);
            Assert.All(Descendants<Button>(view).Where(button => ReferenceEquals(button.Command, model.NextPageCommand)
                || ReferenceEquals(button.Command, model.PreviousPageCommand)), button => Assert.False(button.IsVisible));
            Invoke(action);
            Layout(view, 1280, 800);
            Assert.True(model.ShowsCaptureCoverageDetails && scroll.IsVisible);
        }
        finally { window.Close(); }
    });

    private static (AssetsViewModel, FakeAssetSource) Model(bool incomplete)
    {
        var (model, source) = ObjectNavigationTests.Model();
        source.Page = new([new("DC=contoso,DC=com", "contoso", null, "domainDNS", null)], 201, true, null);
        if (incomplete)
            source.Tree = source.Tree with { Gaps = [new("missing.example", TreeGapReason.DomainNotFullyRead, "Could not read this domain.")] };
        model.Read();
        return (model, source);
    }

    private static Window WindowFor(UserControl view, int width, int height) => new()
    {
        Content = view, Width = width, Height = height, WindowStyle = WindowStyle.None,
        ShowInTaskbar = false, Left = -10000, Top = -10000,
    };

    private static Button CoverageAction(DependencyObject view, AssetsViewModel model) =>
        Assert.Single(Descendants<Button>(view), button => ReferenceEquals(button.Command, model.ToggleCaptureCoverageCommand));

    private static Point At(FrameworkElement element, Visual ancestor) => element.TransformToAncestor(ancestor).Transform(new Point());

    private static void Invoke(Button button) =>
        ((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)!).Invoke();
}
