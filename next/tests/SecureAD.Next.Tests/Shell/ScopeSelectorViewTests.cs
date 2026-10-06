using System.Globalization;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media;
using SecureAD.Evidence;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class ScopeSelectorViewTests
{
    [Theory]
    [InlineData(270, 1)]
    [InlineData(360, 1)]
    [InlineData(270, 1.5)]
    [InlineData(360, 1.5)]
    public void ScopeSegmentsFitTheNavigationWidthWithoutClipping(int navigationWidth, double scale) => OnSta(() =>
    {
        var (model, _) = ObjectNavigationTests.Model();
        var view = View(model);
        view.LayoutTransform = new ScaleTransform(scale, scale);
        var window = new Window { Content = view, Width = 1500, Height = 900, WindowStyle = WindowStyle.None,
            ShowInTaskbar = false, Left = -10000, Top = -10000 };
        window.Show();
        try
        {
            var splitter = Assert.Single(Descendants<GridSplitter>(view));
            var grid = Assert.IsType<Grid>(splitter.Parent);
            grid.ColumnDefinitions[0].Width = new GridLength(navigationWidth);
            Layout(view, 1400, 800);
            Assert.Equal(navigationWidth, grid.ColumnDefinitions[0].ActualWidth, 3);
            var selector = Assert.IsType<UniformGrid>(view.FindName("ScopeSelector"));
            var options = selector.Children.Cast<RadioButton>().ToArray();
            Assert.Equal(new[] { "Base", "One level", "Subtree" }, options.Select(option => option.Content));
            Assert.True(selector.ActualHeight <= 42);
            Assert.Single(Descendants<TextBlock>(view), text => text.Text == "Browsing Scope");
            foreach (var option in options)
            {
                var position = option.TransformToAncestor(selector).Transform(new Point());
                Assert.Equal(0, position.Y, 3);
                Assert.True(position.X + option.ActualWidth <= selector.ActualWidth + .1);
                var label = Assert.IsType<TextBlock>(option.Template.FindName("ScopeLabel", option));
                var labelPosition = label.TransformToAncestor(option).Transform(new Point());
                Assert.InRange(labelPosition.X, 0, option.ActualWidth);
                Assert.True(labelPosition.X + label.ActualWidth <= option.ActualWidth + .1);
                var measured = new FormattedText(label.Text, CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
                    new Typeface(label.FontFamily, label.FontStyle, label.FontWeight, label.FontStretch),
                    label.FontSize, label.Foreground, VisualTreeHelper.GetDpi(label).PixelsPerDip);
                Assert.True(label.ActualWidth >= measured.WidthIncludingTrailingWhitespace - 1);
            }
            var path = Assert.Single(Descendants<TextBlock>(view), text =>
                BindingOperations.GetBinding(text, TextBlock.TextProperty)?.Path.Path == nameof(model.NavigationLocation));
            Assert.Equal(model.NavigationLocation, path.Text);
            Assert.Equal(FontWeights.Normal, path.FontWeight);
            Assert.Equal(view.FindResource("CaptionFontSize"), path.FontSize);
            Assert.Equal(TextWrapping.Wrap, path.TextWrapping);
            Assert.Same(view.FindResource("AttributeSourceBrush"), path.Foreground);
        }
        finally { window.Close(); }
    });

    [Fact]
    public void ScopeSegmentsKeepExclusiveSelectionAndSearchDisabling() => OnSta(() =>
    {
        var (model, source) = ObjectNavigationTests.Model();
        var view = View(model);
        var window = new Window { Content = view, Width = 1200, Height = 800, WindowStyle = WindowStyle.None,
            ShowInTaskbar = false, Left = -10000, Top = -10000 };
        window.Show();
        try
        {
            Layout(view, 1200, 800);
            var selector = Assert.IsType<UniformGrid>(view.FindName("ScopeSelector"));
            var options = selector.Children.Cast<RadioButton>().ToArray();
            Assert.Equal(ListingScope.Subtree, model.Scope);
            Assert.True(options[2].IsChecked);
            foreach (var (option, expected) in options.Zip(new[] { ListingScope.Base, ListingScope.OneLevel, ListingScope.Subtree }))
            {
                var peer = new RadioButtonAutomationPeer(option);
                Assert.Equal(AutomationControlType.RadioButton, peer.GetAutomationControlType());
                Assert.True(peer.IsKeyboardFocusable());
                ((ISelectionItemProvider)peer.GetPattern(PatternInterface.SelectionItem)!).Select();
                Layout(view, 1200, 800);
                Assert.Equal(expected, model.Scope);
                Assert.Equal(expected, source.ListedScope);
                Assert.Same(option, Assert.Single(options, item => item.IsChecked == true));
                var segment = Assert.IsType<Border>(option.Template.FindName("Segment", option));
                var label = Assert.IsType<TextBlock>(option.Template.FindName("ScopeLabel", option));
                Assert.Same(view.FindResource("SelectionBrush"), segment.Background);
                Assert.Same(view.FindResource("FocusBrush"), segment.BorderBrush);
                Assert.Equal(FontWeights.SemiBold, label.FontWeight);
                Assert.Same(view.FindResource("FocusBrush"), label.Foreground);
            }

            ((ISelectionItemProvider)new RadioButtonAutomationPeer(options[0]).GetPattern(PatternInterface.SelectionItem)!).Select();
            model.ObjectSearchText = "Alice";
            model.SearchObjectsCommand.Execute(null);
            Layout(view, 1200, 800);
            Assert.All(options, option => Assert.False(option.IsEnabled));
            Assert.Equal(ListingScope.Base, model.Scope);
            model.ClearObjectSearchCommand.Execute(null);
            Layout(view, 1200, 800);
            Assert.All(options, option => Assert.True(option.IsEnabled));
            Assert.True(options[0].IsChecked);
            Assert.Equal(ListingScope.Base, model.Scope);
        }
        finally { window.Close(); }
    });
}
