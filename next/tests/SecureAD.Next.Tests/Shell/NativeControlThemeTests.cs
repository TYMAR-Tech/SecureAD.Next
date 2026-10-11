using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Markup;
using System.Windows.Media;
using System.Xml.Linq;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class NativeControlThemeTests
{
    [Theory]
    [InlineData("Dark")]
    [InlineData("Light")]
    public void NativeControlsRenderWithThemeSurfacesAndReadableText(string theme) => OnSta(() =>
    {
        _ = XamlReader.Parse("<UserControl xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" />");
        var view = new UserControl();
        view.Resources.MergedDictionaries.Add((ResourceDictionary)Application.LoadComponent(
            new Uri($"/SecureAD;component/Themes/Palette.{theme}.xaml", UriKind.Relative)));
        view.Resources.MergedDictionaries.Add((ResourceDictionary)Application.LoadComponent(
            new Uri("/SecureAD;component/Themes/Brushes.xaml", UriKind.Relative)));
        view.Resources.MergedDictionaries.Add((ResourceDictionary)Application.LoadComponent(
            new Uri("/SecureAD;component/Themes/Controls.xaml", UriKind.Relative)));

        var combo = new ComboBox
        {
            ItemsSource = new[] { new ThemeChoice("Alpha"), new ThemeChoice("Beta") },
            DisplayMemberPath = nameof(ThemeChoice.Label),
            SelectedIndex = 0,
            Width = 260,
        };
        var list = new ListBox { ItemsSource = new[] { "First", "Second" }, SelectedIndex = 0, Height = 90 };
        var grid = new DataGrid
        {
            ItemsSource = new[] { new ThemeRow("Recorded row") },
            AutoGenerateColumns = false,
            IsReadOnly = true,
            Height = 100,
        };
        grid.Columns.Add(new DataGridTextColumn { Header = "Name", Binding = new Binding(nameof(ThemeRow.Name)) });
        var check = new CheckBox { Content = "Include recorded values", IsChecked = true };
        var expander = new Expander
        {
            Header = "Saved grade and coverage",
            Content = new TextBlock { Text = "Recorded details" },
            IsExpanded = true,
        };
        var firstTab = new TabItem { Header = "A - Principal reading pane", Content = new TextBlock { Text = "First layout" } };
        var tabs = new TabControl { Height = 110, Items = { firstTab, new TabItem { Header = "B - Expandable principal groups" } } };
        var progress = new ProgressBar { Minimum = 0, Maximum = 10, Value = 5, Height = 8 };
        view.Content = new StackPanel
        {
            Margin = new Thickness(12),
            Children = { combo, list, grid, check, expander, tabs, progress },
        };

        DashboardRedesignTests.InWindow(view, 900, 720, () =>
        {
            var primary = BrushColor(view.FindResource("PrimaryTextBrush"));
            var raised = BrushColor(view.FindResource("SurfaceRaisedBackground"));
            var header = BrushColor(view.FindResource("AttributeHeaderBackground"));
            var selection = BrushColor(view.FindResource("SelectionBrush"));

            Assert.Equal(raised, BrushColor(combo.Background));
            Assert.Equal(primary, BrushColor(combo.Foreground));
            combo.IsDropDownOpen = true;
            Layout(view, 900, 720);
            var comboItem = Assert.IsType<ComboBoxItem>(combo.ItemContainerGenerator.ContainerFromIndex(0));
            Assert.Equal(primary, BrushColor(comboItem.Foreground));
            var comboToggle = Assert.IsType<ToggleButton>(combo.Template.FindName("DropDownToggle", combo));
            var comboChrome = Assert.IsType<Border>(comboToggle.Template.FindName("ComboChrome", comboToggle));
            Assert.Equal(raised, BrushColor(comboChrome.Background));
            Assert.Contains(Descendants<TextBlock>(comboToggle), text => text.Text == "Alpha");
            var popup = Assert.IsType<Border>(combo.Template.FindName("PopupBorder", combo));
            Assert.Equal(raised, BrushColor(popup.Background));
            Assert.Contains(Descendants<TextBlock>(comboItem), text => text.Text == "Alpha");
            combo.IsDropDownOpen = false;

            Assert.Equal(raised, BrushColor(list.Background));
            Assert.Equal(primary, BrushColor(list.Foreground));
            var selectedItem = Assert.IsType<ListBoxItem>(list.ItemContainerGenerator.ContainerFromIndex(0));
            Assert.Equal(selection, BrushColor(selectedItem.Background));
            Assert.Equal(primary, BrushColor(selectedItem.Foreground));

            Assert.Equal(raised, BrushColor(grid.Background));
            Assert.Same(view.FindResource("TableRow"), grid.RowStyle);
            Assert.Same(view.FindResource("TableCell"), grid.CellStyle);
            var row = Assert.IsType<DataGridRow>(grid.ItemContainerGenerator.ContainerFromIndex(0));
            Assert.Equal(raised, BrushColor(row.Background));
            Assert.Equal(primary, BrushColor(row.Foreground));

            check.ApplyTemplate();
            var checkChrome = Assert.IsType<Border>(check.Template.FindName("CheckChrome", check));
            Assert.Equal(raised, BrushColor(checkChrome.Background));
            Assert.Equal(primary, BrushColor(check.Foreground));

            expander.ApplyTemplate();
            var headerSite = Assert.IsType<ToggleButton>(expander.Template.FindName("HeaderSite", expander));
            var expanderChrome = Assert.IsType<Border>(headerSite.Template.FindName("HeaderChrome", headerSite));
            Assert.Equal(header, BrushColor(expanderChrome.Background));
            Assert.Equal(primary, BrushColor(expander.Foreground));

            tabs.ApplyTemplate();
            firstTab.ApplyTemplate();
            var tabChrome = Assert.IsType<Border>(firstTab.Template.FindName("TabChrome", firstTab));
            Assert.Equal(raised, BrushColor(tabChrome.Background));
            Assert.Equal(primary, BrushColor(firstTab.Foreground));

            Assert.Equal(header, BrushColor(progress.Background));
            Assert.Equal(BrushColor(view.FindResource("AccentBrush")), BrushColor(progress.Foreground));
            Assert.True(Contrast(
                Assert.IsType<SolidColorBrush>(view.FindResource("RailTextBrush")),
                Assert.IsType<SolidColorBrush>(view.FindResource("RailBackground"))) >= 4.5);
        });
    });

    [Fact]
    public void ObjectSectionLocalStylesKeepTheSharedDarkDefaults()
    {
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var path = Path.Combine(shell,
            "Views", "Sections", "ObjectSectionTemplates.xaml");
        var document = XDocument.Load(path);
        var local = document.Descendants().Where(element => element.Name.LocalName == "Style"
            && (string?)element.Attribute("TargetType") is "TextBlock" or "Expander" or "ListBoxItem").ToArray();

        Assert.NotEmpty(local);
        Assert.All(local, style => Assert.NotNull(style.Attribute("BasedOn")));

        var objectHeader = XDocument.Load(Path.Combine(shell, "Views", "ObjectSectionList.xaml"));
        var copy = Assert.Single(objectHeader.Descendants(), element => element.Name.LocalName == "CopyValueButton");
        Assert.Equal("{StaticResource BaseButton}", (string?)copy.Attribute("Style"));
    }

    private sealed record ThemeRow(string Name);
    private sealed record ThemeChoice(string Label);

    private static Color BrushColor(object value) => Assert.IsType<SolidColorBrush>(value).Color;

    private static double Contrast(SolidColorBrush foreground, SolidColorBrush background)
    {
        static double Luminance(Color color)
        {
            static double Linear(byte value) => value / 255d <= .04045
                ? value / 255d / 12.92
                : Math.Pow((value / 255d + .055) / 1.055, 2.4);
            return .2126 * Linear(color.R) + .7152 * Linear(color.G) + .0722 * Linear(color.B);
        }

        var first = Luminance(foreground.Color);
        var second = Luminance(background.Color);
        return (Math.Max(first, second) + .05) / (Math.Min(first, second) + .05);
    }
}
