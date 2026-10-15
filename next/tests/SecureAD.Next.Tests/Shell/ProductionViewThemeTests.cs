using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Markup;
using System.Windows.Media;
using System.Xml.Linq;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class ProductionViewThemeTests
{
    private static readonly string Shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
    private static readonly Color DarkCanvas = Color.FromRgb(21, 27, 36);
    private static readonly Color DarkSurface = Color.FromRgb(32, 41, 54);
    private static readonly Color DarkText = Color.FromRgb(241, 245, 252);
    private static readonly Color LightCanvas = Color.FromRgb(223, 231, 240);
    private static readonly Color LightSurface = Color.FromRgb(255, 255, 255);
    private static readonly Color LightText = Color.FromRgb(18, 22, 26);

    [Fact]
    public void ObjectsSwitchesCanvasHeadingSearchAndGridTogether() => OnSta(() =>
    {
        var (model, _) = ObjectNavigationTests.Model();
        var view = ObjectNavigationViewTests.View(model);
        Layout(view, 1100, 700);

        var search = Assert.Single(Descendants<TextBox>(view), item =>
            BindingOperations.GetBinding(item, TextBox.TextProperty)?.Path.Path == nameof(model.ObjectSearchText));
        var grid = Assert.Single(Descendants<DataGrid>(view), item => ReferenceEquals(item.ItemsSource, model.Objects));
        AssertColors(view, search, grid, DarkCanvas, DarkSurface, DarkText);

        new WpfThemeApplier(view.Resources).Apply(ThemeVariant.Light);
        Layout(view, 1100, 700);

        AssertColors(view, search, grid, LightCanvas, LightSurface, LightText);
    });

    [Fact]
    public void LapsSwitchesHeadingCardsSearchAndGridTogether() => OnSta(() =>
    {
        var view = View("LapsInventoryView.xaml", new ThemeViewModel());
        Layout(view, 1000, 700);

        var heading = Assert.Single(Descendants<TextBlock>(view), item => item.Text == "LAPS coverage");
        var search = Assert.Single(Descendants<TextBox>(view), item =>
            Equals(item.ToolTip, "Filter computers in the selected scope by computer or domain."));
        var grid = Assert.Single(Descendants<DataGrid>(view));
        AssertThemeElements(view, heading, search, grid, DarkSurface, DarkText);
        AssertCards(view, DarkSurface);

        new WpfThemeApplier(view.Resources).Apply(ThemeVariant.Light);
        Layout(view, 1000, 700);

        AssertThemeElements(view, heading, search, grid, LightSurface, LightText);
        AssertCards(view, LightSurface);
    });

    [Fact]
    public void Tier0SwitchesCanvasHeadingCardsAndGridTogether() => OnSta(() =>
    {
        var view = View("Tier0OverviewView.xaml", new ThemeViewModel());
        Layout(view, 1000, 760);

        var heading = Assert.Single(Descendants<TextBlock>(view), item => item.Text == "Tier 0 overview");
        var grid = Assert.Single(Descendants<DataGrid>(view));
        Assert.Equal(DarkCanvas, ColorOf(view.Background));
        Assert.Equal(DarkText, ColorOf(heading.Foreground));
        Assert.Equal(DarkSurface, ColorOf(grid.Background));
        AssertCards(view, DarkSurface);

        new WpfThemeApplier(view.Resources).Apply(ThemeVariant.Light);
        Layout(view, 1000, 760);

        Assert.Equal(LightCanvas, ColorOf(view.Background));
        Assert.Equal(LightText, ColorOf(heading.Foreground));
        Assert.Equal(LightSurface, ColorOf(grid.Background));
        AssertCards(view, LightSurface);
    });

    [Fact]
    public void ApplicationOwnsTheOnlySemanticBrushDictionary()
    {
        var owners = Directory.EnumerateFiles(Shell, "*.xaml", SearchOption.AllDirectories)
            .SelectMany(path => XDocument.Load(path).Descendants().Attributes("Source")
                .Where(source => source.Value.EndsWith("Brushes.xaml", StringComparison.OrdinalIgnoreCase))
                .Select(_ => Path.GetRelativePath(Shell, path)))
            .ToArray();

        Assert.Equal(new[] { "App.xaml" }, owners);
    }

    [Fact]
    public void ProductionXamlDefersEverySemanticBrushLookup()
    {
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var keys = XDocument.Load(Path.Combine(Shell, "Themes", "Palette.Dark.xaml"))
            .Descendants()
            .Select(element => (string?)element.Attribute(xaml + "Key"))
            .Where(key => key?.EndsWith("Color", StringComparison.Ordinal) == true)
            .Select(key => key![..^"Color".Length])
            .ToHashSet(StringComparer.Ordinal);
        var staticLookups = Directory.EnumerateFiles(Shell, "*.xaml", SearchOption.AllDirectories)
            .SelectMany(path => XDocument.Load(path).Descendants().Attributes()
                .Where(attribute => attribute.Value.StartsWith("{StaticResource ", StringComparison.Ordinal)
                    && attribute.Value.EndsWith('}'))
                .Select(attribute => (Path: Path.GetRelativePath(Shell, path),
                    Key: attribute.Value["{StaticResource ".Length..^1])))
            .Where(item => keys.Contains(item.Key))
            .ToArray();

        Assert.Empty(staticLookups);
    }

    internal static UserControl View(string name, object model)
    {
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var root = XDocument.Load(Path.Combine(Shell, "Views", name)).Root!;
        root.Attribute(xaml + "Class")!.Remove();
        root.Attribute(xaml + "ClassModifier")!.Remove();
        var resources = root.Element(wpf + "UserControl.Resources");
        if (resources is null)
        {
            resources = new XElement(wpf + "UserControl.Resources");
            root.AddFirst(resources);
        }

        var definitions = resources.Elements().ToArray();
        resources.RemoveNodes();
        var assembly = typeof(AssetsViewModel).Assembly.GetName().Name;
        var sources = XDocument.Load(Path.Combine(Shell, "App.xaml")).Descendants(wpf + "ResourceDictionary")
            .Attributes("Source").Select(attribute => attribute.Value)
            .Where(source => !source.StartsWith("Views/", StringComparison.Ordinal));
        resources.Add(new XElement(wpf + "ResourceDictionary",
            new XElement(wpf + "ResourceDictionary.MergedDictionaries",
                sources.Select(source => new XElement(wpf + "ResourceDictionary", new XAttribute("Source",
                    source.StartsWith("pack:", StringComparison.Ordinal)
                        ? source
                        : $"pack://application:,,,/{assembly};component/" + source)))),
            definitions));
        var view = (UserControl)XamlReader.Parse(root.ToString());
        view.DataContext = model;
        return view;
    }

    private static void AssertColors(
        UserControl view,
        TextBox search,
        DataGrid grid,
        Color canvas,
        Color surface,
        Color text)
    {
        Assert.Equal(canvas, ColorOf(view.Background));
        Assert.Equal(surface, ColorOf(search.Background));
        Assert.Equal(surface, ColorOf(grid.Background));
        Assert.Equal(text, ColorOf(grid.Foreground));
    }

    private static void AssertThemeElements(
        UserControl view,
        TextBlock heading,
        TextBox search,
        DataGrid grid,
        Color surface,
        Color text)
    {
        Assert.Equal(text, ColorOf(heading.Foreground));
        Assert.Equal(surface, ColorOf(search.Background));
        Assert.Equal(surface, ColorOf(grid.Background));
        Assert.Equal(text, ColorOf(grid.Foreground));
    }

    private static void AssertCards(UserControl view, Color expected)
    {
        var card = Assert.IsType<Style>(view.FindResource("Card"));
        var cards = Descendants<Border>(view).Where(border => ReferenceEquals(border.Style, card)).ToArray();
        Assert.NotEmpty(cards);
        Assert.All(cards, item => Assert.Equal(expected, ColorOf(item.Background)));
    }

    private static Color ColorOf(Brush brush) => Assert.IsType<SolidColorBrush>(brush).Color;

    public sealed class ThemeViewModel
    {
        public string ScopeTreeAction => "Hide scope tree";
        public string LapsLocation => "contoso.com";
        public IReadOnlyList<CountRow> LapsCounts { get; } = [new("Managed by Windows LAPS", 42)];
        public IReadOnlyList<string> LapsStateChoices { get; } = ["Any state"];
        public string LapsStateFilter { get; set; } = "Any state";
        public string LapsSearchText { get; set; } = string.Empty;
        public IReadOnlyList<LapsRow> VisibleLapsComputers { get; } =
            [new("FS01", "contoso.com", "Windows LAPS", "Supported", "2026-10-11", "Not set")];
        public LapsRow SelectedLapsComputer { get; set; }
        public bool HasSelectedLapsComputer => true;
        public int LapsTotal => 1;
        public bool IsLoading => false;
        public bool HasViewRefusal => false;
        public int Tier0ClassifiedCount => 14;
        public int Tier0OtherSupportedCount => 8;
        public int Tier0UnresolvedCount => 2;
        public int Tier0UnassessedCount => 3;
        public bool Tier0HasLimitations => true;
        public string Tier0OverviewStatus => "Saved assessment status";
        public string Tier0OverviewCoverage => "Saved coverage";
        public string Tier0ObjectLimitation => string.Empty;
        public bool Tier0SupportedOnly { get; set; } = true;
        public bool Tier0AllIdentities { get; set; }
        public string Tier0PageDescription => "1 identity";
        public IReadOnlyList<Tier0Row> Tier0Objects { get; } =
            [new("Domain Admins", "contoso.com", "0")];
        public Tier0Row SelectedTier0Object { get; set; }

        public ThemeViewModel()
        {
            SelectedLapsComputer = VisibleLapsComputers[0];
            SelectedTier0Object = Tier0Objects[0];
        }
    }

    public sealed record CountRow(string Label, int Count);

    public sealed record LapsRow(
        string Name,
        string Domain,
        string Management,
        string Capability,
        string WindowsLapsExpiry,
        string LegacyLapsExpiry);

    public sealed record Tier0Row(string Name, string Domain, string Distance);
}
