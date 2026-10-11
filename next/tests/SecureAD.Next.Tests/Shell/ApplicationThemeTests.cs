using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Markup;
using System.Windows.Media;
using System.Xml.Linq;
using SecureAD.Kernel;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class ApplicationThemeTests
{
    [Fact]
    public void DarkIsTheDefaultAndStoredLightIsApplied()
    {
        var store = new FakeSettingsStore();
        var applier = new FakeThemeApplier();
        var theme = new ApplicationTheme(store, applier);

        theme.Load();

        Assert.Equal(ThemeVariant.Dark, theme.Current);
        Assert.Equal([ThemeVariant.Dark], applier.Applied);

        store.Stored = store.Stored with { Appearance = "Light" };
        theme.Load();
        Assert.Equal(ThemeVariant.Light, theme.Current);
        Assert.Equal(ThemeVariant.Light, applier.Applied[^1]);
    }

    [Fact]
    public void ChoosingAppearancePreservesOtherSettingsAndSettingsViewAppliesItImmediately()
    {
        var store = new FakeSettingsStore
        {
            Stored = new(@"D:\audits", 4, "Dark"),
        };
        var applier = new FakeThemeApplier();
        var theme = new ApplicationTheme(store, applier);
        theme.Load();
        var model = new SettingsViewModel(new DomainConcurrency(store), theme);

        model.SelectedAppearance = ThemeVariant.Light;

        Assert.Equal(new(@"D:\audits", 4, "Light"), store.Stored);
        Assert.Equal(ThemeVariant.Light, theme.Current);
        Assert.Equal(ThemeVariant.Light, applier.Applied[^1]);
        Assert.False(model.HasAppearanceProblem);
    }

    [Fact]
    public void ChoosingLightFromTheRenderedSettingsControlPersistsAndAppliesIt() => OnSta(() =>
    {
        var store = new FakeSettingsStore();
        var applier = new FakeThemeApplier();
        var theme = new ApplicationTheme(store, applier);
        theme.Load();
        var model = new SettingsViewModel(new DomainConcurrency(store), theme);
        var view = ProductionViewThemeTests.View("SettingsView.xaml", model);

        DashboardRedesignTests.InWindow(view, 760, 620, () =>
        {
            var choice = Assert.Single(Descendants<ComboBox>(view), item =>
                BindingOperations.GetBinding(item, ItemsControl.ItemsSourceProperty)?.Path.Path
                    == nameof(model.AppearanceChoices));
            choice.IsDropDownOpen = true;
            Layout(view, 760, 620);
            Assert.IsType<ComboBoxItem>(choice.ItemContainerGenerator.ContainerFromItem(ThemeVariant.Light));
            var choicePeer = new ComboBoxAutomationPeer(choice);
            var selection = Assert.IsAssignableFrom<ISelectionItemProvider>(
                new ListBoxItemAutomationPeer(ThemeVariant.Light, choicePeer)
                    .GetPattern(PatternInterface.SelectionItem));

            selection.Select();
            Layout(view, 760, 620);

            Assert.Equal(ThemeVariant.Light, choice.SelectedItem);
            Assert.Equal(ThemeVariant.Light, model.SelectedAppearance);
            Assert.Equal("Light", store.Stored.Appearance);
            Assert.Equal(ThemeVariant.Light, applier.Applied[^1]);
        });
    });

    [Fact]
    public void FailedThemeWriteKeepsTheCurrentThemeAndSurfacesTheFailure()
    {
        var store = new FakeSettingsStore();
        var applier = new FakeThemeApplier();
        var theme = new ApplicationTheme(store, applier);
        theme.Load();
        store.WriteFails = AuditError.Create(ErrorCategory.Shell, "SyntheticWriteFailure",
            ErrorSeverity.Failed, "The appearance could not be stored.", null);
        var model = new SettingsViewModel(new DomainConcurrency(store), theme);

        model.SelectedAppearance = ThemeVariant.Light;

        Assert.Equal(ThemeVariant.Dark, model.SelectedAppearance);
        Assert.Equal(ThemeVariant.Dark, theme.Current);
        Assert.Equal([ThemeVariant.Dark], applier.Applied);
        Assert.True(model.HasAppearanceProblem);
        Assert.Contains("could not be stored", model.AppearanceProblem);
    }

    [Fact]
    public void DarkAndLightPalettesImplementTheSameBrushContract()
    {
        var themes = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell", "Themes");
        var dark = Keys(Path.Combine(themes, "Palette.Dark.xaml"));
        var light = Keys(Path.Combine(themes, "Palette.Light.xaml"));
        Assert.Equal(dark, light);
        Assert.NotEmpty(dark);

        var brushes = XDocument.Load(Path.Combine(themes, "Brushes.xaml"));
        var mappings = brushes.Descendants().Where(element => element.Name.LocalName == "SolidColorBrush")
            .Select(element => (Brush: (string?)element.Attribute(XName.Get("Key", "http://schemas.microsoft.com/winfx/2006/xaml")),
                Color: (string?)element.Attribute("Color"))).ToArray();
        Assert.Equal(dark.Count, mappings.Length);
        Assert.All(mappings, mapping =>
        {
            Assert.NotNull(mapping.Brush);
            Assert.Equal("{DynamicResource " + mapping.Brush + "Color}", mapping.Color);
            Assert.Contains(mapping.Brush + "Color", dark);
        });

        var app = XDocument.Load(Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell", "App.xaml"));
        var sources = app.Descendants().Attributes("Source").Select(attribute => attribute.Value).ToArray();
        Assert.Contains("Themes/Palette.Dark.xaml", sources);
        Assert.DoesNotContain("Themes/Palette.Light.xaml", sources);
    }

    [Fact]
    public void SettingsExposesTheApprovedAppearanceChoiceAndBoundary()
    {
        var path = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell", "Views", "SettingsView.xaml");
        var view = XDocument.Load(path);
        Assert.Contains(view.Descendants().Attributes(),
            attribute => attribute.Value.Contains("AppearanceChoices", StringComparison.Ordinal));
        Assert.Contains(view.Descendants().Attributes(),
            attribute => attribute.Value.Contains("SelectedAppearance", StringComparison.Ordinal));

        var store = new FakeSettingsStore();
        var theme = new ApplicationTheme(store, new FakeThemeApplier());
        theme.Load();
        var model = new SettingsViewModel(new DomainConcurrency(store), theme);
        Assert.Equal("Appearance", model.AppearanceHeading);
        Assert.Contains("Audit evidence, analysis, and saved results do not change",
            model.AppearanceExplanation, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Dark")]
    [InlineData("Light")]
    public void BothThemesMeetTheCoreTextContrastContract(string theme)
    {
        var path = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell",
            "Themes", $"Palette.{theme}.xaml");
        var colors = XDocument.Load(path).Descendants()
            .Where(element => element.Name.LocalName == "Color")
            .ToDictionary(element => (string)element.Attribute(
                    XName.Get("Key", "http://schemas.microsoft.com/winfx/2006/xaml"))!,
                element => (Color)ColorConverter.ConvertFromString(element.Value)!);

        AssertContrast(colors, "PrimaryTextBrushColor", "WindowBackgroundColor");
        AssertContrast(colors, "SecondaryTextBrushColor", "WindowBackgroundColor");
        AssertContrast(colors, "AttributeLabelBrushColor", "AssetNavigationBackgroundColor");
        AssertContrast(colors, "TableHeaderTextBrushColor", "TableHeaderBackgroundColor");
        AssertContrast(colors, "RailTextBrushColor", "RailBackgroundColor");
        AssertContrast(colors, "OnAccentTextBrushColor", "AccentBrushColor");
        AssertContrast(colors, "OnAccentTextBrushColor", "AccentHoverBrushColor");
        AssertContrast(colors, "OnAccentTextBrushColor", "AccentPressedBrushColor");
        AssertContrast(colors, "OnAccentTextBrushColor", "DangerBrushColor");
        AssertContrast(colors, "OnAccentTextBrushColor", "DangerHoverBrushColor");
        AssertContrast(colors, "OnAccentTextBrushColor", "DangerPressedBrushColor");
        AssertContrast(colors, "FaultBrushColor", "FaultSubtleBrushColor");
        AssertContrast(colors, "CriticalFindingBrushColor", "CriticalFindingSubtleBrushColor");
    }

    [Fact]
    public void ExistingControlsChangeImmediatelyWhenThePaletteIsSwapped() => OnSta(() =>
    {
        _ = XamlReader.Parse("<UserControl xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" />");
        var view = new UserControl();
        view.Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri("/SecureAD;component/Themes/Palette.Dark.xaml", UriKind.Relative),
        });
        view.Resources.MergedDictionaries.Add(SourcedDictionary("Brushes.xaml"));
        view.Resources.MergedDictionaries.Add(Dictionary("Controls.xaml"));
        var button = new Button { Content = "Theme sample" };
        view.Content = button;
        Layout(view, 400, 120);
        var darkBackground = ColorOf(button.Background);
        var darkText = ColorOf(button.Foreground);

        new WpfThemeApplier(view.Resources).Apply(ThemeVariant.Light);
        Layout(view, 400, 120);

        Assert.NotEqual(darkBackground, ColorOf(button.Background));
        Assert.NotEqual(darkText, ColorOf(button.Foreground));
        Assert.Equal(Color.FromRgb(255, 255, 255), ColorOf(button.Background));
        Assert.Equal(Color.FromRgb(18, 22, 26), ColorOf(button.Foreground));
    });

    [Fact]
    public void ApplicationScopeSwitchRebuildsBrushesAgainstTheNewPalette() => OnSta(() =>
    {
        _ = XamlReader.Parse("<UserControl xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" />");
        var resources = new ResourceDictionary();
        resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri("/SecureAD;component/Themes/Palette.Dark.xaml", UriKind.Relative),
        });
        resources.MergedDictionaries.Add(SourcedDictionary("Brushes.xaml"));
        var originalBrushes = resources.MergedDictionaries[1];

        new WpfThemeApplier(resources).Apply(ThemeVariant.Light);

        Assert.EndsWith("Palette.Light.xaml",
            resources.MergedDictionaries[0].Source!.OriginalString, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("Brushes.xaml",
            resources.MergedDictionaries[1].Source!.OriginalString, StringComparison.OrdinalIgnoreCase);
        Assert.NotSame(originalBrushes, resources.MergedDictionaries[1]);
    });

    [Fact]
    public void ExistingScreenCanvasTextFieldsAndGridSwitchAsOneUnit() => OnSta(() =>
    {
        _ = XamlReader.Parse("<UserControl xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" />");
        var view = new UserControl();
        view.Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri("/SecureAD;component/Themes/Palette.Dark.xaml", UriKind.Relative),
        });
        view.Resources.MergedDictionaries.Add(SourcedDictionary("Brushes.xaml"));
        view.Resources.MergedDictionaries.Add(Dictionary("Assets.xaml"));
        var canvas = new Grid();
        canvas.SetResourceReference(Panel.BackgroundProperty, "AssetCanvasBackground");
        var heading = new TextBlock { Text = "Objects" };
        var field = new TextBox { Text = "Search captured objects" };
        var table = new DataGrid { Height = 80, AutoGenerateColumns = false };
        canvas.Children.Add(new StackPanel { Children = { heading, field, table } });
        view.Content = canvas;
        Layout(view, 600, 260);
        Assert.Equal(Color.FromRgb(21, 27, 36), ColorOf(canvas.Background));
        Assert.Equal(Color.FromRgb(241, 245, 252), ColorOf(heading.Foreground));

        var applier = new WpfThemeApplier(view.Resources);
        applier.Apply(ThemeVariant.Light);
        Layout(view, 600, 260);

        Assert.Equal(Color.FromRgb(223, 231, 240), ColorOf(canvas.Background));
        Assert.Equal(Color.FromRgb(18, 22, 26), ColorOf(heading.Foreground));
        Assert.Equal(Color.FromRgb(255, 255, 255), ColorOf(field.Background));
        Assert.Equal(Color.FromRgb(255, 255, 255), ColorOf(table.Background));
    });

    private static ResourceDictionary Dictionary(string name) => (ResourceDictionary)Application.LoadComponent(
        new Uri("/SecureAD;component/Themes/" + name, UriKind.Relative));

    private static ResourceDictionary SourcedDictionary(string name) => new()
    {
        Source = new Uri("/SecureAD;component/Themes/" + name, UriKind.Relative),
    };

    private static IReadOnlyList<string> Keys(string path) => XDocument.Load(path).Descendants()
        .Select(element => (string?)element.Attribute(XName.Get("Key", "http://schemas.microsoft.com/winfx/2006/xaml")))
        .Where(key => key is not null).Cast<string>().OrderBy(key => key, StringComparer.Ordinal).ToArray();

    private static Color ColorOf(Brush brush) => Assert.IsType<SolidColorBrush>(brush).Color;

    private static void AssertContrast(IReadOnlyDictionary<string, Color> colors, string foreground, string background)
    {
        static double Luminance(Color color)
        {
            static double Linear(byte value) => value / 255d <= .04045
                ? value / 255d / 12.92
                : Math.Pow((value / 255d + .055) / 1.055, 2.4);
            return .2126 * Linear(color.R) + .7152 * Linear(color.G) + .0722 * Linear(color.B);
        }

        var first = Luminance(colors[foreground]);
        var second = Luminance(colors[background]);
        var ratio = (Math.Max(first, second) + .05) / (Math.Min(first, second) + .05);
        Assert.True(ratio >= 4.5, $"{foreground} over {background} is only {ratio:F2}:1.");
    }

    private sealed class FakeThemeApplier : IThemeApplier
    {
        public List<ThemeVariant> Applied { get; } = [];
        public void Apply(ThemeVariant theme) => Applied.Add(theme);
    }
}
