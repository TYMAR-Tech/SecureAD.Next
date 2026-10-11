using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Xml.Linq;
using SecureAD.Evidence;
using SecureAD.Kernel.Capture;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class AssetCardViewTests
{
    [Fact]
    public void HelpKeepsDefinitionsAndCountingAwayFromTheDataSections() => OnSta(() =>
    {
        var definition = ObjectSectionCatalog.For("computer")
            .Single(section => section.Key == ObjectSectionCatalog.Help);
        var (host, _, _) = Present(new ObjectHelpSectionViewModel(definition));

        Layout(host, 1100, 720);

        Assert.Contains(Descendants<TextBlock>(host), text => text.Text == "What Control edges answers");
        Assert.Contains(Descendants<TextBlock>(host), text => text.Text == "Not a Tier 0 path");
        Assert.Contains(Descendants<Expander>(host),
            expander => Equals(expander.Header, "How control relationships are counted"));
    });

    [Fact]
    public void CardTitleIsInlineAndValuesStaySelectable() => OnSta(() =>
    {
        var row = Row("sAMAccountName", "amorgan");
        var (host, presenter, template) = Present(row);
        Layout(host, 440, 200);
        var title = Assert.IsType<TextBlock>(template.FindName("AttributeTitle", presenter));
        var value = Assert.IsType<TextBox>(template.FindName("AttributeValue", presenter));
        var card = Assert.IsType<Border>(template.FindName("AttributeCardSurface", presenter));
        var header = Assert.IsType<Border>(template.FindName("AttributeCardHeader", presenter));

        Assert.Equal("Account Name (sAMAccountName)", new TextRange(title.ContentStart, title.ContentEnd).Text);
        Assert.DoesNotContain(title.Inlines, inline => inline is LineBreak);
        Assert.True(title.ActualHeight < 30);
        Assert.Equal("amorgan", value.Text);
        Assert.True(value.IsReadOnly && value.IsHitTestVisible && value.FontSize > title.FontSize);
        Assert.NotEqual(ColorOf(card.Background), ColorOf(header.Background));
        Assert.True(Contrast(value.Foreground, card.Background) >= 4.5);
        Assert.True(Contrast(title.Foreground, header.Background) >= 4.5);
        value.SelectAll();
        Assert.Equal("amorgan", value.SelectedText);
    });

    [Fact]
    public void CardsRetainInterpretedRawValuesAndCaveats() => OnSta(() =>
    {
        var row = Row("lastLogonTimestamp", "133700000000000000");
        Assert.True(row.IsInterpreted && row.HasCaveat);
        var (host, presenter, template) = Present(row);
        Layout(host, 420, 350);

        Assert.Equal(row.Worded, Assert.IsType<TextBox>(template.FindName("AttributeValue", presenter)).Text);
        var stored = Assert.IsType<TextBox>(template.FindName("AttributeStored", presenter));
        Assert.Equal(row.Stored, stored.Text);
        Assert.Equal(Visibility.Visible, stored.Visibility);
        var caveat = Assert.IsType<TextBlock>(template.FindName("AttributeCaveat", presenter));
        Assert.Equal(row.Caveat, caveat.Text);
        Assert.Equal(Visibility.Visible, Assert.IsType<Border>(caveat.Parent).Visibility);
        Assert.Equal(TextWrapping.Wrap, caveat.TextWrapping);
    });

    [Fact]
    public void LongCardValuesWrapWithoutLosingTheirCopyableText() => OnSta(() =>
    {
        var original = new string('W', 1000);
        var (host, presenter, template) = Present(Row("description", original));
        Layout(host, 350, 3000);
        var value = Assert.IsType<TextBox>(template.FindName("AttributeValue", presenter));
        Assert.Equal(original, value.Text);
        Assert.True(value.LineCount > 1);
        var last = value.GetRectFromCharacterIndex(original.Length - 1);
        Assert.False(last.IsEmpty);
        Assert.True(last.Right <= value.ActualWidth + 1);
        value.SelectAll();
        Assert.Equal(original, value.SelectedText);
    });

    [Theory]
    [InlineData(true, "No captured value")]
    [InlineData(false, "Not read")]
    public void CardsKeepMissingAndUnreadDistinct(bool wasRead, string expected) => OnSta(() =>
    {
        var row = new AttributeValueViewModel("sAMAccountName", null, wasRead, DateTimeOffset.UnixEpoch);
        var (host, presenter, template) = Present(row);
        Layout(host, 350, 200);

        Assert.Equal(expected, Assert.IsType<TextBox>(template.FindName("AttributeValue", presenter)).Text);
        Assert.Equal(Visibility.Collapsed, Assert.IsType<TextBox>(template.FindName("AttributeStored", presenter)).Visibility);
    });

    [Theory]
    [InlineData(339, 1)]
    [InlineData(679, 1)]
    [InlineData(680, 2)]
    [InlineData(1019, 2)]
    [InlineData(1020, 3)]
    [InlineData(1700, 3)]
    public void ResponsiveFieldsUseAvailableWidthAndKeepRowHeightsLocal(int width, int columns) => OnSta(() =>
    {
        var panel = new FieldGrid { Columns = 3, MinimumColumnWidth = 340 };
        for (var i = 0; i < 9; i++) panel.Children.Add(new Border { Height = i == 0 ? 90 : 20 });
        Layout(panel, width, 500);
        for (var i = 0; i < panel.Children.Count; i++)
        {
            var child = (FrameworkElement)panel.Children[i];
            var position = child.TransformToAncestor(panel).Transform(new Point());
            Assert.Equal(i % columns * (double)width / columns, position.X, 4);
            var row = i / columns;
            Assert.Equal(row == 0 ? 0 : 90 + (row - 1) * 20, position.Y, 4);
            Assert.Equal((double)width / columns, child.ActualWidth, 4);
        }
        Layout(panel, 680, 500);
        Assert.Equal(340, ((FrameworkElement)panel.Children[1]).ActualWidth, 4);
    });

    [Theory]
    [InlineData(600, 1)]
    [InlineData(1200, 2)]
    public void CombinedOverviewKeepsIdentityAndAccountPanelsReadable(int width, int columns) => OnSta(() =>
    {
        var definition = ObjectSectionCatalog.For("user").Single(item => item.Key == ObjectSectionCatalog.Overview);
        var section = new OverviewSectionViewModel(
            definition, Judgement.ControlEdgeDeriverTests.Permissions(), null, "user");
        var (host, _, _) = Present(section);
        Layout(host, width, 360);
        var panel = Assert.Single(Descendants<FieldGrid>(host), item => item.Children.Count == 2
            && item.Children.Cast<UIElement>().All(child => child is Border));
        var positions = panel.Children.Cast<FrameworkElement>().Select(child => child.TransformToAncestor(panel).Transform(new Point())).ToArray();
        Assert.Equal(columns, positions.Count(point => point.Y == 0));
        Assert.Equal(2, panel.Children.Count);
        var scroll = Assert.Single(Descendants<ScrollViewer>(host), item => item.Content is StackPanel);
        Assert.Equal(ScrollBarVisibility.Auto, scroll.VerticalScrollBarVisibility);
        foreach (var toggle in Descendants<CheckBox>(host).Where(item => Equals(item.Content, "Show missing attributes")))
            toggle.IsChecked = true;
        Layout(host, width, 360);
        Assert.Equal(section.Values.Count, Descendants<Border>(host).Count(item => item.Name == "AttributeCardSurface"));
        Assert.All(Descendants<TextBox>(host).Where(item => item.Name == "AttributeValue"), item =>
        {
            Assert.Equal(TextWrapping.Wrap, item.TextWrapping);
            Assert.True(item.ActualWidth <= width);
        });
    });

    [Theory]
    [InlineData(1280, 800)]
    [InlineData(1920, 1080)]
    public void DetachedObjectDetailsAreResizableAndEverySectionIsReachable(int width, int height) => OnSta(() =>
    {
        var (model, source) = Opened();
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var window = XDocument.Load(Path.Combine(shell, "Views", "ObjectDetailWindow.xaml")).Root!;
        Assert.Equal("CanResizeWithGrip", (string?)window.Attribute("ResizeMode"));
        Assert.Equal("780", (string?)window.Attribute("MinWidth"));
        Assert.Equal("520", (string?)window.Attribute("MinHeight"));
        Assert.Single(window.Descendants(), element => element.Name.LocalName == "ObjectView");
        Assert.Empty(window.Descendants(wpf + "TreeView"));

        var (host, _, _) = Present(Assert.IsType<OverviewSectionViewModel>(model.Opened!.Content));
        Layout(host, Math.Max(width - 40, 780), Math.Max(height - 180, 420));
        Assert.NotEmpty(Descendants<FieldGrid>(host));
        Assert.NotEmpty(model.Opened.Sections);
        model.CloseObjectCommand.Execute(null);
        Assert.True(model.ShowsObjectListing);
        Assert.Equal(1, source.ObjectListings);
    });

    [Fact]
    public void TreeSearchCanLeaveAnOpenObjectWithoutReplayingItsSections()
    {
        var (model, source) = Opened();
        Assert.True(model.ShowsDirectoryTree);
        model.ObjectSearchText = "Alice";
        Assert.True(model.SearchObjectsCommand.CanExecute(null));
        var opened = model.Opened;
        model.SearchObjectsCommand.Execute(null);

        Assert.True(model.HasOpenObject);
        Assert.Same(opened, model.Opened);
        Assert.True(model.IsObjectSearch && model.ShowsObjectListing);
        Assert.Single(source.ObjectSearchQueries);
    }

    [Fact]
    public void LocatingADelegationObjectReturnsTheMainWindowToObjects()
    {
        var (model, source) = ObjectNavigationTests.Model();
        source.Attributes = FakeAssetSource.CapturedObject("DC=contoso,DC=com", "user");
        model.Pane = AssetsPane.Delegations;
        model.OpenObject(new ListedObjectViewModel(new("DC=contoso,DC=com", "contoso", null, "user", null)));
        Assert.True(model.HasOpenObject);
        Assert.False(model.ShowsDirectoryTree);
        model.LocateObjectCommand.Execute(null);

        Assert.Equal(AssetsPane.Objects, model.Pane);
        Assert.True(model.HasOpenObject);
        Assert.True(model.ShowsObjectListing && model.ShowsDirectoryTree);
    }

    private static (AssetsViewModel, FakeAssetSource) Opened()
    {
        var (model, source) = ObjectNavigationTests.Model();
        source.Attributes = FakeAssetSource.CapturedObject("DC=contoso,DC=com", "user");
        source.Permissions = Judgement.ControlEdgeDeriverTests.Permissions("DC=contoso,DC=com");
        model.OpenObject(model.Objects[0]);
        Assert.True(model.ReadCompletion.IsCompletedSuccessfully);
        Assert.True(model.HasOpenObject);
        return (model, source);
    }

    private static AttributeValueViewModel Row(string name, string value) =>
        new(name, new ObjectAttribute(name, AttributeCardinality.SingleValued, [new(0, value, null)]),
            true, new DateTimeOffset(2026, 10, 5, 0, 0, 0, TimeSpan.Zero));

    internal static (Grid Host, ContentPresenter Presenter, DataTemplate Template) Present(object content)
    {
        _ = XamlReader.Parse("<UserControl xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" />");
        var host = new Grid();
        foreach (var path in new[] { "Themes/Palette.Dark.xaml", "Themes/Brushes.xaml", "Themes/StateMarks.xaml", "Views/Sections/ObjectSectionTemplates.xaml" })
            host.Resources.MergedDictionaries.Add((ResourceDictionary)Application.LoadComponent(new Uri("/SecureAD;component/" + path, UriKind.Relative)));
        var template = (DataTemplate)host.FindResource(new DataTemplateKey(content.GetType()));
        var presenter = new ContentPresenter { Content = content, ContentTemplate = template };
        host.Children.Add(presenter);
        return (host, presenter, template);
    }

    private static Color ColorOf(object brush) => Assert.IsType<SolidColorBrush>(brush).Color;

    private static double Contrast(Brush foreground, Brush background)
    {
        static double Luminance(Color color)
        {
            static double Linear(byte value) => value / 255d <= .04045 ? value / 255d / 12.92 : Math.Pow((value / 255d + .055) / 1.055, 2.4);
            return .2126 * Linear(color.R) + .7152 * Linear(color.G) + .0722 * Linear(color.B);
        }
        var first = Luminance(ColorOf(foreground));
        var second = Luminance(ColorOf(background));
        return (Math.Max(first, second) + .05) / (Math.Min(first, second) + .05);
    }
}
