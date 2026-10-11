using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Reflection;
using System.Xml.Linq;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Shell.Controls;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class GroupsViewTests
{
    [Theory]
    [InlineData(780, 520)]
    [InlineData(1200, 700)]
    public void GroupsRealViewKeepsReadableColumnsAndReachableActions(int width, int height)
        => OnSta(() =>
    {
        var (model, _) = Model();
        var view = View(model);
        // A hosted view still exercises real input/visibility, but its test viewport must not
        // shrink to the CI desktop's dimensions.
        view.Width = width;
        view.Height = height;
        DashboardRedesignTests.InWindow(view, 600, 400, () =>
        {
            Layout(view, width, height);
            Assert.Equal(width, view.ActualWidth);
            Assert.Equal(height, view.ActualHeight);
            var grid = Assert.Single(Descendants<GroupInventoryGrid>(view));
            Assert.Equal(8, grid.Columns.Count);
            Assert.Equal(model.Groups.Count, grid.Items.Count);
            Assert.True(grid.ActualHeight > 80);
            Assert.True(Descendants<Button>(view).Any(button => button.IsVisible && Equals(button.Content, "Open object window")));
            Assert.Contains(Descendants<TextBlock>(view), text => text.IsVisible && text.Text == "Identity Operators");
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == "17");
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == "Incomplete membership evidence");
            Assert.Contains(Descendants<TextBlock>(view), text => text.IsVisible && text.Text
                == "Incomplete membership evidence. Unresolved references: 2; unreadable references: 1.");
            Assert.DoesNotContain(Descendants<TextBlock>(view), text => text.Text.StartsWith("System.Windows.Controls.Button", StringComparison.Ordinal));
            if (Environment.GetEnvironmentVariable("SECUREAD_GROUPS_RENDER") is { } directory)
            {
                var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
                bitmap.Render(view);
                var encoder = new PngBitmapEncoder();
                encoder.Frames.Add(BitmapFrame.Create(bitmap));
                using var output = File.Create(Path.Combine(directory, $"groups-{width}.png"));
                encoder.Save(output);
            }
        });
    });

    [Fact]
    public void GroupsEnterOpensOnlyASelectedRow() => OnSta(() =>
    {
        var (model, _) = Model();
        var view = View(model);
        DashboardRedesignTests.InWindow(view, 1200, 700, () =>
        {
            Layout(view, 1200, 700);
            var grid = Assert.Single(Descendants<GroupInventoryGrid>(view));
            grid.SelectedItem = model.Groups[0];
            grid.Focus();
            var source = PresentationSource.FromVisual(grid)!;
            grid.RaiseEvent(new KeyEventArgs(Keyboard.PrimaryDevice, source, 0, Key.Enter) { RoutedEvent = Keyboard.KeyDownEvent });
            Assert.NotNull(model.Opened);
            Assert.Equal(model.Groups[0].DistinguishedName, model.Opened.DistinguishedName);
        });
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GroupsDoubleClickUsesClickedRowAndNeverTheHeader(bool header) => OnSta(() =>
    {
        var (model, source) = Model();
        var view = View(model);
        DashboardRedesignTests.InWindow(view, 1200, 700, () =>
        {
            Layout(view, 1200, 700);
            var grid = Assert.Single(Descendants<GroupInventoryGrid>(view));
            grid.SelectedItem = model.Groups[0];
            var element = header ? (DependencyObject)Descendants<DataGridColumnHeader>(grid).First()
                : (DataGridRow)grid.ItemContainerGenerator.ContainerFromIndex(1);
            source.Attributes = FakeAssetSource.CapturedObject(model.Groups[1].DistinguishedName, "group");
            var args = new MouseButtonEventArgs(Mouse.PrimaryDevice, 0, MouseButton.Left)
                { RoutedEvent = Control.MouseDoubleClickEvent, Source = element };
            typeof(GroupInventoryGrid).GetMethod("OnMouseDoubleClick", BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(grid, [args]);
            if (header) Assert.Null(model.Opened);
            else Assert.Equal(model.Groups[1].DistinguishedName, model.Opened!.DistinguishedName);
        });
    });

    [Fact]
    public void GroupsReturnPreservesTheGridScrollPositionAndSelection() => OnSta(() =>
    {
        var (model, source) = Model();
        var view = View(model);
        DashboardRedesignTests.InWindow(view, 780, 520, () =>
        {
            Layout(view, 780, 520);
            var grid = Assert.Single(Descendants<GroupInventoryGrid>(view));
            var selected = model.Groups[^1];
            grid.SelectedItem = selected;
            grid.ScrollIntoView(selected);
            Layout(view, 780, 520);
            var scroll = Descendants<ScrollViewer>(grid).First();
            var before = scroll.VerticalOffset;
            Assert.True(before > 0);
            source.Attributes = FakeAssetSource.CapturedObject(selected.DistinguishedName, "group");
            model.OpenGroupCommand.Execute(selected);
            view.Visibility = Visibility.Collapsed;
            Layout(view, 780, 520);
            model.CloseObject();
            view.Visibility = Visibility.Visible;
            Layout(view, 780, 520);
            Assert.Same(selected, grid.SelectedItem);
            Assert.Equal(before, scroll.VerticalOffset);
        });
    });

    [Fact]
    public void GroupsRefusalKeepsTheFiltersVisibleAndRecoverable() => OnSta(() =>
    {
        var assets = XDocument.Load(Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell", "Views", "AssetsView.xaml"));
        Assert.Equal("{Binding ShowsGroupsSurface, Converter={StaticResource Shown}}",
            Assert.Single(assets.Descendants(), element => element.Name.LocalName == "GroupsView").Attribute("Visibility")!.Value);
        var (model, source) = Model();
        source.GroupFailure = SecureAD.Kernel.AuditError.Create(SecureAD.Kernel.ErrorCategory.Shell, "CycleNotRun",
            SecureAD.Kernel.ErrorSeverity.Failed, "No saved cycle assessment. Clear the filter.", "synthetic");
        model.GroupsOnlyCycles = true;
        var view = View(model);
        DashboardRedesignTests.InWindow(view, 780, 520, () =>
        {
            Layout(view, 780, 520);
            Assert.True(model.HasViewRefusal);
            Assert.True(model.ShowsGroupsSurface);
            var clear = Assert.Single(Descendants<Button>(view), button => Equals(button.Content, "Clear"));
            Assert.True(clear.IsVisible);
            Assert.True(clear.IsEnabled);
            Assert.Contains(Descendants<TextBox>(view), box => box.IsVisible && box.Text.Contains("Clear the filter.", StringComparison.Ordinal));
            source.GroupFailure = null;
            clear.Command.Execute(clear.CommandParameter);
            Layout(view, 780, 520);
            Assert.False(model.HasViewRefusal);
            Assert.True(model.HasListingResult);
        });
    });

    private static UserControl View(AssetsViewModel model)
    {
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var root = XDocument.Load(Path.Combine(shell, "Views", "GroupsView.xaml")).Root!;
        root.Attribute(xaml + "Class")!.Remove();
        root.Attribute(xaml + "ClassModifier")!.Remove();
        var assembly = typeof(AssetsViewModel).Assembly.GetName().Name;
        foreach (var prefix in new[] { "views", "controls" })
        {
            var ns = prefix == "views" ? "clr-namespace:SecureAD.Shell.Views" : "clr-namespace:SecureAD.Shell.Controls";
            root.SetAttributeValue(XNamespace.Xmlns + prefix, ns + ";assembly=" + assembly);
            foreach (var element in root.Descendants().Where(element => element.Name.NamespaceName == ns))
                element.Name = XName.Get(element.Name.LocalName, ns + ";assembly=" + assembly);
        }
        root.SetAttributeValue(XNamespace.Xmlns + "test", "clr-namespace:SecureAD.Next.Tests.Shell;assembly=" + typeof(GroupsViewTests).Assembly.GetName().Name);
        var resources = root.Element(wpf + "UserControl.Resources")!;
        var gridMarkup = root.Descendants().Single(element => element.Name.LocalName == "GroupInventoryGrid");
        Assert.Equal("{Binding OpenGroupCommand}", gridMarkup.Attribute("OpenItemCommand")!.Value);
        gridMarkup.Attribute("OpenItemCommand")!.Remove();
        gridMarkup.Name = wpf + "DataGrid";
        var proxy = resources.Elements().Single(element => element.Name.LocalName == "BindingProxy");
        proxy.ReplaceWith(new XElement(xaml + "Static", new XAttribute(xaml + "Key", "Model"), new XAttribute("Member", "test:ObjectNavigationViewTests.ScreenProxy")));
        var definitions = resources.Elements().ToArray();
        resources.RemoveNodes();
        var sources = XDocument.Load(Path.Combine(shell, "App.xaml")).Descendants(wpf + "ResourceDictionary")
            .Attributes("Source").Select(attribute => attribute.Value);
        resources.Add(new XElement(wpf + "ResourceDictionary", new XElement(wpf + "ResourceDictionary.MergedDictionaries",
            sources.Select(source => new XElement(wpf + "ResourceDictionary", new XAttribute("Source",
                source.StartsWith("pack:", StringComparison.Ordinal) ? source : $"pack://application:,,,/{assembly};component/" + source)))), definitions));
        var view = (UserControl)XamlReader.Parse(root.ToString());
        // Runtime XAML cannot construct internal Shell types. Retain the parsed production
        // columns/bindings and install the actual internal input-routing control, not a substitute.
        var panel = Assert.IsAssignableFrom<Panel>(view.Content);
        var parsed = Assert.Single(panel.Children.OfType<DataGrid>());
        var grid = new GroupInventoryGrid
        {
            AutoGenerateColumns = parsed.AutoGenerateColumns, IsReadOnly = parsed.IsReadOnly,
            HeadersVisibility = parsed.HeadersVisibility, SelectionMode = parsed.SelectionMode,
            SelectionUnit = parsed.SelectionUnit, CanUserSortColumns = parsed.CanUserSortColumns,
            ColumnHeaderStyle = parsed.ColumnHeaderStyle, Style = parsed.Style,
            EnableRowVirtualization = parsed.EnableRowVirtualization,
            GridLinesVisibility = parsed.GridLinesVisibility, HorizontalGridLinesBrush = parsed.HorizontalGridLinesBrush,
            RowBackground = parsed.RowBackground, AlternatingRowBackground = parsed.AlternatingRowBackground,
        };
        foreach (var property in new[] { ItemsControl.ItemsSourceProperty, Selector.SelectedItemProperty })
            BindingOperations.SetBinding(grid, property, BindingOperations.GetBindingBase(parsed, property)!);
        BindingOperations.SetBinding(grid, GroupInventoryGrid.OpenItemCommandProperty, new Binding("OpenGroupCommand"));
        var columns = parsed.Columns.ToArray();
        parsed.Columns.Clear();
        foreach (var column in columns) grid.Columns.Add(column);
        var position = panel.Children.IndexOf(parsed);
        panel.Children.RemoveAt(position);
        panel.Children.Insert(position, grid);
        view.DataContext = model;
        return view;
    }

    private static (AssetsViewModel, FakeAssetSource) Model()
    {
        const string root = "DC=contoso,DC=com";
        var source = new FakeAssetSource
        {
            Tree = new([new(root, "contoso", Guid.NewGuid(), TreeNodeOrigin.Partition, [])], []),
            GroupPage = new(Guid.NewGuid(), new string('a', 64),
                Enumerable.Range(0, 6).Select(i => new GroupInventoryRow(Guid.NewGuid(),
                    $"CN=Group {i},OU=Groups,{root}", i == 0 ? "Identity Operators" : $"Group {i}", $"GRP-{i}",
                    "contoso.com", -2147483646, i + 3, 0, i == 0, "Captured example description.",
                    new(17 + i, 2, 1, GroupMembershipLimitations.UnresolvedReferences | GroupMembershipLimitations.UnreadableReferences))).ToArray(),
                6, null, new(true, null), null),
            Attributes = FakeAssetSource.CapturedObject($"CN=Group 0,OU=Groups,{root}", "group"),
        };
        var model = new AssetsViewModel(source);
        model.Show(@"C:\synthetic-runs\group-layout", false);
        model.Pane = AssetsPane.Groups;
        return (model, source);
    }
}
