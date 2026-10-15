using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Threading;
using System.Xml.Linq;
using SecureAD.Evidence;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class ObjectNavigationViewTests
{
    [Fact]
    public void TreeThemeResolvesItsBrushesWithoutApplicationGlobalResources() => OnSta(() =>
    {
        _ = XamlReader.Parse("<UserControl xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" />");
        var assembly = typeof(AssetsViewModel).Assembly.GetName().Name;
        var resources = new ResourceDictionary();
        resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/{assembly};component/Themes/Palette.Dark.xaml"),
        });
        resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/{assembly};component/Themes/Brushes.xaml"),
        });
        resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/{assembly};component/Themes/Tree.xaml"),
        });

        Assert.True(resources.Contains("BorderBrush"));
        Assert.True(resources.Contains("SurfaceRaisedBackground"));
        Assert.IsType<SolidColorBrush>(resources["BorderBrush"]);
    });

    public static object ScreenProxy
    {
        get
        {
            var proxy = new SecureAD.Shell.Views.BindingProxy();
            BindingOperations.SetBinding(proxy, SecureAD.Shell.Views.BindingProxy.DataProperty, new Binding());
            return proxy;
        }
    }

    [Theory]
    [InlineData(900, 470)]
    [InlineData(1300, 700)]
    public void SearchIsAboveTheUsableTreeAndResultsExposeDomainAndLocation(int width, int height) => OnSta(() =>
    {
        var (model, source) = ObjectNavigationTests.Model();
        var view = View(model);
        var window = new Window { Content = view, Width = width, Height = height, WindowStyle = WindowStyle.None,
            ShowInTaskbar = false, Left = -10000, Top = -10000 };
        window.Show();
        try
        {
            Layout(view, width, height);
            var search = Assert.Single(Descendants<TextBox>(view), item =>
                BindingOperations.GetBinding(item, TextBox.TextProperty)?.Path.Path == nameof(model.ObjectSearchText));
            var tree = Assert.Single(Descendants<TreeView>(view));
            Assert.Contains(Descendants<ContentControl>(tree), item => item.Content is TreeNodeViewModel &&
                ReferenceEquals(item.ContentTemplate, view.FindResource("TreeNodeIcon")));
            Assert.True(search.TransformToAncestor(view).Transform(new Point()).Y < tree.TransformToAncestor(view).Transform(new Point()).Y);
            Assert.True(tree.ActualHeight >= 100, $"The navigation tree has only {tree.ActualHeight} pixels.");
            search.Text = "Alice";
            search.GetBindingExpression(TextBox.TextProperty)!.UpdateSource();
            Assert.Empty(source.ObjectSearchQueries);
            var enter = Assert.Single(search.InputBindings.OfType<KeyBinding>(), binding => binding.Key == Key.Enter);
            Assert.Same(model.SearchObjectsCommand, enter.Command);
            enter.Command.Execute(null);
            Layout(view, width, height);
            Assert.Single(source.ObjectSearchQueries);
            var grid = Assert.Single(Descendants<DataGrid>(view), item => ReferenceEquals(item.ItemsSource, model.Objects));
            var domain = Assert.Single(grid.Columns, column => Equals(column.Header, ObjectNavigationText.Domain));
            var location = Assert.Single(grid.Columns, column => Equals(column.Header, ObjectNavigationText.Location));
            Assert.Equal(Visibility.Visible, domain.Visibility);
            Assert.Equal(Visibility.Visible, location.Visibility);
            Assert.True(grid.ActualHeight >= 100);
            var clear = Assert.Single(Descendants<Button>(view), item => Equals(item.Content, ObjectNavigationText.ClearSearch));
            ((IInvokeProvider)new ButtonAutomationPeer(clear).GetPattern(PatternInterface.Invoke)!).Invoke();
            Layout(view, width, height);
            Assert.False(model.IsObjectSearch);
            Assert.Equal(Visibility.Collapsed, domain.Visibility);
            Assert.True(Assert.Single(Descendants<RadioButton>(view), item => Equals(item.Content, "Subtree")).IsChecked);
        }
        finally { window.Close(); }
    });

    [Fact]
    public void CoverageIsCompactUntilRequestedAndKeepsTheIncompleteIndicatorVisible() => OnSta(() =>
    {
        var (model, source) = ObjectNavigationTests.Model();
        source.Tree = source.Tree with { Gaps =
        [
            new("missing.example", TreeGapReason.DomainNotFullyRead, "Could not read this domain."),
            new("DC=DomainDnsZones,DC=contoso,DC=com", TreeGapReason.PartitionNotRead, "Outside product scope."),
        ] };
        model.Read();
        var view = View(model);
        var window = new Window { Content = view, Width = 1000, Height = 650, WindowStyle = WindowStyle.None,
            ShowInTaskbar = false, Left = -10000, Top = -10000 };
        window.Show();
        try
        {
            Layout(view, 1000, 650);
            Assert.False(model.ShowsCaptureCoverageDetails);
            Assert.Contains(Descendants<TextBlock>(view), item => item.Text == "Capture incomplete" && item.IsVisible);
            var action = Assert.Single(Descendants<Button>(view), item => ReferenceEquals(item.Command, model.ToggleCaptureCoverageCommand));
            ((IInvokeProvider)new ButtonAutomationPeer(action).GetPattern(PatternInterface.Invoke)!).Invoke();
            Layout(view, 1000, 650);
            Assert.True(model.ShowsCaptureCoverageDetails);
            Assert.Contains(Descendants<TextBlock>(view), item => item.Text == ObjectNavigationText.RunGaps && item.IsVisible);
            Assert.Contains(Descendants<TextBlock>(view), item => item.Text == ObjectNavigationText.ScopeNotes && item.IsVisible);
            Assert.DoesNotContain(Descendants<TextBlock>(view), item => item.Text == "Not shown, and why");
        }
        finally { window.Close(); }
    });

    internal static UserControl View(AssetsViewModel model, bool includeObject = false)
    {
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var root = XDocument.Load(Path.Combine(shell, "Views", "AssetsView.xaml")).Root!;
        root.Attribute(xaml + "Class")!.Remove();
        root.Attribute(xaml + "ClassModifier")!.Remove();
        var assembly = typeof(AssetsViewModel).Assembly.GetName().Name;
        root.SetAttributeValue(XNamespace.Xmlns + "vm", "clr-namespace:SecureAD.Shell.ViewModels;assembly=" + assembly);
        root.SetAttributeValue(XNamespace.Xmlns + "views", "clr-namespace:SecureAD.Shell.Views;assembly=" + assembly);
        root.SetAttributeValue(XNamespace.Xmlns + "test", "clr-namespace:SecureAD.Next.Tests.Shell;assembly=" + typeof(ObjectNavigationViewTests).Assembly.GetName().Name);
        // Exercise the actual navigation/listing and coverage markup without constructing the
        // unchanged auxiliary panes, whose compiled constructors require application resources.
        var childViews = root.Descendants().Where(element => element.Name.NamespaceName == "clr-namespace:SecureAD.Shell.Views"
            && element.Name.LocalName != "BindingProxy" && !element.Name.LocalName.Contains('.')).ToArray();
        foreach (var child in childViews)
        {
            if (child.Name.LocalName != "CaptureCoverageView" && !(includeObject && child.Name.LocalName == "ObjectView"))
            { child.Remove(); continue; }
            var coverage = InlineView(child.Name.LocalName);
            foreach (var attribute in child.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration))
                coverage.SetAttributeValue(attribute.Name, attribute.Value);
            foreach (var property in child.Elements())
            {
                Assert.Equal(child.Name.LocalName + ".Style", property.Name.LocalName);
                var styleProperty = new XElement(property) { Name = wpf + "UserControl.Style" };
                foreach (var style in styleProperty.Elements(wpf + "Style"))
                {
                    Assert.Equal("views:" + child.Name.LocalName, style.Attribute("TargetType")?.Value);
                    style.SetAttributeValue("TargetType", "UserControl");
                }
                coverage.AddFirst(styleProperty);
            }
            child.ReplaceWith(coverage);
        }

        XElement InlineView(string name)
        {
            var element = XDocument.Load(Path.Combine(shell, "Views", name + ".xaml")).Root!;
            element.Attribute(xaml + "Class")!.Remove();
            element.Attribute(xaml + "ClassModifier")!.Remove();
            element.SetAttributeValue(XNamespace.Xmlns + "vm", "clr-namespace:SecureAD.Shell.ViewModels;assembly=" + assembly);
            foreach (var nested in element.Descendants().Where(item => item.Name.LocalName == "ObjectSectionList").ToArray())
            {
                var sections = InlineView("ObjectSectionList");
                foreach (var attribute in nested.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration))
                    sections.SetAttributeValue(attribute.Name, attribute.Value);
                nested.ReplaceWith(sections);
            }
            return element;
        }
        QualifyNamespaces(root, assembly);
        var proxyElement = Assert.Single(root.Descendants().Where(element => element.Name.LocalName == "BindingProxy"));
        Assert.Equal("{Binding}", proxyElement.Attribute("Data")?.Value);
        proxyElement.ReplaceWith(new XElement(xaml + "Static", new XAttribute(xaml + "Key", "Screen"),
            new XAttribute("Member", "test:ObjectNavigationViewTests.ScreenProxy")));
        var resources = root.Element(wpf + "UserControl.Resources")!;
        var definitions = resources.Elements().ToArray();
        resources.RemoveNodes();
        var sources = XDocument.Load(Path.Combine(shell, "App.xaml")).Descendants(wpf + "ResourceDictionary")
            .Attributes("Source").Select(attribute => attribute.Value)
            .Where(source => includeObject || !source.StartsWith("Views/", StringComparison.Ordinal));
        resources.Add(new XElement(wpf + "ResourceDictionary",
            new XElement(wpf + "ResourceDictionary.MergedDictionaries", sources.Select(source => new XElement(wpf + "ResourceDictionary",
                new XAttribute("Source", source.StartsWith("pack:", StringComparison.Ordinal) ? source : $"pack://application:,,,/{assembly};component/" + source)))),
            definitions));
        var view = (UserControl)XamlReader.Parse(root.ToString());
        view.DataContext = model;
        return view;
    }

    internal static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T value) yield return value;
            foreach (var descendant in Descendants<T>(child)) yield return descendant;
        }
    }

    internal static UserControl ObjectView(AssetsViewModel model)
    {
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var root = XDocument.Load(Path.Combine(shell, "Views", "ObjectView.xaml")).Root!;
        var sections = XDocument.Load(Path.Combine(shell, "Views", "ObjectSectionList.xaml")).Root!;
        foreach (var element in new[] { root, sections })
        {
            element.Attribute(xaml + "Class")!.Remove();
            element.Attribute(xaml + "ClassModifier")!.Remove();
        }
        // The unchanged clipboard control has separate checks; loose XAML cannot construct its internal type.
        foreach (var copy in sections.Descendants().Where(element => element.Name.LocalName == "CopyValueButton").ToArray())
        {
            copy.Name = wpf + "Button";
            copy.Attribute("Text")?.Remove();
        }
        root.Descendants().Single(element => element.Name.LocalName == "ObjectSectionList").ReplaceWith(sections);
        var assembly = typeof(AssetsViewModel).Assembly.GetName().Name;
        QualifyNamespaces(root, assembly);
        var sources = XDocument.Load(Path.Combine(shell, "App.xaml")).Descendants(wpf + "ResourceDictionary")
            .Attributes("Source").Select(attribute => attribute.Value);
        root.AddFirst(new XElement(wpf + "UserControl.Resources", new XElement(wpf + "ResourceDictionary",
            new XElement(wpf + "ResourceDictionary.MergedDictionaries", sources.Select(source =>
                new XElement(wpf + "ResourceDictionary", new XAttribute("Source",
                    source.StartsWith("pack:", StringComparison.Ordinal) ? source : $"pack://application:,,,/{assembly};component/{source}")))))));
        var view = (UserControl)XamlReader.Parse(root.ToString());
        view.DataContext = model;
        return view;
    }

    private static void QualifyNamespaces(XElement root, string? assembly)
    {
        foreach (var element in root.DescendantsAndSelf())
        {
            var space = element.Name.NamespaceName;
            if (space.StartsWith("clr-namespace:SecureAD.Shell.", StringComparison.Ordinal) && !space.Contains(";assembly=", StringComparison.Ordinal))
                element.Name = XName.Get(element.Name.LocalName, space + ";assembly=" + assembly);
            foreach (var declaration in element.Attributes().Where(attribute => attribute.IsNamespaceDeclaration
                         && attribute.Value.StartsWith("clr-namespace:SecureAD.Shell.", StringComparison.Ordinal)
                         && !attribute.Value.Contains(";assembly=", StringComparison.Ordinal)))
                declaration.Value += ";assembly=" + assembly;
        }
    }

    internal static void Layout(FrameworkElement view, int width, int height)
    {
        Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);
        view.Measure(new Size(width, height));
        view.Arrange(new Rect(0, 0, width, height));
        view.UpdateLayout();
    }

    internal static void OnSta(Action action)
    {
        var scheduled = new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            var operation = dispatcher.InvokeAsync(() =>
            {
                try { action(); }
                finally { dispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
            });
            scheduled.SetResult(operation.Task);
            Dispatcher.Run();
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "The object-navigation layout check timed out.");
        scheduled.Task.Unwrap().GetAwaiter().GetResult();
    }
}
