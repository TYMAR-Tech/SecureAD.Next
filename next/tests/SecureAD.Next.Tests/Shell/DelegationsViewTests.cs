using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Threading;
using System.Xml.Linq;
using SecureAD.Evidence;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class DelegationsViewTests
{
    [Theory]
    [InlineData(900, 470)]
    [InlineData(1300, 700)]
    public void NestedControlsSubmitGroupModeAndRenderHolderAndChain(int width, int height) => OnSta(() =>
    {
        var (model, source) = DelegationViewModelTests.Model();
        model.IncludeGroupHeldPermissions = true;
        source.Delegations = (query, _) => NestedDelegationViewModelTests.GroupPage(query.Principal);
        var view = View(model);
        var window = new Window { Content = view, Width = width, Height = height, WindowStyle = WindowStyle.None,
            ShowInTaskbar = false, Left = -10000, Top = -10000 };
        window.Show();
        try
        {
            model.DelegationPrincipalSearch = "Helpdesk";
            Invoke(view, DelegationText.FindPrincipal);
            Layout(view, width, height);
            var groups = Assert.Single(Descendants<CheckBox>(view), box => Equals(box.Content, DelegationText.IncludeGroups));
            Assert.True(groups.IsChecked);
            Invoke(view, DelegationText.FindDelegations);
            Layout(view, width, height);
            Assert.True(model.HasDelegationAnswer);
            Assert.True(Assert.Single(source.DelegationQueries).Query.IncludeGroupHeldPermissions);
            var grid = Assert.Single(Descendants<DataGrid>(view));
            var holder = Assert.IsType<DataGridTextColumn>(Assert.Single(grid.Columns, column => Equals(column.Header, DelegationText.PermissionHolder)));
            Assert.Equal(nameof(DelegationRowViewModel.PermissionHeldBy), Assert.IsType<Binding>(holder.Binding).Path.Path);
            grid.SetCurrentValue(Selector.SelectedItemProperty, Assert.Single(model.Delegations));
            Layout(view, width, height);
            Assert.Contains(Descendants<TextBox>(view), box => box.Text.Contains("Membership chain", StringComparison.Ordinal)
                && box.Text.Contains("Operators", StringComparison.Ordinal));
            Assert.True(grid.ActualHeight >= 50, $"Selecting a nested entry leaves only {grid.ActualHeight} pixels for results.");
            groups.SetCurrentValue(ToggleButton.IsCheckedProperty, false);
            Layout(view, width, height);
            Assert.False(model.IncludeGroupHeldPermissions);
            Assert.False(model.HasDelegationAnswer);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == DelegationText.Boundary);
        }
        finally { window.Close(); }
    });

    [Theory]
    [InlineData(900, 470)]
    [InlineData(1300, 700)]
    public void RealControlsKeepDirectOnlyQualificationsAndAUsableResultGrid(int width, int height) => OnSta(() =>
    {
        var (model, source) = DelegationViewModelTests.Model();
        var view = View(model);
        var window = new Window
        {
            Content = view,
            Width = width,
            Height = height,
            WindowStyle = WindowStyle.None,
            ShowInTaskbar = false,
            Left = -10000,
            Top = -10000,
        };
        window.Show();
        try
        {
            var name = Descendants<TextBox>(view).Single(box =>
                BindingOperations.GetBinding(box, TextBox.TextProperty)?.Path.Path == nameof(model.DelegationPrincipalSearch));
            name.Text = "Helpdesk";
            name.GetBindingExpression(TextBox.TextProperty)!.UpdateSource();
            Invoke(view, DelegationText.FindPrincipal);
            Layout(view, width, height);
            var picker = Descendants<ComboBox>(view).Single(box =>
                BindingOperations.GetBinding(box, Selector.SelectedItemProperty)?.Path.Path == nameof(model.SelectedDelegationPrincipal));
            Assert.Same(Assert.Single(model.DelegationPrincipals), picker.SelectedItem);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == DelegationText.MatchingPrincipal && text.IsVisible);
            Assert.True(Button(view, DelegationText.FindDelegations).IsEnabled);
            var filter = Descendants<ComboBox>(view).Single(box =>
                BindingOperations.GetBinding(box, Selector.SelectedItemProperty)?.Path.Path == nameof(model.DelegationPermissionFilter));
            filter.SetCurrentValue(Selector.SelectedItemProperty, model.DelegationPermissions[1]);
            var inherited = Assert.Single(Descendants<CheckBox>(view), box => Equals(box.Content, DelegationText.IncludeInherited));
            inherited.SetCurrentValue(ToggleButton.IsCheckedProperty, true);
            Invoke(view, DelegationText.FindDelegations);
            Layout(view, width, height);

            Assert.True(model.HasDelegationAnswer);
            Assert.True(Assert.Single(source.DelegationQueries).Query.IncludeInherited);
            Assert.Equal(DelegationPermission.ResetPassword, source.DelegationQueries[0].Query.Permission);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == DelegationText.Heading && text.IsVisible);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == DelegationText.Boundary && text.IsVisible);
            var grid = Assert.Single(Descendants<DataGrid>(view));
            Assert.True(grid.ActualHeight >= 70, $"The result grid is only {grid.ActualHeight} pixels tall.");
            Assert.Equal(7, grid.Columns.Count);
            grid.SetCurrentValue(Selector.SelectedItemProperty, model.Delegations[0]);
            Layout(view, width, height);
            Assert.True(Button(view, DelegationText.OpenDetails).IsEnabled);
            Assert.Contains(Descendants<TextBox>(view), text => text.Text.Contains("Original entry position", StringComparison.Ordinal));
            Assert.True(grid.ActualHeight >= 50, $"Selecting an entry leaves only {grid.ActualHeight} pixels for results.");
        }
        finally
        {
            window.Close();
        }
    });

    [Fact]
    public void AssetsActuallyHostsTheDelegationView()
    {
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var root = XDocument.Load(Path.Combine(shell, "Views", "AssetsView.xaml"));
        var view = Assert.Single(root.Descendants().Where(element => element.Name.LocalName == "DelegationsView"));
        Assert.Equal("3", view.Attribute("Grid.ColumnSpan")?.Value);
        Assert.Contains("ShowsDelegationsListing", view.Attribute("Visibility")?.Value);
    }

    private static UserControl View(AssetsViewModel model)
    {
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var root = XDocument.Load(Path.Combine(shell, "Views", "DelegationsView.xaml")).Root!;
        root.Attribute(xaml + "Class")!.Remove();
        root.Attribute(xaml + "ClassModifier")!.Remove();
        var assembly = typeof(AssetsViewModel).Assembly.GetName().Name;
        root.SetAttributeValue(XNamespace.Xmlns + "vm", "clr-namespace:SecureAD.Shell.ViewModels;assembly=" + assembly);
        var sources = XDocument.Load(Path.Combine(shell, "App.xaml")).Descendants(wpf + "ResourceDictionary")
            .Attributes("Source").Select(attribute => attribute.Value).Where(source => !source.StartsWith("Views/", StringComparison.Ordinal));
        root.AddFirst(new XElement(wpf + "UserControl.Resources", new XElement(wpf + "ResourceDictionary",
            new XElement(wpf + "ResourceDictionary.MergedDictionaries", sources.Select(source => new XElement(wpf + "ResourceDictionary",
                new XAttribute("Source", source.StartsWith("pack:", StringComparison.Ordinal) ? source : $"pack://application:,,,/{assembly};component/" + source)))))));
        var view = (UserControl)XamlReader.Parse(root.ToString());
        view.DataContext = model;
        Layout(view, 900, 470);
        return view;
    }

    private static Button Button(DependencyObject view, string text) =>
        Assert.Single(Descendants<Button>(view), button => Equals(button.Content, text));

    private static void Invoke(DependencyObject view, string text) =>
        ((IInvokeProvider)new ButtonAutomationPeer(Button(view, text)).GetPattern(PatternInterface.Invoke)!).Invoke();

    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T value) yield return value;
            foreach (var descendant in Descendants<T>(child)) yield return descendant;
        }
    }

    private static void Layout(FrameworkElement view, int width, int height)
    {
        Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);
        view.Measure(new Size(width, height));
        view.Arrange(new Rect(0, 0, width, height));
        view.UpdateLayout();
    }

    private static void OnSta(Action action)
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
        })
        { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "The offline delegation layout check timed out.");
        scheduled.Task.Unwrap().GetAwaiter().GetResult();
    }
}
