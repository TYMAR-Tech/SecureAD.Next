using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Threading;
using System.Xml.Linq;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Security;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class FindingsViewTests
{
    internal static void VerifySavedLapsRowsRender(AssetsViewModel model) => OnSta(() =>
    {
        var view = View(model, "LapsInventoryView.xaml");
        foreach (var width in new[] { 900, 1300 })
        {
            Layout(view, width, 700);
            var grid = Assert.Single(Descendants<DataGrid>(view));
            Assert.Equal(model.LapsComputers.Count, grid.Items.Count);
            Assert.True(grid.ActualHeight >= 50);
            var previous = Assert.Single(Descendants<Button>(view), button => Equals(button.Content, "Previous"));
            var next = Assert.Single(Descendants<Button>(view), button => Equals(button.Content, "Next"));
            Assert.Same(model.PreviousLapsCommand, previous.Command);
            Assert.Same(model.NextLapsCommand, next.Command);
            Assert.Equal(model.HasEarlierLaps, previous.IsEnabled);
            Assert.Equal(model.HasMoreLaps, next.IsEnabled);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == "Page " + model.LapsPageNumber);
            Assert.Contains(Descendants<TextBox>(view), text =>
                Equals(text.ToolTip, "Filter computers in the selected scope by computer or domain."));
        }
        model.Suspend();
    });

    internal static void VerifySavedRowsRender(AssetsViewModel model) => OnSta(() =>
    {
        var view = View(model);
        Layout(view, 900, 430);
        var grid = Assert.Single(Descendants<DataGrid>(view));
        Assert.Equal(model.Findings.Count, grid.Items.Count);
        Assert.True(grid.ActualHeight >= 50);
        if (model.Findings.Count == 0) return;
        var row = model.Findings[0];
        model.SelectedFinding = row;
        Layout(view, 900, 430);
        Assert.Same(row, grid.SelectedItem);
        Assert.False(model.HasFindingPresentation);
        Assert.Empty(Descendants<Expander>(view));
        model.CloseFindingDetails();
        Assert.Same(row, model.SelectedFinding);
        model.Suspend();
    });

    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    public void SummaryGridHasShortTitlesAndNoAutomaticExplanation(int width, int height) => OnSta(() =>
    {
        var (model, source) = Model();
        var view = View(model);
        var grid = Assert.Single(Descendants<DataGrid>(view));
        model.SelectedFinding = model.Findings[0];
        Layout(view, width, height);
        Assert.Equal(new[] { "Severity", "Finding", "Principal", "Affected object", "Domain", "Coverage" },
            grid.Columns.Select(column => column.Header));
        Assert.Same(model.OpenFindingCommand, GridRowAction.GetCommand(grid));
        Assert.Same(model.SelectedFinding, grid.SelectedItem);
        Assert.False(model.HasFindingPresentation);
        Assert.Empty(source.FindingSelections);
        Assert.Empty(Descendants<Expander>(view));
        Assert.DoesNotContain(Descendants<TextBox>(view), text => text.Text == model.Findings[0].Detail);
        Assert.Contains(Descendants<TextBlock>(view), text => text.Text == model.Findings[0].FindingTitle);
        Assert.Contains(Descendants<TextBlock>(view), text => text.Text == model.Findings[0].Rule);
        var panel = Assert.IsType<DockPanel>(grid.Parent);
        var occupied = panel.Children.OfType<FrameworkElement>()
            .Where(child => child != grid && child.Visibility != Visibility.Collapsed)
            .Sum(child => child.ActualHeight + child.Margin.Top + child.Margin.Bottom);
        Assert.True(grid.ActualHeight >= 50);
        Assert.Equal(panel.ActualHeight - occupied, grid.ActualHeight, 1);
    });

    [Fact]
    public void RowGestureUsesTheClickedRowRatherThanTheEarlierSelection() => OnSta(() =>
    {
        var (model, source) = Model();
        source.FindingsPage = source.FindingsPage with
        {
            Findings = [source.FindingsPage.Findings[0], ObjectFindingsPagingTests.Finding(2)],
        };
        model.Read();
        var view = View(model);
        var grid = Assert.Single(Descendants<DataGrid>(view));
        model.SelectedFinding = model.Findings[0];
        Layout(view, 900, 430);
        var clicked = Assert.IsType<DataGridRow>(grid.ItemContainerGenerator.ContainerFromIndex(1));
        grid.RaiseEvent(DoubleClick(clicked));
        Assert.Same(model.Findings[1], model.SelectedFinding);
        Assert.Equal(model.Findings[1].Saved.Reference, Assert.Single(source.FindingSelections).Reference);
        Assert.Equal(model.Findings[1].Detail, model.FindingDetails!.Finding!.Detail);
        model.CloseFindingDetails();
        var header = Descendants<DataGridColumnHeader>(grid).First();
        grid.RaiseEvent(DoubleClick(header));
        Assert.False(model.HasFindingPresentation);
        Assert.Single(source.FindingSelections);
    });

    [Theory]
    [InlineData("FindingDetails.Finding.WhyItMatters")]
    [InlineData("FindingDetails.Finding.WhatToDo")]
    public void GuidanceKeepsReadableBodyText(string path) => OnSta(() =>
    {
        var (model, _) = Model();
        model.OpenFinding(model.Findings[0]);
        var view = View(model, "FindingDetailView.xaml");
        Layout(view, 900, 430);
        var text = BoundText(view, path);
        var finding = model.FindingDetails!.Finding!;
        Assert.Equal(path.EndsWith("WhyItMatters", StringComparison.Ordinal) ? finding.WhyItMatters : finding.WhatToDo, text.Text);
        Assert.Equal(((SolidColorBrush)view.FindResource("PrimaryTextBrush")).Color,
            Assert.IsType<SolidColorBrush>(text.Foreground).Color);
        Assert.Equal(TextWrapping.Wrap, text.TextWrapping);
        Assert.True(text.FontSize >= (double)view.FindResource("BodyFontSize"));
    });

    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    public void ObjectGridUsesTheSameExactFindingAction(int width, int height) => OnSta(() =>
    {
        var (model, source) = Model();
        var selected = model.Findings[0];
        source.Attributes = FakeAssetSource.CapturedObject(selected.DistinguishedName, "user") with { ObjectGuid = selected.Saved.ObjectGuid };
        model.OpenFinding(selected);
        model.OpenAffectedObjectCommand.Execute(null);
        Assert.True(model.ObjectReadCompletion.IsCompletedSuccessfully);
        var opened = model.Opened!;
        opened.Show(ObjectSectionCatalog.Findings);
        Assert.True(opened.ReadCompletion.IsCompletedSuccessfully);
        model.CloseFindingDetails();
        var view = ObjectNavigationViewTests.ObjectView(model);
        Layout(view, width, height);
        var grid = Assert.Single(Descendants<DataGrid>(view));
        Assert.Same(model.OpenFindingCommand, GridRowAction.GetCommand(grid));
        var row = Assert.IsType<DataGridRow>(grid.ItemContainerGenerator.ContainerFromIndex(0));
        grid.RaiseEvent(DoubleClick(row));
        Assert.Equal(selected.Saved.Reference, model.FindingDetails!.Finding!.Saved.Reference);
        Assert.Same(opened, model.Opened);
        model.CloseFindingDetails();
        Assert.Same(Assert.Single(Assert.IsType<FindingsSectionViewModel>(opened.Content).Findings), grid.SelectedItem);
    });

    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    public void WindowContentScrollsWhileItsActionsRemainVisible(int width, int height) => OnSta(() =>
    {
        var (model, source) = Model();
        var longFinding = GenericServiceFinding(source.FindingsPage.Findings[0]) with
        {
            Detail = string.Join(Environment.NewLine, Enumerable.Range(1, 80).Select(index => $"Recorded observation {index}: retain this saved explanation.")),
        };
        source.FindingsPage = source.FindingsPage with
        {
            Findings = [longFinding],
        };
        source.FilterValues = new([longFinding.Severity], [longFinding.RuleId], 1);
        model.Read();
        model.SelectedFinding = model.Findings[0];
        model.OpenFinding(model.SelectedFinding);
        var view = View(model, "FindingDetailView.xaml");
        Layout(view, width, height);
        var scroll = (ScrollViewer)view.FindName("FindingDetailsScroll");
        Assert.True(scroll.ScrollableHeight > 0);
        foreach (var heading in new[] { "Finding", "Why it matters", "What to do" })
            Assert.Equal(FontWeights.SemiBold,
                Assert.Single(Descendants<TextBlock>(scroll), text => text.Text == heading).FontWeight);
        var close = Assert.Single(Descendants<Button>(view), button => Equals(button.Content, "Close"));
        var open = Assert.Single(Descendants<Button>(view), button => Equals(button.Content, "Open affected object"));
        Assert.Same(model.CloseFindingDetailsCommand, close.Command);
        Assert.Same(model.OpenAffectedObjectCommand, open.Command);
        Assert.DoesNotContain(close, Descendants<Button>(scroll));
        foreach (var button in new[] { close, open })
        {
            var bounds = button.TransformToAncestor(view).TransformBounds(new Rect(0, 0, button.ActualWidth, button.ActualHeight));
            Assert.True(bounds.Top >= 0 && bounds.Bottom <= height);
        }
        scroll.ScrollToEnd();
        Layout(view, width, height);
        Assert.True(scroll.VerticalOffset > 0);
        Assert.Equal(model.FindingDetails!.Finding!.MicrosoftReference,
            BoundText(scroll, "FindingDetails.Finding.MicrosoftReference").Text);
        var rows = model.Findings.ToArray();
        var reads = source.FindingsReads;
        ((IInvokeProvider)new ButtonAutomationPeer(close).GetPattern(PatternInterface.Invoke)!).Invoke();
        Layout(view, width, height);
        Assert.False(model.HasFindingPresentation);
        Assert.Same(rows[0], model.SelectedFinding);
        Assert.Equal(rows, model.Findings.ToArray());
        Assert.Equal(reads, source.FindingsReads);
    });

    [Fact]
    public void MembershipTextIsAbsentUntilTheExplicitAction() => OnSta(() =>
    {
        var finding = ServiceRegistrationDetailTests.Finding(ObjectFindingsPagingTests.Finding(1));
        var (model, source) = Model(finding);
        ServiceRegistrationDetailTests.Configure(source, model.Findings[0].Saved);
        model.OpenFinding(model.Findings[0]);
        var view = View(model, "FindingDetailView.xaml");
        Layout(view, 900, 430);
        Assert.False(Assert.Single(source.FindingSelections).Membership);
        Assert.Null(model.FindingDetails!.ServiceRegistration!.Memberships);
        var action = Assert.Single(Descendants<Button>(view), button => Equals(button.Content, "View membership evidence"));
        Assert.True(action.IsEnabled);
        ((IInvokeProvider)new ButtonAutomationPeer(action).GetPattern(PatternInterface.Invoke)!).Invoke();
        Layout(view, 900, 430);
        Assert.Equal(new[] { false }, source.FindingSelections.Select(read => read.Membership));
        Assert.Equal(new[] { "names", "groups" }, source.ServiceReads);
        Assert.Contains("routes were not derived", model.FindingDetails.ServiceRegistration.MembershipCompleteness, StringComparison.Ordinal);
        Assert.Equal(model.FindingDetails.ServiceRegistration.MembershipCompleteness, BoundText(view, "FindingDetails.ServiceRegistration.MembershipCompleteness").Text);
        Assert.False(action.IsEnabled);
    });

    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    public void Sec071KeepsItsSummaryAndExistingSavedRouteAction(int width, int height) => OnSta(() =>
    {
        var generation = Guid.NewGuid();
        var account = Guid.NewGuid();
        var seal = new string('a', 64);
        var finding = new Finding("SEC-071", 1, Severity.High,
            new(FindingSubjectKind.Account, account.ToString("D")), account, "CN=Alice,DC=contoso,DC=com",
            "contoso.com", "user", "Unexpected route", EvidenceCompleteness.Complete,
            new Tier0RouteFindingEvidence(generation, null, seal, seal, "Tier0ControlPlane", account,
                "S-1-5-21-1-2-3-1100", "CN=Alice,DC=contoso,DC=com", 1, seal)) { PrincipalName = "Alice" };
        var (model, source) = Model(finding);
        source.Tier0Summary = SecureAD.Kernel.Result<Tier0FindingSummary?>.Success(
            new(1, generation, null, seal, seal, 1, PathRiskAvailability.Recorded, RuleExecutionOutcome.Succeeded, 9, 7, 0));
        model.RuleFilter = "SEC-071";
        var main = View(model);
        Layout(main, width, height);
        Assert.Contains("Accounts with SEC-071 findings: 7", ((TextBlock)main.FindName("Tier0FindingSummary")).Text);
        model.OpenFinding(model.Findings[0]);
        var detail = View(model, "FindingDetailView.xaml");
        Layout(detail, width, height);
        var action = Assert.Single(Descendants<Button>(detail), button => Equals(button.Content, "View saved routes"));
        Assert.Equal(Visibility.Visible, action.Visibility);
        Assert.Same(model.OpenSavedRoutesCommand, action.Command);
        Assert.Same(model.FindingDetails!.Finding, action.CommandParameter);
    });

    internal static Finding GenericServiceFinding(Finding original)
    {
        var definition = new ServiceAccountWithNonExpiringPassword().Definition;
        var account = new ServiceAccountAssociation(original.ObjectGuid, original.DistinguishedName, original.DomainFqdn,
            DateTimeOffset.UnixEpoch, original.Coverage, ServiceAccountKind.SpnBearingUser,
            [new(0, "top", null), new(1, "person", null), new(2, "user", null)],
            [new(0, "HTTP/service", null)], [new(0, "66048", null)], 66048, []);
        return original with { RuleId = definition.Id, RuleVersion = definition.Version, Severity = definition.Severity,
            ObjectClass = "user", Subject = new(FindingSubjectKind.Account, original.ObjectGuid.ToString("D")),
            Evidence = new ServiceAccountFindingEvidence(account, null) };
    }

    private static (AssetsViewModel Model, FakeAssetSource Source) Model(Finding? finding = null)
    {
        const string domain = "DC=contoso,DC=com";
        finding ??= new Finding("SEC-010", 1, Severity.High,
            new FindingSubject(FindingSubjectKind.Account, "svc-web"), Guid.NewGuid(),
            "CN=svc-web," + domain, "contoso.com", "user", "Unconstrained delegation.",
            EvidenceCompleteness.Complete,
            new UnconstrainedDelegationEvidence(0x80000, false, new DomainControllerSignals(false, false, false)));
        var source = new FakeAssetSource
        {
            Tree = new DirectoryTree([new TreeNode(domain, "contoso", null, TreeNodeOrigin.Partition, [])], []),
            FindingsPage = new FindingsPage([finding], new FindingsPageMark(3, finding.RuleId, finding.DistinguishedName, 1), 1),
            FilterValues = new FindingsFilterValues([finding.Severity], [finding.RuleId], 1),
        };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\findings", false);
        return (model, source);
    }

    internal static FrameworkElement View(AssetsViewModel model, string file = "FindingsView.xaml")
    {
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var root = XDocument.Load(Path.Combine(shell, "Views", file)).Root!;
        root.Attribute(xaml + "Class")!.Remove();
        root.Attribute(xaml + "ClassModifier")!.Remove();
        root.Element(wpf + "UserControl.Resources")?.Remove();
        var assembly = typeof(AssetsViewModel).Assembly.GetName().Name;
        var sources = XDocument.Load(Path.Combine(shell, "App.xaml")).Descendants(wpf + "ResourceDictionary")
            .Attributes("Source").Select(attribute => attribute.Value).Where(source => !source.StartsWith("Views/", StringComparison.Ordinal));
        root.AddFirst(new XElement(wpf + "UserControl.Resources", new XElement(wpf + "ResourceDictionary",
            new XElement(wpf + "ResourceDictionary.MergedDictionaries", sources.Select(source => new XElement(wpf + "ResourceDictionary",
                new XAttribute("Source", source.StartsWith("pack:", StringComparison.Ordinal) ? source : $"pack://application:,,,/{assembly};component/" + source)))))));
        using var xml = System.Xml.XmlReader.Create(new StringReader(root.ToString()));
        using var reader = new System.Xaml.XamlXmlReader(xml, XamlReader.GetWpfSchemaContext(), new System.Xaml.XamlXmlReaderSettings
        { LocalAssembly = typeof(AssetsViewModel).Assembly });
        var view = (UserControl)XamlReader.Load(reader);
        view.Foreground = Brushes.White;
        view.DataContext = model;
        Layout(view, 900, 430);
        return view;
    }

    private static TextBlock BoundText(DependencyObject view, string path) => Assert.Single(Descendants<TextBlock>(view),
        text => BindingOperations.GetBinding(text, TextBlock.TextProperty)?.Path.Path == path);

    private static MouseButtonEventArgs DoubleClick(DependencyObject source) => new(Mouse.PrimaryDevice, Environment.TickCount, MouseButton.Left)
    { RoutedEvent = Control.MouseDoubleClickEvent, Source = source };

    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
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
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "The offline findings layout check timed out.");
        scheduled.Task.Unwrap().GetAwaiter().GetResult();
    }
}
