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
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Security;
using SecureAD.Shell.ViewModels;
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
        Assert.Equal(Visibility.Visible, ((Border)view.FindName("FindingDetails")).Visibility);
        Assert.True(((ScrollViewer)view.FindName("FindingDetailsScroll")).ActualHeight >= 30);
        model.CloseFindingDetails();
        Layout(view, 900, 430);
        Assert.Null(grid.SelectedItem);
        Assert.Equal(Visibility.Collapsed, ((Border)view.FindName("FindingDetails")).Visibility);
        model.Suspend();
    });

    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    public void Sec071SummaryAndRouteActionAreVisibleWithoutHidingTheList(int width, int height) => OnSta(() =>
    {
        var (model, source) = Model();
        var generation = Guid.NewGuid();
        var account = Guid.NewGuid();
        var seal = new string('a', 64);
        source.Tier0Summary = SecureAD.Kernel.Result<Tier0FindingSummary?>.Success(
            new(1, generation, null, seal, seal, 1, PathRiskAvailability.Recorded, RuleExecutionOutcome.Succeeded, 9, 7, 0));
        model.RuleFilter = "SEC-071";
        var row = new FindingRowViewModel(new Finding("SEC-071", 1, Severity.High,
            new(FindingSubjectKind.Account, account.ToString("D")), account, "CN=Alice,DC=contoso,DC=com",
            "contoso.com", "user", "Unexpected route", EvidenceCompleteness.Complete,
            new Tier0RouteFindingEvidence(generation, null, seal, seal, "Tier0ControlPlane", account,
                "S-1-5-21-1-2-3-1100", "CN=Alice,DC=contoso,DC=com", 1, seal)) { PrincipalName = "Alice" });
        model.SelectedFinding = row;
        var view = View(model);
        Layout(view, width, height);
        var summary = (TextBlock)view.FindName("Tier0FindingSummary");
        Assert.Contains("Accounts with SEC-071 findings: 7", summary.Text);
        Assert.Contains("Supported checks only; other routes may exist.", summary.Text);
        var button = Assert.Single(Descendants<Button>(view), value => Equals(value.Content, "View saved routes"));
        Assert.Equal(Visibility.Visible, button.Visibility);
        Assert.Same(model.OpenSavedRoutesCommand, button.Command);
        Assert.Same(row, button.CommandParameter);
        Assert.True(Assert.Single(Descendants<DataGrid>(view)).ActualHeight >= 50);
        Assert.True(((ScrollViewer)view.FindName("FindingDetailsScroll")).ActualHeight >= 30);
    });

    [Fact]
    public void CloseDetailsReturnsTheListSpaceWithoutChangingItsQuestion() => OnSta(() =>
    {
        var (model, source) = Model();
        model.SeverityFilter = "High";
        model.RuleFilter = "SEC-010";
        model.NextFindingsCommand.Execute(null);
        var view = View(model);
        var grid = Assert.Single(Descendants<DataGrid>(view));
        var row = model.Findings[0];
        grid.SetCurrentValue(Selector.SelectedItemProperty, row);
        Layout(view, 900, 430);
        Assert.Same(row, model.SelectedFinding);
        var details = (Border)view.FindName("FindingDetails");
        Assert.Equal(Visibility.Visible, details.Visibility);
        var height = grid.ActualHeight;
        var page = model.FindingsPageNumber;
        var container = model.Selected;
        var reads = source.FindingsReads;
        var items = model.Findings.ToArray();
        var button = CloseButton(view);
        Assert.Same(model.CloseFindingDetailsCommand, button.Command);

        ((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)!).Invoke();
        Layout(view, 900, 430);

        Assert.Null(model.SelectedFinding);
        Assert.Null(grid.SelectedItem);
        Assert.Equal(Visibility.Collapsed, details.Visibility);
        Assert.True(grid.ActualHeight > height + 100);
        Assert.Equal(page, model.FindingsPageNumber);
        Assert.Same(container, model.Selected);
        Assert.Equal("High", model.SeverityFilter);
        Assert.Equal("SEC-010", model.RuleFilter);
        Assert.Equal(items, model.Findings.ToArray());
        Assert.Equal(reads, source.FindingsReads);

        grid.SetCurrentValue(Selector.SelectedItemProperty, row);
        Layout(view, 900, 430);
        Assert.Same(row, model.SelectedFinding);
        Assert.Equal(Visibility.Visible, details.Visibility);
    });

    [Theory]
    [InlineData("SelectedFinding.WhyItMatters")]
    [InlineData("SelectedFinding.WhatToDo")]
    [InlineData("SelectedFinding.About")]
    public void GuidanceUsesReadableBodyTextEvenUnderALightInheritedForeground(string path) => OnSta(() =>
    {
        var (model, _) = Model();
        var view = View(model);
        model.SelectedFinding = model.Findings[0];
        Layout(view, 900, 430);
        var text = BoundText(view, path);
        var expected = path switch
        {
            "SelectedFinding.WhyItMatters" => model.SelectedFinding.WhyItMatters,
            "SelectedFinding.WhatToDo" => model.SelectedFinding.WhatToDo,
            _ => model.SelectedFinding.About,
        };

        Assert.False(string.IsNullOrWhiteSpace(expected));
        Assert.Equal(expected, text.Text);
        Assert.Equal(((SolidColorBrush)view.FindResource("PrimaryTextBrush")).Color,
            Assert.IsType<SolidColorBrush>(text.Foreground).Color);
        Assert.Equal(TextWrapping.Wrap, text.TextWrapping);
        Assert.True(text.FontSize >= (double)view.FindResource("BodyFontSize"));
    });

    [Fact]
    public void ExpandedMembershipEvidenceKeepsItsUncertaintyReadable() => OnSta(() =>
    {
        var (model, _) = Model();
        var view = View(model);
        var row = new FindingRowViewModel(new Finding(
            "SEC-021", 2, Severity.Critical, new FindingSubject(FindingSubjectKind.Account, "Alice"), Guid.NewGuid(),
            "CN=Alice,DC=contoso,DC=com", "contoso.com", "user", "Finding", EvidenceCompleteness.Complete,
            new KerberoastableAccountEvidence("S-1-5-21-11-22-33-1100", ["HTTP/service"], 512)
            { MembershipRoutes = MembershipRouteSummary.NotDerived }));
        model.Findings.Add(row);
        model.SelectedFinding = row;
        Layout(view, 900, 430);
        var expander = Assert.Single(Descendants<Expander>(view));
        Assert.Equal(Visibility.Visible, expander.Visibility);
        expander.IsExpanded = true;
        Layout(view, 900, 430);
        var text = BoundText(expander, "SelectedFinding.MembershipCompleteness");

        Assert.Equal(model.SelectedFinding.MembershipCompleteness, text.Text);
        Assert.Contains("routes were not derived", text.Text, StringComparison.Ordinal);
        Assert.Equal(((SolidColorBrush)view.FindResource("PrimaryTextBrush")).Color,
            Assert.IsType<SolidColorBrush>(text.Foreground).Color);
    });

    [Fact]
    public void GuidanceHasThreeDistinctProminentHeadings() => OnSta(() =>
    {
        var (model, _) = Model();
        var view = View(model);
        model.SelectedFinding = model.Findings[0];
        Layout(view, 900, 430);
        string[] headings = ["WHY IT MATTERS", "WHAT TO DO", "WHAT THIS RULE LOOKS FOR"];
        string[] bodies = ["SelectedFinding.WhyItMatters", "SelectedFinding.WhatToDo", "SelectedFinding.About"];
        var scroll = (ScrollViewer)view.FindName("FindingDetailsScroll");
        for (var i = 0; i < headings.Length; i++)
        {
            var heading = Assert.Single(Descendants<TextBlock>(scroll).Where(text => text.Text == headings[i]));
            var body = BoundText(scroll, bodies[i]);
            Assert.Equal(FontWeights.SemiBold, heading.FontWeight);
            Assert.True(heading.FontSize > body.FontSize);
            var top = heading.TransformToAncestor(scroll).Transform(new Point()).Y;
            Assert.True(body.TransformToAncestor(scroll).Transform(new Point()).Y >= top + heading.ActualHeight);
            if (i > 0)
            {
                var previous = BoundText(scroll, bodies[i - 1]);
                Assert.True(top >= previous.TransformToAncestor(scroll).Transform(new Point()).Y + previous.ActualHeight + 12);
            }
        }
    });

    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    [InlineData(1600, 900)]
    public void LongGuidanceScrollsWithoutHidingTheListOrCloseAction(int width, int height) => OnSta(() =>
    {
        var (model, _) = Model();
        var view = View(model);
        model.SelectedFinding = model.Findings[0];
        Layout(view, width, height);
        var scroll = (ScrollViewer)view.FindName("FindingDetailsScroll");
        var grid = Assert.Single(Descendants<DataGrid>(view));
        var button = CloseButton(view);
        Assert.True(grid.ActualHeight >= 50, $"Findings list height: {grid.ActualHeight}");
        Assert.True(scroll.ScrollableHeight > 0);
        Assert.Equal(ScrollBarVisibility.Disabled, scroll.HorizontalScrollBarVisibility);
        Assert.DoesNotContain(button, Descendants<Button>(scroll));
        var buttonTop = button.TransformToAncestor(view).Transform(new Point()).Y;
        Assert.InRange(buttonTop, 0, height - button.ActualHeight);

        scroll.ScrollToEnd();
        Layout(view, width, height);

        Assert.True(scroll.VerticalOffset > 0);
        var reference = BoundText(scroll, "SelectedFinding.MicrosoftReference");
        Assert.Equal(model.SelectedFinding.MicrosoftReference, reference.Text);
        Assert.Equal(Visibility.Visible, reference.Visibility);
        var referenceTop = reference.TransformToAncestor(scroll).Transform(new Point()).Y;
        Assert.True(referenceTop + reference.ActualHeight <= scroll.ActualHeight + 1);
    });

    private static (AssetsViewModel Model, FakeAssetSource Source) Model()
    {
        const string domain = "DC=contoso,DC=com";
        var finding = new Finding("SEC-010", 1, Severity.High,
            new FindingSubject(FindingSubjectKind.Account, "svc-web"), Guid.NewGuid(),
            "CN=svc-web," + domain, "contoso.com", "user", "Unconstrained delegation.",
            EvidenceCompleteness.Complete,
            new UnconstrainedDelegationEvidence(0x80000, false, new DomainControllerSignals(false, false, false)));
        var source = new FakeAssetSource
        {
            Tree = new DirectoryTree([new TreeNode(domain, "contoso", null, TreeNodeOrigin.Partition, [])], []),
            FindingsPage = new FindingsPage([finding], new FindingsPageMark(3, "SEC-010", finding.DistinguishedName, 1), RulesRan: 1),
            FilterValues = new FindingsFilterValues([Severity.High], ["SEC-010"], RulesRan: 1),
        };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\findings", aCaptureIsRunning: false);
        return (model, source);
    }

    private static FrameworkElement View(AssetsViewModel model, string file = "FindingsView.xaml")
    {
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var root = XDocument.Load(Path.Combine(shell, "Views", file)).Root!;
        root.Attribute(xaml + "Class")!.Remove();
        root.Attribute(xaml + "ClassModifier")!.Remove();
        // Only the unused internal column proxy is omitted. Controls and bindings are the actual
        // production view, with its compiled application theme rather than test-specific styles.
        root.Element(wpf + "UserControl.Resources")?.Remove();
        var assembly = typeof(AssetsViewModel).Assembly.GetName().Name;
        var sources = XDocument.Load(Path.Combine(shell, "App.xaml")).Descendants(wpf + "ResourceDictionary")
            .Attributes("Source").Select(attribute => attribute.Value).Where(source => !source.StartsWith("Views/", StringComparison.Ordinal));
        root.AddFirst(new XElement(wpf + "UserControl.Resources", new XElement(wpf + "ResourceDictionary",
            new XElement(wpf + "ResourceDictionary.MergedDictionaries", sources.Select(source => new XElement(wpf + "ResourceDictionary",
                new XAttribute("Source", source.StartsWith("pack:", StringComparison.Ordinal) ? source : $"pack://application:,,,/{assembly};component/" + source)))))));
        var view = (UserControl)XamlReader.Parse(root.ToString());
        view.Foreground = Brushes.White;
        view.DataContext = model;
        Layout(view, 900, 430);
        return view;
    }

    private static Button CloseButton(DependencyObject view) => Assert.Single(Descendants<Button>(view)
        .Where(button => Equals(button.Content, "Close details")));

    private static TextBlock BoundText(DependencyObject view, string path) => Assert.Single(Descendants<TextBlock>(view)
        .Where(text => BindingOperations.GetBinding(text, TextBlock.TextProperty)?.Path.Path == path));

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
