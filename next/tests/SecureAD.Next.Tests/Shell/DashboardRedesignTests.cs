using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Markup;
using System.Windows.Media;
using System.Xml.Linq;
using SecureAD.Evidence;
using SecureAD.Evidence.Inventory;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class DashboardRedesignTests
{
    private const string Bundle = @"C:\synthetic-runs\dashboard";

    [Theory]
    [InlineData(DomainReadOutcome.Read, "Read")]
    [InlineData(DomainReadOutcome.PartiallyRead, "Partially read")]
    [InlineData(DomainReadOutcome.NotRead, "Not read")]
    [InlineData(DomainReadOutcome.ExcludedByChoice, "Excluded by choice")]
    [InlineData(DomainReadOutcome.ExcludedForWantOfCandidates, "No writable controller")]
    public void DomainBadgesDescribeTheSavedOutcomeWithoutInventingCounts(DomainReadOutcome outcome, string status)
    {
        var coverage = outcome switch
        {
            DomainReadOutcome.Read => DomainCoverage.Read("example"),
            DomainReadOutcome.ExcludedByChoice => DomainCoverage.Excluded("example", ExclusionKind.ByChoice, "Chosen exclusion"),
            DomainReadOutcome.ExcludedForWantOfCandidates => DomainCoverage.Excluded("example", ExclusionKind.ForWantOfCandidates, "No controller"),
            DomainReadOutcome.PartiallyRead => DomainCoverage.PartiallyRead("example", "Unread evidence"),
            _ => DomainCoverage.NotRead("example", "Unread evidence"),
        };
        var domain = outcome == DomainReadOutcome.Read
            ? DomainInventory.Counted(coverage, ObjectCounts.None, false) : DomainInventory.NotCounted(coverage);
        var row = new DomainInventoryRowViewModel(domain);
        Assert.Equal(status, row.CaptureStatus);
        Assert.Equal(outcome == DomainReadOutcome.Read ? "0" : null, row.Users);
    }

    [Theory]
    [InlineData(0, 0, false, "This forest declares no Group Policy objects.")]
    [InlineData(17, 17, true, "17 of 17 policies read in full")]
    [InlineData(17, 14, true, "14 of 17 policies read in full")]
    public void PolicySummaryPreservesTheExactDenominatorAndZeroState(int declared, int read, bool bar, string expected)
    {
        var (model, _) = Model(false, declared, read);
        Assert.Equal(expected, model.PolicyCoverageSummary);
        Assert.Equal(declared, model.PoliciesDeclaredCount);
        Assert.Equal(read, model.PoliciesReadCount);
        Assert.Equal(bar, model.HasDeclaredPolicies);
        Assert.Equal(read != declared, model.SomePoliciesWereNotRead);
    }

    [Theory]
    [InlineData(0, false, "No unidentified group members reported", false)]
    [InlineData(8, false, "8 groups have unidentified members", true)]
    [InlineData(1, false, "1 group has unidentified members", true)]
    [InlineData(null, false, "Group membership has not been worked out yet", true)]
    [InlineData(0, true, "Saved membership results could not be read.", true)]
    public void MembershipPanelDistinguishesKnownZeroMissingAndFailedDerivation(int? groups, bool fail, string heading, bool limited)
    {
        var (model, source) = Model(false);
        source.GroupsWithUnidentifiedMembers = groups;
        if (fail) source.GroupsWithUnidentifiedMembersFails = Error("Cannot validate membership generation.");
        model.Show(Bundle);
        Assert.Equal(heading, model.MembershipSummary);
        Assert.Equal(limited, model.HasCoverageLimitations);
        Assert.False(string.IsNullOrWhiteSpace(model.MembershipDetail));
        if (limited) Assert.Equal(model.MembershipNotice!.Detail, model.MembershipDetail);
        else Assert.Contains("outside the capture scope", model.MembershipDetail);
    }

    [Fact]
    public void CoverageSummaryAndScopeDisclosureFollowRunChanges()
    {
        var (model, source) = Model(false);
        Assert.Equal("3 of 3 declared domains read", model.DomainCoverageSummary);
        Assert.False(model.HasCoverageLimitations);
        model.ShowsCaptureScope = true;
        source.Inventory = Inventory(true, 17, 14);
        model.Show(Bundle);
        Assert.False(model.ShowsCaptureScope);
        Assert.Equal("2 of 3 declared domains read", model.DomainCoverageSummary);
        Assert.True(model.HasCoverageLimitations);
        model.ShowsCaptureScope = true;
        model.Clear();
        Assert.False(model.ShowsCaptureScope);
        Assert.Empty(model.DomainCoverageSummary);
        Assert.Empty(model.PolicyCoverageSummary);
        Assert.Empty(model.MembershipSummary);
        Assert.Empty(model.MembershipDetail);
        Assert.False(model.HasDeclaredPolicies);
        Assert.False(model.HasCoverageLimitations);
    }

    [Theory]
    [InlineData(1280, 800)]
    [InlineData(1920, 1080)]
    [InlineData(740, 800)]
    public void RealDashboardShowsCoverageBeforeMetricsAndCompactDomainRows(int width, int height) => OnSta(() =>
    {
        var (model, source) = Model(false);
        var view = View(model);
        InWindow(view, width, height, () =>
        {
            var badge = Text(view, nameof(model.DomainCoverageSummary));
            var metrics = new[] { nameof(model.TotalUsers), nameof(model.TotalComputers), nameof(model.TotalGroups), nameof(model.TotalOrganisationalUnits) }
                .Select(name => Text(view, name)).ToArray();
            Assert.Equal(new[] { "2,087", "11", "2,194", "179" }, metrics.Select(text => text.Text));
            Assert.All(metrics, text =>
            {
                Assert.True(text.IsVisible);
                Assert.True(At(text, view).Y > At(badge, view).Y);
                Assert.Equal(32, text.FontSize);
            });
            Assert.Equal(At(metrics[0], view).Y, At(metrics[1], view).Y, 3);
            Assert.Equal(At(metrics[2], view).Y, At(metrics[3], view).Y, 3);
            if (width >= 1200) Assert.Equal(At(metrics[0], view).Y, At(metrics[2], view).Y, 3);
            else Assert.True(At(metrics[2], view).Y > At(metrics[0], view).Y);
            Assert.NotEqual(((SolidColorBrush)view.Background).Color, Colors.White);
            var table = Assert.Single(Descendants<DataGrid>(view));
            Assert.Equal(3, table.Items.Count);
            Assert.Equal(new[] { "Domain", "Capture status", "Users", "Computers", "Groups", "OUs" }, table.Columns.Select(column => column.Header));
            Assert.True(table.ActualHeight < 230);
            Assert.All(Descendants<DataGridRow>(table), row => Assert.Equal(Visibility.Collapsed, row.DetailsVisibility));
            var expander = Assert.Single(Descendants<Expander>(view));
            Assert.False(expander.IsExpanded);
            expander.IsExpanded = true;
            Layout(view, width, height);
            Assert.True(model.ShowsCaptureScope);
            Assert.Equal(model.ObjectClassScopeStatement, Text(view, nameof(model.ObjectClassScopeStatement)).Text);
            Assert.True(Text(view, nameof(model.ObjectClassScopeStatement)).IsVisible);
            Assert.Equal(1, source.InventoryReads);
            Assert.Equal(0, source.FindingsReads);
            Assert.Empty(source.ControlQueries);
            var bar = Assert.Single(Descendants<ProgressBar>(view));
            Assert.Equal(17, bar.Maximum);
            Assert.Equal(17, bar.Value);
        });
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DomainGapsRemainVisibleWithoutCountCellsAndWarningsCannotHideInScopeDetails(bool noController) => OnSta(() =>
    {
        var (model, source) = Model(true, 17, 14, noController);
        source.GroupsWithUnidentifiedMembers = 8;
        model.Show(Bundle);
        var view = View(model);
        InWindow(view, 1280, 1000, () =>
        {
            Assert.Equal("2 of 3 declared domains read", Text(view, nameof(model.DomainCoverageSummary)).Text);
            Assert.Equal("2,053", Text(view, nameof(model.TotalUsers)).Text);
            var table = Assert.Single(Descendants<DataGrid>(view));
            var uncounted = Assert.Single(model.Domains, domain => !domain.CountsAreShown);
            var row = Assert.IsType<DataGridRow>(table.ItemContainerGenerator.ContainerFromItem(uncounted));
            Assert.Equal(Visibility.Visible, row.DetailsVisibility);
            Assert.Contains(Descendants<TextBlock>(row), text => text.Text == uncounted.Explanation && text.IsVisible);
            Assert.Null(uncounted.Users);
            Assert.Equal(noController ? "No writable controller" : "Excluded by choice", uncounted.CaptureStatus);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == "Some captured evidence needs qualification" && text.IsVisible);
            Assert.True(Text(view, nameof(model.MembershipSummary)).IsVisible);
            Assert.Equal(model.ConfidentialCaveat!.Detail, Text(view, "ConfidentialCaveat.Detail").Text);
            Assert.False(Assert.Single(Descendants<Expander>(view)).IsExpanded);
            if (noController)
                Assert.True(At(Text(view, "Warning.Title"), view).Y < At(Text(view, nameof(model.DomainCoverageSummary)), view).Y);
            var bar = Assert.Single(Descendants<ProgressBar>(view));
            Assert.Equal(14, bar.Value);
            Assert.Equal(17, bar.Maximum);
            Assert.Contains("3 could not be read", Text(view, nameof(model.Policies)).Text);
        });
    });

    [Fact]
    public void AllUncountedAndZeroPolicyStatesDoNotRenderInventedMetrics() => OnSta(() =>
    {
        var (model, source) = Model(false, 0, 0);
        source.Inventory = ForestInventory.Of("contoso.example",
            [DomainInventory.NotCounted(DomainCoverage.Excluded("contoso.example", ExclusionKind.ByChoice, "Excluded"))], 0, 0, []);
        model.Show(Bundle);
        var view = View(model);
        InWindow(view, 1000, 750, () =>
        {
            Assert.False(Text(view, nameof(model.TotalUsers)).IsVisible);
            Assert.Contains("nothing to total", Text(view, nameof(model.TotalsCover)).Text);
            Assert.False(Assert.Single(Descendants<ProgressBar>(view)).IsVisible);
            Assert.Equal("This forest declares no Group Policy objects.", Text(view, nameof(model.PolicyCoverageSummary)).Text);
            Assert.Equal("0 of 1 declared domains read", Text(view, nameof(model.DomainCoverageSummary)).Text);
        });
    });

    [Fact]
    public async Task LoadingAndRefusalHideThePreviousDashboard()
    {
        var (model, source) = Model(false);
        var notifications = new List<string?>();
        model.PropertyChanged += (_, args) => notifications.Add(args.PropertyName);
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = async (value, token) => { await completion.Task.WaitAsync(token); return value; };
        source.InventoryFails = Error("Inventory identity mismatch.");
        model.Show(Bundle);
        Assert.True(model.IsLoading);
        Assert.False(model.HasRun);
        Assert.Empty(model.DomainCoverageSummary);
        completion.SetResult();
        await model.ReadCompletion;
        Assert.True(model.HasRefusal);
        Assert.False(model.HasRun);
        Assert.Empty(model.MembershipSummary);
        Assert.Contains(nameof(model.DomainCoverageSummary), notifications);
        Assert.Contains(nameof(model.MembershipSummary), notifications);
        Assert.Contains(nameof(model.PolicyCoverageSummary), notifications);
    }

    internal static (DashboardViewModel, FakeAssetSource) Model(bool incomplete, int declared = 17, int read = 17, bool noController = false)
    {
        var source = new FakeAssetSource { Inventory = Inventory(incomplete, declared, read, noController), GroupsWithUnidentifiedMembers = 0 };
        var model = new DashboardViewModel(source);
        model.Show(Bundle);
        return (model, source);
    }

    private static ForestInventory Inventory(bool incomplete, int declared, int read, bool noController = false) => ForestInventory.Of(
        "contoso.example",
        [
            DomainInventory.Counted(DomainCoverage.Read("contoso.example"), new(6, 3, 50, 4), incomplete),
            DomainInventory.Counted(DomainCoverage.Read("emea.contoso.example"), new(2047, 4, 2093, 169), false),
            incomplete
                ? DomainInventory.NotCounted(DomainCoverage.Excluded("apac.contoso.example",
                    noController ? ExclusionKind.ForWantOfCandidates : ExclusionKind.ByChoice, "Recorded reason."))
                : DomainInventory.Counted(DomainCoverage.Read("apac.contoso.example"), new(34, 4, 51, 6), false),
        ], declared, read, ["dnsNode", "dnsZone"]);

    private static AuditError Error(string message) => AuditError.Create(ErrorCategory.Shell, "SyntheticDashboardFailure", ErrorSeverity.Failed, message, Bundle);

    internal static UserControl View(DashboardViewModel model)
    {
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var root = XDocument.Load(Path.Combine(shell, "Views", "DashboardView.xaml")).Root!;
        root.Attribute(xaml + "Class")!.Remove();
        root.Attribute(xaml + "ClassModifier")!.Remove();
        var assembly = typeof(DashboardViewModel).Assembly.GetName().Name;
        var resources = new XElement(wpf + "UserControl.Resources", new XElement(wpf + "ResourceDictionary",
            new XElement(wpf + "ResourceDictionary.MergedDictionaries",
                XDocument.Load(Path.Combine(shell, "App.xaml")).Descendants(wpf + "ResourceDictionary").Attributes("Source")
                    .Where(attribute => !attribute.Value.StartsWith("Views/", StringComparison.Ordinal))
                    .Select(attribute => new XElement(wpf + "ResourceDictionary", new XAttribute("Source",
                        attribute.Value.StartsWith("pack:", StringComparison.Ordinal) ? attribute.Value
                        : $"pack://application:,,,/{assembly};component/" + attribute.Value))))));
        root.AddFirst(resources);
        var view = (UserControl)XamlReader.Parse(root.ToString());
        view.DataContext = model;
        return view;
    }

    internal static void InWindow(UserControl view, int width, int height, Action assertions)
    {
        var window = new Window { Content = view, Width = width, Height = height, WindowStyle = WindowStyle.None,
            ShowInTaskbar = false, Left = -10000, Top = -10000 };
        window.Show();
        try { Layout(view, width, height); assertions(); }
        finally { window.Close(); }
    }

    private static TextBlock Text(DependencyObject view, string binding) => Assert.Single(Descendants<TextBlock>(view),
        text => BindingOperations.GetBinding(text, TextBlock.TextProperty)?.Path.Path == binding);

    private static Point At(FrameworkElement child, Visual ancestor) => child.TransformToAncestor(ancestor).Transform(new Point());
}
