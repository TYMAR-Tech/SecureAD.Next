using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Threading;
using System.Xml.Linq;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Controls;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;
using Xunit.Sdk;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class ControlEdgeSizingTests
{
    private static readonly XNamespace Wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    private static readonly XNamespace Xaml = "http://schemas.microsoft.com/winfx/2006/xaml";

    [Theory]
    [InlineData(900, 430, false)]
    [InlineData(900, 430, true)]
    [InlineData(1300, 650, false)]
    [InlineData(1300, 650, true)]
    [InlineData(1600, 900, false)]
    public void PopulatedTablesRemainReachableAndScrollToTheirLastRows(int width, int height, bool evidenceExpanded)
        => OnSta(() => VerifyPopulated(width, height, evidenceExpanded));

    [Theory]
    [InlineData(900, 520)]
    [InlineData(1300, 720)]
    public void LoadedObjectSectionKeepsWhiteSelectionWhenFocusMovesIntoContent(int width, int height) => OnSta(() =>
    {
        var section = Model(2, 0);
        var completion = new TaskCompletionSource<ObjectSectionViewModel>();
        var opened = new ObjectViewModel(
            "CN=Target,DC=example,DC=invalid",
            "group",
            "group",
            (_, _) => completion.Task);
        opened.Show(ObjectSectionCatalog.ControlEdges);
        var pane = Pane(section, opened: opened);
        var window = new Window
        {
            Content = pane,
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
            Layout(pane, width, height);
            var tabs = Assert.Single(Descendants<ListBox>(pane),
                list => AutomationProperties.GetName(list) == "Object sections");
            var strip = Assert.Single(Descendants<Border>(pane),
                border => border.Name == "ObjectSectionTabStrip");
            Assert.Equal(new CornerRadius(20), strip.CornerRadius);
            Assert.Equal(
                Assert.IsType<SolidColorBrush>(pane.FindResource("RailBackground")).Color,
                Assert.IsType<SolidColorBrush>(strip.Background).Color);
            Assert.Equal(ObjectSectionCatalog.ControlEdges,
                Assert.IsAssignableFrom<ObjectSectionViewModel>(tabs.SelectedItem).Key);

            completion.SetResult(section);
            Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);
            opened.ReadCompletion.GetAwaiter().GetResult();
            Layout(pane, width, height);

            var selected = Assert.IsAssignableFrom<ObjectSectionViewModel>(tabs.SelectedItem);
            Assert.Equal(ObjectSectionCatalog.ControlEdges, selected.Key);
            var item = Assert.IsType<ListBoxItem>(tabs.ItemContainerGenerator.ContainerFromItem(selected));
            item.ApplyTemplate();
            var chrome = Assert.IsType<Border>(item.Template.FindName("ObjectSectionTabChrome", item));
            var selectedBackground = Assert.IsType<SolidColorBrush>(
                pane.FindResource("SelectedObjectTabBackground")).Color;
            var selectedText = Assert.IsType<SolidColorBrush>(
                pane.FindResource("SelectedObjectTabTextBrush")).Color;

            Assert.True(item.IsSelected);
            Assert.Equal(Colors.White, selectedBackground);
            Assert.Equal(Color.FromRgb(18, 22, 26), selectedText);
            Assert.Equal(selectedBackground, Assert.IsType<SolidColorBrush>(chrome.Background).Color);
            Assert.Equal(selectedText, Assert.IsType<SolidColorBrush>(chrome.BorderBrush).Color);
            Assert.Equal(selectedText, Assert.IsType<SolidColorBrush>(item.Foreground).Color);
            Assert.Equal(new Thickness(1), chrome.BorderThickness);
            Assert.Equal(new CornerRadius(18), chrome.CornerRadius);
            var label = Assert.Single(Descendants<TextBlock>(item),
                text => text.Text == "Control edges");
            Assert.Equal(selectedText, Assert.IsType<SolidColorBrush>(label.Foreground).Color);
            var overview = Assert.IsAssignableFrom<ObjectSectionViewModel>(
                tabs.Items.Cast<ObjectSectionViewModel>().Single(section => section.Key == ObjectSectionCatalog.Overview));
            var unselectedItem = Assert.IsType<ListBoxItem>(
                tabs.ItemContainerGenerator.ContainerFromItem(overview));
            unselectedItem.ApplyTemplate();
            var unselectedChrome = Assert.IsType<Border>(
                unselectedItem.Template.FindName("ObjectSectionTabChrome", unselectedItem));
            Assert.Equal(new CornerRadius(18), unselectedChrome.CornerRadius);
            Assert.Equal(
                Assert.IsType<SolidColorBrush>(pane.FindResource("RailSelectedBackground")).Color,
                Assert.IsType<SolidColorBrush>(unselectedChrome.Background).Color);
            Assert.Equal(
                Assert.IsType<SolidColorBrush>(pane.FindResource("RailTextBrush")).Color,
                Assert.IsType<SolidColorBrush>(unselectedItem.Foreground).Color);

            var search = Assert.Single(Descendants<TextBox>(pane), text =>
                BindingOperations.GetBinding(text, TextBox.TextProperty)?.Path.Path == "EdgeSearchText");
            Assert.True(search.Focus());
            Keyboard.Focus(search);
            Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);

            Assert.True(item.IsSelected);
            Assert.Equal(selectedBackground, Assert.IsType<SolidColorBrush>(chrome.Background).Color);
            Assert.Equal(selectedText, Assert.IsType<SolidColorBrush>(chrome.BorderBrush).Color);

            new WpfThemeApplier(pane.Resources).Apply(ThemeVariant.Light);
            Layout(pane, width, height);
            selectedBackground = Assert.IsType<SolidColorBrush>(
                pane.FindResource("SelectedObjectTabBackground")).Color;
            selectedText = Assert.IsType<SolidColorBrush>(
                pane.FindResource("SelectedObjectTabTextBrush")).Color;
            Assert.Equal(Colors.White, selectedBackground);
            Assert.Equal(Color.FromRgb(18, 22, 26), selectedText);
            Assert.Equal(selectedBackground, Assert.IsType<SolidColorBrush>(chrome.Background).Color);
            Assert.Equal(selectedText, Assert.IsType<SolidColorBrush>(chrome.BorderBrush).Color);
            Assert.Equal(selectedText, Assert.IsType<SolidColorBrush>(item.Foreground).Color);
            Assert.Equal(selectedText, Assert.IsType<SolidColorBrush>(label.Foreground).Color);
            Assert.Equal(
                Assert.IsType<SolidColorBrush>(pane.FindResource("RailSelectedBackground")).Color,
                Assert.IsType<SolidColorBrush>(unselectedChrome.Background).Color);
            Assert.Equal(
                Assert.IsType<SolidColorBrush>(pane.FindResource("RailTextBrush")).Color,
                Assert.IsType<SolidColorBrush>(unselectedItem.Foreground).Color);
            Assert.Equal(
                Assert.IsType<SolidColorBrush>(pane.FindResource("RailBackground")).Color,
                Assert.IsType<SolidColorBrush>(strip.Background).Color);
        }
        finally { window.Close(); }
    });

    [Theory]
    [InlineData(900, false)]
    [InlineData(1300, true)]
    public void SelectedEdgeDetailsMoveBesideTheListOnlyWhenWidthAllows(int width, bool beside) => OnSta(() =>
    {
        var pane = Pane(Model(2, 0));
        Layout(pane, width, 650);
        var control = Tables(pane).Control;
        var detail = Assert.Single(Descendants<Expander>(pane), item => item.Name == "ControlEvidence");
        detail.IsExpanded = true;
        Layout(pane, width, 650);

        var controlLeft = control.TranslatePoint(new(), pane).X;
        var detailLeft = detail.TranslatePoint(new(), pane).X;
        var controlTop = control.TranslatePoint(new(), pane).Y;
        var detailTop = detail.TranslatePoint(new(), pane).Y;
        if (beside)
        {
            Assert.True(detailLeft > controlLeft + control.ActualWidth);
            Assert.True(detailTop < controlTop + control.ActualHeight);
        }
        else
        {
            Assert.InRange(Math.Abs(detailLeft - controlLeft), 0, 12);
            Assert.True(detailTop >= controlTop + control.ActualHeight);
        }
    });

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void ShortRequesterListsFollowTheirNoticeWithoutWastedHeight(int count) => OnSta(() =>
    {
        var vm = Model(2, count);
        vm.ShowsRequesterDetails = true;
        var pane = Pane(vm);
        Layout(pane, 1300, 900);
        var requester = Tables(pane).Requester;
        var notice = Notice(pane, nameof(vm.RequesterCoverage));
        Assert.Equal(count, requester.Items.Count);
        Assert.Equal(vm.RequesterCoverage, notice.Text);
        var gap = Top(requester, pane) - Top(notice, pane) - notice.ActualHeight;
        Assert.InRange(gap, 0, 8);
        Assert.True(requester.ActualHeight < 180, $"A {count}-row table unnecessarily occupies {requester.ActualHeight} units.");
        if (count > 0)
        {
            var row = Assert.IsType<DataGridRow>(requester.ItemContainerGenerator.ContainerFromIndex(count - 1));
            Assert.InRange(row.ActualHeight, 16, requester.ActualHeight);
            AssertInside(row, requester);
        }
    });

    [Fact]
    public void RequesterFailureNoticeRemainsReachableBelowAFullControlPage() => OnSta(() =>
    {
        var vm = Model(60, 0, failRequester: true);
        vm.ShowsRequesterDetails = true;
        var pane = Pane(vm);
        Layout(pane, 900, 430);
        var (control, requester) = Tables(pane);
        Assert.Equal(60, control.Items.Count);
        Assert.Empty(requester.Items);
        var notice = Notice(pane, nameof(vm.RequesterCoverage));
        Assert.Contains("Synthetic requester read failure", notice.Text);
        var outer = SectionScroll(pane, requester);
        outer.ScrollToVerticalOffset(outer.VerticalOffset + Top(notice, outer));
        Layout(pane, 900, 430);
        AssertInside(notice, outer);
        AssertInside(notice, pane);
    });

    [Theory]
    [InlineData("unbounded-control")]
    [InlineData("collapsed-requester")]
    [InlineData("no-section-scroll")]
    public void GeometryAssertionsRejectBrokenLayoutsEvenWhenSizingAttributesRemain(string mutation) => OnSta(() =>
    {
        Assert.ThrowsAny<XunitException>(() => VerifyPopulated(900, 430, true, mutation));
    });

    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    [InlineData(1600, 900)]
    public void SelectedRequesterProofAndPlainAnswersAreReachableInTheRealTemplate(int width, int height)
        => OnSta(() => VerifyRequesterEvidence(width, height));

    [Theory]
    [InlineData("unbound-requester-selection")]
    [InlineData("unbound-requester-evidence")]
    [InlineData("collapsed-requester-evidence")]
    public void RequesterProofChecksRejectBrokenSelectionEvidenceAndLayout(string mutation) => OnSta(() =>
    {
        Assert.ThrowsAny<XunitException>(() => VerifyRequesterEvidence(900, 430, mutation));
    });

    [Fact]
    public void ExpandedRequesterProofClearsWhenTheNextReadFails() => OnSta(() =>
    {
        var (pane, vm, expander, evidence) = VerifyRequesterEvidence(900, 430);
        vm.Configure(true, false,
            (_, _, _) => Result<ControlEdgePage>.Success(new([], 0, 0, 0, 0, true, true, false, 0) { GenerationId = Guid.Empty }),
            _ => Result<SelfMembershipAssessmentSet>.Failure(AuditError.Create(ErrorCategory.Shell, "SyntheticFailure",
                ErrorSeverity.Failed, "Synthetic requester read failure", null)));
        Layout(pane, 900, 430);
        Assert.Null(vm.SelectedRequesterAssessment);
        Assert.Empty(evidence.Text);
        Assert.Equal(Visibility.Collapsed, expander.Visibility);
        Assert.Equal("Synthetic requester read failure", Notice(pane, nameof(vm.RequesterCoverage)).Text);
    });

    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    [InlineData(1600, 900)]
    public void PasswordResetWordingAndEvidenceBindInTheUnchangedTemplate(int width, int height) => OnSta(() =>
    {
        var edge = Assert.Single(Judgement.PasswordResetControlTests.Evaluate(Judgement.ControlEdgeDeriverTests.Permissions(
            Judgement.PasswordResetControlTests.Reset(0))).Edges);
        VerifyCredentialEvidence(edge, width, height, "Password-reset permission",
            "Permission evidence only. A password reset and subsequent sign-in have not been tested.", "password-reset permission");
    });

    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    [InlineData(1600, 900)]
    public void KeyCredentialWordingAndEvidenceBindInTheUnchangedTemplate(int width, int height) => OnSta(() =>
    {
        var edge = Assert.Single(Judgement.KeyCredentialLinkControlTests.Evaluate(Judgement.ControlEdgeDeriverTests.Permissions(
            Judgement.KeyCredentialLinkControlTests.Write(0))).Edges);
        VerifyCredentialEvidence(edge, width, height, "Key-credential write permission",
            "Permission evidence only. A key-credential write and subsequent sign-in have not been tested. This does not establish account takeover or a completed path to Tier 0.",
            "key-credential write permission");
    });

    [Theory]
    [InlineData(900, 430, ControlCapability.CanReplicateSecretDomainData, "Secret-data replication permission")]
    [InlineData(1300, 650, ControlCapability.CanReplicateSecretDomainData, "Secret-data replication permission")]
    [InlineData(1600, 900, ControlCapability.CanReplicateSecretDomainData, "Secret-data replication permission")]
    [InlineData(900, 430, ControlCapability.CanReplicateFilteredAttributes, "Filtered-attribute replication permission")]
    [InlineData(1300, 650, ControlCapability.CanReplicateFilteredAttributes, "Filtered-attribute replication permission")]
    [InlineData(1600, 900, ControlCapability.CanReplicateFilteredAttributes, "Filtered-attribute replication permission")]
    public void ReplicationWordingAndProofRemainReachableInTheGroupedTemplate(int width, int height, ControlCapability capability, string label) => OnSta(() =>
    {
        var edge = ReplicationEdges().Single(item => item.Capability == capability);
        VerifyCredentialEvidence(edge, width, height, label,
            "Permission evidence only. No replication operation or credential extraction was performed.", "replication permissions");
    });

    [Fact]
    public void RealTableGroupsReplicationSeparatelyWithoutHidingRows() => OnSta(() =>
    {
        var edges = ReplicationEdges();
        var vm = Model(0, 0);
        var other = edges[0] with { Capability = ControlCapability.CanWriteDacl };
        vm.Configure(true, false,
            (_, _, _) => Result<ControlEdgePage>.Success(new([.. edges, other], 0, 3, 0, 0, true, true, true, 3) { GenerationId = Guid.Empty }),
            _ => Result<SelfMembershipAssessmentSet>.Success(new([], true, Guid.Empty)));
        var pane = Pane(vm);
        Layout(pane, 1300, 650);
        var grid = Tables(pane).Control;
        Assert.Equal(3, grid.Items.Count);
        Assert.Collection(grid.Items.Groups!.Cast<CollectionViewGroup>(),
            group => Assert.Equal(2, group.ItemCount), group => Assert.Equal(1, group.ItemCount));
        Assert.Contains(Descendants<TextBlock>(grid), text => text.Text.StartsWith("Replication permissions —", StringComparison.Ordinal));
        Assert.Contains("groups cover this page only", vm.SupportedScope);
    });

    [Theory]
    [InlineData(900, 430, ControlCapability.IsOwnerAndCanRewriteDacl, "Existing-owner permission control")]
    [InlineData(1300, 650, ControlCapability.IsOwnerAndCanRewriteDacl, "Existing-owner permission control")]
    [InlineData(1600, 900, ControlCapability.IsOwnerAndCanRewriteDacl, "Existing-owner permission control")]
    [InlineData(900, 430, ControlCapability.CanBecomeOwnerAndRewriteDacl, "Owner-change permission control — not verified; not counted")]
    [InlineData(1300, 650, ControlCapability.CanBecomeOwnerAndRewriteDacl, "Owner-change permission control — not verified; not counted")]
    [InlineData(1600, 900, ControlCapability.CanBecomeOwnerAndRewriteDacl, "Owner-change permission control — not verified; not counted")]
    public void OwnershipWordingAndProofRemainReachable(int width, int height, ControlCapability capability, string label) => OnSta(() =>
    {
        var descriptor = capability == ControlCapability.IsOwnerAndCanRewriteDacl
            ? $"O:{Judgement.SelfMembershipDiscoveryTests.UserSid}G:SYD:"
            : $"O:SYG:SYD:(A;;WO;;;{Judgement.SelfMembershipDiscoveryTests.UserSid})";
        var directory = OwnershipWorkflowTests.Prepared(descriptor);
        using var reader = JudgementReader.Open(directory).Value;
        var edge = reader.ReadControlEdges(Judgement.SelfMembershipDiscoveryTests.TargetDn, null, null, true, 0).Edges.Single(item => item.Capability == capability);
        VerifyCredentialEvidence(edge, width, height, label, "No owner or permission change was performed.", "existing-owner permission control");
    });

    private static IReadOnlyList<ControlEdge> ReplicationEdges() => Judgement.ReplicationControlTests.Evaluate(
        Judgement.ControlEdgeDeriverTests.Permissions(Judgement.ReplicationControlTests.Right(0, Judgement.ReplicationControlTests.ChangesGuid),
            Judgement.ReplicationControlTests.Right(1, Judgement.ReplicationControlTests.AllGuid))).Edges;

    private static void VerifyCredentialEvidence(ControlEdge edge, int width, int height, string label, string caveat, string scope)
    {
        var vm = Model(0, 0);
        vm.Configure(true, false,
            (_, _, _) => Result<ControlEdgePage>.Success(new([edge], 0, 1, 0, 0, true, true, false, 1) { GenerationId = Guid.Empty }),
            _ => Result<SelfMembershipAssessmentSet>.Success(new([], true, Guid.Empty)));
        var pane = Pane(vm);
        Layout(pane, width, height);
        var (control, requester) = Tables(pane);
        var row = Assert.IsType<DataGridRow>(control.ItemContainerGenerator.ContainerFromIndex(0));
        Assert.Equal(label, Assert.IsType<TextBlock>(control.Columns[2].GetCellContent(row)).Text);
        Assert.InRange(control.ActualHeight, 120, 240.1);
        AssertInside(row, control);
        var expander = Assert.Single(Descendants<Expander>(pane).Where(item => item.Name == "ControlEvidence"));
        expander.IsExpanded = true;
        Layout(pane, width, height);
        var text = Assert.Single(Descendants<TextBox>(expander));
        Assert.Contains(caveat, text.Text);
        Assert.Equal(vm.SelectedEdge!.Evidence, text.Text);
        var outer = SectionScroll(pane, requester);
        outer.ScrollToVerticalOffset(outer.VerticalOffset + Top(expander, outer));
        Layout(pane, width, height);
        Assert.True(expander.ActualHeight > 0 && Top(expander, pane) < pane.ActualHeight);
        Assert.Contains(scope, vm.SupportedScope);
    }

    private static (FrameworkElement Pane, ControlEdgesSectionViewModel Model, Expander Expander, TextBox Evidence)
        VerifyRequesterEvidence(int width, int height, string? mutation = null)
    {
        var vm = Model(60, 40);
        vm.ShowsRequesterDetails = true;
        var pane = Pane(vm, mutation);
        Layout(pane, width, height);
        var requester = Tables(pane).Requester;
        Assert.Same(vm.RequesterAssessments[0], requester.SelectedItem);
        var selected = vm.RequesterAssessments[^1];
        requester.SelectedItem = selected;
        Descendants<ScrollViewer>(requester).First().ScrollToEnd();
        Layout(pane, width, height);
        Assert.Same(selected, vm.SelectedRequesterAssessment);
        var row = Assert.IsType<DataGridRow>(requester.ItemContainerGenerator.ContainerFromIndex(requester.Items.Count - 1));
        Assert.Equal(new[] { selected.Requester, selected.Target, "Add to group", "Authorized", "Own account only", "Unknown" },
            requester.Columns.Select(column => Assert.IsType<TextBlock>(column.GetCellContent(row)).Text));
        var expander = Assert.Single(Descendants<Expander>(pane).Where(item => item.Name == "RequesterEvidence"));
        Assert.Equal("View selected requester evidence and limitations", expander.Header);
        expander.IsExpanded = true;
        Layout(pane, width, height);
        var evidence = Assert.Single(Descendants<TextBox>(expander));
        Assert.Equal(selected.Evidence, evidence.Text);
        Assert.True(evidence.IsReadOnly);
        var evidenceScroll = Assert.Single(Descendants<ScrollViewer>(expander).Where(scroll => ReferenceEquals(scroll.Content, evidence)));
        Assert.InRange(evidenceScroll.ActualHeight, 1, 240.1);
        Assert.True(expander.ActualHeight > evidenceScroll.ActualHeight);
        Assert.True(evidenceScroll.ScrollableHeight > 0, "Long requester proof must scroll within its bounded area.");
        evidenceScroll.ScrollToEnd();
        var outer = SectionScroll(pane, requester);
        outer.ScrollToVerticalOffset(outer.VerticalOffset + Top(expander, outer));
        Layout(pane, width, height);
        AssertInside(expander, outer);
        AssertInside(expander, pane);
        Assert.InRange(Tables(pane).Control.ActualHeight, 120, 320.1);
        Assert.InRange(requester.ActualHeight, 60, 210.1);
        return (pane, vm, expander, evidence);
    }

    private static void VerifyPopulated(int width, int height, bool expanded, string? mutation = null)
    {
        var vm = Model(60, 40);
        if (mutation == "collapsed-requester") vm.ShowsRequesterDetails = true;
        var pane = Pane(vm, mutation);
        Layout(pane, width, height);
        var expander = Assert.Single(Descendants<Expander>(pane).Where(item => item.Name == "ControlEvidence"));
        expander.IsExpanded = expanded;
        Layout(pane, width, height);
        var (control, requester) = Tables(pane);
        Assert.Equal(60, control.Items.Count);
        Assert.Equal(40, requester.Items.Count);
        Assert.InRange(control.ActualHeight, 120, 320.1);
        if (mutation == "collapsed-requester") Assert.InRange(requester.ActualHeight, 60, 210.1);
        var outer = SectionScroll(pane, requester);
        Assert.True(outer.ViewportHeight > 180, "The object pane leaves no usable table viewport.");
        foreach (var table in new[] { control })
        {
            var scroll = Descendants<ScrollViewer>(table).First();
            Assert.True(scroll.ScrollableHeight > 0, "A full table must scroll instead of growing beyond its pane.");
            scroll.ScrollToEnd();
            Layout(pane, width, height);
            var row = Assert.IsType<DataGridRow>(table.ItemContainerGenerator.ContainerFromIndex(table.Items.Count - 1));
            Assert.InRange(row.ActualHeight, 16, table.ActualHeight);
            AssertInside(row, table);
            var cell = Assert.IsType<TextBlock>(table.Columns[0].GetCellContent(row));
            Assert.Equal(vm.Rows[^1].Holder, cell.Text);
        }
        if (expanded)
        {
            var evidence = Assert.Single(Descendants<TextBox>(expander));
            Assert.Equal(vm.SelectedEdge!.Evidence, evidence.Text);
            outer.ScrollToVerticalOffset(outer.VerticalOffset + Top(expander, outer));
            Layout(pane, width, height);
            Assert.True(evidence.ActualHeight > 0);
            Assert.True(Top(expander, pane) < pane.ActualHeight && Top(expander, pane) + expander.ActualHeight > 0);
        }
        Assert.Contains(Descendants<Button>(pane), button => ReferenceEquals(button.Command, vm.FirstPageCommand));
        Assert.Contains(Descendants<Button>(pane), button => ReferenceEquals(button.Command, vm.NextPageCommand));
        Assert.Equal(vm.AnalysisSummary, Notice(pane, nameof(vm.AnalysisSummary)).Text);
        Assert.Equal(vm.CaptureSummary, Notice(pane, nameof(vm.CaptureSummary)).Text);
        Assert.Equal(vm.UnexpectedSummary, Notice(pane, nameof(vm.UnexpectedSummary)).Text);
        Assert.Equal(vm.ExpectednessUnknownSummary,
            Notice(pane, nameof(vm.ExpectednessUnknownSummary)).Text);
        Assert.Equal(vm.ExpectedSummary, Notice(pane, nameof(vm.ExpectedSummary)).Text);
    }

    private static ControlEdgesSectionViewModel Model(int controls, int requesters, bool failRequester = false)
    {
        var edge = Judgement.GroupMembershipControlTests.Membership(Judgement.ControlEdgeDeriverTests.Permissions(
            Judgement.GroupMembershipControlTests.Scoped(0, 0x28))).Edges.First();
        var assessments = Enumerable.Range(1, requesters).Select(i => new SelfMembershipAssessment(
            new($"CN=Demo user {i:00},DC=example,DC=invalid", "CN=Target,DC=example,DC=invalid", SelfMembershipOperation.Add, null),
            Guid.Empty, null, new('a', 64), Guid.NewGuid(), "S-1-5-21-1-2-3-1", Guid.NewGuid(),
            "S-1-5-21-1-2-3-2", Guid.NewGuid(), "S-1-5-21-1-2-3-1", ControlEvaluationState.Established,
            ControlEvaluationState.Established, ControlEvaluationState.Unknown, "Computed", DateTimeOffset.UnixEpoch,
            512, false, [SelfMembershipIssue.LiveOperationNotEvaluated], [], [9])).ToArray();
        var vm = new ControlEdgesSectionViewModel(new(ObjectSectionCatalog.ControlEdges, "Control edges", []));
        vm.Configure(true, false,
            (_, _, _) => Result<ControlEdgePage>.Success(new(Enumerable.Repeat(edge, controls).ToArray(), 0, controls, 0, 0,
                true, true, true, controls) { GenerationId = Guid.Empty }),
            _ => failRequester
                ? Result<SelfMembershipAssessmentSet>.Failure(AuditError.Create(ErrorCategory.Shell, "SelfMembershipAssessmentsUnreadable",
                    ErrorSeverity.Failed, "Synthetic requester read failure: stored answers could not be read; no requester answer is being shown.", null))
                : Result<SelfMembershipAssessmentSet>.Success(new(assessments, true, Guid.Empty)));
        return vm;
    }

    private static FrameworkElement Pane(
        ControlEdgesSectionViewModel vm,
        string? mutation = null,
        ObjectViewModel? opened = null)
    {
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var template = new XElement(XDocument.Load(Path.Combine(shell, "Views", "Sections", "ObjectSectionTemplates.xaml"))
            .Root!.Elements(Wpf + "DataTemplate").Single(element => (string?)element.Attribute("DataType") == "{x:Type vm:ControlEdgesSectionViewModel}"));
        template.Attribute("DataType")!.Remove();
        var proxy = template.Descendants().Single(element => element.Name.LocalName == "BindingProxy");
        proxy.ReplaceWith(new XElement(Xaml + "Static", new XAttribute(Xaml + "Key", "ControlSection"),
            new XAttribute("Member", "test:ObjectNavigationViewTests.ScreenProxy")));
        var control = template.Descendants(Wpf + "DataGrid")
            .Single(element => (string?)element.Attribute(Xaml + "Name") == "ControlPermissions");
        var requester = template.Descendants(Wpf + "DataGrid")
            .Single(element => (string?)element.Attribute(Xaml + "Name") == "RequesterAssessmentsTable");
        if (mutation == "unbound-full-control-count") template.Descendants(Wpf + "TextBlock")
            .Single(element => (string?)element.Attribute("Text") == "{Binding SelectedEdge.CountStatus}").Attribute("Text")!.Remove();
        if (mutation == "unbounded-control") control.Attribute("MaxHeight")?.Remove();
        if (mutation == "collapsed-requester") requester.SetAttributeValue("Height", "0");
        if (mutation == "unbound-requester-selection") requester.Attribute("SelectedItem")!.Remove();
        var requesterEvidence = template.Descendants(Wpf + "Expander")
            .Single(element => (string?)element.Attribute(Xaml + "Name") == "RequesterEvidence");
        if (mutation == "unbound-requester-evidence") requesterEvidence.Descendants(Wpf + "TextBox").Single().Attribute("Text")!.Remove();
        if (mutation == "collapsed-requester-evidence") requesterEvidence.SetAttributeValue("Height", "0");
        if (mutation == "no-section-scroll")
        {
            var scroll = template.Descendants(Wpf + "ScrollViewer")
                .Single(element => (string?)element.Attribute(Xaml + "Name") == "ControlEdgesScroll");
            var replacement = new XElement(scroll.Elements().Single(element => element.Name != Wpf + "ScrollViewer.Resources"));
            replacement.AddFirst(new XElement(Wpf + "StackPanel.Resources",
                scroll.Element(Wpf + "ScrollViewer.Resources")!.Elements()));
            scroll.ReplaceWith(replacement);
        }
        var objectView = XDocument.Load(Path.Combine(shell, "Views", "ObjectView.xaml")).Root!;
        objectView.Attribute(Xaml + "Class")!.Remove();
        objectView.Attribute(Xaml + "ClassModifier")!.Remove();
        var sectionList = XDocument.Load(Path.Combine(shell, "Views", "ObjectSectionList.xaml")).Root!;
        sectionList.Attribute(Xaml + "Class")!.Remove();
        sectionList.Attribute(Xaml + "ClassModifier")!.Remove();
        foreach (var copy in sectionList.Descendants().Where(element => element.Name.LocalName == "CopyValueButton").ToArray())
        {
            copy.Name = Wpf + "Button";
            copy.Attribute("Text")?.Remove();
        }
        var sectionHost = Assert.Single(objectView.Descendants().Where(element => element.Name.LocalName == "ObjectSectionList"));
        foreach (var attribute in sectionHost.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration))
            sectionList.SetAttributeValue(attribute.Name, attribute.Value);
        sectionHost.ReplaceWith(sectionList);
        objectView.Descendants(Wpf + "ContentControl").Single().Add(new XElement(Wpf + "ContentControl.ContentTemplate", template));
        objectView.Attribute("Grid.Column")?.Remove();
        var assetsDock = XDocument.Load(Path.Combine(shell, "Views", "AssetsView.xaml")).Root!.Element(Wpf + "DockPanel")!;
        var sources = XDocument.Load(Path.Combine(shell, "App.xaml")).Descendants(Wpf + "ResourceDictionary")
            .Attributes("Source").Select(attribute => attribute.Value).Where(source => !source.StartsWith("Views/", StringComparison.Ordinal));
        var assemblyName = typeof(ControlEdgesSectionViewModel).Assembly.GetName().Name;
        var dictionaries = sources.Select(source => new XElement(Wpf + "ResourceDictionary", new XAttribute("Source",
            source.StartsWith("pack:", StringComparison.Ordinal) ? source : $"pack://application:,,,/{assemblyName};component/" + source)));
        var root = new XElement(Wpf + "UserControl", new XAttribute(XNamespace.Xmlns + "x", Xaml.NamespaceName),
            new XAttribute(XNamespace.Xmlns + "test",
                "clr-namespace:SecureAD.Next.Tests.Shell;assembly=" + typeof(ControlEdgeSizingTests).Assembly.GetName().Name),
            new XElement(Wpf + "UserControl.Resources", new XElement(Wpf + "ResourceDictionary",
                new XElement(Wpf + "ResourceDictionary.MergedDictionaries", dictionaries))),
            new XElement(Wpf + "DockPanel", new XAttribute("Margin", assetsDock.Attribute("Margin")!.Value),
                new XElement(Wpf + "Grid", objectView)));
        var adaptiveMarkup = root.Descendants().Single(element => element.Name.LocalName == "AdaptiveDetailPanel");
        adaptiveMarkup.Name = Wpf + "StackPanel";
        adaptiveMarkup.SetAttributeValue("Orientation", "Vertical");
        adaptiveMarkup.Attribute("Breakpoint")?.Remove();
        adaptiveMarkup.Attribute("Gap")?.Remove();
        var pane = (FrameworkElement)XamlReader.Parse(root.ToString());
        var objectModel = opened ?? new ObjectViewModel("CN=Target,DC=example,DC=invalid", "group", "group",
            (_, _) => Task.FromResult<ObjectSectionViewModel>(vm));
        if (opened is null) objectModel.Show(ObjectSectionCatalog.ControlEdges);
        pane.DataContext = new { Opened = objectModel };
        pane.Measure(new(1600, 900));
        pane.Arrange(new(new(), new Size(1600, 900)));
        pane.UpdateLayout();
        var placeholder = Assert.Single(Descendants<StackPanel>(pane), element => element.Name == "ControlDetailLayout");
        var parent = Assert.IsAssignableFrom<Panel>(VisualTreeHelper.GetParent(placeholder));
        var adaptive = new AdaptiveDetailPanel { Name = placeholder.Name, Breakpoint = 1050, Gap = 12 };
        if (parent is Grid)
        {
            Grid.SetRow(adaptive, Grid.GetRow(placeholder));
            Grid.SetRowSpan(adaptive, Grid.GetRowSpan(placeholder));
        }
        while (placeholder.Children.Count != 0)
        {
            var child = placeholder.Children[0];
            placeholder.Children.RemoveAt(0);
            adaptive.Children.Add(child);
        }
        var position = parent.Children.IndexOf(placeholder);
        parent.Children.RemoveAt(position);
        parent.Children.Insert(position, adaptive);
        return pane;
    }

    private static (DataGrid Control, DataGrid Requester) Tables(DependencyObject pane)
    {
        var tables = Descendants<DataGrid>(pane).Where(table => table.Name is "ControlPermissions" or "RequesterAssessmentsTable").ToArray();
        Assert.Equal(2, tables.Length);
        return (tables[0], tables[1]);
    }

    private static TextBlock Notice(DependencyObject pane, string property) => Assert.Single(Descendants<TextBlock>(pane)
        .Where(text => BindingOperations.GetBinding(text, TextBlock.TextProperty)?.Path.Path == property));

    private static ScrollViewer SectionScroll(DependencyObject pane, DataGrid requester) =>
        Assert.Single(Descendants<ScrollViewer>(pane).Where(scroll => scroll.Name == "ControlEdgesScroll"));

    private static double Top(FrameworkElement element, Visual ancestor) => element.TransformToAncestor(ancestor).Transform(new Point()).Y;

    private static void AssertInside(FrameworkElement element, FrameworkElement ancestor)
    {
        var top = Top(element, ancestor);
        Assert.True(top >= -1 && top + element.ActualHeight <= ancestor.ActualHeight + 1,
            $"{element.GetType().Name} spans {top:F1}..{top + element.ActualHeight:F1} inside {ancestor.GetType().Name} height {ancestor.ActualHeight:F1}.");
    }

    private static void Layout(FrameworkElement pane, int width, int height)
    {
        pane.Measure(new Size(width, height));
        pane.Arrange(new Rect(0, 0, width, height));
        pane.UpdateLayout();
        pane.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
        pane.UpdateLayout();
    }

    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T match) yield return match;
            foreach (var descendant in Descendants<T>(child)) yield return descendant;
        }
    }

    private static void OnSta(Action action)
    {
        Exception? error = null;
        var thread = new Thread(() =>
        {
            try { action(); }
            catch (Exception caught) { error = caught; }
            finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); }
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "The no-window WPF layout check timed out.");
        if (error is not null) ExceptionDispatchInfo.Capture(error).Throw();
    }
}
