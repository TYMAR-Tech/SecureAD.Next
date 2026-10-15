using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Evidence;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData(900)]
    [InlineData(1300)]
    public void Arch04BrowsingFlowKeepsSearchPagingObjectFindingsAndReturnOnLightweightProducts(int width) =>
        ObjectNavigationViewTests.OnSta(() => OneThread.Run(async () =>
        {
            var directory = BrowsingRun();
            using var counts = new FindingsVerificationCounts(directory);
            using var source = new BundleAssetSource();
            var screen = new AssetsViewModel(source) { Pane = AssetsPane.Objects };
            using (var heavy = new FindingsHeavyLocks(directory))
            {
                screen.Show(directory, false);
                await screen.ReadCompletion;
                Assert.Null(screen.Refusal);
                Assert.Null(screen.ViewRefusal);
                var first = screen.Objects.Select(row => row.DistinguishedName).ToArray();
                Assert.Equal(100, first.Length);
                Assert.True(screen.HasNextPage);
                screen.NextPage();
                await screen.ReadCompletion;
                Assert.False(first.Intersect(screen.Objects.Select(row => row.DistinguishedName)).Any());
                screen.PreviousPage();
                await screen.ReadCompletion;
                Assert.Equal(first, screen.Objects.Select(row => row.DistinguishedName));
                screen.NextPage();
                await screen.ReadCompletion;
                screen.ObjectSearchText = "operator-204";
                screen.SearchObjectsCommand.Execute(null);
                await screen.ReadCompletion;
                Assert.Equal("Person 204", Assert.Single(screen.Objects).Name);
                var navigationView = ObjectNavigationViewTests.View(screen);
                DrawBrowsing(navigationView, width);
                var objectsGrid = Assert.Single(ObjectNavigationViewTests.Descendants<DataGrid>(navigationView),
                    grid => ReferenceEquals(grid.ItemsSource, screen.Objects));
                Assert.Equal(1, objectsGrid.Items.Count);
                Assert.True(objectsGrid.ActualHeight >= 50);
                screen.Scope = ListingScope.Base;
                screen.ClearObjectSearchCommand.Execute(null);
                await screen.ReadCompletion;
                Assert.Null(screen.ViewRefusal);
                Assert.Equal(1, screen.PageNumber);
                Assert.Equal(NavigationBrowsingTests.Root, Assert.Single(screen.Objects).DistinguishedName);
                screen.Scope = ListingScope.Subtree;
                await screen.ReadCompletion;
                screen.Pane = AssetsPane.Findings;
                await screen.ReadCompletion;
                Assert.Null(screen.ViewRefusal);
                screen.RuleFilter = "SEC-022";
                await screen.ReadCompletion;
                var original = screen.Findings.Select(FindingDisplaySnapshot).ToArray();
                Assert.Equal(50, original.Length);
                var findingsView = FindingsViewTests.View(screen);
                DrawBrowsing(findingsView, width);
                var findingsGrid = Assert.Single(ObjectNavigationViewTests.Descendants<DataGrid>(findingsView));
                Assert.Equal(screen.Findings.Count, findingsGrid.Items.Count);
                Assert.True(findingsGrid.ActualHeight >= 50);
                screen.OpenFinding(screen.Findings.Single(row => row.DistinguishedName == NavigationBrowsingTests.Group));
                await screen.ObjectReadCompletion;
                Assert.NotNull(screen.Opened);
                Assert.Null(screen.ObjectRefusal);
                Assert.Null(screen.Opened.Refusal);
                Assert.Equal(ObjectSectionCatalog.Findings, screen.Opened.SelectedKey);
                Assert.Single(Assert.IsType<FindingsSectionViewModel>(screen.Opened.Content).Findings);
                var objectView = ObjectNavigationViewTests.ObjectView(screen);
                DrawBrowsing(objectView, width);
                Assert.Contains(ObjectNavigationViewTests.Descendants<TextBlock>(objectView),
                    text => text.Text == screen.Opened.Heading && text.ActualWidth > 0 && text.ActualHeight > 0);
                screen.Opened.Show(ObjectSectionCatalog.Help);
                await screen.Opened.ReadCompletion;
                Assert.IsType<ObjectHelpSectionViewModel>(screen.Opened.Content);
                screen.Opened.Show(ObjectSectionCatalog.Findings);
                await screen.Opened.ReadCompletion;
                screen.CloseObject();
                await screen.ReadCompletion;
                Assert.Equal(original, screen.Findings.Select(FindingDisplaySnapshot));
                Assert.Equal(0, counts.Heavy);
                screen.Suspend();
                source.CloseRun();
                screen.Show(directory, false);
                await screen.ReadCompletion;
                Assert.Null(screen.ViewRefusal);
                Assert.Equal(original, screen.Findings.Select(FindingDisplaySnapshot));
                Assert.Equal(0, counts.Heavy);
            }

            screen.OpenFinding(screen.Findings.Single(row => row.DistinguishedName == NavigationBrowsingTests.Group));
            await screen.ObjectReadCompletion;
            screen.Opened!.Show(ObjectSectionCatalog.Membership);
            await screen.Opened.ReadCompletion;
            var membership = Assert.IsType<GroupMembershipSectionViewModel>(screen.Opened.Content);
            Assert.Equal(50, membership.Members.Count);
            Assert.Equal("123 recorded values - page 1", membership.PageDescription);
            membership.NextCommand.Execute(null);
            await membership.ReadCompletion;
            membership.NextCommand.Execute(null);
            await membership.ReadCompletion;
            Assert.Equal(23, membership.Members.Count);
            Assert.Equal("123 recorded values - page 3", membership.PageDescription);
            membership.SelectedView = "Member of";
            await membership.ReadCompletion;
            Assert.Equal(NavigationBrowsingTests.Root, Assert.Single(membership.Members).RecordedName);
            screen.Opened.Show(ObjectSectionCatalog.Overview);
            await screen.Opened.ReadCompletion;
            Assert.Null(screen.Opened.Refusal);
            Assert.IsType<OverviewSectionViewModel>(screen.Opened.Content);
            DrawBrowsing(ObjectNavigationViewTests.ObjectView(screen), width);
            Assert.Equal(1, counts.Count("evidence"));
            screen.CloseObject();
            await screen.ReadCompletion;
            Assert.Null(screen.ViewRefusal);
            screen.Suspend();
        }));

    [Fact]
    public async Task Arch04ObjectOverviewRequestsOnlyItsOwnCapturedAttributeFamily()
    {
        var (screen, source) = ObjectNavigationTests.Model();
        source.Attributes = FakeAssetSource.CapturedObject(NavigationBrowsingTests.Root, "group");
        source.Permissions = Judgement.ControlEdgeDeriverTests.Permissions(NavigationBrowsingTests.Root);
        screen.OpenObject(new(new(NavigationBrowsingTests.Root, "contoso", source.Attributes.ObjectGuid, "group", null)));
        await screen.ObjectReadCompletion;
        Assert.NotNull(screen.Opened);
        Assert.Null(screen.Opened.Refusal);
        Assert.IsType<OverviewSectionViewModel>(screen.Opened.Content);
        Assert.Equal("Identity", source.Reads[0]);
        var expected = ObjectSectionCatalog.For("group").Single(section => section.Key == ObjectSectionCatalog.Overview).Attributes;
        Assert.Equal(expected.Order(StringComparer.OrdinalIgnoreCase),
            Assert.Single(source.AttributeSelections).Order(StringComparer.OrdinalIgnoreCase));
        Assert.DoesNotContain("member", source.AttributeSelections[0], StringComparer.OrdinalIgnoreCase);
        screen.Suspend();
    }

    [Fact]
    public void Arch04TreeCreatesOnlyRequestedBranchesAndObservesTheirSelection()
    {
        const string root = "DC=contoso,DC=com";
        var branches = Enumerable.Range(0, 20).Select(index => new TreeNode($"OU=B{index}," + root,
            "B" + index, null, TreeNodeOrigin.Captured,
            Enumerable.Range(0, 100).Select(child => new TreeNode($"OU=C{child},OU=B{index}," + root,
                "C" + child, null, TreeNodeOrigin.Captured, [])).ToArray())).ToArray();
        var created = new List<TreeNodeViewModel>();
        var selected = new List<TreeNodeViewModel>();
        var tree = new TreeNodeViewModel(new(root, "contoso", null, TreeNodeOrigin.Partition, branches), node =>
        {
            created.Add(node);
            node.PropertyChanged += (_, change) =>
            {
                if (change.PropertyName == nameof(TreeNodeViewModel.IsSelected) && node.IsSelected) selected.Add(node);
            };
        });
        Assert.Single(created);
        Assert.Equal(20, tree.Children.Count);
        Assert.Equal(21, created.Count);
        var child = tree.Children[7].Children[13];
        child.IsSelected = true;
        Assert.Same(child, Assert.Single(selected));
        Assert.Equal(121, created.Count);
        Assert.Same(tree.Children[7].Children, tree.Children[7].Children);
    }

    private static string BrowsingRun()
    {
        var directory = NavigationBrowsingTests.Capture();
        var root = AnalysisStoreLifecycle.ResolveCapture(directory).Value;
        using (var writer = DerivationWriter.Create(directory, root.EvidenceSeal, NavigationBrowsingTests.When))
            writer.Complete(NavigationBrowsingTests.When.AddMinutes(1));
        using var captured = BundleReader.Open(directory).Value;
        var names = new[] { NavigationBrowsingTests.Group }.Concat(Enumerable.Range(0, 60).Select(NavigationBrowsingTests.Person));
        var findings = names.Select(dn => new Finding("SEC-022", 1, Severity.High,
            new(FindingSubjectKind.Account, dn), captured.ReadObjectIdentity(dn)!.ObjectGuid!.Value,
            dn, "contoso.com", dn == NavigationBrowsingTests.Group ? "group" : "user",
            "Recorded browsing fixture", EvidenceCompleteness.Complete, new UserAccountControlEvidence(514))
        { PrincipalName = dn == NavigationBrowsingTests.Group ? "Operators" : captured.ReadObjectIdentity(dn)!.DistinguishedName }).ToArray();
        WriteFindingsFixture(directory, findings);
        return directory;
    }

    private static void DrawBrowsing(FrameworkElement view, int width)
    {
        ObjectNavigationViewTests.Layout(view, width, 700);
        var bitmap = new RenderTargetBitmap(width, 700, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(view);
        var pixels = new byte[width * 700 * 4];
        bitmap.CopyPixels(pixels, width * 4, 0);
        Assert.Contains(pixels, pixel => pixel != 0);
        Assert.True(view.ActualWidth > 0);
    }
}
