using System.Windows.Controls;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class PermissionLayoutTests
{
    [Fact]
    public void BothApprovedPresentationsUseTheSameCapturedPrincipalEntries() => OnSta(() =>
    {
        var entry = Judgement.GroupMembershipControlTests.Scoped(0, 0x28);
        var permissions = Judgement.ControlEdgeDeriverTests.Permissions(entry);
        var section = new PermissionsSectionViewModel(
            new(ObjectSectionCatalog.Permissions, "Permissions", ["nTSecurityDescriptor"]),
            permissions,
            PermissionVocabulary.Shipped,
            null,
            "Synthetic classification refusal.");
        var (host, presenter, _) = AssetCardViewTests.Present(section);
        Layout(host, 1200, 700);

        var tabs = Assert.Single(Descendants<TabControl>(presenter));
        Assert.Collection(tabs.Items.Cast<TabItem>(),
            tab => Assert.Equal("A - Principal reading pane", tab.Header),
            tab => Assert.Equal("B - Expandable principal groups", tab.Header));

        tabs.SelectedIndex = 0;
        Layout(host, 1200, 700);
        var principal = Assert.Single(section.Principals);
        Assert.Contains(Descendants<ListBox>(presenter), list =>
            ReferenceEquals(Assert.Single(list.Items.Cast<object>()), principal));

        tabs.SelectedIndex = 1;
        Layout(host, 1200, 700);
        var group = Assert.Single(Descendants<Expander>(presenter), item =>
            ReferenceEquals(item.DataContext, principal));
        group.IsExpanded = true;
        Layout(host, 1200, 700);
        Assert.Contains(Descendants<DataGrid>(group), grid =>
            grid.Items.Cast<object>().SequenceEqual(principal.VisibleEntries.Cast<object>()));

        section.PermissionSearchText = "no matching permission";
        Assert.Empty(section.VisiblePrincipals);
        section.PermissionSearchText = "";
        Assert.Single(section.VisiblePrincipals);
    });
}
