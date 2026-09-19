using System.Windows.Controls;
using System.Windows.Data;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using Xunit.Sdk;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class ControlEdgeSizingTests
{
    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    [InlineData(1600, 900)]
    public Task MemberRowsRoutesAndPartialWarningRemainReachable(int width, int height) =>
        VerifyMemberAttributionAsync(width, height, false);

    [Fact]
    public async Task MemberSizingCheckRejectsAnUnboundMemberCell() =>
        await Assert.ThrowsAnyAsync<XunitException>(() => VerifyMemberAttributionAsync(900, 430, true));

    private static async Task VerifyMemberAttributionAsync(int width, int height, bool unbind)
    {
        using var reader = Judgement.MemberAttributionTests.Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})"));
        using var source = new BundleAssetSource();
        var vm = await MemberAttributionPresentationTests.OpenAsync(source, reader.BundleDirectory, UserDn, false);
        OnSta(() => VerifyMemberLayout(vm, width, height, unbind));
    }

    private static void VerifyMemberLayout(ControlEdgesSectionViewModel vm, int width, int height, bool unbind)
    {
        var pane = Pane(vm);
        Layout(pane, width, height);
        var expander = Assert.Single(Descendants<Expander>(pane).Where(item => item.Name == "MemberEvidence"));
        expander.IsExpanded = true;
        Layout(pane, width, height);
        var table = Assert.Single(Descendants<DataGrid>(pane).Where(item => item.Name == "MemberPrincipals"));
        var row = Assert.IsType<DataGridRow>(table.ItemContainerGenerator.ContainerFromIndex(0));
        var cell = Assert.IsType<TextBlock>(table.Columns[0].GetCellContent(row));
        if (unbind) BindingOperations.ClearBinding(cell, TextBlock.TextProperty);
        Assert.Equal(vm.MemberPanel.Rows[0].Member, cell.Text);
        Assert.Contains(Descendants<TextBlock>(pane), text => text.Text == vm.MemberPanel.Status && text.ActualHeight > 0);
        var route = Assert.Single(Descendants<TextBox>(expander).Where(text =>
            BindingOperations.GetBinding(text, TextBox.TextProperty)?.Path.Path == "SelectedRow.Routes"));
        Assert.Equal(vm.MemberPanel.SelectedRow!.Routes, route.Text);
        Assert.InRange(table.ActualHeight, 1, 220.1);
        var outer = SectionScroll(pane, Tables(pane).Requester);
        outer.ScrollToVerticalOffset(outer.VerticalOffset + Top(expander, outer));
        Layout(pane, width, height);
        Assert.True(expander.ActualHeight > 0 && Top(expander, pane) < pane.ActualHeight);
    }
}
