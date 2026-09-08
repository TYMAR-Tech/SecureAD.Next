using System.Windows.Controls;
using Xunit;
using Xunit.Sdk;
using static SecureAD.Next.Tests.Judgement.FullControlEvaluatorTests;
using static SecureAD.Next.Tests.Judgement.FullControlStorageTests;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class ControlEdgeSizingTests
{
    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    [InlineData(1600, 900)]
    public void FullControlSummaryCountStatusAndProofRemainReachable(int width, int height)
        => OnSta(() => VerifyFullControl(width, height));

    [Fact]
    public void FullControlSizingCheckRejectsAnUnboundCountStatus()
        => OnSta(() => Assert.ThrowsAny<XunitException>(() => VerifyFullControl(900, 430, "unbound-full-control-count")));

    private static void VerifyFullControl(int width, int height, string? mutation = null)
    {
        using var reader = Open(Store([Evaluation(Allow(0), Allow(1))]));
        var vm = FullControlPresentationTests.Model(reader);
        var pane = Pane(vm, mutation);
        Layout(pane, width, height);
        var (control, requester) = Tables(pane);
        var summary = Assert.IsType<DataGridRow>(control.ItemContainerGenerator.ContainerFromIndex(0));
        Assert.Equal("Full-control permissions", Assert.IsType<TextBlock>(control.Columns[2].GetCellContent(summary)).Text);
        Assert.Contains(Descendants<TextBlock>(control), text => text.Text == "Count status");
        var support = vm.Rows.Single(row => row.Capability == "Can change permissions (WRITE_DAC)");
        control.ScrollIntoView(support);
        Layout(pane, width, height);
        var supportRow = Assert.IsType<DataGridRow>(control.ItemContainerGenerator.ContainerFromItem(support));
        Assert.Equal("Included in full-control count — not counted again",
            Assert.Single(Descendants<TextBlock>(control.Columns[^1].GetCellContent(supportRow))).Text);
        AssertInside(supportRow, control);
        vm.SelectedEdge = vm.Rows[0];
        var expander = Assert.Single(Descendants<Expander>(pane).Where(item => item.Name != "RequesterEvidence"));
        expander.IsExpanded = true;
        Layout(pane, width, height);
        var text = Assert.Single(Descendants<TextBox>(expander));
        Assert.Equal(vm.SelectedEdge.Evidence, text.Text);
        Assert.Contains("Removing one complete grant route alone leaves another route", text.Text);
        Assert.True(text.IsReadOnly);
        var proofScroll = Assert.Single(Descendants<ScrollViewer>(expander).Where(scroll => ReferenceEquals(scroll.Content, text)));
        Assert.InRange(proofScroll.ActualHeight, 1, 240.1);
        Assert.True(proofScroll.ScrollableHeight > 0);
        var outer = SectionScroll(pane, requester);
        outer.ScrollToVerticalOffset(outer.VerticalOffset + Top(expander, outer));
        Layout(pane, width, height);
        Assert.True(expander.ActualHeight > 0 && Top(expander, pane) < pane.ActualHeight);
    }
}
