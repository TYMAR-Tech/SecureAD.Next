using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class DelegationsRedesignTests
{
    [Theory]
    [InlineData(900, 470)]
    [InlineData(1300, 800)]
    [InlineData(1920, 1080)]
    public void TwoStepSearchAndSelectedEvidenceStaySeparateAndUsable(int width, int height) => OnSta(() =>
    {
        var (model, source) = DelegationViewModelTests.Model();
        model.IncludeGroupHeldPermissions = true;
        source.Delegations = (query, _) => NestedDelegationViewModelTests.GroupPage(query.Principal);
        var view = DelegationsViewTests.View(model);
        DashboardRedesignTests.InWindow(view, width, height, () =>
        {
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == DelegationText.PrincipalStep);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == DelegationText.PermissionStep);
            model.DelegationPrincipalSearch = "Helpdesk";
            var search = Assert.Single(Descendants<TextBox>(view), box =>
                BindingOperations.GetBinding(box, TextBox.TextProperty)?.Path.Path == nameof(model.DelegationPrincipalSearch));
            var enter = Assert.Single(search.InputBindings.OfType<KeyBinding>());
            Assert.Equal(Key.Enter, enter.Key);
            Assert.Same(model.FindDelegationPrincipalCommand, enter.Command);
            enter.Command.Execute(null);
            Layout(view, width, height);
            model.FindDelegationsCommand.Execute(null);
            Layout(view, width, height);
            var table = Assert.Single(Descendants<DataGrid>(view));
            table.SelectedItem = Assert.Single(model.Delegations);
            Layout(view, width, height);
            var row = model.SelectedDelegation!;
            var original = Assert.Single(Descendants<Expander>(view));
            Assert.Equal("Membership and original evidence", original.Header);
            Assert.False(original.IsExpanded);
            original.IsExpanded = true;
            Layout(view, width, height);
            var member = Bound(view, "SelectedDelegation.MembershipDetail");
            Assert.Equal(row.MembershipDetail, member.Text);
            Assert.Contains("Membership chain", member.Text);
            Assert.Contains("Supporting captured membership links", member.Text);
            Assert.DoesNotContain("Original entry position", member.Text);
            var evidence = Bound(view, "SelectedDelegation.OriginalDetail");
            Assert.Equal(row.OriginalDetail, evidence.Text);
            Assert.Equal(row.MembershipDetail + "\n" + row.OriginalDetail, row.Detail);
            Assert.Contains("Original entry position", evidence.Text);
            evidence.SelectAll();
            Assert.Equal(evidence.Text, evidence.SelectedText);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text.Contains(row.RecordedOn, StringComparison.Ordinal));
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text.Contains(row.AppliesTo, StringComparison.Ordinal));
            Assert.True(table.ActualHeight >= 50);
            var panels = Descendants<FieldGrid>(view).ToArray();
            Assert.NotEmpty(panels);
            var first = panels[0];
            var secondPosition = first.Children[1].TransformToAncestor(first).Transform(new Point());
            Assert.Equal(width < 1000, secondPosition.Y > 0);
            if (width >= 1300)
            {
                var picker = Assert.Single(Descendants<ComboBox>(view), box =>
                    BindingOperations.GetBinding(box, System.Windows.Controls.Primitives.Selector.SelectedItemProperty)?.Path.Path
                    == nameof(model.SelectedDelegationPrincipal));
                var searchScroll = Assert.Single(Descendants<ScrollViewer>(view), scroll =>
                    scroll.Content is StackPanel panel && Descendants<TextBox>(panel).Contains(search));
                Assert.True(picker.TransformToAncestor(searchScroll).Transform(new Point(0, picker.ActualHeight)).Y
                    <= searchScroll.ActualHeight);
            }
            Assert.Single(source.DelegationQueries);
            Assert.True(Assert.Single(Descendants<Button>(view), button => ReferenceEquals(button.Command, model.OpenDelegationDetailsCommand)).IsEnabled);
        });
    });

    [Fact]
    public void DirectEntryDetailsDoNotInventMembership()
    {
        var (model, _) = DelegationViewModelTests.Model();
        model.DelegationPrincipalSearch = "Helpdesk";
        model.FindDelegationPrincipalCommand.Execute(null);
        model.FindDelegationsCommand.Execute(null);
        var row = Assert.Single(model.Delegations);
        Assert.Equal("Direct entry: names the selected principal's SID.", row.MembershipDetail);
        Assert.DoesNotContain("Membership chain", row.MembershipDetail);
        Assert.Contains(row.RecordedOn, row.OriginalDetail);
        Assert.Contains("raw mask:", row.OriginalDetail);
    }

    [Fact]
    public void ChangingFiltersRemovesTheSelectedEntryAndShowsTheUnperformedState() => OnSta(() =>
    {
        var (model, _) = DelegationViewModelTests.Model();
        model.DelegationPrincipalSearch = "Helpdesk";
        model.FindDelegationPrincipalCommand.Execute(null);
        model.FindDelegationsCommand.Execute(null);
        model.SelectedDelegation = model.Delegations[0];
        var view = DelegationsViewTests.View(model);
        DashboardRedesignTests.InWindow(view, 1300, 800, () =>
        {
            var edit = Assert.Single(Descendants<Button>(view), button =>
                ReferenceEquals(button.Command, model.EditDelegationSearchCommand));
            ((IInvokeProvider)new ButtonAutomationPeer(edit).GetPattern(PatternInterface.Invoke)!).Invoke();
            Layout(view, 1300, 800);
            var inherited = Assert.Single(Descendants<CheckBox>(view), box => Equals(box.Content, DelegationText.IncludeInherited));
            ((IToggleProvider)new CheckBoxAutomationPeer(inherited).GetPattern(PatternInterface.Toggle)!).Toggle();
            Layout(view, 1300, 800);
            Assert.False(model.HasDelegationSelection || model.HasDelegationAnswer);
            Assert.False(Assert.Single(Descendants<DataGrid>(view)).IsVisible);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == model.DelegationStatus && text.IsVisible);
            Assert.Contains("No search has been completed", model.DelegationStatus);
        });
    });

    private static TextBox Bound(DependencyObject view, string path) =>
        Assert.Single(Descendants<TextBox>(view), box => BindingOperations.GetBinding(box, TextBox.TextProperty)?.Path.Path == path);
}
