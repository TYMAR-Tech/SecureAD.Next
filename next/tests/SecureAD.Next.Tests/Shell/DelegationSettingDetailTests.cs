using System.Windows;
using System.Windows.Controls;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class DelegationSettingDetailTests
{
    public static IEnumerable<object[]> Kinds()
    {
        yield return ["SEC-010", "user", false];
        yield return ["SEC-011", "computer", true];
        yield return ["SEC-011", "msDS-ManagedServiceAccount", true];
        yield return ["SEC-011", "msDS-GroupManagedServiceAccount", true];
    }

    public static IEnumerable<object[]> States()
    {
        foreach (var kind in Kinds())
            foreach (var disabled in new[] { false, true })
                yield return [.. kind, disabled];
    }

    public static IEnumerable<object[]> VisualCases()
    {
        foreach (var kind in Kinds())
            foreach (var width in new[] { 900, 1300 })
                yield return [.. kind, width];
    }

    [Theory]
    [MemberData(nameof(States))]
    public void DelegationUsesSelectedSavedFactsWithoutMovingAccountKinds(
        string ruleId, string objectClass, bool computerClass, bool disabled)
    {
        var (model, source) = Model(ruleId, objectClass, computerClass, disabled);
        var row = Assert.Single(model.Findings);
        model.SelectedFinding = row;
        Assert.Empty(source.AccountSettingReads);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        Assert.True(details.HasFinding);
        Assert.Equal("Unconstrained delegation: Enabled", details.CapturedSetting!.Setting);
        Assert.Equal(disabled ? "Disabled" : "Enabled", details.CapturedSetting.AccountState);
        Assert.Equal(computerClass, details.CapturedSetting.HasControllerRoleNote);
        Assert.False(details.CapturedSetting.HasControllerDisagreement);
        Assert.Equal(ruleId, details.Finding!.Rule);
        Assert.Equal(objectClass, details.Finding.ObjectClass);
        Assert.Equal("High", details.Finding.Severity);
        Assert.Equal("May be incomplete", details.Finding.Coverage);
        Assert.Equal(row.Saved, details.Finding.Saved);
        Assert.Equal(row.Saved.Reference!.Value, Assert.Single(source.AccountSettingReads));
        Assert.False(details.ShowsSavedDescription);
        Assert.False(details.Finding.HasMembershipEvidence);
        Assert.Null(details.ServiceRegistration);
        Assert.Empty(source.PathQueries);
        Assert.Empty(source.ControlQueries);
        model.CloseFindingDetails();
        Assert.Same(row, model.SelectedFinding);
        Assert.Null(details.CapturedSetting);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public void StoredControllerIndicatorsQualifyAPositiveWithoutReclassifyingIt(int mask)
    {
        var signals = new DomainControllerSignals((mask & 1) != 0, (mask & 2) != 0, (mask & 4) != 0);
        var (model, _) = Model("SEC-011", "computer", true, false, signals);
        model.OpenFinding(Assert.Single(model.Findings));
        var setting = model.FindingDetails!.CapturedSetting!;
        Assert.True(model.FindingDetails.HasFinding);
        Assert.True(setting.HasControllerRoleNote);
        Assert.Equal("Domain-controller role is not independently verified by this saved finding.", setting.ControllerRoleNote);
        Assert.Equal(mask is > 0 and < 7, setting.HasControllerDisagreement);
        Assert.Equal("Captured controller indicators disagree. Verify the actual role before changing delegation.",
            setting.ControllerDisagreement);
        Assert.Single(model.Findings);
        Assert.Equal("SEC-011", model.FindingDetails.Finding!.Rule);
    }

    [Theory]
    [InlineData(0x00082000u, 1)]
    [InlineData(0x00080200u, 2)]
    [InlineData(0x00080200u, 4)]
    [InlineData(0x00082000u, 7)]
    [InlineData(0x04080200u, 0)]
    public void ConflictingUserControllerFactsUseTheExistingWarning(uint control, int mask)
    {
        var saved = new SavedAccountSetting(new(Guid.NewGuid(), 1), "SEC-010", Guid.NewGuid(),
            new(FindingSubjectKind.Account, "captured account"), "CN=Captured,DC=contoso,DC=com", new(control))
        {
            Delegation = new(false, new((mask & 1) != 0, (mask & 2) != 0, (mask & 4) != 0)),
        };
        var setting = new CapturedAccountSettingViewModel(saved);
        Assert.True(setting.HasControllerDisagreement);
        Assert.False(setting.HasControllerRoleNote);
        Assert.Equal("Captured controller indicators disagree. Verify the actual role before changing delegation.",
            setting.ControllerDisagreement);
    }

    [Theory]
    [InlineData("SEC-010", "user", false, false)]
    [InlineData("SEC-010", "user", false, true)]
    [InlineData("SEC-011", "computer", true, false)]
    [InlineData("SEC-011", "computer", true, true)]
    public void MissingOrWrongDelegationContextIsAnExplicitRefusal(
        string ruleId, string objectClass, bool computerClass, bool wrongKind)
    {
        var (model, source) = Model(ruleId, objectClass, computerClass, false);
        var row = Assert.Single(model.Findings);
        source.AccountSettingRead = reference => Result<SavedAccountSetting>.Success(
            new(reference, ruleId, row.Saved.ObjectGuid, row.Saved.Subject, row.DistinguishedName, new(0x00081000))
            {
                Delegation = wrongKind ? new(!computerClass, new(false, false, false)) : null,
            });
        model.OpenFinding(row);
        Assert.True(model.FindingDetails!.HasRefusal);
        Assert.Contains("does not match", model.FindingDetails.Refusal, StringComparison.Ordinal);
        Assert.False(model.FindingDetails.HasFinding);
        Assert.Null(model.FindingDetails.CapturedSetting);
        Assert.Single(model.Findings);
    }

    [Theory]
    [InlineData("SEC-022", 0x00400200u)]
    [InlineData("SEC-028", 0x00000220u)]
    [InlineData("SEC-029", 0x00000280u)]
    [InlineData("SEC-033", 0x00200200u)]
    public void ExistingAccountOptionsDoNotAcquireControllerRoleClaims(string ruleId, uint control)
    {
        var reference = new FindingReference(Guid.NewGuid(), 1);
        var fact = new SavedAccountSetting(reference, ruleId, Guid.NewGuid(),
            new(FindingSubjectKind.Account, "captured account"), "CN=Captured,DC=example", new(control));
        Assert.True(fact.HasReportedSetting);
        Assert.True(fact.HasExpectedContext);
        var view = new CapturedAccountSettingViewModel(fact);
        Assert.False(view.HasControllerRoleNote);
        Assert.False(view.HasControllerDisagreement);
        Assert.False((fact with { Delegation = new(true, new(false, true, false)) }).HasExpectedContext);
    }

    [Theory]
    [InlineData("SEC-010", "user", false)]
    [InlineData("SEC-011", "computer", true)]
    public async Task BothFindingEntryPointsUseTheSameSavedDelegationAnswer(string ruleId, string objectClass, bool computerClass)
    {
        var (model, source) = Model(ruleId, objectClass, computerClass, false, new(false, true, false));
        var row = Assert.Single(model.Findings);
        source.Attributes = FakeAssetSource.CapturedObject(row.DistinguishedName, objectClass) with { ObjectGuid = row.Saved.ObjectGuid };
        source.Permissions = Judgement.ControlEdgeDeriverTests.Permissions(row.DistinguishedName);
        model.OpenFinding(row);
        Assert.True(model.FindingDetails!.CapturedSetting!.HasControllerDisagreement);
        model.OpenAffectedObjectCommand.Execute(null);
        await model.ObjectReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(model.Opened);
        opened.Show(ObjectSectionCatalog.Findings);
        await opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        var fromObject = Assert.Single(section.Findings);
        model.CloseFindingDetails();
        model.OpenFinding(fromObject);
        Assert.Equal(row.Saved.Reference, model.FindingDetails!.Finding!.Saved.Reference);
        Assert.Equal(computerClass, model.FindingDetails.CapturedSetting!.HasControllerRoleNote);
        Assert.True(model.FindingDetails.CapturedSetting.HasControllerDisagreement);
        Assert.Equal(new[] { row.Saved.Reference!.Value, row.Saved.Reference.Value }, source.AccountSettingReads);
        Assert.Same(opened, model.Opened);
        Assert.Same(section, opened.Content);
    }

    [Theory]
    [MemberData(nameof(VisualCases))]
    public void DelegationPanelShowsActualTypeAndQualifiedRoleWithoutOldHostClaims(
        string ruleId, string objectClass, bool computerClass, int width) => OnSta(() =>
    {
        var disagreement = computerClass && width == 1300;
        var signals = new DomainControllerSignals(false, disagreement, false);
        var (model, _) = Model(ruleId, objectClass, computerClass, width == 1300, signals);
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window
        {
            Content = view, Width = width, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false,
        };
        try
        {
            host.Show();
            Layout(view, width, 700);
            var scroll = (ScrollViewer)view.FindName("FindingDetailsScroll");
            foreach (var expected in new[]
            {
                "Captured setting", "Unconstrained delegation: Enabled", "Object type: " + objectClass,
                "Account state at capture: " + (width == 1300 ? "Disabled" : "Enabled"),
            })
            {
                var text = Assert.Single(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == expected);
                Assert.True(text.ActualWidth > 0 && text.ActualHeight > 0);
                var bounds = text.TransformToAncestor(scroll).TransformBounds(new Rect(0, 0, text.ActualWidth, text.ActualHeight));
                Assert.True(bounds.Top >= 0 && bounds.Bottom <= scroll.ActualHeight);
            }
            Assert.Equal(computerClass, Descendants<TextBlock>(view).Any(value => value.IsVisible
                && value.Text == "Domain-controller role is not independently verified by this saved finding."));
            Assert.Equal(disagreement, Descendants<TextBlock>(view).Any(value => value.IsVisible
                && value.Text == "Captured controller indicators disagree. Verify the actual role before changing delegation."));
            foreach (var note in Descendants<TextBlock>(view).Where(value => value.IsVisible
                && (value.Text.StartsWith("Domain-controller role is not", StringComparison.Ordinal)
                    || value.Text.StartsWith("Captured controller indicators disagree.", StringComparison.Ordinal))))
            {
                var bounds = note.TransformToAncestor(scroll).TransformBounds(new Rect(0, 0, note.ActualWidth, note.ActualHeight));
                Assert.True(bounds.Top >= 0 && bounds.Bottom <= scroll.ActualHeight);
            }
            Assert.DoesNotContain(Descendants<TextBox>(view), value => value.IsVisible && value.Text == model.Findings[0].Detail);
            Assert.DoesNotContain(Descendants<Button>(view),
                value => value.IsVisible && Equals(value.Content, "View membership evidence"));
            var definition = RuleCatalogue.All.Single(rule => rule.Definition.Id == ruleId).Definition;
            var rules = new RuleRowViewModel(ruleId, definition, null);
            Assert.Equal(rules.WhyItMatters, model.FindingDetails!.Finding!.WhyItMatters);
            Assert.Equal(rules.WhatToDo, model.FindingDetails.Finding.WhatToDo);
        }
        finally { host.Close(); }
    });

    [Fact]
    public void ComputerClassTitleDoesNotAssertANonControllerOrMoveManagedAccounts()
    {
        var (model, _) = Model("SEC-011", "msDS-GroupManagedServiceAccount", true, false);
        var row = Assert.Single(model.Findings);
        model.OpenFinding(row);
        var definition = new UnconstrainedDelegationOnNonDomainController().Definition;
        Assert.Equal("Unconstrained delegation on a computer-class account", row.FindingTitle);
        Assert.Equal(row.FindingTitle, model.FindingDetails!.Finding!.FindingTitle);
        Assert.Equal(row.FindingTitle, new RuleRowViewModel("SEC-011", definition, null).Name);
        Assert.Equal("SEC-011", model.FindingDetails.Finding.Rule);
        Assert.Equal("msDS-GroupManagedServiceAccount", model.FindingDetails.Finding.ObjectClass);
        Assert.Equal("High", model.FindingDetails.Finding.Severity);
    }

    private static (AssetsViewModel Model, FakeAssetSource Source) Model(
        string ruleId, string objectClass, bool computerClass, bool disabled, DomainControllerSignals? signals = null)
    {
        signals ??= new(false, false, false);
        var control = 0x00080000u | (computerClass ? 0x1000u : 0x200u) | (disabled ? 2u : 0u);
        if (signals.ServerTrustAccountBit) control |= 0x2000;
        var finding = new Finding(ruleId, 1, Severity.High, new(FindingSubjectKind.Account, "captured account"),
            Guid.NewGuid(), "CN=Captured,OU=Accounts,DC=contoso,DC=com", "contoso.com", objectClass,
            "Original saved host and ticket claims remain historical.", EvidenceCompleteness.MayBeMissingConfidentialValues,
            new UnconstrainedDelegationEvidence(control, computerClass, signals)) { PrincipalName = "captured account" };
        var source = new FakeAssetSource
        {
            FindingsPage = new([finding], null, 1),
            FilterValues = new([Severity.High], [ruleId], 1),
        };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\delegation-detail", false);
        return (model, source);
    }
}
