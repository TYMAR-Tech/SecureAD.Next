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

public sealed class AccountSettingDetailTests
{
    public static IEnumerable<object[]> Rules()
    {
        yield return ["SEC-028", 0x00000020u, "Password not required", Severity.High];
        yield return ["SEC-029", 0x00000080u, "Store password using reversible encryption", Severity.High];
        yield return ["SEC-033", 0x00200000u, "Use Kerberos DES encryption types for this account", Severity.Medium];
    }

    public static IEnumerable<object[]> States()
    {
        foreach (var rule in Rules())
            foreach (var objectClass in new[] { "user", "computer" })
                foreach (var disabled in new[] { false, true })
                    yield return [.. rule, objectClass, disabled];
    }

    public static IEnumerable<object[]> VisualCases()
    {
        foreach (var rule in Rules())
            foreach (var width in new[] { 900, 1300 })
                yield return [.. rule, width];
    }

    [Theory]
    [MemberData(nameof(States))]
    public void EachRuleUsesItsOwnSavedFlagAndCapturedState(string ruleId, uint flag, string label,
        Severity severity, string objectClass, bool disabled)
    {
        var control = flag | (objectClass == "computer" ? 0x1000u : 0x200u) | (disabled ? 2u : 0);
        var (model, source) = Model(ruleId, control, severity, objectClass);
        var row = Assert.Single(model.Findings);
        model.SelectedFinding = row;
        Assert.Empty(source.AccountSettingReads);
        model.OpenFinding(row);
        var detail = model.FindingDetails!;
        Assert.True(detail.HasFinding);
        Assert.True(detail.HasCapturedSetting);
        Assert.False(detail.ShowsSavedDescription);
        Assert.Equal(label + ": Enabled", detail.CapturedSetting!.Setting);
        Assert.Equal(disabled ? "Disabled" : "Enabled", detail.CapturedSetting.AccountState);
        Assert.Equal(severity.ToString(), detail.Finding!.Severity);
        Assert.Equal("May be incomplete", detail.Finding.Coverage);
        Assert.Equal(objectClass, detail.Finding.ObjectClass);
        Assert.Equal(row.Saved, detail.Finding.Saved);
        Assert.Equal(row.Saved.Reference!.Value, Assert.Single(source.AccountSettingReads));
        Assert.False(detail.Finding.HasMembershipEvidence);
        Assert.Null(detail.MembershipDetails);
        model.CloseFindingDetails();
        Assert.Same(row, model.SelectedFinding);
        Assert.Null(detail.CapturedSetting);
    }

    [Theory]
    [MemberData(nameof(Rules))]
    public void SettingsCannotBeSubstitutedBetweenSupportedRules(string ruleId, uint flag, string label, Severity severity)
    {
        var (model, source) = Model(ruleId, flag | 0x200u, severity, "user");
        var row = Assert.Single(model.Findings);
        var otherRule = ruleId == "SEC-028" ? "SEC-029" : "SEC-028";
        source.AccountSettingRead = reference => Result<SavedAccountSetting>.Success(
            new(reference, otherRule, row.Saved.ObjectGuid, row.Saved.Subject, row.DistinguishedName, new(0x006002a0)));
        model.OpenFinding(row);
        Assert.True(model.FindingDetails!.HasRefusal);
        Assert.Contains("does not match", model.FindingDetails.Refusal, StringComparison.Ordinal);
        Assert.False(model.FindingDetails.HasFinding);
        Assert.Null(model.FindingDetails.CapturedSetting);
        Assert.Equal(label, new SavedAccountSetting(row.Saved.Reference!.Value, ruleId, row.Saved.ObjectGuid,
            row.Saved.Subject, row.DistinguishedName, new(flag)).SettingName);
    }

    [Theory]
    [MemberData(nameof(Rules))]
    public void AnotherAccountOptionCannotStandInForTheReportedFlag(string ruleId, uint flag, string label, Severity severity)
    {
        var (model, source) = Model(ruleId, flag | 0x200u, severity, "user");
        var row = Assert.Single(model.Findings);
        source.AccountSettingRead = reference => Result<SavedAccountSetting>.Success(
            new(reference, ruleId, row.Saved.ObjectGuid, row.Saved.Subject, row.DistinguishedName, new(0x00400200)));
        model.OpenFinding(row);
        Assert.True(model.FindingDetails!.HasRefusal);
        Assert.False(model.FindingDetails.HasFinding);
        Assert.False(model.FindingDetails.HasCapturedSetting);
        Assert.Single(model.Findings);
        Assert.DoesNotContain(label, model.FindingDetails.Refusal, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(VisualCases))]
    public void EachRuleRendersItsOwnSettingWithoutClaimingMoreThanWasCaptured(
        string ruleId, uint flag, string label, Severity severity, int width) => OnSta(() =>
    {
        var disabled = width == 1300;
        var objectClass = disabled ? "computer" : "user";
        var control = flag | (disabled ? 0x1002u : 0x200u);
        var (model, _) = Model(ruleId, control, severity, objectClass);
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window
        {
            Content = view, Width = width, Height = 700, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false,
        };
        try
        {
            host.Show();
            Layout(view, width, 650);
            foreach (var expected in new[]
            {
                "Captured setting", label + ": Enabled", "Account state at capture: " + (disabled ? "Disabled" : "Enabled"),
                "Object type: " + objectClass,
            })
            {
                var text = Assert.Single(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == expected);
                Assert.True(text.ActualWidth > 0 && text.ActualHeight > 0);
            }
            Assert.DoesNotContain(Descendants<TextBox>(view), text => text.IsVisible && text.Text == model.Findings[0].Detail);
            Assert.DoesNotContain(Descendants<Button>(view),
                button => button.IsVisible && Equals(button.Content, "View membership evidence"));
            var definition = RuleCatalogue.All.Single(rule => rule.Definition.Id == ruleId).Definition;
            var rulesRow = new RuleRowViewModel(ruleId, definition, null);
            Assert.Equal(rulesRow.WhyItMatters, model.FindingDetails!.Finding!.WhyItMatters);
            Assert.Equal(rulesRow.WhatToDo, model.FindingDetails.Finding.WhatToDo);
            Assert.Equal(rulesRow.About, model.FindingDetails.Finding.About);
        }
        finally { host.Close(); }
    });

    [Fact]
    public void ReversibleStorageTitleNamesTheOptionAcrossBothFindingAndRulesPresentation()
    {
        var (model, _) = Model("SEC-029", 0x280, Severity.High, "user");
        var row = Assert.Single(model.Findings);
        model.OpenFinding(row);
        var definition = new ReversiblePasswordEncryption().Definition;
        var rulesRow = new RuleRowViewModel("SEC-029", definition, null);
        Assert.Equal("Reversible password storage enabled", row.FindingTitle);
        Assert.Equal(row.FindingTitle, model.FindingDetails!.Finding!.FindingTitle);
        Assert.Equal(row.FindingTitle, rulesRow.Name);
        Assert.Equal("SEC-029", row.Rule);
        Assert.Equal("High", row.Severity);
        Assert.Equal("Original saved description is retained, not parsed.", row.Detail);
    }

    private static (AssetsViewModel Model, FakeAssetSource Source) Model(
        string ruleId, uint control, Severity severity, string objectClass)
    {
        var finding = new Finding(ruleId, 1, severity, new(FindingSubjectKind.Account, "same-friendly-name"),
            Guid.NewGuid(), "CN=Same name,OU=Accounts,DC=one,DC=example", "one.example", objectClass,
            "Original saved description is retained, not parsed.", EvidenceCompleteness.MayBeMissingConfidentialValues,
            new UserAccountControlEvidence(control)) { PrincipalName = "same-friendly-name" };
        var source = new FakeAssetSource
        {
            FindingsPage = new([finding], null, 1),
            FilterValues = new([severity], [ruleId], 1),
        };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\account-settings-detail", false);
        return (model, source);
    }
}
