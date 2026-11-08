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

public sealed class Sec022FindingDetailTests
{
    [Theory]
    [InlineData("user", false)]
    [InlineData("user", true)]
    [InlineData("computer", false)]
    [InlineData("computer", true)]
    public void SelectedFactsComeFromSavedFlagsWithoutReadingThemForGridRows(string objectClass, bool disabled)
    {
        var (model, source) = Model(objectClass, disabled);
        var selected = model.Findings[0];
        model.SelectedFinding = selected;
        Assert.Empty(source.AccountSettingReads);
        model.OpenFinding(selected);
        var detail = model.FindingDetails!;
        Assert.True(detail.ReadCompletion.IsCompletedSuccessfully);
        Assert.True(detail.HasFinding);
        Assert.True(detail.HasCapturedSetting);
        Assert.False(detail.ShowsSavedDescription);
        Assert.Equal(disabled ? "Disabled" : "Enabled", detail.CapturedSetting!.AccountState);
        Assert.Equal("Do not require Kerberos preauthentication: Enabled", detail.CapturedSetting.Setting);
        Assert.Equal(objectClass, detail.Finding!.ObjectClass);
        Assert.Equal("High", detail.Finding.Severity);
        Assert.Equal("May be incomplete", detail.Finding.Coverage);
        Assert.Equal(selected.Saved, detail.Finding.Saved);
        Assert.Equal(selected.Saved.Reference!.Value, Assert.Single(source.AccountSettingReads));
        Assert.Empty(source.Reads.Where(read => read is "Attributes" or "Permissions" or "Classification"));
        Assert.False(detail.Finding.HasMembershipEvidence);
        Assert.Null(detail.ServiceRegistration);
        model.CloseFindingDetails();
        Assert.Same(selected, model.SelectedFinding);
        Assert.Null(detail.CapturedSetting);
        model.OpenFinding(selected);
        Assert.Equal(disabled ? "Disabled" : "Enabled", model.FindingDetails!.CapturedSetting!.AccountState);
        Assert.Equal(2, source.AccountSettingReads.Count);
    }

    [Fact]
    public void AnotherRuleKeepsItsOriginalDescriptionWithoutASettingRead()
    {
        var (model, source) = Model("user", false);
        var selected = model.Findings[1];
        model.OpenFinding(selected);
        var detail = model.FindingDetails!;
        Assert.True(detail.HasFinding);
        Assert.True(detail.ShowsSavedDescription);
        Assert.False(detail.HasCapturedSetting);
        Assert.Null(detail.CapturedSetting);
        Assert.Equal(selected.Detail, detail.Finding!.Detail);
        Assert.Empty(source.AccountSettingReads);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("object")]
    [InlineData("subject")]
    [InlineData("dn")]
    [InlineData("flag")]
    public void MissingOrMismatchedSettingIsRefusedInsteadOfInventingAccountState(string defect)
    {
        var (model, source) = Model("user", false);
        var selected = model.Findings[0];
        var reference = selected.Saved.Reference!.Value;
        var valid = new SavedAccountSetting(reference, selected.Rule, selected.Saved.ObjectGuid, selected.Saved.Subject,
            selected.DistinguishedName, new(0x00400200));
        source.AccountSettingRead = _ => defect == "missing"
            ? Result<SavedAccountSetting>.Failure(AuditError.Create(ErrorCategory.Shell,
                "MissingSavedSetting", ErrorSeverity.Failed, "The saved account setting is unavailable.", "test"))
            : Result<SavedAccountSetting>.Success(defect switch
            {
                "generation" => valid with { Reference = reference with { GenerationId = Guid.NewGuid() } },
                "finding" => valid with { Reference = reference with { FindingId = reference.FindingId + 1 } },
                "object" => valid with { ObjectGuid = Guid.NewGuid() },
                "subject" => valid with { Subject = new(FindingSubjectKind.Account, "another account") },
                "dn" => valid with { DistinguishedName = "CN=Another,DC=elsewhere,DC=example" },
                _ => valid with { AccountControl = new(0x200) },
            });
        model.OpenFinding(selected);
        var detail = model.FindingDetails!;
        Assert.True(detail.HasRefusal);
        Assert.Contains(defect == "missing" ? "unavailable" : "does not match", detail.Refusal, StringComparison.Ordinal);
        Assert.False(detail.HasFinding);
        Assert.False(detail.HasCapturedSetting);
        Assert.False(detail.ShowsSavedDescription);
        Assert.Null(detail.CapturedSetting);
        Assert.Equal(2, model.Findings.Count);
        Assert.Equal(selected.Detail, model.Findings[0].Detail);
    }

    [Theory]
    [InlineData("close")]
    [InlineData("run")]
    [InlineData("stale")]
    public void CapturedSettingCannotRemainVisibleAfterItsLifetimeEnds(string action)
    {
        var (model, source) = Model("computer", true);
        model.OpenFinding(model.Findings[0]);
        var detail = model.FindingDetails!;
        Assert.True(detail.HasCapturedSetting);
        if (action == "close") model.CloseFindingDetails();
        else if (action == "run") model.Clear();
        else
        {
            source.IsCurrent = false;
            model.OpenAffectedObjectCommand.Execute(null);
            Assert.True(detail.HasRefusal);
        }
        Assert.False(detail.HasCapturedSetting);
        Assert.Null(detail.CapturedSetting);
        Assert.False(detail.HasFinding);
        Assert.False(model.HasObjectPresentation);
    }

    [Theory]
    [InlineData(900, false)]
    [InlineData(900, true)]
    [InlineData(1300, false)]
    [InlineData(1300, true)]
    public void CapturedPanelRendersWithoutTheOldProseOrMembershipSection(int width, bool disabled) => OnSta(() =>
    {
        var (model, source) = Model(disabled ? "computer" : "user", disabled);
        model.OpenFinding(model.Findings[0]);
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
            var visible = Descendants<TextBlock>(view).Where(text => text.IsVisible).ToArray();
            foreach (var text in new[]
            {
                "Captured setting", "Do not require Kerberos preauthentication: Enabled",
                "Account state at capture: " + (disabled ? "Disabled" : "Enabled"),
                "Object type: " + (disabled ? "computer" : "user"),
            })
            {
                var displayed = Assert.Single(visible, item => item.Text == text);
                Assert.True(displayed.ActualWidth > 0 && displayed.ActualHeight > 0);
            }
            Assert.DoesNotContain(visible, text => text.Text == "Finding");
            Assert.DoesNotContain(Descendants<TextBox>(view), text => text.IsVisible && text.Text == model.Findings[0].Detail);
            Assert.DoesNotContain(Descendants<Button>(view), button => button.IsVisible && Equals(button.Content, "View membership evidence"));
            Assert.DoesNotContain(visible, text => text.Text.Contains("4194816", StringComparison.Ordinal)
                || text.Text.Contains("4194818", StringComparison.Ordinal));
            var guidance = RuleGuidanceCatalogue.For("SEC-022")!;
            Assert.Equal(guidance.WhyItMatters, model.FindingDetails!.Finding!.WhyItMatters);
            Assert.Equal(guidance.WhatToDo, model.FindingDetails.Finding.WhatToDo);
            Assert.Equal(guidance.About, model.FindingDetails.Finding.About);
            Assert.Equal(model.Findings[0].Saved.Reference!.Value, Assert.Single(source.AccountSettingReads));
        }
        finally
        {
            host.Close();
        }
    });

    private static (AssetsViewModel Model, FakeAssetSource Source) Model(string objectClass, bool disabled)
    {
        var control = objectClass == "computer" ? 0x00401000u : 0x00400200u;
        if (disabled) control |= 2;
        var finding = new Finding("SEC-022", 1, Severity.High,
            new(FindingSubjectKind.Account, "same-friendly-name"), Guid.NewGuid(),
            "CN=Same name,OU=Accounts,DC=one,DC=example", "one.example", objectClass,
            disabled ? "Misleading original prose says enabled." : "Misleading original prose says disabled.",
            EvidenceCompleteness.MayBeMissingConfidentialValues, new UserAccountControlEvidence(control)) { PrincipalName = "same-friendly-name" };
        var otherGuid = Guid.NewGuid();
        var other = FindingsViewTests.GenericServiceFinding(finding with
        {
            ObjectGuid = otherGuid, DomainFqdn = "two.example",
            DistinguishedName = "CN=Same name,OU=Accounts,DC=two,DC=example",
            Detail = "Other rule's unchanged saved description.",
        });
        var source = new FakeAssetSource
        {
            FindingsPage = new([finding, other], null, 2),
            FilterValues = new([finding.Severity, other.Severity], [finding.RuleId, other.RuleId], 2),
        };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\sec022-detail", false);
        return (model, source);
    }
}
