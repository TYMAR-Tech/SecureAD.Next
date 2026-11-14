using System.Windows;
using System.Windows.Controls;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

[Collection("Finding window resources")]
public sealed class ProtectionMarkerDetailTests
{
    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    [InlineData("group")]
    public void SavedConditionsRemainReportedAssessmentRatherThanIndependentFlags(string kind)
    {
        var (model, source) = Model(kind);
        Assert.Empty(source.ProtectionMarkerReads);
        var selected = Assert.Single(model.Findings);
        model.OpenFinding(selected);
        var details = model.FindingDetails!;
        var panel = Assert.IsType<ProtectionMarkerViewModel>(details.ProtectionMarker);
        Assert.Equal("Captured principal", panel.AffectedObject);
        Assert.Equal(kind, panel.ObjectType);
        Assert.Equal("Medium", details.Finding!.Severity);
        Assert.Equal("1", panel.ReportedAdminCount);
        Assert.Equal("Disabled", panel.ReportedInheritance);
        Assert.Equal("Not protected", panel.SavedProtection);
        Assert.Equal(SavedProtectionMarker.AssessmentNote, panel.AssessmentNote);
        Assert.False(details.ShowsSavedDescription);
        Assert.False(details.ShowsStandardIdentity);
        Assert.Equal(selected.Saved.Reference!.Value, Assert.Single(source.ProtectionMarkerReads));
        Assert.Empty(source.AccountSettingReads);
        Assert.Empty(source.ControlQueries);
        Assert.Empty(source.PathQueries);
        Assert.Empty(source.Reads.Where(value => value is "Attributes" or "Permissions" or "Classification"));
        var guidance = RuleGuidanceCatalogue.For("SEC-030")!;
        Assert.Equal(guidance.WhyItMatters, details.Finding.WhyItMatters);
        Assert.Equal(guidance.WhatToDo, details.Finding.WhatToDo);
        Assert.Equal(guidance.About, details.Finding.About);
        Assert.Contains("does not establish that history", guidance.WhyItMatters, StringComparison.Ordinal);
        Assert.Contains("Review its current explicit permissions", guidance.WhatToDo, StringComparison.Ordinal);
        Assert.Contains("Clearing adminCount alone does not re-enable inheritance", guidance.WhatToDo, StringComparison.Ordinal);
        Assert.Contains("enabling inheritance does not remove existing explicit grants", guidance.WhatToDo, StringComparison.Ordinal);
        Assert.DoesNotContain("was privileged once", guidance.WhyItMatters, StringComparison.Ordinal);
        Assert.DoesNotContain("snapshot of AdminSDHolder", guidance.WhatToDo, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("object")]
    [InlineData("subject")]
    [InlineData("sid")]
    [InlineData("coverage")]
    [InlineData("null-object")]
    public void InvalidSavedAssessmentIsRefusedInsteadOfInventingReportedConditions(string defect)
    {
        var (model, source) = Model("user");
        var read = source.ProtectionMarkerRead!;
        source.ProtectionMarkerRead = reference =>
        {
            if (defect == "missing") return Result<SavedProtectionMarker>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "MissingMarker", ErrorSeverity.Failed, SavedProtectionMarker.InvalidDetails, null));
            var marker = read(reference).Value;
            return Result<SavedProtectionMarker>.Success(defect switch
            {
                "generation" => marker with { Reference = reference with { GenerationId = Guid.NewGuid() } },
                "finding" => marker with { Reference = reference with { FindingId = reference.FindingId + 1 } },
                "object" => marker with { Object = marker.Object with { ObjectGuid = Guid.NewGuid() } },
                "subject" => marker with { Subject = new(FindingSubjectKind.Account, "other") },
                "sid" => marker with { Sid = "not a SID" },
                "null-object" => marker with { Object = null! },
                _ => marker with { Coverage = EvidenceCompleteness.Complete },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.Equal(SavedProtectionMarker.InvalidDetails, model.FindingDetails!.Refusal);
        Assert.False(model.FindingDetails.HasFinding);
        Assert.Null(model.FindingDetails.ProtectionMarker);
    }

    [Theory]
    [InlineData("rule")]
    [InlineData("version")]
    [InlineData("severity")]
    [InlineData("class")]
    [InlineData("dn")]
    public void MarkerCannotBindToAnotherRuleVersionSeverityOrObject(string defect)
    {
        var (model, source) = Model("user");
        var selected = Assert.Single(model.Findings).Saved;
        var marker = source.ProtectionMarkerRead!(selected.Reference!.Value).Value;
        selected = defect switch
        {
            "rule" => selected with { RuleId = "SEC-031" },
            "version" => selected with { RuleVersion = 2 },
            "severity" => selected with { Severity = Severity.Low },
            "class" => selected with { ObjectClass = "group" },
            _ => selected with { DistinguishedName = "CN=Other,DC=contoso,DC=com" },
        };
        Assert.False(marker.Matches(selected));
    }

    [Theory]
    [InlineData("close")]
    [InlineData("run")]
    [InlineData("stale")]
    public void AssessmentCannotRemainVisibleAfterItsLifetimeEnds(string action)
    {
        var (model, source) = Model("computer");
        model.OpenFinding(Assert.Single(model.Findings));
        var details = model.FindingDetails!;
        Assert.NotNull(details.ProtectionMarker);
        if (action == "close") model.CloseFindingDetails();
        else if (action == "run") model.Clear();
        else { source.IsCurrent = false; model.OpenAffectedObjectCommand.Execute(null); }
        Assert.Null(details.ProtectionMarker);
        Assert.False(details.HasFinding);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ClosedOrExpiredWindowsCannotPublishLateAssessment(bool expire) => OneThread.Run(async () =>
    {
        var (model, source) = Model("user");
        var row = Assert.Single(model.Findings);
        var marker = source.ProtectionMarkerRead!(row.Saved.Reference!.Value).Value;
        var content = FindingDetailContent.FromSaved(row.Saved) with { ProtectionMarker = marker };
        var release = new TaskCompletionSource<Result<FindingDetailContent>>(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = (value, _) => value is Result<FindingDetailContent> ? Complete(release.Task) : Task.FromResult(value);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var pending = details.ReadCompletion;
        Assert.False(pending.IsCompleted);
        if (expire) source.IsCurrent = false; else model.CloseFindingDetails();
        release.SetResult(Result<FindingDetailContent>.Success(content));
        await pending;
        Assert.Null(details.ProtectionMarker);
        Assert.False(details.HasFinding);
    });

    [Fact]
    public void BothEntryPointsKeepTheExactSavedAssessmentAndReturnContext() => OneThread.Run(async () =>
    {
        var (model, source) = Model("user");
        var row = Assert.Single(model.Findings);
        model.SelectedFinding = row;
        source.Attributes = FakeAssetSource.CapturedObject(row.DistinguishedName, row.ObjectClass) with { ObjectGuid = row.Saved.ObjectGuid };
        source.Permissions = ControlEdgeDeriverTests.Permissions(row.DistinguishedName);
        model.OpenFinding(row);
        model.OpenAffectedObjectCommand.Execute(null);
        await model.ObjectReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(model.Opened);
        opened.Show(ObjectSectionCatalog.Findings);
        await opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        model.CloseFindingDetails();
        model.OpenFinding(Assert.Single(section.Findings));
        Assert.Equal(row.Saved.Reference, model.FindingDetails!.Finding!.Saved.Reference);
        Assert.NotNull(model.FindingDetails.ProtectionMarker);
        Assert.Equal(2, source.ProtectionMarkerReads.Count);
        Assert.Same(row, model.SelectedFinding);
        Assert.Same(opened, model.Opened);
        Assert.Same(section, opened.Content);
    });

    [Theory]
    [InlineData(900)]
    [InlineData(1300)]
    public void ActualWindowLabelsReportedConditionsAndRetainsCoverageAndActions(int width) => OnSta(() =>
    {
        var (model, _) = Model("group");
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, width, 700);
            foreach (var label in new[] { "Saved assessment", "Reported adminCount: 1", "Reported permission inheritance: Disabled",
                "Saved protection assessment: Not protected", SavedProtectionMarker.AssessmentNote, "May be incomplete" })
                Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == label);
            Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "SID: S-1-5-21-1-2-3-1100");
            foreach (var label in new[] { "Open affected object", "Close" })
                Assert.Contains(Descendants<Button>(view), button => button.IsVisible && Equals(button.Content, label));
            Assert.DoesNotContain(Descendants<TextBlock>(view), value => value.IsVisible && value.Text.Contains("was privileged once", StringComparison.Ordinal));
        }
        finally { host.Close(); }
    });

    private static async Task<object> Complete(Task<Result<FindingDetailContent>> task) => await task;
    internal static (AssetsViewModel Model, FakeAssetSource Source) Model(string kind)
    {
        var finding = new Finding("SEC-030", 1, Severity.Medium, new(FindingSubjectKind.Account, "Captured principal"),
            Guid.NewGuid(), "CN=Captured principal,DC=contoso,DC=com", "contoso.com", kind, "Old original full marker prose.",
            EvidenceCompleteness.MayBeMissingConfidentialValues, new AdminCountWithoutProtectionEvidence("S-1-5-21-1-2-3-1100"))
        { PrincipalName = "Captured principal" };
        var source = new FakeAssetSource { FindingsPage = new([finding], null, 1),
            FilterValues = new([Severity.Medium], ["SEC-030"], 1) };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\protection-marker", false);
        var selected = Assert.Single(model.Findings).Saved;
        source.ProtectionMarkerRead = reference => Result<SavedProtectionMarker>.Success(new(reference, selected.Subject,
            new(selected.ObjectGuid, selected.DistinguishedName, selected.DomainFqdn, selected.ObjectClass),
            selected.PrincipalName, "S-1-5-21-1-2-3-1100", selected.Coverage));
        return (model, source);
    }
}
