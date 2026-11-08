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
public sealed class OwnershipAssessmentDetailTests
{
    public static IEnumerable<object[]> AssessmentCases() => new[] { "SEC-031", "SEC-032" }.SelectMany(rule =>
        new[] { ObjectOwnerStanding.Exists, ObjectOwnerStanding.DoesNotExist }.SelectMany(standing =>
            new[] { false, true }.Select(complete => new object[] { rule, standing, complete })));
    public static IEnumerable<object[]> InvalidCases() => new[] { "SEC-031", "SEC-032" }.SelectMany(rule =>
        new[] { "missing", "generation", "object", "sid", "standing", "membership", "coverage" }.Select(defect => new object[] { rule, defect }));
    public static IEnumerable<object[]> ViewCases() => new[] { "SEC-031", "SEC-032" }.SelectMany(rule =>
        new[] { 900, 1300 }.SelectMany(width => new[] { false, true }.Select(complete => new object[] { rule, width, complete })));

    [Theory]
    [MemberData(nameof(AssessmentCases))]
    public void SavedOwnerStandingMembershipAndProtectionRemainSeparate(string rule, ObjectOwnerStanding standing, bool complete)
    {
        var (model, source) = Model(rule, standing, complete);
        Assert.Empty(source.OwnershipAssessmentReads);
        var row = Assert.Single(model.Findings);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = Assert.IsType<OwnershipAssessmentViewModel>(details.OwnershipAssessment);
        Assert.Equal(rule == "SEC-031" ? "Low" : "Medium", details.Finding!.Severity);
        Assert.Equal(rule == "SEC-031" ? SavedOwnershipAssessment.OrdinaryTitle : SavedOwnershipAssessment.ProtectedTitle,
            details.Finding.FindingTitle);
        Assert.Equal("Captured target", panel.AffectedObject);
        Assert.Equal("S-1-5-21-1-2-3-1200", panel.OwnerSid);
        Assert.Equal(standing == ObjectOwnerStanding.DoesNotExist, panel.IsMissing);
        Assert.Equal(standing == ObjectOwnerStanding.DoesNotExist ? "Recorded as missing in the saved assessment" : "Present in captured evidence",
            panel.OwnerStatus);
        Assert.Equal(complete ? "Complete" : "May be incomplete", panel.MembershipEvidence);
        Assert.Equal(!complete, panel.HasMembershipLimit);
        Assert.Equal(rule == "SEC-031" ? "Outside the AdminSDHolder-protected set" : "In the AdminSDHolder-protected set",
            panel.TargetClassification);
        Assert.False(details.ShowsSavedDescription);
        Assert.False(details.ShowsStandardIdentity);
        Assert.Equal(row.Saved.Reference!.Value, Assert.Single(source.OwnershipAssessmentReads));
        Assert.Empty(source.ControlQueries);
        Assert.Empty(source.PathQueries);
        Assert.Empty(source.Reads.Where(value => value is "Attributes" or "Permissions" or "Classification"));
        var guidance = RuleGuidanceCatalogue.For(rule)!;
        Assert.Equal(guidance.WhyItMatters, details.Finding.WhyItMatters);
        Assert.Equal(guidance.WhatToDo, details.Finding.WhatToDo);
        Assert.Equal(SavedOwnershipAssessment.Action, guidance.WhatToDo);
        Assert.Equal(standing == ObjectOwnerStanding.DoesNotExist ? "Name not resolved from saved evidence." : "Captured owner", panel.OwnerName);
        Assert.Contains("not unconditionally", guidance.WhyItMatters, StringComparison.Ordinal);
        Assert.Contains("recorded missing owner is not an actor", guidance.WhyItMatters, StringComparison.Ordinal);
        Assert.Contains("Do not blanket-replace computer or service-account owners", guidance.WhatToDo, StringComparison.Ordinal);
        Assert.DoesNotContain("within about the last hour", guidance.WhyItMatters, StringComparison.Ordinal);
        if (rule == "SEC-032") Assert.Contains("does not date an ownership change", guidance.WhyItMatters, StringComparison.Ordinal);

    }

    [Fact]
    public void CapturedReadAndOwnerPolicyMembershipCompletenessAreNotConflated()
    {
        var (model, _) = Model("SEC-031", ObjectOwnerStanding.Exists, true, coverage: EvidenceCompleteness.MayBeMissingConfidentialValues);
        model.OpenFinding(Assert.Single(model.Findings));
        var details = model.FindingDetails!;
        Assert.Equal("May be incomplete", details.Finding!.Coverage);
        Assert.Equal("Complete", details.OwnershipAssessment!.MembershipEvidence);
        Assert.False(details.OwnershipAssessment.HasMembershipLimit);
    }

    [Theory]
    [InlineData("SEC-031")]
    [InlineData("SEC-032")]
    public void UnresolvedNameDoesNotBecomeADeletedOwner(string rule)
    {
        var (model, _) = Model(rule, ObjectOwnerStanding.Exists, true, unnamed: true);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.OwnershipAssessment!;
        Assert.Equal("Name not resolved from saved evidence.", panel.OwnerName);
        Assert.Equal("Present in captured evidence", panel.OwnerStatus);
        Assert.False(panel.IsMissing);
    }

    [Theory]
    [MemberData(nameof(InvalidCases))]
    public void InvalidSavedOwnerFactsAreRefusedInsteadOfOldProse(string rule, string defect)
    {
        var (model, source) = Model(rule, ObjectOwnerStanding.Exists, true);
        var read = source.OwnershipAssessmentRead!;
        source.OwnershipAssessmentRead = reference =>
        {
            if (defect == "missing") return Result<SavedOwnershipAssessment>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "MissingSavedOwnership", ErrorSeverity.Failed, SavedOwnershipAssessment.InvalidDetails, null));
            var value = read(reference).Value;
            return Result<SavedOwnershipAssessment>.Success(defect switch
            {
                "generation" => value with { Reference = reference with { GenerationId = Guid.NewGuid() } },
                "object" => value with { Object = value.Object with { ObjectGuid = Guid.NewGuid() } },
                "sid" => value with { OwnerSid = "not a SID" },
                "standing" => value with { Standing = (ObjectOwnerStanding)99 },
                "coverage" => value with { Coverage = EvidenceCompleteness.MayBeMissingConfidentialValues },
                _ => value with { MembershipWasComplete = false },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.Equal(SavedOwnershipAssessment.InvalidDetails, model.FindingDetails!.Refusal);
        Assert.False(model.FindingDetails.HasFinding);
        Assert.Null(model.FindingDetails.OwnershipAssessment);
    }

    [Theory]
    [InlineData("version")]
    [InlineData("severity")]
    [InlineData("subject")]
    [InlineData("class")]
    public void SavedOwnershipCannotBindToAnotherAssessment(string defect)
    {
        var (model, source) = Model("SEC-031", ObjectOwnerStanding.Exists, true);
        var row = Assert.Single(model.Findings).Saved;
        var value = source.OwnershipAssessmentRead!(row.Reference!.Value).Value;
        row = defect switch
        {
            "version" => row with { RuleVersion = 2 },
            "severity" => row with { Severity = Severity.Medium },
            "subject" => row with { Subject = new(FindingSubjectKind.DirectoryObject, "other") },
            _ => row with { ObjectClass = "computer" },
        };
        Assert.False(value.Matches(row));
    }

    [Theory]
    [InlineData("SEC-031")]
    [InlineData("SEC-032")]
    public void BothEntryPointsPreserveTheExactOwnerTargetAndReturnContext(string rule) => OneThread.Run(async () =>
    {
        var (model, source) = Model(rule, ObjectOwnerStanding.Exists, true);
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
        var firstDetails = model.FindingDetails!;
        model.CloseFindingDetails();
        Assert.Null(firstDetails.OwnershipAssessment);
        model.OpenFinding(Assert.Single(section.Findings));
        Assert.Equal(row.Saved.Reference, model.FindingDetails!.Finding!.Saved.Reference);
        Assert.NotNull(model.FindingDetails.OwnershipAssessment);
        Assert.Equal(2, source.OwnershipAssessmentReads.Count);
        Assert.Same(row, model.SelectedFinding);
        Assert.Same(opened, model.Opened);
        var secondDetails = model.FindingDetails!;
        source.IsCurrent = false;
        Assert.False(secondDetails.CheckCurrent());
        Assert.Null(secondDetails.OwnershipAssessment);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ClosedOrExpiredOwnershipReadCannotPublishLater(bool expire) => OneThread.Run(async () =>
    {
        var (model, source) = Model("SEC-032", ObjectOwnerStanding.Exists, true);
        var row = Assert.Single(model.Findings);
        var ownership = source.OwnershipAssessmentRead!(row.Saved.Reference!.Value).Value;
        var content = FindingDetailContent.FromSaved(row.Saved) with { OwnershipAssessment = ownership };
        var release = new TaskCompletionSource<Result<FindingDetailContent>>(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = (value, _) => value is Result<FindingDetailContent> ? Complete(release.Task) : Task.FromResult(value);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var pending = details.ReadCompletion;
        Assert.False(pending.IsCompleted);
        if (expire) source.IsCurrent = false; else model.CloseFindingDetails();
        release.SetResult(Result<FindingDetailContent>.Success(content));
        await pending;
        Assert.False(details.HasFinding);
        Assert.Null(details.OwnershipAssessment);
    });

    [Theory]
    [MemberData(nameof(ViewCases))]
    public void RealPanelKeepsSavedOwnerStandingAndMembershipLimitsExplicit(string rule, int width, bool complete) => OnSta(() =>
    {
        var (model, _) = Model(rule, complete ? ObjectOwnerStanding.Exists : ObjectOwnerStanding.DoesNotExist, complete, unnamed: true);
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, width, 700);
            foreach (var label in new[] { "Saved ownership assessment",
                complete ? "Recorded owner status: Present in captured evidence" : "Recorded owner status: Recorded as missing in the saved assessment",
                complete ? "Owner-policy membership evidence: Complete" : "Owner-policy membership evidence: May be incomplete" })
                Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == label);
            Assert.Equal(!complete, Descendants<TextBlock>(view).Any(value => value.IsVisible && value.Text == SavedOwnershipAssessment.MissingOwnerNote));
            Assert.Equal(!complete, Descendants<TextBlock>(view).Any(value => value.IsVisible && value.Text == SavedOwnershipAssessment.MembershipNote));
            Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "SID: S-1-5-21-1-2-3-1200");
            Assert.DoesNotContain(Descendants<TextBlock>(view), value => value.IsVisible
                && value.Text.Contains("can rewrite that object's permissions whenever", StringComparison.Ordinal));
        }
        finally { host.Close(); }
    });

    private static async Task<object> Complete(Task<Result<FindingDetailContent>> task) => await task;
    internal static (AssetsViewModel Model, FakeAssetSource Source) Model(string rule, ObjectOwnerStanding standing, bool complete, bool unnamed = false,
        EvidenceCompleteness coverage = EvidenceCompleteness.Complete)
    {
        var evidence = new ObjectOwnershipEvidence("S-1-5-21-1-2-3-1200",
            unnamed || standing == ObjectOwnerStanding.DoesNotExist ? null : "Captured owner", standing, "user", complete);
        var finding = new Finding(rule, 3, rule == "SEC-031" ? Severity.Low : Severity.Medium,
            new(FindingSubjectKind.DirectoryObject, "CN=Captured target,DC=contoso,DC=com"), Guid.NewGuid(),
            "CN=Captured target,DC=contoso,DC=com", "contoso.com", "user", "Original unconditional owner prose.",
            coverage, evidence) { PrincipalName = "Captured target" };
        var source = new FakeAssetSource { FindingsPage = new([finding], null, 1),
            FilterValues = new([finding.Severity], [rule], 1) };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\ownership", false);
        var selected = Assert.Single(model.Findings).Saved;
        source.OwnershipAssessmentRead = reference => Result<SavedOwnershipAssessment>.Success(new(reference, rule, selected.Subject,
            new(selected.ObjectGuid, selected.DistinguishedName, selected.DomainFqdn, selected.ObjectClass),
            selected.PrincipalName, evidence.OwnerSid, evidence.OwnerName, evidence.Standing, complete, selected.Coverage));
        return (model, source);
    }
}
