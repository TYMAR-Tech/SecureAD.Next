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

[Collection("Finding window resources")]
public sealed class GroupReviewDetailTests
{
    [Theory]
    [InlineData("SEC-050")]
    [InlineData("SEC-051")]
    public void SavedReviewHeaderDoesNotExpandReferencesOrInventPopulationCounts(string rule)
    {
        var (model, source) = Model(rule);
        Assert.Empty(source.GroupReviewReads);
        model.OpenFinding(Assert.Single(model.Findings));
        var details = model.FindingDetails!;
        var panel = Assert.IsType<GroupReviewViewModel>(details.GroupReview);
        Assert.Equal("Low", details.Finding!.Severity);
        Assert.Equal(new[] { "header" }, source.GroupReviewReads);
        Assert.False(details.ShowsSavedDescription); Assert.False(details.ShowsStandardIdentity);
        if (rule == "SEC-050")
        {
            Assert.Equal(11, panel.DirectCount); Assert.Equal(10, panel.ReviewThreshold); Assert.Equal(3, panel.KnownTotal);
            Assert.Contains("not a count of people", panel.DirectNote, StringComparison.Ordinal);
            Assert.Contains("not Microsoft limits", panel.PolicyNote, StringComparison.Ordinal);
        }
        else
        {
            Assert.Equal("Nested is a member of Renamed DA.", panel.Direction);
            Assert.Equal("contoso.com", panel.DestinationDomain);
            Assert.Equal("Security-enabled group", panel.NestedType);
            Assert.Contains("not an effective-access calculation", panel.NestingScope, StringComparison.Ordinal);
        }
        Assert.Empty(source.ControlQueries); Assert.Empty(source.PathQueries);
    }

    [Theory]
    [InlineData("SEC-050")]
    [InlineData("SEC-051")]
    public void RequestedReferencePagesPreserveAllOccurrencesWithoutChangingTheSavedCounts(string rule)
    {
        var (model, source) = Model(rule);
        model.OpenFinding(Assert.Single(model.Findings)); var panel = model.FindingDetails!.GroupReview!;
        panel.ViewReferencesCommand.Execute(null);
        Assert.Equal(50, panel.References!.Rows.Count);
        panel.References.NextPageCommand.Execute(null);
        Assert.Equal(7, panel.References.Rows.Count);
        panel.References.PreviousPageCommand.Execute(null);
        Assert.Equal(50, panel.References.Rows.Count);
        Assert.Equal(4, source.GroupReviewReads.Count);
        Assert.Equal(rule == "SEC-050" ? 11 : null, panel.DirectCount);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("group")]
    [InlineData("threshold")]
    public void InvalidSavedGroupReviewCannotFallBackToOldProse(string defect)
    {
        var (model, source) = Model("SEC-050");
        var read = source.GroupReviewRead!;
        source.GroupReviewRead = reference =>
        {
            if (defect == "missing") return Result<SavedGroupReview>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "MissingReview", ErrorSeverity.Failed, SavedGroupReview.InvalidDetails("SEC-050"), null));
            var value = read(reference).Value;
            return Result<SavedGroupReview>.Success(defect switch
            {
                "generation" => value with { Reference = reference with { GenerationId = Guid.NewGuid() } },
                "group" => value with { Affected = value.Affected with { Identity = value.Affected.Identity with { ObjectGuid = Guid.NewGuid() } } },
                _ => value with { ReviewThreshold = 11 },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.False(model.FindingDetails!.HasFinding);
        Assert.Equal(SavedGroupReview.InvalidDetails("SEC-050"), model.FindingDetails.Refusal);
    }

    [Theory]
    [InlineData("SEC-050", 900)]
    [InlineData("SEC-050", 1300)]
    [InlineData("SEC-051", 900)]
    [InlineData("SEC-051", 1300)]
    public void RealWindowShowsTheAppropriateSavedReviewWithoutOldProofProse(string rule, int width) => OnSta(() =>
    {
        var (model, _) = Model(rule); model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000, ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == (rule == "SEC-050" ? "Saved group-size review" : "Saved direct group nesting"));
            Assert.Contains(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, "View saved direct references"));
            Assert.DoesNotContain(Descendants<TextBlock>(view), value => value.IsVisible && value.Text.Contains("Raw proof", StringComparison.Ordinal));
        }
        finally { host.Close(); }
    });

    [Theory]
    [InlineData("SEC-050", false)]
    [InlineData("SEC-050", true)]
    [InlineData("SEC-051", false)]
    [InlineData("SEC-051", true)]
    public void ClosingOrExpiringTheSelectedFindingClearsLoadedReferences(string rule, bool expire)
    {
        var (model, source) = Model(rule); model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.GroupReview!; panel.ViewReferencesCommand.Execute(null);
        var references = panel.References!;
        if (expire) { source.IsCurrent = false; Assert.False(model.FindingDetails.CheckCurrent()); }
        else model.CloseFindingDetails();
        Assert.Empty(references.Rows); Assert.False(references.NextPageCommand.CanExecute(null));
        Assert.False(panel.ViewReferencesCommand.CanExecute(null)); Assert.Null(model.FindingDetails?.GroupReview);
    }

    [Theory]
    [InlineData("truncated")]
    [InlineData("position")]
    [InlineData("continuation")]
    [InlineData("context")]
    public void AnInvalidRequestedReferencePageIsAnExplicitRefusal(string defect)
    {
        var (model, source) = Model("SEC-050"); var read = source.GroupReviewReferencesRead!;
        source.GroupReviewReferencesRead = (reference, after) =>
        {
            var page = read(reference, after).Value;
            return Result<SavedGroupReferences>.Success(defect switch
            {
                "truncated" => page with { References = page.References.Take(49).ToArray() },
                "position" => page with { References = page.References.Select(value => value with { Position = value.Position + 1 }).ToArray() },
                "continuation" => page with { Next = null },
                _ => page with { Context = page.Context with { KnownTotal = 999 } },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings)); var panel = model.FindingDetails!.GroupReview!;
        panel.ViewReferencesCommand.Execute(null);
        Assert.Null(panel.References); Assert.Equal(SavedGroupReview.InvalidDetails("SEC-050"), panel.Refusal);
    }

    [Theory]
    [InlineData(-2147483646L, "Security-enabled group")]
    [InlineData(2L, "Distribution group")]
    [InlineData(null, "Not established from saved evidence.")]
    public void ARecordedGroupTypeDoesNotBecomeAPermissionOrPopulationClaim(long? type, string expected)
    {
        var (model, source) = Model("SEC-051"); var read = source.GroupReviewRead!;
        source.GroupReviewRead = reference => Result<SavedGroupReview>.Success(read(reference).Value with
            { Affected = read(reference).Value.Affected with { GroupType = type }, HasForeignReference = true });
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.GroupReview!;
        Assert.Equal(expected, panel.NestedType); Assert.True(panel.HasForeignReference);
        Assert.Contains("foreign-security-principal", panel.ForeignReferenceNote, StringComparison.Ordinal);
    }

    [Fact]
    public void UnreadableReferencesDoNotBecomeMissingOrInventedNames()
    {
        var (model, source) = Model("SEC-050"); var read = source.GroupReviewReferencesRead!;
        source.GroupReviewReferencesRead = (reference, after) =>
        {
            var page = read(reference, after).Value;
            return Result<SavedGroupReferences>.Success(page with { References = page.References.Select((value,index) =>
                index == 1 ? value with { DistinguishedName = null } : value).ToArray() });
        };
        model.OpenFinding(Assert.Single(model.Findings)); var panel = model.FindingDetails!.GroupReview!;
        panel.ViewReferencesCommand.Execute(null);
        Assert.Equal("Unreadable saved reference.", panel.References!.Rows[1].Value);
        Assert.Equal(11, panel.DirectCount); Assert.Equal(3, panel.KnownTotal);
    }

    [Theory]
    [InlineData("SEC-050")]
    [InlineData("SEC-051")]
    public void RequestsCompletingAfterSuspensionCannotRestoreAClosedPanel(string rule) => OneThread.Run(async () =>
    {
        var (model, source) = Model(rule); var row = Assert.Single(model.Findings).Saved;
        var saved = source.GroupReviewRead!(row.Reference!.Value).Value;
        var completion = new TaskCompletionSource<Result<SavedGroupReferences>>();
        var panel = new GroupReviewViewModel(saved, (_, _) => completion.Task, () => true);
        panel.ViewReferencesCommand.Execute(null); var work = panel.ReadCompletion;
        panel.Suspend(); completion.SetResult(source.GroupReviewReferencesRead!(row.Reference.Value, null));
        await work;
        Assert.Null(panel.References); Assert.Null(panel.Refusal); Assert.False(panel.ViewReferencesCommand.CanExecute(null));
    });

    internal static (AssetsViewModel Model, FakeAssetSource Source) Model(string rule)
    {
        var target = Guid.NewGuid(); var affected = rule == "SEC-050" ? target : Guid.NewGuid();
        var targetDn = "CN=Renamed DA,DC=contoso,DC=com"; var affectedDn = rule == "SEC-050" ? targetDn : "CN=Nested,DC=contoso,DC=com";
        var evidence = new GroupMembershipReviewEvidence(new string('a',64), Guid.NewGuid(), new string('b',64), 1, 1, null, null,
            rule == "SEC-050" ? GroupMembershipReviewKind.PrivilegedGroupSize : GroupMembershipReviewKind.GroupNestedInDomainAdmins,
            target, rule == "SEC-050" ? null : affected, [], [], [new(0, "CN=Member,DC=contoso,DC=com", null)], [],
            rule == "SEC-050" ? 11 : null, rule == "SEC-050" ? 10 : null,
            rule == "SEC-050" ? new(3,0,0,[]) : null, true, []);
        var finding = new Finding(rule, 1, Severity.Low, new(FindingSubjectKind.DirectoryObject,
            rule == "SEC-050" ? affected.ToString("D") : affected.ToString("D") + ":" + target.ToString("D")),
            affected, affectedDn, "contoso.com", "group", "Raw proof should not be shown", EvidenceCompleteness.Complete, evidence);
        var source = new FakeAssetSource { FindingsPage = new([finding], null, 1), FilterValues = new([Severity.Low], [rule], 1) };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings }; model.Show(@"C:\offline-fixture\group-review", false);
        var row = Assert.Single(model.Findings).Saved;
        var destination = new SavedReviewGroup(new(target,targetDn,"contoso.com","group"),"S-1-5-21-1-2-3-512",null,-2147483646);
        var subject = rule == "SEC-050" ? destination : new SavedReviewGroup(new(affected,affectedDn,"contoso.com","group"),"S-1-5-21-1-2-3-1200",null,-2147483646);
        source.GroupReviewRead = reference => Result<SavedGroupReview>.Success(new(reference,rule,row.Subject,subject,destination,
            rule == "SEC-050" ? 11 : null,rule == "SEC-050" ? 10 : null,rule == "SEC-050" ? 3 : null,
            rule == "SEC-050" ? 0 : null,rule == "SEC-050" ? 0 : null,GroupMembershipLimitations.None,true,"",true,57,false));
        source.GroupReviewReferencesRead = (reference, after) =>
        {
            var context = source.GroupReviewRead(reference).Value; var start=after?.Offset??0;
            var rows=Enumerable.Range((int)start,Math.Min(50,57-(int)start)).Select(index=>new SavedGroupReference(index,"CN=Repeated member,DC=contoso,DC=com")).ToArray();
            return Result<SavedGroupReferences>.Success(new(context,rows,start==0?new(reference.GenerationId,reference.FindingId,affected,target,50):null));
        };
        return (model,source);
    }
}
