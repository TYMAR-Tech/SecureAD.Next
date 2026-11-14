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
public sealed class PermissionControlDetailTests
{
    [Theory]
    [InlineData(ObjectTakeoverRight.GenericAll, false, false)]
    [InlineData(ObjectTakeoverRight.GenericAll, true, true)]
    [InlineData(ObjectTakeoverRight.WriteDacl, false, true)]
    [InlineData(ObjectTakeoverRight.WriteDacl, true, false)]
    [InlineData(ObjectTakeoverRight.WriteOwner, false, false)]
    [InlineData(ObjectTakeoverRight.WriteOwner, true, true)]
    public void PermissionControlShowsReportedRightAndHonestLimitsWithoutEagerChain(ObjectTakeoverRight right, bool inherited, bool complete)
    {
        var (model, source) = Model(right, inherited, complete);
        Assert.Empty(source.PermissionControlReads);
        model.OpenFinding(Assert.Single(model.Findings));
        var details = model.FindingDetails!; var panel = Assert.IsType<PermissionControlViewModel>(details.PermissionControl);
        Assert.Equal(new[] { "header" }, source.PermissionControlReads); Assert.Null(panel.Chain);
        Assert.Equal("High", details.Finding!.Severity); Assert.Equal(SavedPermissionControl.Title, details.Finding.FindingTitle);
        Assert.False(details.ShowsSavedDescription); Assert.False(details.ShowsStandardIdentity);
        Assert.Equal(inherited ? "Inherited" : "Explicit", panel.EntryContext);
        Assert.Equal(complete ? "Complete" : "May be incomplete", panel.Expansion);
        Assert.Equal(right == ObjectTakeoverRight.WriteOwner, panel.IsOwnership);
        Assert.Equal(right == ObjectTakeoverRight.GenericAll, panel.IsFullControlCategory);
        Assert.Contains("known limitations", panel.CalculationLimits, StringComparison.Ordinal);
        Assert.Contains("not corrected permission calculation", panel.ExpansionNote, StringComparison.Ordinal);
        Assert.Contains("does not identify the exact entry", panel.EntryNote, StringComparison.Ordinal);
        Assert.Equal(SavedPermissionControl.Risk, RuleGuidanceCatalogue.For("SEC-060")!.WhyItMatters);
        Assert.Equal(SavedPermissionControl.Action, RuleGuidanceCatalogue.For("SEC-060")!.WhatToDo);
        Assert.Empty(source.ControlQueries); Assert.Empty(source.PathQueries);
    }

    [Fact]
    public void PermissionControlChainKeepsFiftyOrderedIdentifiersAndPreviousPage()
    {
        var (model, source) = Model(ObjectTakeoverRight.WriteDacl); model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.PermissionControl!; panel.ViewChainCommand.Execute(null);
        var chain = Assert.IsType<PermissionControlChainViewModel>(panel.Chain);
        var first = chain.Steps.ToArray(); Assert.Equal(50, first.Length);
        chain.NextPageCommand.Execute(null); Assert.Equal(5, chain.Steps.Count); Assert.False(chain.NextPageCommand.CanExecute(null));
        Assert.Equal("S-1-5-21-1-2-3-513", chain.Steps[^1].Sid);
        chain.PreviousPageCommand.Execute(null); Assert.Equal(first, chain.Steps);
        Assert.Equal(new[] { "header", "chain", "chain", "chain" }, source.PermissionControlReads);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("object")]
    [InlineData("broad")]
    [InlineData("right")]
    [InlineData("complete")]
    public void PermissionControlInvalidInitialFactsCannotFallBackToOriginalTakeoverProse(string defect)
    {
        var (model, source) = Model(ObjectTakeoverRight.WriteDacl); var read = source.PermissionControlRead!;
        source.PermissionControlRead = reference =>
        {
            if (defect == "missing") return Result<SavedPermissionControl>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "MissingControl", ErrorSeverity.Failed, SavedPermissionControl.InvalidDetails, null));
            var value = read(reference).Value;
            return Result<SavedPermissionControl>.Success(defect switch
            {
                "generation" => value with { Reference = reference with { GenerationId = Guid.NewGuid() } },
                "object" => value with { Object = value.Object with { ObjectGuid = Guid.NewGuid() } },
                "broad" => value with { BroadSid = "S-1-5-21-1-2-3-999" },
                "right" => value with { ReportedRight = (ObjectTakeoverRight)999 },
                _ => value with { ExpansionWasComplete = false },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.False(model.FindingDetails!.HasFinding); Assert.Null(model.FindingDetails.PermissionControl);
        Assert.Equal(SavedPermissionControl.InvalidDetails, model.FindingDetails.Refusal);
    }

    [Theory]
    [InlineData("context")]
    [InlineData("page")]
    [InlineData("identity")]
    public void PermissionControlRequestedChainRefusesOtherContextsGapsAndInvalidIdentifiers(string defect)
    {
        var (model, source) = Model(ObjectTakeoverRight.WriteDacl); var read = source.PermissionControlChainRead!;
        source.PermissionControlChainRead = (reference, after) =>
        {
            var page = read(reference, after).Value;
            return Result<SavedPermissionControlChain>.Success(defect switch
            {
                "context" => page with { Context = page.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } },
                "page" => page with { Next = null },
                _ => page with { Steps = page.Steps.Select(step => step with { Sid = "invalid identifier" }).ToArray() },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings)); var panel = model.FindingDetails!.PermissionControl!;
        panel.ViewChainCommand.Execute(null);
        Assert.Null(panel.Chain); Assert.Equal(SavedPermissionControl.InvalidDetails, panel.Refusal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PermissionControlCloseAndExpiryClearLoadedChainsAndDisableHeldPaging(bool expire)
    {
        var (model, source) = Model(ObjectTakeoverRight.WriteOwner); model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.PermissionControl!; panel.ViewChainCommand.Execute(null);
        var chain = panel.Chain!;
        if (expire) { source.IsCurrent = false; Assert.False(model.FindingDetails.CheckCurrent()); } else model.CloseFindingDetails();
        Assert.Empty(chain.Steps); Assert.False(chain.NextPageCommand.CanExecute(null)); Assert.False(panel.ViewChainCommand.CanExecute(null));
    }

    [Fact]
    public void PermissionControlLateChainCannotRestoreASuspendedPanel() => OneThread.Run(async () =>
    {
        var (model, source) = Model(ObjectTakeoverRight.WriteDacl); var reference = Assert.Single(model.Findings).Saved.Reference!.Value;
        var pending = new TaskCompletionSource<Result<SavedPermissionControlChain>>();
        var panel = new PermissionControlViewModel(source.PermissionControlRead!(reference).Value, (_, _) => pending.Task, () => true);
        panel.ViewChainCommand.Execute(null); var work = panel.ReadCompletion;
        panel.Suspend(); pending.SetResult(source.PermissionControlChainRead!(reference, null)); await work;
        Assert.Null(panel.Chain); Assert.False(panel.ViewChainCommand.CanExecute(null));
    });

    [Fact]
    public void PermissionControlBothEntryPointsReadFreshFactsAndKeepObjectAndGridSelection() => OneThread.Run(async () =>
    {
        var (model, source) = Model(ObjectTakeoverRight.WriteDacl); var selected = Assert.Single(model.Findings);
        model.SelectedFinding = selected; model.OpenFinding(selected); var panel = model.FindingDetails!.PermissionControl!;
        source.Attributes = FakeAssetSource.CapturedObject(panel.Object.DistinguishedName, panel.Object.ObjectClass)
            with { ObjectGuid = panel.Object.ObjectGuid };
        model.OpenAffectedObjectCommand.Execute(null); await model.ObjectReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(model.Opened); opened.Show(ObjectSectionCatalog.Findings); await opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(opened.Content); var row = Assert.Single(section.Findings); section.SelectedFinding = row;
        model.CloseFindingDetails(); model.OpenFinding(row);
        Assert.NotSame(panel, model.FindingDetails!.PermissionControl);
        Assert.Equal(new[] { "header", "header" }, source.PermissionControlReads);
        Assert.Same(section, opened.Content); Assert.Same(row, section.SelectedFinding); Assert.Same(selected, model.SelectedFinding);
    });

    [Theory]
    [InlineData(ObjectTakeoverRight.GenericAll, 900)]
    [InlineData(ObjectTakeoverRight.GenericAll, 1300)]
    [InlineData(ObjectTakeoverRight.WriteDacl, 900)]
    [InlineData(ObjectTakeoverRight.WriteDacl, 1300)]
    [InlineData(ObjectTakeoverRight.WriteOwner, 900)]
    [InlineData(ObjectTakeoverRight.WriteOwner, 1300)]
    public void PermissionControlRealWindowDrawsOnlySupportedClaimsAndRequestedChain(ObjectTakeoverRight right, int width) => OnSta(() =>
    {
        var (model, _) = Model(right); model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000, ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Saved permission-control assessment");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == SavedPermissionControl.CalculationLimits);
            Assert.Equal(right == ObjectTakeoverRight.WriteOwner, Descendants<TextBlock>(view).Any(value => value.IsVisible && value.Text == SavedPermissionControl.OwnerNote));
            Assert.Equal(right == ObjectTakeoverRight.GenericAll, Descendants<TextBlock>(view).Any(value => value.IsVisible && value.Text == SavedPermissionControl.FullControlNote));
            Assert.DoesNotContain(Descendants<TextBox>(view), value => value.IsVisible && value.Text.Contains("Original takeover", StringComparison.Ordinal));
            var action = Assert.Single(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, "View saved supporting chain"));
            action.BringIntoView(); Layout(view, width, 700);
            var viewport = Assert.Single(Descendants<ScrollViewer>(view), value => value.Name == "FindingDetailsScroll");
            var visible = viewport.TransformToAncestor(view).TransformBounds(new Rect(viewport.RenderSize));
            var bounds = action.TransformToAncestor(view).TransformBounds(new Rect(action.RenderSize));
            Assert.True(action.ActualHeight > 0);
            Assert.InRange(bounds.Top, visible.Top, visible.Bottom - action.ActualHeight);
            action.Command.Execute(null); Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Saved supporting chain");
            Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "Saved step 0");
            Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "SID: S-1-5-21-1-2-3-1200");
        }
        finally { host.Close(); }
    });

    private static (AssetsViewModel Model, FakeAssetSource Source) Model(ObjectTakeoverRight right, bool inherited = false, bool complete = true)
    {
        const string dn = "CN=Target,DC=contoso,DC=com", domain = "contoso.com", broad = "S-1-5-21-1-2-3-513";
        var guid = Guid.NewGuid();
        var steps = Enumerable.Range(0, 55).Select(index => new PathStep(index == 54 ? broad : "S-1-5-21-1-2-3-" + (1200 + index),
            "Saved step " + index)).ToArray();
        var subject = new FindingSubject(FindingSubjectKind.Account, BroadPrincipalCanTakeOverObject.SubjectKeyFor(broad));
        var finding = new Finding("SEC-060", 2, Severity.High, subject, guid, dn, domain, "user",
            "Original takeover prose must not be loaded.", EvidenceCompleteness.Complete,
            new ObjectTakeoverEvidence(steps[0].Sid, "Recorded holder", broad, "Domain Users", steps, right,
                inherited ? "an inherited scope" : null, complete)) { PrincipalName = "Domain Users" };
        var source = new FakeAssetSource { FindingsPage = new([finding], null, 1), FilterValues = new([Severity.High], ["SEC-060"], 1) };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings }; model.Show(@"C:\offline-fixture\permission-control", false);
        SavedPermissionControl Header(FindingReference reference) => new(reference, subject, new(guid, dn, domain, "user"),
            finding.PrincipalName, steps[0].Sid, "Recorded holder", broad, "Domain Users", right, inherited, complete,
            EvidenceCompleteness.Complete, steps.Length);
        source.PermissionControlRead = reference => Result<SavedPermissionControl>.Success(Header(reference));
        source.PermissionControlChainRead = (reference, after) =>
        {
            var start = after?.Ordinal + 1 ?? 0;
            var page = steps.Skip((int)start).Take(50).Select((step, index) => new SavedPermissionControlStep(start + index, step.Sid, step.Name)).ToArray();
            return Result<SavedPermissionControlChain>.Success(new(Header(reference), page, start + page.Length < steps.Length
                ? new(reference.GenerationId, reference.FindingId, guid, page[^1].Ordinal) : null));
        };
        return (model, source);
    }
}
