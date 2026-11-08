using System.Windows;
using System.Windows.Controls;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class AttributeWritePermissionDetailTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PermissionPanelUsesSavedHolderTargetStateAndGuidanceWithoutOtherAnalysis(bool disabled)
    {
        var (model, source, _) = Model(2, disabled: disabled);
        var row = Assert.Single(model.Findings);
        model.SelectedFinding = row;
        Assert.Empty(source.AttributeWritePermissionReads);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = Assert.IsType<AttributeWritePermissionViewModel>(details.AttributeWritePermission);
        Assert.True(details.HasFinding);
        Assert.False(details.ShowsSavedDescription);
        Assert.False(details.ShowsStandardIdentity);
        Assert.Null(details.CapturedSetting);
        Assert.Null(details.DelegationConfiguration);
        Assert.Equal("Captured holder", panel.Holder);
        Assert.Equal(AttributeWritePermissionReadTests.HolderSid, panel.Sid);
        Assert.Equal("Captured target", panel.TargetName);
        Assert.Equal("user", panel.Target.ObjectClass);
        Assert.Equal(disabled ? "Disabled" : "Enabled", panel.AccountState);
        Assert.Equal(AttributeWritePermissionReadTests.AttributeName, panel.Attribute);
        Assert.Equal(2, panel.Entries.Count);
        Assert.Equal("High", details.Finding!.Severity);
        Assert.Equal("SEC-014", details.Finding.Rule);
        Assert.Equal("Complete", details.Finding.Coverage);
        Assert.Empty(source.AccountSettingReads);
        Assert.Empty(source.ConstrainedDelegationReads);
        Assert.Empty(source.ResourceDelegationReads);
        Assert.Empty(source.ControlQueries);
        Assert.Empty(source.PathQueries);
        Assert.Null(details.ServiceRegistration);
        var rules = new RuleRowViewModel("SEC-014", new UnexpectedResourceBasedDelegationWrite().Definition, null);
        Assert.Equal(rules.WhyItMatters, details.Finding.WhyItMatters);
        Assert.Equal(rules.WhatToDo, details.Finding.WhatToDo);
        Assert.Contains("A group-held permission does not establish authorization for each member.", rules.WhyItMatters, StringComparison.Ordinal);
        Assert.Contains("It does not show that delegation is configured or in use", rules.WhyItMatters, StringComparison.Ordinal);
        Assert.Contains("other rights in the same assignment", rules.WhatToDo, StringComparison.Ordinal);
        Assert.Contains("verify its original source and wider impact", rules.WhatToDo, StringComparison.Ordinal);
        Assert.Contains("Do not clear legitimate RBCD configuration", rules.WhatToDo, StringComparison.Ordinal);
        model.CloseFindingDetails();
        Assert.Same(row, model.SelectedFinding);
        Assert.Empty(panel.Entries);
    }

    [Fact]
    public void OriginalEntryPagesKeepPreviousPositionAndIndependentCoverage() => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(127);
        var row = Assert.Single(model.Findings);
        model.OpenFinding(row);
        var panel = model.FindingDetails!.AttributeWritePermission!;
        var first = panel.Entries.ToArray();
        Assert.Equal(50, first.Length);
        Assert.Equal("Page 1", panel.PageLabel);
        Assert.False(panel.PreviousPageCommand.CanExecute(null));
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal("Page 2", panel.PageLabel);
        Assert.Equal(Enumerable.Range(50, 50), panel.Entries.Select(entry => entry.Ordinal));
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal(27, panel.Entries.Count);
        Assert.False(panel.NextPageCommand.CanExecute(null));
        Assert.Equal("Complete", model.FindingDetails.Finding!.Coverage);
        panel.PreviousPageCommand.Execute(null);
        await panel.ReadCompletion;
        panel.PreviousPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal("Page 1", panel.PageLabel);
        Assert.Equal(first, panel.Entries);
        Assert.Equal(new int?[] { null, 49, 99, 49, null }, source.AttributeWritePermissionReads.Select(read => read.After?.Ordinal));
    });

    [Fact]
    public void BothFindingEntryPointsUseTheSameSavedWritePermissionAndReturnContext() => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(1);
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
        Assert.Equal(2, source.AttributeWritePermissionReads.Count);
        Assert.All(source.AttributeWritePermissionReads, read => Assert.Equal(row.Saved.Reference!.Value, read.Reference));
        Assert.Same(row, model.SelectedFinding);
        Assert.Same(opened, model.Opened);
        Assert.Same(section, opened.Content);
    });

    [Theory]
    [InlineData("missing")]
    [InlineData("holder")]
    [InlineData("target")]
    [InlineData("generation")]
    [InlineData("coverage")]
    [InlineData("too-many")]
    [InlineData("null-context")]
    [InlineData("next")]
    public void InvalidSavedPermissionDetailsAreRefusedInsteadOfProseFallback(string defect)
    {
        var (model, source, _) = Model(51);
        var read = source.AttributeWritePermissionRead!;
        source.AttributeWritePermissionRead = (reference, after) =>
        {
            if (defect == "missing") return Result<SavedAttributeWritePermission>.Failure(AuditError.Create(
                ErrorCategory.Evidence, "MissingWritePermission", ErrorSeverity.Failed, SavedAttributeWritePermission.InvalidDetailsForRule("SEC-014"), null));
            var page = read(reference, after).Value;
            page = defect switch
            {
                "holder" => page with { Context = page.Context with { HolderSid = "S-1-5-21-1-2-3-9999" } },
                "target" => page with { Context = page.Context with { Target = page.Context.Target with { ObjectGuid = Guid.NewGuid() } } },
                "generation" => page with { Context = page.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } },
                "coverage" => page with { Context = page.Context with { EvidenceIsComplete = false } },
                "too-many" => page with { Entries = [.. page.Entries, new(50, false, SavedPropertyWriteScope.AllProperties, null, false,
                    AttributeWritePermissionKind.ResourceBasedConstrainedDelegation)] },
                "null-context" => page with { Context = null! },
                _ => page with { Next = page.Next!.Value with { Ordinal = 50 } },
            };
            return Result<SavedAttributeWritePermission>.Success(page);
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.True(model.FindingDetails!.HasRefusal);
        Assert.Equal(SavedAttributeWritePermission.InvalidDetailsForRule("SEC-014"), model.FindingDetails.Refusal);
        Assert.False(model.FindingDetails.HasFinding);
        Assert.Null(model.FindingDetails.AttributeWritePermission);
    }

    [Theory]
    [InlineData("context")]
    [InlineData("next")]
    [InlineData("unavailable")]
    public void FailedPermissionContinuationKeepsItsPageAndAllowsRetry(string defect) => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(127);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.AttributeWritePermission!;
        var first = panel.Entries.ToArray();
        var read = source.AttributeWritePermissionRead!;
        source.AttributeWritePermissionRead = (reference, after) =>
        {
            if (defect == "unavailable") return Result<SavedAttributeWritePermission>.Failure(AuditError.Create(
                ErrorCategory.Evidence, "WritePageUnavailable", ErrorSeverity.Failed, "Requested saved permission page is unavailable.", null));
            var page = read(reference, after).Value;
            return Result<SavedAttributeWritePermission>.Success(defect == "context"
                ? page with { Context = page.Context with { ExpectednessReason = "UnexpectedOutsideAuthorityScope" } }
                : page with { Next = page.Next!.Value with { TargetGuid = Guid.NewGuid() } });
        };
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.True(panel.HasRefusal);
        Assert.Equal("Page 1", panel.PageLabel);
        Assert.Equal(first, panel.Entries);
        source.AttributeWritePermissionRead = read;
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.False(panel.HasRefusal);
        Assert.Equal("Page 2", panel.PageLabel);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ClosedOrExpiredPermissionPagesCannotPublishLateAnswers(bool expire) =>
        CheckClosedOrExpiredPermissionPages(expire, AttributeWritePermissionKind.ResourceBasedConstrainedDelegation);

    internal static void CheckClosedOrExpiredPermissionPages(bool expire, AttributeWritePermissionKind kind) => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(51, kind: kind);
        var row = Assert.Single(model.Findings);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = details.AttributeWritePermission!;
        var first = source.AttributeWritePermissionRead!(row.Saved.Reference!.Value, null).Value;
        var next = source.AttributeWritePermissionRead(row.Saved.Reference.Value, first.Next).Value;
        var release = new TaskCompletionSource<Result<SavedAttributeWritePermission>>(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = (value, _) => value is Result<SavedAttributeWritePermission> ? Complete(release.Task) : Task.FromResult(value);
        panel.NextPageCommand.Execute(null);
        var pending = panel.ReadCompletion;
        Assert.False(pending.IsCompleted);
        if (expire) source.IsCurrent = false; else model.CloseFindingDetails();
        release.SetResult(Result<SavedAttributeWritePermission>.Success(next));
        await pending;
        Assert.Empty(panel.Entries);
        Assert.Null(details.AttributeWritePermission);
        Assert.False(details.HasFinding);
        if (expire) Assert.True(details.HasRefusal);
    });

    [Theory]
    [InlineData(900, false)]
    [InlineData(1300, false)]
    [InlineData(900, true)]
    [InlineData(1300, true)]
    public void RealPermissionPanelDistinguishesEntryMeaningInheritanceAndNullDacl(int width, bool nullDacl) =>
        CheckRealPermissionPanel(width, nullDacl, AttributeWritePermissionKind.ResourceBasedConstrainedDelegation);

    internal static void CheckRealPermissionPanel(int width, bool nullDacl, AttributeWritePermissionKind kind) => OnSta(() =>
    {
        var (model, _, _) = Model(nullDacl ? 0 : 2, nullDacl: nullDacl, kind: kind, scope: SavedPropertyWriteScope.Attribute);
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show();
            Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Captured write permission");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Target account: Captured target");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible
                && value.Text == "Attribute: " + AttributeWritePermissionReadTests.Family(kind).Attribute);
            Assert.Equal(nullDacl, Descendants<TextBlock>(view).Any(value => value.IsVisible && value.Text == SavedAttributeWritePermission.NullDaclNote));
            if (!nullDacl)
            {
                var attributeLabel = kind == AttributeWritePermissionKind.ResourceBasedConstrainedDelegation
                    ? "RBCD attribute" : AttributeWritePermissionFamilyReadTests.AttributeLabel(kind);
                Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible
                    && value.Text == "Permission scope: " + attributeLabel);
                Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Allow");
                Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Deny");
                Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Assignment: Inherited");
                var note = Assert.Single(Descendants<TextBlock>(view), value => value.IsVisible
                    && value.Text.StartsWith("The original source of this inherited assignment", StringComparison.Ordinal));
                note.BringIntoView();
                Layout(view, width, 700);
                var scroll = (ScrollViewer)view.FindName("FindingDetailsScroll");
                var bounds = note.TransformToAncestor(scroll).TransformBounds(new Rect(0, 0, note.ActualWidth, note.ActualHeight));
                Assert.True(bounds.Left >= 0 && bounds.Right <= scroll.ActualWidth);
                Assert.Equal(TextWrapping.Wrap, note.TextWrapping);
            }
            Assert.DoesNotContain(Descendants<TextBox>(view), value => value.IsVisible && value.Text.Contains("mask 0x", StringComparison.Ordinal));
            Assert.DoesNotContain(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, "View membership evidence"));
            foreach (var label in new[] { "Open affected object", "Close" })
                Assert.Contains(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, label));
        }
        finally { host.Close(); }
    });

    private static async Task<object> Complete(Task<Result<SavedAttributeWritePermission>> read) => await read;

    internal static (AssetsViewModel Model, FakeAssetSource Source, AttributeWritePermissionEvidence Evidence) Model(
        int count, bool disabled = false, bool nullDacl = false,
        AttributeWritePermissionKind kind = AttributeWritePermissionKind.ResourceBasedConstrainedDelegation,
        SavedPropertyWriteScope scope = SavedPropertyWriteScope.AllProperties)
    {
        var (evidence, _, sources) = AttributeWritePermissionReadTests.Fixture(count, scope, nullDacl, kind);
        evidence = evidence with { AccountControl = [new(0, disabled ? "514" : "512", null)] };
        if (sources.Length > 1) sources[1] = sources[1] with { IsDeny = true, IsInherited = true };
        var source = new FakeAssetSource
        {
            FindingsPage = new([AttributeWritePermissionReadTests.Finding(evidence)], null, 1),
            FilterValues = new([Severity.High], [AttributeWritePermissionReadTests.Family(kind).Rule], 1),
        };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\attribute-write-permission", false);
        var row = Assert.Single(model.Findings);
        evidence = evidence with { GenerationId = row.Saved.Reference!.Value.GenerationId };
        var bound = evidence;
        source.AttributeWritePermissionRead = (_, after) =>
        {
            var entries = sources.Where(entry => entry.Ordinal > (after?.Ordinal ?? -1)).Take(50).ToArray();
            var next = sources.Count(entry => entry.Ordinal > (after?.Ordinal ?? -1)) > 50
                ? new AttributeWritePermissionMark(bound.GenerationId, row.Saved.Reference!.Value.FindingId, row.Saved.ObjectGuid, entries[^1].Ordinal)
                : (AttributeWritePermissionMark?)null;
            return Result<SavedAttributeWritePermission>.Success(
                AttributeWritePermissionReadTests.Project(bound, row.Saved, entries, sources.Length, after, next));
        };
        return (model, source, evidence);
    }
}
