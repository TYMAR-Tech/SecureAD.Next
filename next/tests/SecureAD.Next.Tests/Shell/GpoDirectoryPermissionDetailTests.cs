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

[Collection("Finding window resources")]
public sealed class GpoDirectoryPermissionDetailTests
{
    [Theory]
    [InlineData("SEC-080")]
    [InlineData("SEC-081")]
    public void FindingPanelUsesSavedHolderTargetOperationsAndApprovedCaution(string rule)
    {
        var (model, source, _) = Model(rule, 2);
        var row = Assert.Single(model.Findings);
        model.SelectedFinding = row;
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = Assert.IsType<GpoDirectoryPermissionViewModel>(details.GpoDirectoryPermission);
        Assert.True(details.HasFinding);
        Assert.False(details.ShowsSavedDescription);
        Assert.False(details.ShowsStandardIdentity);
        Assert.Equal("Captured holder", panel.Holder);
        Assert.Equal(GpoDirectoryPermissionTests.HolderSid, panel.Sid);
        Assert.Equal(rule == "SEC-080" ? "GPO" : "Link scope", panel.TargetLabel);
        Assert.Equal(2, panel.Entries.Count);
        Assert.Contains("not authorization for every group member", panel.Caution, StringComparison.Ordinal);
        Assert.Equal("High", details.Finding!.Severity);
        Assert.Equal(rule, details.Finding.Rule);
        Assert.Empty(source.ControlQueries);
        Assert.Empty(source.PathQueries);
        Assert.Empty(source.AttributeWritePermissionReads);
        Assert.Empty(source.GmsaPasswordReadersReads);
        model.CloseFindingDetails();
        Assert.Same(row, model.SelectedFinding);
        Assert.Empty(panel.Entries);
        Assert.Null(details.GpoDirectoryPermission);
    }

    [Theory]
    [InlineData("SEC-080")]
    [InlineData("SEC-081")]
    public void OriginalEntryPagingAcceptsEquivalentContextAndKeepsReturnPosition(string rule) => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(rule, 127);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.GpoDirectoryPermission!;
        Assert.Equal(50, panel.Entries.Count);
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal(Enumerable.Range(50, 50), panel.Entries.Select(entry => entry.Ordinal));
        Assert.False(panel.HasRefusal);
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal(27, panel.Entries.Count);
        Assert.False(panel.NextPageCommand.CanExecute(null));
        panel.PreviousPageCommand.Execute(null);
        await panel.ReadCompletion;
        panel.PreviousPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal(Enumerable.Range(0, 50), panel.Entries.Select(entry => entry.Ordinal));
        Assert.Equal(new int?[] { null, 49, 99, 49, null }, source.GpoDirectoryPermissionReads.Select(read => read.After?.Ordinal));
    });

    [Theory]
    [InlineData("target")]
    [InlineData("holder")]
    [InlineData("generation")]
    [InlineData("coverage")]
    public void WrongSelectedFactsRefuseRatherThanDisplayAnotherQuestion(string defect)
    {
        var (model, source, _) = Model("SEC-080", 1);
        var read = source.GpoDirectoryPermissionRead!;
        source.GpoDirectoryPermissionRead = (reference, after) =>
        {
            var page = read(reference, after).Value;
            var context = defect switch
            {
                "target" => page.Context with { Target = page.Context.Target with { ObjectGuid = Guid.NewGuid() } },
                "holder" => page.Context with { HolderSid = GpoDirectoryPermissionTests.DomainSid + "-1500" },
                "generation" => page.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } },
                _ => page.Context with { EvidenceIsComplete = !page.Context.EvidenceIsComplete },
            };
            return Result<SavedGpoDirectoryPermission>.Success(page with { Context = context });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.False(model.FindingDetails!.HasFinding);
        Assert.Null(model.FindingDetails.GpoDirectoryPermission);
        Assert.Contains(SavedGpoDirectoryPermission.InvalidDetails, model.FindingDetails.Refusal!, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ClosedOrExpiredWindowCannotAcceptALateEntryPage(bool expire) => OneThread.Run(async () =>
    {
        var (model, source, _) = Model("SEC-081", 51);
        var row = Assert.Single(model.Findings);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = details.GpoDirectoryPermission!;
        var first = source.GpoDirectoryPermissionRead!(row.Saved.Reference!.Value, null).Value;
        var next = source.GpoDirectoryPermissionRead(row.Saved.Reference.Value, first.Next).Value;
        var release = new TaskCompletionSource<Result<SavedGpoDirectoryPermission>>(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = (value, _) => value is Result<SavedGpoDirectoryPermission> ? Complete(release.Task) : Task.FromResult(value);
        panel.NextPageCommand.Execute(null);
        var pending = panel.ReadCompletion;
        Assert.False(pending.IsCompleted);
        if (expire) source.IsCurrent = false; else model.CloseFindingDetails();
        release.SetResult(Result<SavedGpoDirectoryPermission>.Success(next));
        await pending;
        Assert.Empty(panel.Entries);
        Assert.Null(details.GpoDirectoryPermission);
        Assert.False(details.HasFinding);
    });

    [Theory]
    [InlineData("SEC-080", 900)]
    [InlineData("SEC-080", 1300)]
    [InlineData("SEC-081", 900)]
    [InlineData("SEC-081", 1300)]
    public void ActualFindingViewShowsItsApprovedFactsAndCommonActions(string rule, int width) => OnSta(() =>
    {
        var (model, _, _) = Model(rule, 1);
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show();
            Layout(view, width, 700);
            foreach (var label in new[] { "Permission holder: Captured holder", "Permission identified", "Why the holder is unexpected" })
                Assert.Contains(Descendants<TextBlock>(view), text => text.IsVisible && text.Text == label);
            Assert.Contains(Descendants<TextBlock>(view), text => text.IsVisible
                && text.Text.StartsWith(rule == "SEC-080" ? "GPO:" : "Link scope:", StringComparison.Ordinal));
            Assert.DoesNotContain(Descendants<TextBox>(view), text => text.IsVisible && text.Text.Contains("mask 0x", StringComparison.Ordinal));
            foreach (var action in new[] { "Open affected object", "Close" })
                Assert.Contains(Descendants<Button>(view), button => button.IsVisible && Equals(button.Content, action));
        }
        finally { host.Close(); }
    });

    private static async Task<object> Complete(Task<Result<SavedGpoDirectoryPermission>> read) => await read;

    private static (AssetsViewModel Model, FakeAssetSource Source, GpoDirectoryPermissionEvidence Evidence) Model(string rule, int count)
    {
        var kind = rule == "SEC-080" ? "groupPolicyContainer" : "organizationalUnit";
        var finding = Assert.Single(GpoDirectoryPermissionTests.Assess(rule,
            Enumerable.Range(0, count).Select(index => GpoDirectoryPermissionTests.Entry(index, 0x20)).ToArray(), kind).Findings);
        var source = new FakeAssetSource { FindingsPage = new([finding], null, 1),
            FilterValues = new([Severity.High], [rule], 1) };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\gpo-directory-permissions", false);
        var row = Assert.Single(model.Findings);
        var evidence = GpoDirectoryPermissionTests.Evidence(finding) with { GenerationId = row.Saved.Reference!.Value.GenerationId };
        source.GpoDirectoryPermissionRead = (reference, after) =>
        {
            var context = GpoDirectoryPermissionStorage.Context(reference, evidence, count) with
                { Operations = evidence.Rights.Select(right => new SavedGpoDirectoryOperation(right.Operation, right.State)).ToArray() };
            var entries = Enumerable.Range(0, count).Where(index => index > (after?.Ordinal ?? -1)).Take(50)
                .Select(index => new SavedGpoDirectoryEntry(index, false, false, "All properties", "Recorded policy write", true)).ToArray();
            var next = (after?.Ordinal ?? -1) + entries.Length + 1 < count
                ? new GpoDirectoryPermissionMark(reference.GenerationId, reference.FindingId, context.Target.ObjectGuid, entries[^1].Ordinal)
                : (GpoDirectoryPermissionMark?)null;
            return Result<SavedGpoDirectoryPermission>.Success(new(context, entries, next));
        };
        return (model, source, evidence);
    }
}
