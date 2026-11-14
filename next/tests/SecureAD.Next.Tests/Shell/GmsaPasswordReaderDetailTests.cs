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
public sealed class GmsaPasswordReaderDetailTests
{
    [Fact]
    public void TheFindingWindowUsesSavedServiceHolderRiskAndLimitsWithoutUnrelatedAnalysis()
    {
        var (model, source, _) = Model(1);
        var row = Assert.Single(model.Findings);
        model.SelectedFinding = row;
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = Assert.IsType<GmsaPasswordReadersViewModel>(details.GmsaPasswordReaders);
        Assert.True(details.HasFinding);
        Assert.False(details.ShowsSavedDescription);
        Assert.False(details.ShowsStandardIdentity);
        Assert.Equal("svc-app$ (contoso.com)", panel.ServiceAccount);
        Assert.Equal("Authenticated Users (S-1-5-11)", panel.BroadIdentity);
        Assert.Equal("Enabled", panel.AccountState);
        Assert.Equal("Captured reader 6000", Assert.Single(panel.Holders).PermissionHolder);
        Assert.Equal("Through a group", Assert.Single(panel.Holders).Inclusion);
        Assert.Equal("High", details.Finding!.Severity);
        Assert.Contains("not an individual member's authorization", panel.ScopeNote, StringComparison.Ordinal);
        Assert.Contains("Check dependent services", details.Finding.WhatToDo, StringComparison.Ordinal);
        Assert.Empty(source.ControlQueries);
        Assert.Empty(source.PathQueries);
        Assert.Empty(source.AttributeWritePermissionReads);
        Assert.Empty(source.AccountSettingReads);
        model.CloseFindingDetails();
        Assert.Same(row, model.SelectedFinding);
        Assert.Empty(panel.Holders);
        Assert.Null(details.GmsaPasswordReaders);
    }

    [Fact]
    public void PagingKeepsWholeFindingCompletenessAndAcceptsEquivalentDeserializedContext() => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(127, incomplete: true);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.GmsaPasswordReaders!;
        Assert.Equal(50, panel.Holders.Count);
        Assert.True(panel.HasLimitations);
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal(Enumerable.Range(50, 50), panel.Holders.Select(holder => holder.Ordinal));
        Assert.False(panel.HasRefusal);
        Assert.True(panel.HasLimitations);
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal(27, panel.Holders.Count);
        Assert.False(panel.NextPageCommand.CanExecute(null));
        panel.PreviousPageCommand.Execute(null);
        await panel.ReadCompletion;
        panel.PreviousPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal(Enumerable.Range(0, 50), panel.Holders.Select(holder => holder.Ordinal));
        Assert.Equal(new int?[] { null, 49, 99, 49, null }, source.GmsaPasswordReadersReads.Select(read => read.After?.Ordinal));
    });

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("target")]
    [InlineData("identity")]
    [InlineData("coverage")]
    public void WrongSavedContextIsARefusalNotAWorkingFindingWindow(string defect)
    {
        var (model, source, _) = Model(1);
        var read = source.GmsaPasswordReadersRead!;
        source.GmsaPasswordReadersRead = (reference, after) =>
        {
            if (defect == "missing")
                return Result<SavedGmsaPasswordReaders>.Failure(AuditError.Create(ErrorCategory.Evidence,
                    "SyntheticGmsaRefusal", ErrorSeverity.Failed, SavedGmsaPasswordReaders.InvalidDetails, null));
            var page = read(reference, after).Value;
            var context = defect switch
            {
                "generation" => page.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } },
                "target" => page.Context with { ObjectGuid = Guid.NewGuid() },
                "identity" => page.Context with { BroadName = "Another identity" },
                _ => page.Context with { EvidenceIsComplete = !page.Context.EvidenceIsComplete },
            };
            return Result<SavedGmsaPasswordReaders>.Success(page with { Context = context });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.False(model.FindingDetails!.HasFinding);
        Assert.Null(model.FindingDetails.GmsaPasswordReaders);
        Assert.Contains(SavedGmsaPasswordReaders.InvalidDetails, model.FindingDetails.Refusal!, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ClosedOrExpiredWindowsCannotAcceptALateHolderPage(bool expire) => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(51);
        var row = Assert.Single(model.Findings);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = details.GmsaPasswordReaders!;
        var first = source.GmsaPasswordReadersRead!(row.Saved.Reference!.Value, null).Value;
        var next = source.GmsaPasswordReadersRead(row.Saved.Reference.Value, first.Next).Value;
        var release = new TaskCompletionSource<Result<SavedGmsaPasswordReaders>>(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = (value, _) => value is Result<SavedGmsaPasswordReaders> ? Complete(release.Task) : Task.FromResult(value);
        panel.NextPageCommand.Execute(null);
        var pending = panel.ReadCompletion;
        Assert.False(pending.IsCompleted);
        if (expire) source.IsCurrent = false; else model.CloseFindingDetails();
        release.SetResult(Result<SavedGmsaPasswordReaders>.Success(next));
        await pending;
        Assert.Empty(panel.Holders);
        Assert.Null(details.GmsaPasswordReaders);
        Assert.False(details.HasFinding);
        if (expire) Assert.True(details.HasRefusal);
    });

    [Theory]
    [InlineData(900)]
    [InlineData(1300)]
    public void RealFindingViewShowsApprovedFactsAndActionsWithoutRawDescriptorText(int width) => OnSta(() =>
    {
        var (model, _, _) = Model(1);
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show();
            Layout(view, width, 700);
            foreach (var fact in new[] { "Service account: svc-app$ (contoso.com)",
                "Broad identity: Authenticated Users (S-1-5-11)", "Permission holder: Captured reader 6000",
                "Through a group", "Account state at capture: Enabled" })
                Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == fact);
            Assert.DoesNotContain(Descendants<TextBox>(view), value => value.IsVisible && value.Text.Contains("mask 0x", StringComparison.Ordinal));
            foreach (var action in new[] { "Open affected object", "Close" })
                Assert.Contains(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, action));
        }
        finally { host.Close(); }
    });

    [Theory]
    [InlineData("CapturedInput.msDS-GroupMSAMembership.ZeroValue", "unset or unreadable")]
    [InlineData("CapturedInput.msDS-GroupMSAMembership.IncompleteValue", "could not be read completely")]
    [InlineData("PrincipalExpansion.GmsaReaderScopeUnsupported", "object-specific scope")]
    [InlineData("PrincipalExpansion.GmsaReaderDenialUnassessed", "individual requester's")]
    [InlineData("PrincipalExpansion.MembershipProcessingLimit", "processing limit")]
    public void MissingCaptureUnsupportedAnalysisAndProcessingLimitsHaveDifferentExplanations(string token, string expected)
    {
        var text = SavedGmsaPasswordReaders.DescribeLimitation(token);
        Assert.Contains(expected, text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("expiry", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("protected", text, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<object> Complete(Task<Result<SavedGmsaPasswordReaders>> read) => await read;

    internal static (AssetsViewModel Model, FakeAssetSource Source, GmsaPasswordReaderEvidence Evidence) Model(int count, bool incomplete = false)
    {
        var finding = GmsaPasswordReaderTests.FindingWithHolders(count, captureComplete: !incomplete);
        var source = new FakeAssetSource
        {
            FindingsPage = new([finding], null, 1),
            FilterValues = new([Severity.High], ["SEC-102"], 1),
        };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\gmsa-password-readers", false);
        var row = Assert.Single(model.Findings);
        var proof = GmsaPasswordReaderTests.Proof(finding) with { GenerationId = row.Saved.Reference!.Value.GenerationId };
        source.GmsaPasswordReadersRead = (reference, after) =>
        {
            var context = GmsaPasswordReaderStorage.Context(reference, proof) with { Limitations = proof.Limitations.ToArray() };
            var holders = proof.Grants.Select((grant, ordinal) => new SavedGmsaPasswordReaderHolder(ordinal,
                grant.HolderSid, grant.HolderScope, grant.HolderName, grant.IsDirect, grant.GrantOrdinals.Count,
                false, grant.HasNullDacl, grant.MembershipIsComplete))
                .Where(holder => holder.Ordinal > (after?.Ordinal ?? -1)).Take(50).ToArray();
            var next = (after?.Ordinal ?? -1) + holders.Length + 1 < context.HolderCount
                ? new GmsaPasswordReaderMark(reference.GenerationId, reference.FindingId, context.ObjectGuid, holders[^1].Ordinal)
                : (GmsaPasswordReaderMark?)null;
            return Result<SavedGmsaPasswordReaders>.Success(new(context, holders, next));
        };
        return (model, source, proof);
    }
}
