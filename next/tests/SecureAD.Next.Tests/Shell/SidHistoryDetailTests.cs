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
public sealed class SidHistoryDetailTests
{
    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    [InlineData("group")]
    public void EveryReportedClassUsesTheSameSavedValuesAndConditionalGuidance(string kind)
    {
        var (model, source, _) = Model(2, 1, kind);
        Assert.Empty(source.SidHistoryReads);
        model.OpenFinding(Assert.Single(model.Findings));
        var details = model.FindingDetails!;
        var panel = Assert.IsType<SidHistoryViewModel>(details.SidHistory);
        Assert.Equal(kind, panel.ObjectType);
        Assert.Equal("Captured principal", panel.AffectedObject);
        Assert.Equal("S-1-5-21-1-2-3-1100", panel.ObjectSid);
        Assert.Equal(2, panel.Flagged.Values.Count);
        Assert.All(panel.Flagged.Values, row => Assert.Equal("Domain Admins", row.RecognisedType));
        Assert.Null(panel.Other);
        Assert.Single(source.SidHistoryReads);
        Assert.False(details.ShowsSavedDescription);
        Assert.False(details.ShowsStandardIdentity);
        Assert.Equal("High", details.Finding!.Severity);
        var guidance = RuleGuidanceCatalogue.For("SEC-027")!;
        Assert.Equal(guidance.WhyItMatters, details.Finding.WhyItMatters);
        Assert.Equal(guidance.WhatToDo, details.Finding.WhatToDo);
        Assert.Contains("Actual access depends on resource permissions", guidance.WhyItMatters, StringComparison.Ordinal);
        Assert.Contains("user, computer or group shown", guidance.WhatToDo, StringComparison.Ordinal);
        Assert.DoesNotContain("Set-ADUser", guidance.WhatToDo, StringComparison.Ordinal);
        Assert.Contains("Custom identifiers are not assessed for privilege", guidance.About, StringComparison.Ordinal);
        Assert.Empty(source.ControlQueries);
        Assert.Empty(source.PathQueries);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(50)]
    [InlineData(51)]
    [InlineData(127)]
    public void FlaggedPagingKeepsOriginalOrderAndOtherValuesAreExplicit(int count) => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(count, 51);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.SidHistory!;
        var values = new List<int>();
        do
        {
            values.AddRange(panel.Flagged.Values.Select(row => row.Ordinal));
            if (!panel.Flagged.NextPageCommand.CanExecute(null)) break;
            panel.Flagged.NextPageCommand.Execute(null);
            await panel.Flagged.ReadCompletion;
        } while (true);
        Assert.Equal(Enumerable.Range(0, count).Select(index => index * 2), values);
        panel.LoadOtherCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal(50, panel.Other!.Values.Count);
        Assert.All(panel.Other.Values, row => Assert.Equal("Not ranked by this rule.", row.RecognisedType));
        panel.Other.NextPageCommand.Execute(null);
        await panel.Other.ReadCompletion;
        Assert.Single(panel.Other.Values);
        panel.Other.PreviousPageCommand.Execute(null);
        await panel.Other.ReadCompletion;
        Assert.Equal("Page 1", panel.Other.PageLabel);
        Assert.Equal(50, panel.Other.Values.Count);
        Assert.Equal(1, panel.Other.Values[0].Ordinal);
        Assert.Equal(SidHistoryPageKind.Other, source.SidHistoryReads[^1].After!.Value.Kind);
    });

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public void EmptyOtherValuesAreEstablishedOnlyAfterTheExplicitSuccessfulRead(int unreadable) => OneThread.Run(async () =>
    {
        var (model, _, _) = Model(1, 0, unreadable: unreadable, ownSid: false, limited: true);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.SidHistory!;
        Assert.False(panel.HasOther);
        Assert.False(panel.HasNoOther);
        Assert.Equal("Not established from captured evidence.", panel.ObjectSid);
        Assert.Equal(unreadable, panel.UnreadableValues);
        Assert.Equal(unreadable > 0, panel.HasUnreadable);
        Assert.True(panel.HasCaptureLimit);
        panel.LoadOtherCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.True(panel.HasOther);
        Assert.True(panel.HasNoOther);
        Assert.Empty(panel.Other!.Values);
        Assert.Single(panel.Flagged.Values);
    });

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("object")]
    [InlineData("unreadable")]
    [InlineData("kind")]
    [InlineData("null-context")]
    [InlineData("category")]
    [InlineData("type-name")]
    public void InvalidInitialHistoryIsRefusedWithoutTheOldProse(string defect)
    {
        var (model, source, _) = Model(1, 1);
        var read = source.SidHistoryRead!;
        source.SidHistoryRead = (reference, after) =>
        {
            if (defect == "missing") return Result<SavedSidHistory>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "MissingSidHistory", ErrorSeverity.Failed, SavedSidHistory.InvalidDetails, null));
            var page = read(reference, after).Value;
            return Result<SavedSidHistory>.Success(defect switch
            {
                "generation" => page with { Context = page.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } },
                "object" => page with { Context = page.Context with { Object = page.Context.Object with { ObjectGuid = Guid.NewGuid() } } },
                "unreadable" => page with { Context = page.Context with { UnreadableValues = 99 } },
                "null-context" => page with { Context = null! },
                "category" => page with { Values = [page.Values[0] with { Sid = "S-1-5-21-1-2-3-1200" }] },
                "type-name" => page with { Values = [page.Values[0] with { RecognisedType = "Enterprise Admins" }] },
                _ => page with { Kind = SidHistoryPageKind.Other },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.Equal(SavedSidHistory.InvalidDetails, model.FindingDetails!.Refusal);
        Assert.False(model.FindingDetails.HasFinding);
        Assert.Null(model.FindingDetails.SidHistory);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InvalidContinuationKeepsItsPageAndAllowsRetry(bool other) => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(51, 51);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.SidHistory!;
        if (other) { panel.LoadOtherCommand.Execute(null); await panel.ReadCompletion; }
        var child = other ? panel.Other! : panel.Flagged;
        var before = child.Values.ToArray();
        var read = source.SidHistoryRead!;
        source.SidHistoryRead = (reference, after) =>
        {
            var page = read(reference, after).Value;
            return Result<SavedSidHistory>.Success(page with { Context = page.Context with
                { Reference = reference with { GenerationId = Guid.NewGuid() } } });
        };
        child.NextPageCommand.Execute(null);
        await child.ReadCompletion;
        Assert.True(child.HasRefusal);
        Assert.Equal("Page 1", child.PageLabel);
        Assert.Equal(before, child.Values);
        source.SidHistoryRead = read;
        child.NextPageCommand.Execute(null);
        await child.ReadCompletion;
        Assert.False(child.HasRefusal);
        Assert.Equal("Page 2", child.PageLabel);
        Assert.Single(child.Values);
    });

    [Fact]
    public void FailedOtherValueReadCannotBecomeAnEmptySuccessfulList() => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(1, 1);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.SidHistory!;
        var read = source.SidHistoryRead!;
        source.SidHistoryRead = (_, _) => Result<SavedSidHistory>.Failure(AuditError.Create(ErrorCategory.Evidence,
            "UnavailableSidHistory", ErrorSeverity.Failed, SavedSidHistory.InvalidDetails, null));
        panel.LoadOtherCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal(SavedSidHistory.InvalidDetails, panel.Refusal);
        Assert.False(panel.HasOther);
        Assert.False(panel.HasNoOther);
        Assert.True(panel.LoadOtherCommand.CanExecute(null));
        source.SidHistoryRead = read;
        panel.LoadOtherCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.False(panel.HasRefusal);
        Assert.Single(panel.Other!.Values);
    });

    [Fact]
    public void BothFindingEntryPointsKeepTheExactObjectAndReturnContext() => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(1, 1);
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
        Assert.NotNull(model.FindingDetails.SidHistory);
        Assert.Equal(2, source.SidHistoryReads.Count);
        Assert.Same(row, model.SelectedFinding);
        Assert.Same(opened, model.Opened);
        Assert.Same(section, opened.Content);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ClosedAndExpiredWindowsCannotPublishLateOtherValues(bool expire) => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(1, 1);
        var row = Assert.Single(model.Findings);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = details.SidHistory!;
        var first = source.SidHistoryRead!(row.Saved.Reference!.Value, null).Value;
        var other = source.SidHistoryRead(row.Saved.Reference.Value, first.Start with { Kind = SidHistoryPageKind.Other }).Value;
        var released = new TaskCompletionSource<Result<SavedSidHistory>>(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = (value, _) => value is Result<SavedSidHistory> ? Complete(released.Task) : Task.FromResult(value);
        panel.LoadOtherCommand.Execute(null);
        var pending = panel.ReadCompletion;
        Assert.False(pending.IsCompleted);
        if (expire) source.IsCurrent = false; else model.CloseFindingDetails();
        released.SetResult(Result<SavedSidHistory>.Success(other));
        await pending;
        Assert.Null(panel.Other);
        Assert.Empty(panel.Flagged.Values);
        Assert.Null(details.SidHistory);
    });

    [Theory]
    [InlineData(900)]
    [InlineData(1300)]
    public void ActualWindowKeepsFlaggedOtherAndUnreadableMeaningsDistinct(int width) => OnSta(() =>
    {
        var (model, _, _) = Model(1, 1, unreadable: 2);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.SidHistory!;
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Captured SID history");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Unreadable SID-history values: 2");
            Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "SID: S-1-5-21-1-2-3-512");
            Assert.DoesNotContain(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Other captured SID-history values");
            panel.LoadOtherCommand.Execute(null);
            Assert.True(panel.ReadCompletion.IsCompletedSuccessfully);
            Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Other captured SID-history values");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Not ranked by this rule.");
            Assert.DoesNotContain(Descendants<TextBlock>(view), value => value.IsVisible && value.Text.Contains("Set-ADUser", StringComparison.Ordinal));
        }
        finally { host.Close(); }
    });

    private static async Task<object> Complete(Task<Result<SavedSidHistory>> task) => await task;
    internal static (AssetsViewModel Model, FakeAssetSource Source, SavedHistoryValue[] Values) Model(int flagged, int other,
        string kind = "user", int unreadable = 0, bool ownSid = true, bool limited = false)
    {
        var values = Enumerable.Range(0, flagged).Select(index => new SavedHistoryValue(index * 2, "S-1-5-21-1-2-3-512", "Domain Admins"))
            .Concat(Enumerable.Range(0, other).Select(index => new SavedHistoryValue(index * 2 + 1, $"S-1-5-21-1-2-3-{1200 + index}", null)))
            .OrderBy(value => value.Ordinal).ToArray();
        var evidence = new PrivilegedSidHistoryEvidence(ownSid ? "S-1-5-21-1-2-3-1100" : null,
            values.Select(value => value.Sid).ToArray(), values.Where(value => value.RecognisedType is not null)
                .Select(value => new PrivilegedSidHistoryMatch(value.Sid, 512, value.RecognisedType!)).ToArray(), unreadable);
        var finding = new Finding("SEC-027", PrivilegedSidHistory.RuleVersion, Severity.High, new(FindingSubjectKind.Account, "Captured principal"),
            Guid.NewGuid(), "CN=Captured principal,DC=contoso,DC=com", "contoso.com", kind, "Old unbounded raw history prose.",
            limited ? EvidenceCompleteness.MayBeMissingConfidentialValues : EvidenceCompleteness.Complete, evidence) { PrincipalName = "Captured principal" };
        var source = new FakeAssetSource { FindingsPage = new([finding], null, 1), FilterValues = new([Severity.High], ["SEC-027"], 1) };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\sid-history", false);
        var selected = Assert.Single(model.Findings).Saved;
        var context = new SidHistoryContext(selected.Reference!.Value, selected.Subject,
            new(selected.ObjectGuid, selected.DistinguishedName, selected.DomainFqdn, selected.ObjectClass),
            selected.PrincipalName, evidence.ObjectSid, unreadable, selected.Coverage);
        source.SidHistoryRead = (_, after) =>
        {
            var pageKind = after?.Kind ?? SidHistoryPageKind.Flagged;
            var rows = values.Where(value => value.Ordinal > (after?.Ordinal ?? -1)
                && (value.RecognisedType is not null) == (pageKind == SidHistoryPageKind.Flagged)).Take(51).ToArray();
            var page = rows.Take(50).ToArray();
            SidHistoryMark? next = rows.Length > 50
                ? new(selected.Reference.Value.GenerationId, selected.Reference.Value.FindingId, selected.ObjectGuid, pageKind, page[^1].Ordinal) : null;
            return Result<SavedSidHistory>.Success(new(context, pageKind, page, next));
        };
        return (model, source, values);
    }
}
