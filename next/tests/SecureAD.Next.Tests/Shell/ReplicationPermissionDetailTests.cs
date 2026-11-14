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
public sealed class ReplicationPermissionDetailTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void HeaderKeepsSavedRightsHolderRootPolicyAndLimitsSeparate(bool nullDacl, bool incomplete)
    {
        var (model, source) = Model(nullDacl: nullDacl, incomplete: incomplete);
        Assert.Empty(source.ReplicationPermissionReads);
        var row = Assert.Single(model.Findings);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = Assert.IsType<ReplicationPermissionViewModel>(details.ReplicationPermission);
        Assert.Equal("Critical", details.Finding!.Severity);
        Assert.Equal("Established", panel.Changes);
        Assert.Equal("Established", panel.ChangesAll);
        Assert.Equal("DC=contoso,DC=com", panel.Root.DistinguishedName);
        Assert.Equal(nullDacl ? "S-1-1-0" : "S-1-5-21-1-2-3-1200", panel.Sid);
        Assert.Equal(nullDacl, panel.HasNullDacl);
        Assert.Equal(incomplete, panel.HasLimitations);
        Assert.Equal(incomplete ? "May be incomplete" : "Complete", details.Finding.Coverage);
        Assert.False(details.ShowsSavedDescription);
        Assert.False(details.ShowsStandardIdentity);
        Assert.Single(source.ReplicationPermissionReads);
        Assert.Empty(source.ControlQueries);
        Assert.Empty(source.PathQueries);
        Assert.Empty(source.Reads.Where(value => value is "Attributes" or "Permissions" or "Classification"));
        Assert.Equal(RuleGuidanceCatalogue.For("SEC-002")!.WhatToDo, details.Finding.WhatToDo);
        Assert.Contains("not proof of malicious use", panel.PolicyNote, StringComparison.Ordinal);
    }

    [Fact]
    public void PagesKeepOriginalOccurrencesAndDoNotChangeTheSavedAssessment()
    {
        var (model, source) = Model(total: 53);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.ReplicationPermission!;
        Assert.Equal(50, panel.Entries.Count);
        panel.NextPageCommand.Execute(null);
        Assert.True(panel.ReadCompletion.IsCompletedSuccessfully);
        Assert.Equal("Page 2", panel.PageLabel);
        Assert.Equal(new[] { 50, 51, 52 }, panel.Entries.Select(entry => entry.Saved.Ordinal));
        Assert.Equal("Established", panel.ChangesAll);
        Assert.False(panel.HasLimitations);
        panel.PreviousPageCommand.Execute(null);
        Assert.Equal("Page 1", panel.PageLabel);
        Assert.Equal(Enumerable.Range(0, 50), panel.Entries.Select(entry => entry.Saved.Ordinal));
        Assert.Equal(new int?[] { null, 49, null }, source.ReplicationPermissionReads.Select(read => read.After?.Ordinal));
    }

    [Fact]
    public void OtherSavedEntryTypesAndScopesStayExplicitlyUnassessed()
    {
        var (model, source) = Model();
        var read = source.ReplicationPermissionRead!;
        source.ReplicationPermissionRead = (reference, after) =>
        {
            var value = read(reference, after).Value;
            return Result<SavedReplicationPermission>.Success(value with { Entries = value.Entries.Select(entry => entry with
                { EntryType = "Other saved entry (not re-evaluated here)", Scope = "Other saved scope (not re-evaluated here)" }).ToArray() });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.ReplicationPermission!;
        Assert.All(panel.Entries, entry =>
        {
            Assert.Equal("Other saved entry (not re-evaluated here)", entry.EntryType);
            Assert.Equal("Other saved scope (not re-evaluated here)", entry.Scope);
        });
        Assert.Equal("Established", panel.ChangesAll);
    }

    [Fact]
    public void HolderNamesComeFromTheSavedAnswerWithoutReplacingTheSid()
    {
        var (model, source) = Model();
        var read = source.ReplicationPermissionRead!;
        source.ReplicationPermissionRead = (reference, after) =>
        {
            var value = read(reference, after).Value;
            return Result<SavedReplicationPermission>.Success(value with { Context = value.Context with { HolderName = "Saved named holder" } });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.Equal("Saved named holder", model.FindingDetails!.ReplicationPermission!.Holder);
        Assert.Equal("S-1-5-21-1-2-3-1200", model.FindingDetails.ReplicationPermission.Sid);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("root")]
    [InlineData("sid")]
    [InlineData("scope")]
    [InlineData("empty")]
    [InlineData("order")]
    [InlineData("cursor")]
    [InlineData("truncated")]
    public void InvalidSavedReplicationDataIsRefusedInsteadOfGenericProse(string defect)
    {
        var (model, source) = Model(total: 53);
        var read = source.ReplicationPermissionRead!;
        source.ReplicationPermissionRead = (reference, after) =>
        {
            if (defect == "missing") return Result<SavedReplicationPermission>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "MissingReplication", ErrorSeverity.Failed, SavedReplicationPermission.InvalidDetails, null));
            var value = read(reference, after).Value;
            return Result<SavedReplicationPermission>.Success(defect switch
            {
                "generation" => value with { Context = value.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } },
                "root" => value with { Context = value.Context with { Root = value.Context.Root with { ObjectGuid = Guid.NewGuid() } } },
                "sid" => value with { Context = value.Context with { HolderSid = "not a SID" } },
                "scope" => value with { Context = value.Context with { HolderScope = "other.example" } },
                "empty" => value with { Entries = [] },
                "order" => value with { Entries = value.Entries.Reverse().ToArray() },
                "truncated" => value with { Next = null },
                _ => value with { Next = value.Next!.Value with { EdgeId = 99 } },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.Equal(SavedReplicationPermission.InvalidDetails, model.FindingDetails!.Refusal);
        Assert.False(model.FindingDetails.HasFinding);
        Assert.Null(model.FindingDetails.ReplicationPermission);
    }

    [Theory]
    [InlineData("version")]
    [InlineData("severity")]
    [InlineData("subject")]
    [InlineData("domain")]
    [InlineData("class")]
    public void ReplicationContextCannotBindToAnotherSavedAnswer(string defect)
    {
        var (model, source) = Model();
        var row = Assert.Single(model.Findings).Saved;
        var value = source.ReplicationPermissionRead!(row.Reference!.Value, null).Value.Context;
        row = defect switch
        {
            "version" => row with { RuleVersion = 2 },
            "severity" => row with { Severity = Severity.High },
            "subject" => row with { Subject = new(FindingSubjectKind.DirectoryObject, "other") },
            "domain" => row with { DomainFqdn = "other.example" },
            _ => row with { ObjectClass = "configuration" },
        };
        Assert.False(value.Matches(row));
    }

    [Theory]
    [InlineData("entry")]
    [InlineData("generation")]
    [InlineData("error")]
    [InlineData("short")]
    public void BadNextPageKeepsTheLastValidEntriesAndShowsRefusal(string defect)
    {
        var (model, source) = Model(total: 53);
        var read = source.ReplicationPermissionRead!;
        source.ReplicationPermissionRead = (reference, after) =>
        {
            var value = read(reference, after);
            if (after is null) return value;
            if (defect == "error") return Result<SavedReplicationPermission>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "ReplicationPageUnavailable", ErrorSeverity.Failed, "Saved replication page unavailable.", null));
            return Result<SavedReplicationPermission>.Success(defect == "short" ? value.Value with { Entries = value.Value.Entries.Take(1).ToArray() }
                : defect == "entry" ? value.Value with { Entries = [] }
                : value.Value with { Context = value.Value.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.ReplicationPermission!;
        panel.NextPageCommand.Execute(null);
        Assert.Equal("Page 1", panel.PageLabel);
        Assert.Equal(50, panel.Entries.Count);
        Assert.True(panel.HasRefusal);
        Assert.Equal(defect == "error" ? "Saved replication page unavailable." : SavedReplicationPermission.InvalidDetails, panel.Refusal);
    }

    [Fact]
    public void BothEntryPointsKeepTheExactDomainRootAndClearLoadedPanels() => OneThread.Run(async () =>
    {
        var (model, source) = Model();
        var row = Assert.Single(model.Findings);
        model.SelectedFinding = row;
        source.Attributes = FakeAssetSource.CapturedObject(row.DistinguishedName, row.ObjectClass) with { ObjectGuid = row.Saved.ObjectGuid };
        source.Permissions = ControlEdgeDeriverTests.Permissions(row.DistinguishedName);
        model.OpenFinding(row);
        var first = model.FindingDetails!.ReplicationPermission!;
        model.OpenAffectedObjectCommand.Execute(null);
        await model.ObjectReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(model.Opened);
        opened.Show(ObjectSectionCatalog.Findings); await opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        model.CloseFindingDetails();
        Assert.Empty(first.Entries);
        model.OpenFinding(Assert.Single(section.Findings));
        Assert.Equal(row.Saved.Reference, model.FindingDetails!.Finding!.Saved.Reference);
        Assert.Same(row, model.SelectedFinding);
        var panel = model.FindingDetails.ReplicationPermission!;
        source.IsCurrent = false;
        Assert.False(model.FindingDetails.CheckCurrent());
        Assert.Empty(panel.Entries);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CloseOrExpiryPreventsLatePages(bool expire) => OneThread.Run(async () =>
    {
        var (model, source) = Model(total: 53);
        var read = source.ReplicationPermissionRead!;
        var release = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = (value, _) => value is Result<SavedReplicationPermission> permission && permission.IsSuccess
            && permission.Value.Entries[0].Ordinal == 50 ? release.Task : Task.FromResult(value);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.ReplicationPermission!;
        panel.NextPageCommand.Execute(null); var pending = panel.ReadCompletion;
        Assert.False(pending.IsCompleted);
        if (expire) source.IsCurrent = false; else model.CloseFindingDetails();
        var row = Assert.Single(model.Findings).Saved;
        var reference = row.Reference!.Value;
        release.SetResult(read(reference, new(reference.GenerationId, reference.FindingId, row.ObjectGuid, 1, 49)));
        await pending;
        Assert.Empty(panel.Entries);
        Assert.False(panel.HasRefusal);
    });

    [Theory]
    [InlineData(900, false)]
    [InlineData(1300, false)]
    [InlineData(900, true)]
    [InlineData(1300, true)]
    public void ActualWindowShowsBothRightsAndDistinctNullDaclState(int width, bool nullDacl) => OnSta(() =>
    {
        var (model, _) = Model(nullDacl: nullDacl);
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000, ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, width, 700);
            foreach (var label in new[] { "Saved replication-permission assessment",
                "Replicating Directory Changes: Established", "Replicating Directory Changes All: Established" })
                Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == label);
            Assert.Equal(nullDacl, Descendants<TextBlock>(view).Any(value => value.IsVisible && value.Text == SavedAttributeWritePermission.NullDaclNote));
            Assert.Equal(!nullDacl, Descendants<TextBlock>(view).Any(value => value.IsVisible && value.Text == "Saved permission entries"));
        }
        finally { host.Close(); }
    });

    internal static (AssetsViewModel Model, FakeAssetSource Source) Model(int total = 2, bool nullDacl = false, bool incomplete = false)
    {
        var guid = Guid.NewGuid(); var root = "DC=contoso,DC=com"; var sid = nullDacl ? "S-1-1-0" : "S-1-5-21-1-2-3-1200";
        var evidence = new ReplicationPermissionEvidence(Guid.NewGuid(), new string('a', 64), Guid.NewGuid(), new string('b', 64),
            1, 11, 2, 2, guid, root, "contoso.com", "domainDNS", "PartitionRoot", sid, null, null,
            "UnexpectedNotControlPlane", nullDacl ? "GrantsEveryoneEverything" : "Determinate", [], [],
            incomplete ? ["CaptureIncomplete"] : []);
        var finding = new Finding("SEC-002", 1, Severity.Critical, new(FindingSubjectKind.DirectoryObject, sid + ":"),
            guid, root, "contoso.com", "domainDNS", "Raw saved replication proof prose.", EvidenceCompleteness.Complete, evidence);
        var source = new FakeAssetSource { FindingsPage = new([finding], null, 1), FilterValues = new([Severity.Critical], ["SEC-002"], 1) };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\replication", false);
        var row = Assert.Single(model.Findings).Saved;
        source.ReplicationPermissionRead = (reference, after) =>
        {
            var context = new ReplicationPermissionContext(reference, row.Subject, new(guid, root, "contoso.com", "domainDNS"), 1,
                sid, null, null, nullDacl ? "UnexpectedBroadPrincipal" : "UnexpectedNotControlPlane", nullDacl, incomplete, false,
                !incomplete, nullDacl ? 0 : total);
            var start = after?.Ordinal + 1 ?? 0;
            var entries = nullDacl ? [] : Enumerable.Range(start, Math.Min(50, total - start))
                .Select(index => new SavedReplicationPermissionEntry(index, "Allow", sid, null,
                    index % 2 == 0 ? "Replicating Directory Changes" : "Replicating Directory Changes All", index % 2 == 0)).ToArray();
            return Result<SavedReplicationPermission>.Success(new(context, entries,
                !nullDacl && start + entries.Length < total ? new(reference.GenerationId, reference.FindingId, guid, 1, entries[^1].Ordinal) : null, start));
        };
        return (model, source);
    }
}
