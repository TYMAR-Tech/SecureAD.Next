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

public sealed class ResourceDelegationDetailTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ResourcePanelUsesSavedResourceGrantsAndQualifiedRoleWithoutOtherAnalysis(bool established)
    {
        var (model, source, _) = Model(ResourceDelegationReadTests.Evidence(2, established: established));
        var row = Assert.Single(model.Findings);
        model.SelectedFinding = row;
        Assert.Empty(source.ResourceDelegationReads);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = Assert.IsType<DelegationConfigurationViewModel>(details.DelegationConfiguration);
        Assert.True(details.HasFinding);
        Assert.True(panel.IsResourceBased);
        Assert.False(panel.IsConstrained);
        Assert.False(details.ShowsSavedDescription);
        Assert.False(details.ShowsStandardIdentity);
        Assert.Null(details.CapturedSetting);
        Assert.Equal("Captured RBCD configuration", panel.Heading);
        Assert.Equal("resource account", panel.ResourceName);
        Assert.Equal("computer", panel.Resource.ObjectClass);
        Assert.Equal(established ? "Established Tier 0 resource."
            : "Identified controller or dependency of Tier 0; not itself classified as Tier 0.", panel.ResourceRelevance);
        Assert.Equal("High", details.Finding!.Severity);
        Assert.Equal("Complete", details.Finding.Coverage);
        Assert.Equal("SEC-013", details.Finding.Rule);
        Assert.Equal(SavedDelegationConfiguration.ResourceStatement, panel.Statement);
        Assert.Equal(SavedDelegationConfiguration.ResourceScopeNote, panel.ScopeNote);
        Assert.Equal(2, panel.Holders.Count);
        Assert.Equal("Captured group holder", panel.Holders[0].DisplayName);
        Assert.Equal("S-1-5-21-1-2-3-1100", panel.Holders[0].Sid);
        Assert.Equal("Name not resolved from captured evidence.", panel.Holders[1].DisplayName);
        Assert.Equal("S-1-5-21-1-2-3-1101", panel.Holders[1].Sid);
        Assert.Empty(panel.Services);
        Assert.Empty(source.ConstrainedDelegationReads);
        Assert.Empty(source.AccountSettingReads);
        Assert.Empty(source.PathQueries);
        Assert.Empty(source.ControlQueries);
        Assert.Null(details.ServiceRegistration);
        Assert.All(source.FindingSelections, value => Assert.False(value.Membership));
        Assert.Equal(row.Saved.Reference!.Value, Assert.Single(source.ResourceDelegationReads).Reference);
        var rules = new RuleRowViewModel("SEC-013", new ResourceBasedDelegationOnRelevantResource().Definition, null);
        Assert.Equal(rules.WhyItMatters, details.Finding.WhyItMatters);
        Assert.Equal(rules.WhatToDo, details.Finding.WhatToDo);
        Assert.Contains("A group-held grant does not establish authorization for each member.", rules.WhyItMatters, StringComparison.Ordinal);
        Assert.Contains("does not establish current service use, working delegation", rules.WhyItMatters, StringComparison.Ordinal);
        Assert.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity on the resource account", rules.WhatToDo, StringComparison.Ordinal);
        Assert.Contains("Do not clear the entire configuration indiscriminately", rules.WhatToDo, StringComparison.Ordinal);
        Assert.Contains("or change general object permissions as a substitute.", rules.WhatToDo, StringComparison.Ordinal);
        model.CloseFindingDetails();
        Assert.Same(row, model.SelectedFinding);
        Assert.Empty(panel.Holders);
    }

    [Fact]
    public void HolderPagesKeepExactOrderPreviousPositionsAndIndependentCoverage() => OneThread.Run(async () =>
    {
        var (model, source, evidence) = Model(ResourceDelegationReadTests.Evidence(127));
        var row = Assert.Single(model.Findings);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = details.DelegationConfiguration!;
        var first = panel.Holders.ToArray();
        Assert.Equal(50, first.Length);
        Assert.Equal("Page 1", panel.PageLabel);
        Assert.False(panel.PreviousPageCommand.CanExecute(null));
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal("Page 2", panel.PageLabel);
        Assert.Equal(evidence.Grants.Skip(50).Take(50).Select(grant => grant.TrusteeSid), panel.Holders.Select(holder => holder.Sid));
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal("Page 3", panel.PageLabel);
        Assert.Equal(27, panel.Holders.Count);
        Assert.False(panel.NextPageCommand.CanExecute(null));
        Assert.False(panel.HasLimitations);
        Assert.Equal("Complete", details.Finding!.Coverage);
        panel.PreviousPageCommand.Execute(null);
        await panel.ReadCompletion;
        panel.PreviousPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal("Page 1", panel.PageLabel);
        Assert.Equal(first, panel.Holders);
        Assert.Equal(new long?[] { null, 50, 100, 50, null }, source.ResourceDelegationReads.Select(read => read.After?.Offset));
        Assert.Same(row, model.Findings[0]);
    });

    [Fact]
    public void BothEntryPointsUseTheSameSavedResourceAndKeepObjectReturnContext() => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(ResourceDelegationReadTests.Evidence(1));
        var row = Assert.Single(model.Findings);
        model.SelectedFinding = row;
        source.Attributes = FakeAssetSource.CapturedObject(row.DistinguishedName, row.ObjectClass) with { ObjectGuid = row.Saved.ObjectGuid };
        source.Permissions = ControlEdgeDeriverTests.Permissions(row.DistinguishedName);
        model.OpenFinding(row);
        var resource = model.FindingDetails!.DelegationConfiguration!.Resource;
        model.OpenAffectedObjectCommand.Execute(null);
        await model.ObjectReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(model.Opened);
        opened.Show(ObjectSectionCatalog.Findings);
        await opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        model.CloseFindingDetails();
        model.OpenFinding(Assert.Single(section.Findings));
        Assert.Equal(resource, model.FindingDetails!.DelegationConfiguration!.Resource);
        Assert.Equal(2, source.ResourceDelegationReads.Count);
        Assert.All(source.ResourceDelegationReads, read => Assert.Equal(row.Saved.Reference!.Value, read.Reference));
        Assert.Same(row, model.SelectedFinding);
        Assert.Same(opened, model.Opened);
        Assert.Same(section, opened.Content);
    });

    [Theory]
    [InlineData("missing")]
    [InlineData("family")]
    [InlineData("resource")]
    [InlineData("generation")]
    [InlineData("coverage")]
    [InlineData("too-many")]
    [InlineData("null-context")]
    [InlineData("bad-sid")]
    [InlineData("empty-name")]
    [InlineData("next")]
    public void InvalidSavedResourceDetailsAreRefusedWithoutProseFallback(string defect)
    {
        var (model, source, _) = Model(ResourceDelegationReadTests.Evidence(51));
        var read = source.ResourceDelegationRead!;
        source.ResourceDelegationRead = (reference, after) =>
        {
            if (defect == "missing") return Result<SavedDelegationConfiguration>.Failure(AuditError.Create(
                ErrorCategory.Evidence, "MissingSavedRBCD", ErrorSeverity.Failed, SavedDelegationConfiguration.ResourceInvalidDetails, null));
            var page = read(reference, after).Value;
            page = defect switch
            {
                "family" => page with { Context = page.Context with { Kind = DelegationConfigurationKind.Constrained } },
                "resource" => page with { Context = page.Context with { Resource = page.Context.Resource with { ObjectGuid = Guid.NewGuid() } } },
                "generation" => page with { Context = page.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } },
                "coverage" => page with { Context = page.Context with { EvidenceIsComplete = false } },
                "too-many" => page with { Holders = [.. page.Holders, new("S-1-5-21-1-2-3-9999", Name: null)] },
                "null-context" => page with { Context = null! },
                "bad-sid" => page with { Holders = [new("not a SID", Name: null)] },
                "empty-name" => page with { Holders = [new("S-1-5-21-1-2-3-1100", "")] },
                _ => page with { Next = page.Next!.Value with { Offset = 51 } },
            };
            return Result<SavedDelegationConfiguration>.Success(page);
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.True(model.FindingDetails!.HasRefusal);
        Assert.Equal(SavedDelegationConfiguration.ResourceInvalidDetails, model.FindingDetails.Refusal);
        Assert.False(model.FindingDetails.HasFinding);
        Assert.Null(model.FindingDetails.DelegationConfiguration);
        Assert.False(model.FindingDetails.ShowsSavedDescription);
    }

    [Theory]
    [InlineData("context")]
    [InlineData("next")]
    [InlineData("unavailable")]
    public void FailedResourceContinuationKeepsItsPageAndAllowsRetry(string defect) => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(ResourceDelegationReadTests.Evidence(127));
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.DelegationConfiguration!;
        var first = panel.Holders.ToArray();
        var read = source.ResourceDelegationRead!;
        source.ResourceDelegationRead = (reference, after) =>
        {
            if (defect == "unavailable") return Result<SavedDelegationConfiguration>.Failure(AuditError.Create(
                ErrorCategory.Evidence, "SavedRBCDUnavailable", ErrorSeverity.Failed, "Requested saved holder page is unavailable.", null));
            var page = read(reference, after).Value;
            return Result<SavedDelegationConfiguration>.Success(defect == "context"
                ? page with { Context = page.Context with { EstablishedTier0 = false } }
                : page with { Next = page.Next!.Value with { ResourceGuid = Guid.NewGuid() } });
        };
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.True(panel.HasRefusal);
        Assert.Equal("Page 1", panel.PageLabel);
        Assert.Equal(first, panel.Holders);
        source.ResourceDelegationRead = read;
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.False(panel.HasRefusal);
        Assert.Equal("Page 2", panel.PageLabel);
        Assert.Equal(50, panel.Holders.Count);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ClosedOrExpiredResourcePagesCannotPublishLateAnswers(bool expire) => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(ResourceDelegationReadTests.Evidence(51));
        var row = Assert.Single(model.Findings);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = details.DelegationConfiguration!;
        var first = source.ResourceDelegationRead!(row.Saved.Reference!.Value, null).Value;
        var next = source.ResourceDelegationRead(row.Saved.Reference.Value, first.Next).Value;
        var release = new TaskCompletionSource<Result<SavedDelegationConfiguration>>(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = (value, _) => value is Result<SavedDelegationConfiguration>
            ? Complete(release.Task) : Task.FromResult(value);
        panel.NextPageCommand.Execute(null);
        var pending = panel.ReadCompletion;
        Assert.False(pending.IsCompleted);
        if (expire) source.IsCurrent = false;
        else model.CloseFindingDetails();
        release.SetResult(Result<SavedDelegationConfiguration>.Success(next));
        await pending;
        Assert.Empty(panel.Holders);
        Assert.Null(details.DelegationConfiguration);
        Assert.False(details.HasFinding);
        if (expire) Assert.True(details.HasRefusal);
    });

    [Theory]
    [InlineData(900, false)]
    [InlineData(1300, false)]
    [InlineData(900, true)]
    [InlineData(1300, true)]
    public void RealRBCDWindowShowsHoldersOrNullDaclWithoutFictionalEntriesOrHiddenProof(int width, bool nullDacl) => OnSta(() =>
    {
        var evidence = ResourceDelegationReadTests.Evidence(nullDacl ? 0 : 2, nullDacl, established: false)
            with { Limitations = ["ResourceDelegationEntryUnsupported", "OtherRequesterDenyMembershipUnassessed"] };
        var (model, _, _) = Model(evidence);
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show();
            Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Captured RBCD configuration");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Resource: resource account");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Object type: computer");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible
                && value.Text == "Resource relevance: Identified controller or dependency of Tier 0; not itself classified as Tier 0.");
            Assert.Equal(nullDacl, Descendants<TextBlock>(view).Any(value => value.IsVisible && value.Text == SavedDelegationConfiguration.NullDaclNote));
            Assert.Equal(!nullDacl, Descendants<TextBlock>(view).Any(value => value.IsVisible && value.Text == "Configured delegation holders"));
            if (!nullDacl)
            {
                var name = Assert.Single(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "Captured group holder");
                var sid = Assert.Single(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "SID: S-1-5-21-1-2-3-1100");
                Assert.True(name.IsReadOnly && sid.IsReadOnly);
                Assert.Equal(TextWrapping.Wrap, sid.TextWrapping);
                sid.BringIntoView();
                Layout(view, width, 700);
                var scroll = (ScrollViewer)view.FindName("FindingDetailsScroll");
                var bounds = sid.TransformToAncestor(scroll).TransformBounds(new Rect(0, 0, sid.ActualWidth, sid.ActualHeight));
                Assert.True(bounds.Left >= 0 && bounds.Right <= scroll.ActualWidth);
                Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "Name not resolved from captured evidence.");
            }
            else
                Assert.DoesNotContain(Descendants<TextBox>(view), value => value.IsVisible && value.Text.Contains("S-1-1-0", StringComparison.Ordinal));
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Saved evidence limitations");
            Assert.Equal(2, model.FindingDetails!.DelegationConfiguration!.Limitations.Count);
            Assert.DoesNotContain(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Configured service names");
            Assert.DoesNotContain(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, "View membership evidence"));
            foreach (var label in new[] { "Open affected object", "Close" })
                Assert.Contains(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, label));
            foreach (var label in new[] { "Previous", "Next" })
                Assert.Equal(!nullDacl, Descendants<Button>(view).Any(value => value.IsVisible && Equals(value.Content, label)));
        }
        finally { host.Close(); }
    });

    private static async Task<object> Complete(Task<Result<SavedDelegationConfiguration>> read) => await read;

    private static (AssetsViewModel Model, FakeAssetSource Source, DelegationConfigurationEvidence Evidence) Model(
        DelegationConfigurationEvidence evidence)
    {
        var source = new FakeAssetSource
        {
            FindingsPage = new([ResourceDelegationReadTests.Finding(evidence)], null, 1),
            FilterValues = new([Severity.High], ["SEC-013"], 1),
        };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\resource-delegation-detail", false);
        var row = Assert.Single(model.Findings);
        evidence = evidence with { Scope = evidence.Scope with { GenerationId = row.Saved.Reference!.Value.GenerationId } };
        var bound = evidence;
        source.ResourceDelegationRead = (_, after) =>
        {
            var page = ResourceDelegationReadTests.Project(bound, row.Saved, after);
            return Result<SavedDelegationConfiguration>.Success(page with
            {
                Holders = page.Holders.Select(holder => holder.Sid == "S-1-5-21-1-2-3-1100"
                    ? holder with { Name = "Captured group holder" } : holder).ToArray(),
            });
        };
        return (model, source, evidence);
    }
}
