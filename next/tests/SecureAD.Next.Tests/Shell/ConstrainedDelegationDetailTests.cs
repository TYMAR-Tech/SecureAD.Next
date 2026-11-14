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

public sealed class ConstrainedDelegationDetailTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void StructuredDelegationShowsSavedRolesAndGuidanceWithoutOtherAnalysisOrGridReads(bool established)
    {
        var (model, source, _) = Model(2, established);
        var row = Assert.Single(model.Findings);
        model.SelectedFinding = row;
        Assert.Empty(source.ConstrainedDelegationReads);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = Assert.IsType<DelegationConfigurationViewModel>(details.DelegationConfiguration);
        Assert.True(details.HasFinding);
        Assert.False(details.ShowsSavedDescription);
        Assert.False(details.ShowsStandardIdentity);
        Assert.Null(details.CapturedSetting);
        Assert.Equal("delegating account", panel.DelegatingAccount);
        Assert.Equal("user", panel.Account.ObjectClass);
        Assert.Equal("contoso.com", panel.Resource.DomainFqdn);
        Assert.Equal(established ? "Established Tier 0 resource."
            : "Identified controller or dependency of Tier 0; not itself classified as Tier 0.", panel.ResourceRelevance);
        Assert.Equal("High", details.Finding!.Severity);
        Assert.Equal("Complete", details.Finding.Coverage);
        Assert.Equal("SEC-012", details.Finding.Rule);
        Assert.Equal(SavedDelegationConfiguration.ConstrainedStatement, panel.Statement);
        Assert.Equal(row.Saved.Reference!.Value, Assert.Single(source.ConstrainedDelegationReads).Reference);
        Assert.Empty(source.AccountSettingReads);
        Assert.Empty(source.PathQueries);
        Assert.Empty(source.ControlQueries);
        Assert.Null(details.ServiceRegistration);
        Assert.All(source.FindingSelections, value => Assert.False(value.Membership));
        var rules = new RuleRowViewModel("SEC-012", new ConstrainedDelegationToRelevantService().Definition, null);
        Assert.Equal(rules.WhyItMatters, details.Finding.WhyItMatters);
        Assert.Equal(rules.WhatToDo, details.Finding.WhatToDo);
        Assert.Contains("Where Kerberos permits delegation", rules.WhyItMatters, StringComparison.Ordinal);
        Assert.Contains("does not establish current service use, working delegation", rules.WhyItMatters, StringComparison.Ordinal);
        Assert.Contains("msDS-AllowedToDelegateTo on the delegating account", rules.WhatToDo, StringComparison.Ordinal);
        Assert.Contains("Do not remove the resource's legitimate servicePrincipalName registration", rules.WhatToDo, StringComparison.Ordinal);
        Assert.Contains("or switch to unconstrained delegation as a shortcut", rules.WhatToDo, StringComparison.Ordinal);
        model.CloseFindingDetails();
        Assert.Same(row, model.SelectedFinding);
        Assert.Empty(panel.Services);
    }

    [Fact]
    public async Task ServicePagesPreserveDuplicatesPreviousPositionsAndIndependentCoverage()
    {
        var (model, source, evidence) = Model(127);
        var row = Assert.Single(model.Findings);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = details.DelegationConfiguration!;
        Assert.Equal(50, panel.Services.Count);
        Assert.Equal("Page 1", panel.PageLabel);
        Assert.False(panel.PreviousPageCommand.CanExecute(null));
        Assert.True(panel.NextPageCommand.CanExecute(null));
        var first = panel.Services.ToArray();
        Assert.Equal(first[0], first[1]);
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal("Page 2", panel.PageLabel);
        Assert.Equal(evidence.Services.Skip(50).Take(50).Select(value => value.ConfiguredService), panel.Services);
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal("Page 3", panel.PageLabel);
        Assert.Equal(27, panel.Services.Count);
        Assert.False(panel.NextPageCommand.CanExecute(null));
        Assert.True(panel.PreviousPageCommand.CanExecute(null));
        Assert.False(panel.HasLimitations);
        Assert.Equal("Complete", details.Finding!.Coverage);
        panel.PreviousPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal("Page 2", panel.PageLabel);
        panel.PreviousPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal("Page 1", panel.PageLabel);
        Assert.Equal(first, panel.Services);
        Assert.Null(source.ConstrainedDelegationReads[^1].After);
        Assert.Equal(new long?[] { null, 50, 100, 50, null }, source.ConstrainedDelegationReads.Select(value => value.After?.Offset));
        Assert.Same(row, model.Findings[0]);
    }

    [Fact]
    public async Task MainAndObjectFindingsShareTheSameConstrainedDelegationReaderAndReturnContext()
    {
        var (model, source, _) = Model(1);
        var row = Assert.Single(model.Findings);
        model.SelectedFinding = row;
        source.Attributes = FakeAssetSource.CapturedObject(row.DistinguishedName, row.ObjectClass) with { ObjectGuid = row.Saved.ObjectGuid };
        source.Permissions = ControlEdgeDeriverTests.Permissions(row.DistinguishedName);
        model.OpenFinding(row);
        var first = model.FindingDetails!.DelegationConfiguration!.Resource;
        model.OpenAffectedObjectCommand.Execute(null);
        await model.ObjectReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(model.Opened);
        opened.Show(ObjectSectionCatalog.Findings);
        await opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        model.CloseFindingDetails();
        model.OpenFinding(Assert.Single(section.Findings));
        Assert.Equal(first, model.FindingDetails!.DelegationConfiguration!.Resource);
        Assert.Equal(2, source.ConstrainedDelegationReads.Count);
        Assert.All(source.ConstrainedDelegationReads, read => Assert.Equal(row.Saved.Reference!.Value, read.Reference));
        Assert.Same(row, model.SelectedFinding);
        Assert.Same(opened, model.Opened);
        Assert.Same(section, opened.Content);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("account")]
    [InlineData("resource")]
    [InlineData("generation")]
    [InlineData("coverage")]
    [InlineData("too-many")]
    [InlineData("next")]
    [InlineData("null-context")]
    [InlineData("empty-value")]
    public void InvalidInitialDelegationDetailsAreExplicitRefusalsNotOriginalProseFallbacks(string defect)
    {
        var (model, source, _) = Model(51);
        var read = source.ConstrainedDelegationRead!;
        source.ConstrainedDelegationRead = (reference, after) =>
        {
            var original = read(reference, after);
            if (defect == "missing")
                return Result<SavedDelegationConfiguration>.Failure(AuditError.Create(ErrorCategory.Evidence,
                    "MissingSavedDelegation", ErrorSeverity.Failed, SavedDelegationConfiguration.ConstrainedInvalidDetails, null));
            var page = original.Value;
            page = defect switch
            {
                "account" => page with { Context = page.Context with { Account = page.Context.Account with { ObjectGuid = Guid.NewGuid() } } },
                "resource" => page with { Context = page.Context with { Resource = page.Context.Resource with { ObjectGuid = Guid.NewGuid() } } },
                "generation" => page with { Context = page.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } },
                "coverage" => page with { Context = page.Context with { EvidenceIsComplete = false } },
                "too-many" => page with { Services = [.. page.Services, "LDAP/not-requested.example"] },
                "null-context" => page with { Context = null! },
                "empty-value" => page with { Services = [""] },
                _ => page with { Next = page.Next!.Value with { Offset = 51 } },
            };
            return Result<SavedDelegationConfiguration>.Success(page);
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.True(model.FindingDetails!.HasRefusal);
        Assert.Equal(SavedDelegationConfiguration.ConstrainedInvalidDetails, model.FindingDetails.Refusal);
        Assert.False(model.FindingDetails.HasFinding);
        Assert.Null(model.FindingDetails.DelegationConfiguration);
        Assert.False(model.FindingDetails.ShowsSavedDescription);
    }

    [Theory]
    [InlineData("context")]
    [InlineData("next")]
    [InlineData("unavailable")]
    public async Task FailedContinuationKeepsItsOriginalPageAndAllowsARealRetry(string defect)
    {
        var (model, source, _) = Model(127);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.DelegationConfiguration!;
        var first = panel.Services.ToArray();
        var read = source.ConstrainedDelegationRead!;
        source.ConstrainedDelegationRead = (reference, after) =>
        {
            if (defect == "unavailable") return Result<SavedDelegationConfiguration>.Failure(AuditError.Create(
                ErrorCategory.Evidence, "SavedDelegationUnavailable", ErrorSeverity.Failed, "Requested saved service page is unavailable.", null));
            var page = read(reference, after).Value;
            return Result<SavedDelegationConfiguration>.Success(defect == "context"
                ? page with { Context = page.Context with { EstablishedTier0 = false } }
                : page with { Next = page.Next!.Value with { ResourceGuid = Guid.NewGuid() } });
        };
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.True(panel.HasRefusal);
        Assert.Equal("Page 1", panel.PageLabel);
        Assert.Equal(first, panel.Services);
        Assert.True(panel.NextPageCommand.CanExecute(null));
        source.ConstrainedDelegationRead = read;
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.False(panel.HasRefusal);
        Assert.Equal("Page 2", panel.PageLabel);
        Assert.Equal(50, panel.Services.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ClosedOrExpiredDelegationPagesCannotPublishLateAnswers(bool expire)
    {
        var (model, source, _) = Model(51);
        var row = Assert.Single(model.Findings);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = details.DelegationConfiguration!;
        var first = source.ConstrainedDelegationRead!(row.Saved.Reference!.Value, null).Value;
        var next = source.ConstrainedDelegationRead(row.Saved.Reference.Value, first.Next).Value;
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
        Assert.Empty(panel.Services);
        Assert.Null(details.DelegationConfiguration);
        Assert.False(details.HasFinding);
        if (expire) Assert.True(details.HasRefusal);
    }

    [Theory]
    [InlineData(900)]
    [InlineData(1300)]
    public void RealDelegationPanelWrapsAndPreservesLongCopyableServicesAndQualifiedResourceText(int width) => OnSta(() =>
    {
        var evidence = ConstrainedDelegationReadTests.Evidence(1, false);
        var service = "HTTP/resource.contoso.com:8443/" + new string('i', 1100);
        evidence = evidence with
        {
            Services = [new(0, service, 0, service)],
            Limitations = ["ServiceResourceUnresolved", "ServiceResourceAmbiguous", "ResourceRelevanceUnassessed", "ConfiguredServiceUnsupported"],
        };
        var (model, _, _) = Model(evidence);
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show();
            Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Captured delegation");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Delegating account: delegating account");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Object type: user");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible
                && value.Text == "Resource relevance: Identified controller or dependency of Tier 0; not itself classified as Tier 0.");
            var text = Assert.Single(Descendants<TextBox>(view), value => value.IsVisible && value.Text == service);
            Assert.True(text.IsReadOnly);
            Assert.Equal(TextWrapping.Wrap, text.TextWrapping);
            Assert.Equal(service.Length, text.Text.Length);
            text.BringIntoView();
            Layout(view, width, 700);
            var scroll = (ScrollViewer)view.FindName("FindingDetailsScroll");
            var bounds = text.TransformToAncestor(scroll).TransformBounds(new Rect(0, 0, text.ActualWidth, text.ActualHeight));
            Assert.True(bounds.Left >= 0 && bounds.Right <= scroll.ActualWidth);
            Assert.True(text.ActualHeight > text.FontSize * 2);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Saved evidence limitations");
            Assert.Equal(4, model.FindingDetails!.DelegationConfiguration!.Limitations.Count);
            Assert.DoesNotContain(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, "View membership evidence"));
            Assert.DoesNotContain(Descendants<TextBox>(view), value => value.IsVisible && value.Text.Contains("msDS-AllowedToDelegateTo[", StringComparison.Ordinal));
            foreach (var label in new[] { "Previous", "Next", "Open affected object", "Close" })
                Assert.Contains(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, label));
        }
        finally { host.Close(); }
    });

    private static async Task<object> Complete(Task<Result<SavedDelegationConfiguration>> read) => await read;

    private static (AssetsViewModel Model, FakeAssetSource Source, DelegationConfigurationEvidence Evidence) Model(
        int count, bool established = true) => Model(ConstrainedDelegationReadTests.Evidence(count, established));

    private static (AssetsViewModel Model, FakeAssetSource Source, DelegationConfigurationEvidence Evidence) Model(
        DelegationConfigurationEvidence evidence)
    {
        var source = new FakeAssetSource
        {
            FindingsPage = new([ConstrainedDelegationReadTests.Finding(evidence)], null, 1),
            FilterValues = new([Severity.High], ["SEC-012"], 1),
        };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\constrained-delegation-detail", false);
        var row = Assert.Single(model.Findings);
        evidence = evidence with { Scope = evidence.Scope with { GenerationId = row.Saved.Reference!.Value.GenerationId } };
        var bound = evidence;
        source.ConstrainedDelegationRead = (_, after) => Result<SavedDelegationConfiguration>.Success(
            ConstrainedDelegationReadTests.Project(bound, row.Saved, after));
        return (model, source, evidence);
    }
}
