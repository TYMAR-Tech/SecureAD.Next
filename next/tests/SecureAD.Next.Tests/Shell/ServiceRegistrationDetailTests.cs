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
public sealed class ServiceRegistrationDetailTests
{
    [Theory]
    [InlineData(0u, "Not established by this finding.")]
    [InlineData(512u, "Enabled")]
    [InlineData(514u, "Disabled")]
    public void SavedAccountStateAndServiceVisibilityDoNotInventLiveAnswers(uint control, string expected)
    {
        var (model, source) = Model(control: control);
        model.OpenFinding(Assert.Single(model.Findings));
        var details = model.FindingDetails!;
        var panel = Assert.IsType<ServiceRegistrationViewModel>(details.ServiceRegistration);
        Assert.Equal(expected, panel.AccountState);
        Assert.Equal("Critical", details.Finding!.Severity);
        Assert.Equal(ServiceRegistrationPresentation.Title, details.Finding.FindingTitle);
        Assert.Equal(50, panel.Names.Rows.Count);
        Assert.True(panel.HasUnreadableNames);
        Assert.True(panel.HasDirectProtection);
        Assert.Equal(new[] { "names" }, source.ServiceReads);
        Assert.False(details.ShowsSavedDescription);
        Assert.False(details.ShowsStandardIdentity);
        Assert.Contains("does not establish ticket issuance", details.Finding.WhyItMatters, StringComparison.Ordinal);
    }

    [Fact]
    public void OnlyTheRequestedGroupRouteAndStepPagesAreLoaded()
    {
        var (model, source) = Model();
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.ServiceRegistration!;
        panel.ViewMembershipCommand.Execute(null);
        Assert.Equal(new[] { "names", "groups" }, source.ServiceReads);
        Assert.Equal(50, panel.Memberships!.Rows.Count);
        panel.Memberships.Rows[1].ViewCommand.Execute(null);
        Assert.Equal("routes", source.ServiceReads[^1]);
        Assert.Equal(50, panel.Routes!.Rows.Count);
        panel.Routes.Rows[2].ViewCommand.Execute(null);
        Assert.Equal("steps", source.ServiceReads[^1]);
        Assert.Equal(50, panel.Steps!.Rows.Count);
        panel.Steps.NextPageCommand.Execute(null);
        Assert.Equal(5, panel.Steps.Rows.Count);
        Assert.True(panel.Steps.IsContinuation);
        Assert.Equal("Group 1 (ad.lab)", panel.SelectedMembership);
        Assert.Equal("Root 2 (ad.lab)", panel.SelectedRoot);
        panel.Memberships.NextPageCommand.Execute(null);
        Assert.Equal(5, panel.Memberships.Rows.Count);
        Assert.Null(panel.Routes);
        Assert.Null(panel.Steps);
    }

    [Theory]
    [InlineData("groups")]
    [InlineData("routes")]
    [InlineData("steps")]
    public void InvalidRequestedBranchesAreExplicitlyRefused(string level)
    {
        var (model, source) = Model();
        if (level == "groups")
        {
            var read = source.InitialMembershipsRead!;
            source.InitialMembershipsRead = (reference, after) => Result<SavedInitialMemberships>.Success(read(reference, after).Value with { Memberships = [] });
        }
        else if (level == "routes")
        {
            var read = source.MembershipRoutesRead!;
            source.MembershipRoutesRead = (reference, group, after) => Result<SavedMembershipRoutes>.Success(read(reference, group, after).Value with
                { Context = read(reference, group, after).Value.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } });
        }
        else
        {
            var read = source.MembershipStepsRead!;
            source.MembershipStepsRead = (reference, group, route, after) => Result<SavedMembershipSteps>.Success(read(reference, group, route, after).Value with { Steps = [] });
        }
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.ServiceRegistration!;
        panel.ViewMembershipCommand.Execute(null);
        if (level != "groups") panel.Memberships!.Rows[0].ViewCommand.Execute(null);
        if (level == "steps") panel.Routes!.Rows[0].ViewCommand.Execute(null);
        Assert.Equal(SavedServiceRegistrations.InvalidDetails, panel.Refusal);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("truncated")]
    public void InvalidInitialSavedServiceFactsCannotBecomeGenericSuccess(string defect)
    {
        var (model, source) = Model();
        var read = source.ServiceNamesRead!;
        source.ServiceNamesRead = (reference, after) =>
        {
            if (defect == "missing") return Result<SavedServiceRegistrations>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "MissingServiceFacts", ErrorSeverity.Failed, SavedServiceRegistrations.InvalidDetails, null));
            var value = read(reference, after).Value;
            return Result<SavedServiceRegistrations>.Success(defect == "generation"
                ? value with { Context = value.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } }
                : value with { Next = null });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.False(model.FindingDetails!.HasFinding);
        Assert.Null(model.FindingDetails.ServiceRegistration);
        Assert.Equal(SavedServiceRegistrations.InvalidDetails, model.FindingDetails.Refusal);
    }

    [Fact]
    public void DirectProtectionIsNotInventedAsAMembership()
    {
        var (model, source) = Model();
        var names = source.ServiceNamesRead!; var groups = source.InitialMembershipsRead!;
        source.ServiceNamesRead = (reference, after) =>
        {
            var value = names(reference, after).Value;
            return Result<SavedServiceRegistrations>.Success(value with { Context = value.Context with { InitialMembershipCount = 0 } });
        };
        source.InitialMembershipsRead = (reference, after) =>
        {
            var value = groups(reference, after).Value;
            return Result<SavedInitialMemberships>.Success(value with { Context = value.Context with { InitialMembershipCount = 0 }, Memberships = [], Next = null });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.ServiceRegistration!;
        panel.ViewMembershipCommand.Execute(null);
        Assert.True(panel.HasDirectProtection);
        Assert.True(panel.HasNoMemberships);
        Assert.True(panel.HasPartialEmpty);
        Assert.Empty(panel.Memberships!.Rows);
        Assert.Null(panel.Routes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CloseAndExpiryClearLoadedBranchRows(bool expire)
    {
        var (model, source) = Model();
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.ServiceRegistration!;
        panel.ViewMembershipCommand.Execute(null);
        var groups = panel.Memberships!;
        if (expire) { source.IsCurrent = false; Assert.False(model.FindingDetails.CheckCurrent()); }
        else model.CloseFindingDetails();
        Assert.Empty(groups.Rows);
        Assert.Empty(panel.Names.Rows);
        Assert.Null(panel.Routes);
    }

    [Theory]
    [InlineData(900)]
    [InlineData(1300)]
    public void RealWindowShowsIndependentSavedFactsAndRequestedBranches(int width) => OnSta(() =>
    {
        var (model, _) = Model();
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000, ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Saved service-registration assessment");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Membership branches have not been opened.");
            model.FindingDetails!.ServiceRegistration!.ViewMembershipCommand.Execute(null); Layout(view, width, 700);
            Assert.Contains(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, "View supporting chains"));
            var panel = model.FindingDetails.ServiceRegistration;
            panel.Memberships!.Rows[0].ViewCommand.Execute(null);
            panel.Routes!.Rows[0].ViewCommand.Execute(null);
            Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text.Contains("--member of-->", StringComparison.Ordinal));
        }
        finally { host.Close(); }
    });

    internal static Finding Finding(Finding original, uint control = 512) => original with
    {
        RuleId = "SEC-021", RuleVersion = 2, Severity = Severity.Critical, ObjectClass = "user",
        Subject = new(FindingSubjectKind.Account, original.PrincipalName),
        Evidence = new KerberoastableAccountEvidence("S-1-5-21-1-2-3-1100",
            Enumerable.Range(0, 55).Select(index => "HTTP/service" + index).ToArray(), control, 2)
        { ProtectionCatalogueVersion = 2, DirectProtectionCatalogueEntryId = 500, DirectProtectionName = "Recorded direct protection",
            MembershipRoutes = MembershipRouteSummary.NotDerived },
    };

    internal static void Configure(FakeAssetSource source, FindingListItem selected, uint control = 512)
    {
        var account = new MembershipRoutePrincipal("S-1-5-21-1-2-3-1100", null, selected.DistinguishedName);
        ServiceRegistrationContext Context(FindingReference reference) => new(reference, selected.Subject,
            new(selected.ObjectGuid, selected.DistinguishedName, selected.DomainFqdn, selected.ObjectClass), selected.PrincipalName,
            account.Sid, control, 2, 2, 500, "Recorded direct protection", MembershipRouteIncompleteReason.NotDerived, 55, 55, selected.Coverage);
        SavedInitialMembership Group(int ordinal) => new(ordinal,
            new("S-1-5-21-1-2-3-" + (2000 + ordinal), "ad.lab", $"CN=Group {ordinal},DC=ad,DC=lab"), false, 55);
        SavedMembershipRoute Route(int ordinal) => new(ordinal, ordinal + 1, "Root " + ordinal,
            ordinal % 2 == 0 ? MembershipRouteAuthorization.SecurityEnabled : MembershipRouteAuthorization.DistributionGroup, true, 55)
            { RootPrincipal = new("S-1-5-21-1-2-3-3054", "ad.lab", "CN=Step 54,DC=ad,DC=lab") };
        source.ServiceNamesRead = (reference, after) =>
        {
            var start = after?.Ordinal + 1 ?? 0; var values = Enumerable.Range(start, Math.Min(50, 55 - start)).Select(index => new SavedServiceName(index, "HTTP/service" + index)).ToArray();
            return Result<SavedServiceRegistrations>.Success(new(Context(reference), values, start == 0 ? new(reference.GenerationId, reference.FindingId, selected.ObjectGuid, 49) : null));
        };
        source.InitialMembershipsRead = (reference, after) =>
        {
            var start = after?.Ordinal + 1 ?? 0;
            return Result<SavedInitialMemberships>.Success(new(Context(reference), Enumerable.Range(start, Math.Min(50, 55 - start)).Select(Group).ToArray(),
                start == 0 ? new(reference.GenerationId, reference.FindingId, selected.ObjectGuid, 49) : null));
        };
        source.MembershipRoutesRead = (reference, group, after) =>
        {
            var start = after?.Ordinal + 1 ?? 0;
            return Result<SavedMembershipRoutes>.Success(new(Context(reference), Group(group), Enumerable.Range(start, Math.Min(50, 55 - start)).Select(Route).ToArray(),
                start == 0 ? new(reference.GenerationId, reference.FindingId, selected.ObjectGuid, group, 49) : null));
        };
        source.MembershipStepsRead = (reference, group, route, after) =>
        {
            var start = after?.Ordinal + 1 ?? 0;
            return Result<SavedMembershipSteps>.Success(new(Context(reference), Group(group), Route(route),
                Enumerable.Range(start, Math.Min(50, 55 - start)).Select(index => new SavedMembershipStep(index,
                    index == 0 ? account : index == 1 ? Group(group).Principal : new("S-1-5-21-1-2-3-" + (3000 + index), "ad.lab", $"CN=Step {index},DC=ad,DC=lab"), false)).ToArray(),
                start == 0 ? new(reference.GenerationId, reference.FindingId, selected.ObjectGuid, group, route, 49) : null));
        };
    }

    internal static (AssetsViewModel Model, FakeAssetSource Source) Model(uint control = 512)
    {
        var finding = Finding(ObjectFindingsPagingTests.Finding(1), control);
        var source = new FakeAssetSource { FindingsPage = new([finding], null, 1), FilterValues = new([Severity.Critical], ["SEC-021"], 1) };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\service-registration", false);
        Configure(source, Assert.Single(model.Findings).Saved, control);
        return (model, source);
    }
}
