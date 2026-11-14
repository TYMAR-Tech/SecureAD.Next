using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Derivation;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class MembershipEvidencePresentationTests
{
    [Fact]
    public void OuterRootsAreShownUnderTheirSharedInitialMembership()
    {
        var summary = MembershipRouteTests.Derive([512, 519, 1200, 1100], [(0, 1), (1, 2), (2, 3)])[3];
        var row = Row(summary);
        Assert.True(row.HasMembershipEvidence);
        var group = Assert.Single(summary.Memberships);
        var display = new ServiceMembershipViewModel(new(0, group.InitialMembership, false, group.Routes.Count), new RelayCommand(() => { }));
        Assert.Contains("1200", display.Identity, StringComparison.Ordinal);
        Assert.Contains(group.Routes.Select(Route), route => route.Root.StartsWith("Domain Admins (", StringComparison.Ordinal));
        Assert.Contains(group.Routes.Select(Route), route => route.Root.StartsWith("Enterprise Admins (", StringComparison.Ordinal));
        Assert.Contains("not every possible path", ServiceRegistrationPresentation.MembershipNote, StringComparison.Ordinal);
        Assert.Equal("Complete", row.Coverage);
    }

    [Fact]
    public void APartialSummaryShowsItsReasonAndNeverLooksLikeCompleteCoverage()
    {
        var summary = MembershipRouteTests.Derive([512, 1100], [(0, 1)])[1].WithIncompleteReasons(
            MembershipRouteIncompleteReason.EdgeBudgetReached | MembershipRouteIncompleteReason.StorageBudgetReached);
        var row = Row(summary);
        Assert.Contains("examined-membership limit", summary.CompletenessDescription, StringComparison.Ordinal);
        Assert.Contains("stored-evidence size limit", summary.CompletenessDescription, StringComparison.Ordinal);
        Assert.Contains("not a total", summary.CompletenessDescription, StringComparison.Ordinal);
        Assert.Equal("May be incomplete", row.Coverage);
        Assert.Equal(FactState.NotEstablished, row.State);
        Assert.NotEmpty(summary.Memberships);
    }

    [Fact]
    public void PrimaryMembershipAndDistributionPathsAreNotLabelledAsOrdinaryAuthorization()
    {
        var primary = MembershipRouteTests.Derive([512, 1100], [], primaryGroup: 0)[1];
        var primaryRoute = Assert.Single(Assert.Single(primary.Memberships).Routes);
        Assert.True(new ServiceStepViewModel(new(1, primaryRoute.Steps[1].Principal, primaryRoute.Steps[1].IsPrimaryGroup)).IsPrimaryGroup);
        Assert.Equal("Protection not established by this chain.", Route(primaryRoute).Protection);
        var distribution = MembershipRouteTests.Derive([512, 1200, 1100], [(0, 1), (1, 2)], distribution: 1)[2];
        var shown = Route(Assert.Single(Assert.Single(distribution.Memberships).Routes));
        Assert.Contains("does not confer membership-based authorization", shown.Authorization, StringComparison.Ordinal);
        Assert.Equal("Protection established by this chain.", shown.Protection);
    }

    [Fact]
    public void AnAbsentSummaryIsDisplayedAsNotDerivedRatherThanNoMemberships()
    {
        var row = Row(MembershipRouteSummary.NotDerived);
        Assert.True(row.HasMembershipEvidence);
        Assert.Contains("routes were not derived", MembershipRouteSummary.NotDerived.CompletenessDescription, StringComparison.Ordinal);
        Assert.Equal(FactState.NotEstablished, row.State);
    }

    private static ServiceRouteViewModel Route(MembershipRoute route) => new(new(0, route.CatalogueEntryId,
        route.RootName, route.Authorization, route.EstablishesProtection, route.Steps.Count)
        { RootPrincipal = route.Steps[^1].Principal }, new RelayCommand(() => { }));

    private static FindingRowViewModel Row(MembershipRouteSummary summary) => new(new Finding(
        "SEC-021", 2, Severity.Critical, new FindingSubject(FindingSubjectKind.Account, "Alice"), Guid.NewGuid(),
        "CN=Alice,DC=ad,DC=lab", "ad.lab", "user", "Finding", EvidenceCompleteness.Complete,
        new KerberoastableAccountEvidence("S-1-5-21-11-22-33-1100", ["HTTP/service"], 512)
        { MembershipRoutes = summary }));
}
