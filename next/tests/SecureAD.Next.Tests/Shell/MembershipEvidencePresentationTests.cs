using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
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
        Assert.Equal(1, row.MembershipDetails.Split("Initial membership:", StringSplitOptions.None).Length - 1);
        Assert.Contains("CN=1200,DC=ad,DC=lab", row.MembershipDetails, StringComparison.Ordinal);
        Assert.Contains("Domain Admins", row.MembershipDetails, StringComparison.Ordinal);
        Assert.Contains("Enterprise Admins", row.MembershipDetails, StringComparison.Ordinal);
        Assert.Contains("--member of-->", row.MembershipDetails, StringComparison.Ordinal);
        Assert.Equal("Complete", row.Coverage);
    }

    [Fact]
    public void APartialSummaryShowsItsReasonAndNeverLooksLikeCompleteCoverage()
    {
        var summary = MembershipRouteTests.Derive([512, 1100], [(0, 1)])[1].WithIncompleteReasons(
            MembershipRouteIncompleteReason.EdgeBudgetReached | MembershipRouteIncompleteReason.StorageBudgetReached);
        var row = Row(summary);
        Assert.Contains("examined-membership limit", row.MembershipCompleteness, StringComparison.Ordinal);
        Assert.Contains("stored-evidence size limit", row.MembershipCompleteness, StringComparison.Ordinal);
        Assert.Contains("not a total", row.MembershipCompleteness, StringComparison.Ordinal);
        Assert.Equal("May be incomplete", row.Coverage);
        Assert.Equal(FactState.NotEstablished, row.State);
        Assert.Contains("Initial membership:", row.MembershipDetails, StringComparison.Ordinal);
    }

    [Fact]
    public void PrimaryMembershipAndDistributionPathsAreNotLabelledAsOrdinaryAuthorization()
    {
        var primary = Row(MembershipRouteTests.Derive([512, 1100], [], primaryGroup: 0)[1]);
        Assert.Contains("--primary group-->", primary.MembershipDetails, StringComparison.Ordinal);
        Assert.Contains("Protection through primary-group membership is not established", primary.MembershipDetails, StringComparison.Ordinal);
        var distribution = Row(MembershipRouteTests.Derive([512, 1200, 1100], [(0, 1), (1, 2)], distribution: 1)[2]);
        Assert.Contains("does not confer membership-based authorization", distribution.MembershipDetails, StringComparison.Ordinal);
        Assert.Contains("Protection is established", distribution.MembershipDetails, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAbsentSummaryIsDisplayedAsNotDerivedRatherThanNoMemberships()
    {
        var row = Row(MembershipRouteSummary.NotDerived);
        Assert.True(row.HasMembershipEvidence);
        Assert.Contains("routes were not derived", row.MembershipCompleteness, StringComparison.Ordinal);
        Assert.Equal(FactState.NotEstablished, row.State);
    }

    private static FindingRowViewModel Row(MembershipRouteSummary summary) => new(new Finding(
        "SEC-021", 2, Severity.Critical, new FindingSubject(FindingSubjectKind.Account, "Alice"), Guid.NewGuid(),
        "CN=Alice,DC=ad,DC=lab", "ad.lab", "user", "Finding", EvidenceCompleteness.Complete,
        new KerberoastableAccountEvidence("S-1-5-21-11-22-33-1100", ["HTTP/service"], 512)
        { MembershipRoutes = summary }));
}
