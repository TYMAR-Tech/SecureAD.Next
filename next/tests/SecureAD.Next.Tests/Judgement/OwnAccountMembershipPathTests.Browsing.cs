using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Shell.Services;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Fact]
    public async Task Tier0BrowsingShowsLongerBestAndShorterConditionalThroughTheShellReader()
    {
        var directory = BestRouteCapture();
        await RunCoverageHostAsync("shell", directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var source = new BundleAssetSource();
        source.SelectRun(directory);
        var result = source.ReadSavedTier0Path(directory, UserDn);
        Assert.True(result.IsSuccess, result.Error?.Description);
        var saved = result.Value!;
        Assert.True(saved.IsBound);
        var routes = Assert.IsType<Tier0RouteDetails>(saved.Routes);
        Assert.Equal((2, 3, RouteFeasibility.Direct), (routes.Distance.SupportedDistance, routes.BestGrade!.Length, routes.BestGrade.Feasibility));
        Assert.Equal(2, routes.ShortestSteps.Count);
        Assert.Equal(3, routes.BestSteps.Count);
        Assert.Contains(routes.ShortestSteps, step => step.Kind == Tier0PathStepKind.OwnAccountMembership);
        Assert.All(routes.BestSteps, step => Assert.Equal(Tier0PathStepKind.Membership, step.Kind));
        Assert.All(routes.ShortestSteps.Where(step => step.PermissionId.HasValue),
            step => Assert.Contains(routes.Permissions, edge => edge.Id == step.PermissionId && edge.Target == step.To.DistinguishedName));
    }
}
