using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class Tier0PathTests
{
    [Theory]
    [InlineData(CoreDn)]
    [InlineData(RootDn)]
    public void BestRouteFixedTargetsRemainZeroHopWithoutChangingClassification(string target)
    {
        var directory = Captured(depth: 2);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var result = reader.ReadBestSupportedRoute(target)!;
        Assert.NotNull(result.Selection.Best);
        Assert.Equal(RouteSourceKind.FixedTarget, result.Selection.Best!.Source);
        Assert.Equal(0, result.Selection.Best.Grade.Length);
        Assert.Empty(result.Steps);
        Assert.True(reader.ReadTier0ObjectDistance(target)!.Facts.IsMinimumEstablished);
    }

    [Fact]
    public void BestRouteConsidersBothTerminalPermissionsBeforeShortestSelectionDiscardsOne()
    {
        var directory = Captured(descriptor: $"O:SYG:SYD:(A;;WD;;;{UserSid})",
            rootDescriptor: $"O:SYG:SYD:(A;;WD;;;{UserSid})");
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var best = reader.ReadBestSupportedRoute(UserDn)!;
        Assert.Equal(2, best.Selection.CompleteCandidates);
        Assert.Equal((RouteSourceKind.Terminal, RouteFeasibility.Direct, 1),
            (best.Selection.Best!.Source, best.Selection.Best.Grade.Feasibility, best.Selection.Best.Grade.Length));
        Assert.NotNull(Assert.Single(best.Steps).PermissionId);
        Assert.Equal(reader.Description.EvidenceSeal, best.Selection.EvidenceSeal);
    }

    [Fact]
    public void BestRouteUnavailableInputsDoNotBecomeAnEmptySuccessfulRoute()
    {
        var directory = Captured(depth: 2);
        Judge(directory);
        using var reader = Open(directory);
        var best = Assert.IsType<SavedBestSupportedRoute>(reader.ReadBestSupportedRoute(UserDn));
        Assert.Null(best.Selection.Best);
        Assert.Empty(best.Steps);
        Assert.Equal(0, best.Selection.CompleteCandidates);
        Assert.False(best.Coverage.InputsComplete);
    }
}
