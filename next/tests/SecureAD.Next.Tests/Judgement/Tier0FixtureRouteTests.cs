using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;
using Xunit.Abstractions;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// Proves the shared fixture's Tier-0 route admits its target, before other suites rely on it.
/// </summary>
/// <remarks>
/// A route that silently failed to admit anything would make every suite that passes
/// <c>tier0Route: true</c> assert against an empty product, so this checks the mechanism directly and
/// checks the negative case beside it.
/// </remarks>
public sealed class Tier0FixtureRouteTests(ITestOutputHelper output)
{
    [Fact]
    public void TheSharedFixtureRouteAdmitsItsUserForAssessment()
    {
        var directory = Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})", tier0Route: true);
        output.WriteLine(directory);
        Derive(directory);
        JudgeGated(directory);
        using var reader = Open(directory);
        Assert.NotEmpty(reader.ReadControlEdges(UserDn, null, null, true, 0).Edges);
    }

    /// <summary>
    /// The negative control: without the route the same capture yields nothing, so the assertion
    /// above is measuring the route rather than something that would pass regardless.
    /// </summary>
    [Fact]
    public void TheSameFixtureWithoutTheRouteIsAssessedAsNothing()
    {
        var directory = Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})", tier0Route: false);
        output.WriteLine(directory);
        Derive(directory);
        JudgeGated(directory);
        using var reader = Open(directory);
        Assert.Empty(reader.ReadControlEdges(UserDn, null, null, true, 0).Edges);
    }

    private static void JudgeGated(string directory)
    {
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [], Tier0DiscoveryBudget.Laboratory,
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, selfMembershipDiscoveryBudget: null);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }
}
