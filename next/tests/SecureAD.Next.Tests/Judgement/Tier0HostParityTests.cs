using SecureAD.Audit.Capture;
using SecureAD.Cli;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using Xunit;
using Xunit.Abstractions;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>Checks saved assessment scope through the actual CLI and GUI judging entry points.</summary>
public sealed class Tier0HostParityTests(ITestOutputHelper output)
{
    /// <summary>A completed host run must describe its control counts with the same scope.</summary>
    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task EveryHostRecordsDiscoveryScopedCountsAsync(string host)
    {
        var directory = Bundle(tier0Route: true);

        using var reader = await RunHostAsync(host, directory);

        Assert.True(reader.ReadControlEdges(TargetDn, null, null, true, 0).IsScopedToDiscovery);
    }

    /// <summary>A scope label is insufficient if the host still assesses an unrelated object's permission.</summary>
    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task EveryHostLeavesUnrelatedControlUnassessedAsync(string host)
    {
        var directory = Bundle(sddl: $"O:SYG:SYD:(A;;WD;;;{UserSid})", tier0Route: true);

        using var reader = await RunHostAsync(host, directory);

        Assert.Empty(reader.ReadControlEdges(TargetDn, null, null, true, 0).Edges);
    }

    /// <summary>Tier-0 assessment alignment must not activate the separate requester scan.</summary>
    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task EveryHostLeavesRequesterDiscoveryInactiveAsync(string host)
    {
        var directory = Bundle(tier0Route: true, tier0RouteFromTarget: true);

        using var reader = await RunHostAsync(host, directory);

        Assert.Equal("NotStarted", reader.ReadSelfMembershipSummary()?.Verdict);
    }

    private async Task<JudgementReader> RunHostAsync(string host, string directory)
    {
        output.WriteLine(directory);
        switch (host)
        {
            case "shell":
                Derive(directory);
                var result = await new JudgingLauncher(discoveryBudget: null).RunAsync(directory,
                    JudgingRun.NobodyIsWatching, CancellationToken.None);
                Assert.True(result.IsSuccess, result.Error?.Description);
                break;
            case "cli-offline":
                Derive(directory);
                var offline = Assert.IsType<CommandLine>(CommandLine.Parse(["--judge", directory]));
                Assert.Equal(0, await Program.RunAsync(offline, CancellationToken.None, discoveryBudget: null,
                    capture: _ => throw new InvalidOperationException("Offline judging must not capture.")));
                break;
            case "cli-capture":
                var capture = Assert.IsType<CommandLine>(CommandLine.Parse(["--library", Path.GetDirectoryName(directory)!]));
                Assert.Equal(0, await Program.RunAsync(capture, CancellationToken.None, discoveryBudget: null,
                    capture: token =>
                    {
                        token.ThrowIfCancellationRequested();
                        return Task.FromResult(Result<CaptureRunResult>.Success(new(RunCompletion.Sealed, directory, null)));
                    }));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(host), host, null);
        }

        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return Assert.IsType<JudgementReader>(opened.Value);
    }
}
