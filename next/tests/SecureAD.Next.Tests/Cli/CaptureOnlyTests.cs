using SecureAD.Audit.Capture;
using SecureAD.Cli;
using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Cli;

/// <summary>
/// What <c>--capture</c> does, which is stop.
/// </summary>
/// <remarks>
/// <para>
/// <b>Parsing the flag and obeying it are different things, and only the second matters.</b> The
/// argument tests next door prove <c>CaptureOnly</c> is set; nothing there would notice if the
/// driver read it and carried on deriving anyway.
/// </para>
/// <para>
/// <b>Why the flag exists.</b> A capture of the owner's forest is the phase nothing has ever
/// measured - the predecessor put it at 30-40 minutes against nine domains, with analysis four to
/// five hours on top - and timing it through the shell drags the shell's own accumulated memory
/// into every figure (<c>P-199</c>). A command that captures and stops gives a clean process per
/// run, so the memory and disk figures from three runs are comparable.
/// </para>
/// </remarks>
public sealed class CaptureOnlyTests
{
    /// <summary>
    /// Asking to capture only seals the bundle and derives nothing.
    /// </summary>
    [Fact]
    public async Task CapturingOnlyStopsAfterTheSeal()
    {
        var bundle = SelfMembershipDiscoveryTests.Bundle();

        var exit = await Program.RunAsync(
            Parsed(bundle, "--capture"),
            CancellationToken.None,
            discoveryBudget: null,
            capture: (protect, _) => Task.FromResult(Sealed(bundle, protect)));

        Assert.Equal(0, exit);

        Assert.False(
            File.Exists(Path.Combine(bundle, "derivation.current.json")),
            "--capture derived the bundle anyway, so a capture asked to stop did not.");

        Assert.False(
            File.Exists(Path.Combine(bundle, "judgement.current.json")),
            "--capture judged the bundle anyway.");
    }

    /// <summary>
    /// The negative control: without the flag, the same path does derive.
    /// </summary>
    /// <remarks>
    /// Without this, the test above passes just as well against a build where deriving is broken,
    /// or against a bundle that could never have been derived in the first place - which would make
    /// it a check on nothing.
    /// </remarks>
    [Fact]
    public async Task WithoutTheFlagTheSameRunDerives()
    {
        var bundle = SelfMembershipDiscoveryTests.Bundle();

        await Program.RunAsync(
            Parsed(bundle),
            CancellationToken.None,
            discoveryBudget: null,
            capture: (protect, _) => Task.FromResult(Sealed(bundle, protect)));

        Assert.True(
            File.Exists(Path.Combine(bundle, "derivation.current.json")),
            "The ordinary run did not derive, so the capture-only test proves nothing.");
    }

    private static CommandLine Parsed(string bundle, params string[] rest) =>
        Assert.IsType<CommandLine>(
            CommandLine.Parse([.. new[] { "--library", Path.GetDirectoryName(bundle)! }, .. rest]));

    private static Result<CaptureRunResult> Sealed(string bundle, Func<string, ProtectedRunFiles> protect)
    {
        protect(bundle);
        return new CaptureRunResult(RunCompletion.Sealed, bundle, Error: null);
    }
}
