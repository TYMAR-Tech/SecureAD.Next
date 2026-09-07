using SecureAD.Judgement;
using SecureAD.Next.Tests.Shell;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// What the completion screen tells an operator about the own-account membership scan.
/// </summary>
/// <remarks>
/// The failure these guard against is silence. A judging that completed every rule while the
/// requester scan never ran must not read as a forest where nobody can add themselves to a group.
/// </remarks>
public sealed class SelfMembershipNoticeTests
{
    [Fact]
    public async Task AScanThatDidNotRunIsStatedRatherThanLeftSilent()
    {
        var report = await ShellReport(budget: null);

        Assert.Contains("were not scheduled", report, StringComparison.Ordinal);
        Assert.Contains("no processing limit is configured", report, StringComparison.Ordinal);
        Assert.Contains("not a finding that nobody can add themselves", report, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AScanThatRanReportsWhatItStoredAndWhatItCouldNotDecide()
    {
        var report = await ShellReport(SelfMembershipDiscoveryTests.TestBudget);

        Assert.Contains("own-account membership answer(s)", report, StringComparison.Ordinal);
        Assert.Contains("account/group pair(s)", report, StringComparison.Ordinal);
        Assert.Contains("could not be decided", report, StringComparison.Ordinal);
        Assert.DoesNotContain("were not scheduled", report, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AStoppedScanSaysItDidNotReadEverythingCaptured()
    {
        var report = await ShellReport(new SelfMembershipDiscoveryBudget(100, 1000, 1000, 0));

        Assert.Contains("stopped at its configured limit", report, StringComparison.Ordinal);
        Assert.Contains("What it found is kept", report, StringComparison.Ordinal);
    }

    private static async Task<string> ShellReport(SelfMembershipDiscoveryBudget? budget)
    {
        var directory = SelfMembershipDiscoveryTests.Bundle();
        var settings = new FakeSettingsStore { Stored = new ShellSettings(Path.GetDirectoryName(directory)!) };
        var location = new RunLibraryLocation(settings);
        location.Load();
        var screen = new NewAuditViewModel(location,
            new FakeCaptureLauncher { Outcome = new CaptureOutcome(true, directory) },
            new FakeNewAuditDialog(), new FakeRunOpener(), new DerivationLauncher(),
            new JudgingLauncher(budget));

        await screen.OpenAsync();
        await screen.StartAsync();

        Assert.DoesNotContain("could not be judged", screen.JudgingReport, StringComparison.OrdinalIgnoreCase);
        return screen.JudgingReport;
    }
}
