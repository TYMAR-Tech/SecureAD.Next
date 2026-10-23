using SecureAD.Cli;
using SecureAD.Judgement;
using SecureAD.Kernel;
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
    public void AScanThatDidNotRunIsStatedRatherThanLeftSilent() => OneThread.Run(async () =>
    {
        var report = await ShellReport(budget: null);

        Assert.Contains("The separate Self-Membership scan was not run", report, StringComparison.Ordinal);
        Assert.Contains("no processing limit is configured", report, StringComparison.Ordinal);
        Assert.Contains("Tier 0 requester checks have their own saved coverage", report, StringComparison.Ordinal);
        Assert.Contains("this does not mean nobody can add themselves", report, StringComparison.Ordinal);
    });

    [Fact]
    public void CliCompletionDistinguishesTheSeparateMembershipScan()
    {
        var directory = SelfMembershipDiscoveryTests.Bundle();
        SelfMembershipDiscoveryTests.Derive(directory);
        var when = SelfMembershipDiscoveryTests.Started;
        var judged = JudgingRun.JudgeAudit(directory, RuleCatalogue.All, JudgingRun.ProductionPathRequesterPolicy,
            when, when, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, null);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal(PathRequesterCoverageState.EvaluatedSupportedQuestions, reader.ReadPathRequesterCoverage().Verdict);
        var summary = Program.Summarise(directory, reader.Description.GenerationId,
            PathRequesterPolicy.SupportedCapturedQuestions, CancellationToken.None);
        Assert.True(summary.IsSuccess, summary.Error?.Description);
        var report = summary.Value;

        Assert.Contains("The separate Self-Membership scan was not run", report, StringComparison.Ordinal);
        Assert.Contains("Tier 0 requester checks have their own saved coverage", report, StringComparison.Ordinal);
        Assert.Contains("this does not mean nobody can add themselves", report, StringComparison.Ordinal);
        Assert.DoesNotContain("Own-account membership questions were not scheduled", report, StringComparison.Ordinal);
    }

    [Fact]
    public void AScanThatRanReportsWhatItStoredAndWhatItCouldNotDecide() => OneThread.Run(async () =>
    {
        var report = await ShellReport(SelfMembershipDiscoveryTests.TestBudget);

        Assert.Contains("own-account membership answer(s)", report, StringComparison.Ordinal);
        Assert.Contains("account/group pair(s)", report, StringComparison.Ordinal);
        Assert.Contains("could not be decided", report, StringComparison.Ordinal);
        Assert.DoesNotContain("were not scheduled", report, StringComparison.Ordinal);
    });

    [Fact]
    public void AStoppedScanSaysItDidNotReadEverythingCaptured() => OneThread.Run(async () =>
    {
        var report = await ShellReport(new SelfMembershipDiscoveryBudget(100, 1000, 1000, 0));

        Assert.Contains("stopped at its configured limit", report, StringComparison.Ordinal);
        Assert.Contains("What it found is kept", report, StringComparison.Ordinal);
    });

    private static async Task<string> ShellReport(SelfMembershipDiscoveryBudget? budget)
    {
        Assert.NotNull(SynchronizationContext.Current);
        var ownerThread = Environment.CurrentManagedThreadId;
        var progressThreads = new System.Collections.Concurrent.ConcurrentQueue<int>();
        var directory = SelfMembershipDiscoveryTests.Bundle();
        var settings = new FakeSettingsStore { Stored = new ShellSettings(Path.GetDirectoryName(directory)!, DomainsAtOnce: null) };
        var location = new RunLibraryLocation(settings);
        location.Load();
        var screen = new NewAuditViewModel(location,
            new FakeCaptureLauncher { Outcome = new CaptureOutcome(true, directory) },
            new FakeNewAuditDialog(), new FakeRunOpener(), new DerivationLauncher(),
            new JudgingLauncher(budget), new DomainConcurrency(settings));
        screen.Progress.RecentReports.CollectionChanged += (_, _) =>
            progressThreads.Enqueue(Environment.CurrentManagedThreadId);

        await screen.OpenAsync();
        await screen.StartAsync();

        Assert.NotEmpty(progressThreads);
        Assert.All(progressThreads, thread => Assert.Equal(ownerThread, thread));
        Assert.DoesNotContain("could not be judged", screen.JudgingReport, StringComparison.OrdinalIgnoreCase);
        return screen.JudgingReport;
    }
}
