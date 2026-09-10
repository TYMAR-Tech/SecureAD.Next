using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class AuditProgressTests
{
    [Fact]
    public void ElapsedRefreshDoesNotInventWorkProgress()
    {
        var time = new ManualTime();
        var progress = new AuditProgressViewModel(time);
        progress.Begin("Judging");
        progress.Report("Judging", "1,000 objects");
        time.Advance(10);
        progress.Refresh();
        Assert.Equal(("1,000 objects", "Elapsed: 00:00:10", "Last phase/progress update: 00:00:10 ago"),
            (progress.Counter, progress.Elapsed, progress.LastUpdateAge));
    }

    [Fact]
    public void WorkReportResetsOnlyTheLastUpdateAge()
    {
        var time = new ManualTime();
        var progress = new AuditProgressViewModel(time);
        progress.Begin("Judging");
        time.Advance(10);
        progress.Report("Judging", "2,000 objects");
        Assert.Equal(("Elapsed: 00:00:10", "Last phase/progress update: 00:00:00 ago"), (progress.Elapsed, progress.LastUpdateAge));
    }

    [Fact]
    public void AWorkReportCannotEraseTheStoppingNotice()
    {
        var progress = new AuditProgressViewModel(new ManualTime());
        progress.Begin("Judging");
        progress.RequestStop();
        progress.Report("Publishing", "3,000 objects");
        Assert.StartsWith("Stopping", progress.Status, StringComparison.Ordinal);
    }

    [Fact]
    public void EndedProgressCannotBeChangedByLateReportsOrTicks()
    {
        var time = new ManualTime();
        var progress = new AuditProgressViewModel(time);
        progress.Begin("Judging");
        progress.End("Stopped");
        time.Advance(20);
        progress.Report("Still judging", "999");
        progress.Refresh();
        Assert.Equal(("Stopped", "Elapsed: 00:00:00", false), (progress.Status, progress.Elapsed, progress.IsActive));
    }

    [Fact]
    public async Task SealedCaptureDoesNotHideJudgingProgressOrClaimCompletion()
    {
        var deriving = new ControlledDerivation();
        var judging = new ControlledJudging();
        var screen = Model(deriving, judging);
        var run = screen.StartAsync();
        try
        {
            deriving.Complete();
            await judging.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await ReportAndWait(screen.Progress, () => screen.Progress.Counter.Contains("5,000", StringComparison.Ordinal),
                () => judging.Progress!.Report(new(5000)));
            Assert.Equal((true, false, true, "This audit is running"),
                (screen.IsJudging, screen.HasFinished, screen.Report!.Contains("Sealed", StringComparison.Ordinal), screen.StepQuestion));
        }
        finally { deriving.Complete(); judging.Complete(); await run; }
    }

    [Fact]
    public async Task DerivationSubphaseIsVisibleWithoutResettingTheReadCounter()
    {
        var deriving = new ControlledDerivation();
        var judging = new ControlledJudging();
        var screen = Model(deriving, judging);
        var run = screen.StartAsync();
        try
        {
            await ReportAndWait(screen.Progress, () => screen.ObjectsDerived == 2000,
                () => deriving.Progress!.Report(new("MembershipAndNesting", 2000)));
            await ReportAndWait(screen.Progress, () => screen.Progress.Status.Contains("expanding security-group", StringComparison.Ordinal),
                () => deriving.Progress!.Report(new("ExpansionPhase", 0)));
            Assert.Equal((2000L, string.Empty), (screen.ObjectsDerived, screen.Progress.Counter));
        }
        finally { deriving.Complete(); judging.Complete(); await run; }
    }

    [Fact]
    public async Task StoppingJudgingPreservesSealedEvidenceAndStatesUnconfirmedCompletion()
    {
        var deriving = new ControlledDerivation();
        var judging = new ControlledJudging();
        var screen = Model(deriving, judging);
        var run = screen.StartAsync();
        deriving.Complete();
        await judging.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        screen.Stop();
        await run.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal((false, false, true, true), (screen.Progress.IsActive, screen.HasFinished,
            screen.Report!.Contains("already sealed", StringComparison.Ordinal),
            screen.JudgingReport!.Contains("has not been confirmed", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task FailedJudgingIsNotShownAsACompletedAudit()
    {
        var screen = Model(new FakeDerivationLauncher(), new FakeJudgingLauncher { Fails = Failures.Any("Synthetic failure") });
        await screen.StartAsync();
        Assert.Contains("incomplete or unavailable", screen.Progress.Status, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DegradedJudgingKeepsItsUncertaintyInTheVisibleOutcome()
    {
        var screen = Model(new FakeDerivationLauncher(), new FakeJudgingLauncher
        {
            Outcome = new(JudgementRunState.CompletedDegraded, 12, new Dictionary<SecureAD.Evidence.Findings.Severity, int>(), []),
        });
        await screen.StartAsync();
        Assert.Equal((true, true, false), (screen.HasJudgingReport,
            screen.JudgingReport!.Contains("not the whole picture", StringComparison.Ordinal), screen.Progress.IsActive));
    }

    [Fact]
    public async Task RetryClearsThePreviousJudgementAndBundle()
    {
        var capture = new FakeCaptureLauncher();
        var screen = Model(new FakeDerivationLauncher(), new FakeJudgingLauncher(), capture);
        await screen.StartAsync();
        capture.Cancels = true;
        await screen.StartAsync();
        Assert.Equal((false, null, null), (screen.HasFinished, screen.BundleDirectory, screen.JudgingReport));
    }

    internal static NewAuditViewModel Model(IDerivationLauncher deriving, IJudgingLauncher judging, FakeCaptureLauncher? capture = null)
    {
        var location = new RunLibraryLocation(new FakeSettingsStore { Stored = new ShellSettings(@"D:\audits") });
        location.Load();
        return new(location, capture ?? new FakeCaptureLauncher(), new FakeNewAuditDialog(), new FakeRunOpener(), deriving, judging)
            { Screen = AuditScreen.Review };
    }

    private static async Task ReportAndWait(AuditProgressViewModel progress, Func<bool> observed, Action report)
    {
        var arrived = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        void Changed(object? sender, System.ComponentModel.PropertyChangedEventArgs args)
        {
            if (observed()) arrived.TrySetResult(true);
        }
        progress.PropertyChanged += Changed;
        try { report(); await arrived.Task.WaitAsync(TimeSpan.FromSeconds(10)); }
        finally { progress.PropertyChanged -= Changed; }
    }

    private sealed class ManualTime : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        public void Advance(int seconds) => _ticks += TimeSpan.FromSeconds(seconds).Ticks;
    }

    private sealed class ControlledDerivation : IDerivationLauncher
    {
        private readonly TaskCompletionSource<Result<DerivingOutcome>> _done = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IProgress<DerivationProgress>? Progress { get; private set; }
        public Task<Result<DerivingOutcome>> RunAsync(string bundleDirectory, IProgress<DerivationProgress> progress, CancellationToken cancellationToken)
        {
            Progress = progress;
            return _done.Task.WaitAsync(cancellationToken);
        }
        public void Complete() => _done.TrySetResult(Result<DerivingOutcome>.Success(new(DerivationRunState.Completed, 1, 1, true)));
    }

    private sealed class ControlledJudging : IJudgingLauncher
    {
        private readonly TaskCompletionSource<Result<JudgingOutcome>> _done = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IProgress<JudgingRun.JudgingProgress>? Progress { get; private set; }
        public Task<Result<JudgingOutcome>> RunAsync(string bundleDirectory, IProgress<JudgingRun.JudgingProgress> progress, CancellationToken cancellationToken)
        {
            Progress = progress;
            Entered.TrySetResult(true);
            return _done.Task.WaitAsync(cancellationToken);
        }
        public void Complete() => _done.TrySetResult(Result<JudgingOutcome>.Success(new(JudgementRunState.Completed, 5000, new Dictionary<SecureAD.Evidence.Findings.Severity, int>(), [])));
    }
}
