using System.Diagnostics;
using SecureAD.Audit.Sysvol;
using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Capture;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Sysvol;

// These tests launch both executable hosts and deliberately block worker processes. Do not make
// their safety watchdogs or unrelated WPF layout checks race the rest of the suite for resources.
[CollectionDefinition(nameof(SysvolWorkerCollection), DisableParallelization = true)]
public sealed class SysvolWorkerCollection { }

[Collection(nameof(SysvolWorkerCollection))]
public sealed class SysvolWorkerTests(ITestOutputHelper output)
{
    // The first production capture reached 200 MB of run.log with domains still to go, because
    // every operation wrote a line before the request and one per worker progress event. These two
    // checks hold the reduction: an ordinary operation costs one line, and no failure was traded
    // away to get there.
    [Fact]
    public async Task AnOrdinaryOperationCostsOneLineRatherThanOnePerProgressEvent()
    {
        var directory = Path.Combine(Path.GetTempPath(), "securead-worker-volume-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        output.WriteLine(directory);
        await File.WriteAllBytesAsync(Path.Combine(directory, "sample.bin"), new byte[512 * 1024]);
        var log = new RecordingRunLog();
        await using var reader = new IsolatedSysvolFileReader(() => HostCommand("securead-cli.dll"), TimeSpan.FromSeconds(30), log, TimeProvider.System);
        var observed = 0;
        reader.Watching = (_, _) => observed++;
        var target = GpoTarget.Of(Guid.NewGuid(), "volume policy", directory);

        var result = await reader.ReadFileAsync(target, "sample.bin", CancellationToken.None);

        // A half-megabyte read reports progress repeatedly - once per 64 KB chunk plus the open -
        // so the events and the lines must differ: were every event still written, the two numbers
        // would be equal and this would not measure anything.
        // A half-megabyte read reports progress repeatedly - once per 64 KB chunk plus the open -
        // so the events and the lines must differ: were every event still written, the two numbers
        // would be equal and this would not measure anything. The worker-startup line is excluded
        // because it is written once per worker, not once per operation.
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.True(observed > 1, $"Expected the worker to report progress more than once, saw {observed}.");
        Assert.Equal(1, log.Notes.Count(entry => RecordingRunLog.Value(entry.Detail, "operation") != "StartWorker"));
    }

    [Fact]
    public async Task AFailedOperationIsStillRecordedInFull()
    {
        // A locked file, not a missing one: an absent file is a legitimate "nothing there" and
        // returns success, so it would not exercise the failure path at all.
        var directory = Path.Combine(Path.GetTempPath(), "securead-worker-locked-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        output.WriteLine(directory);
        var locked = Path.Combine(directory, "locked.bin");
        await File.WriteAllBytesAsync(locked, [1, 2, 3]);
        using var exclusive = new FileStream(locked, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var log = new RecordingRunLog();
        await using var reader = new IsolatedSysvolFileReader(() => HostCommand("securead-cli.dll"), TimeSpan.FromSeconds(30), log, TimeProvider.System);
        var target = GpoTarget.Of(Guid.NewGuid(), "locked policy", directory);

        var result = await reader.ReadFileAsync(target, "locked.bin", CancellationToken.None);

        Assert.False(result.IsSuccess, "A file locked against sharing should not read as evidence.");
        var failure = Assert.Single(log.Errors);
        Assert.Equal(target.GpoGuid.ToString("D"), RecordingRunLog.Value(failure.Detail, "gpo"));
    }

    [Theory]
    [InlineData("securead-cli.dll")]
    [InlineData("SecureAD.dll")]
    public async Task ExecutableHostsServeAcquisitionWithoutStartingAnAudit(string assembly)
    {
        var directory = Path.Combine(Path.GetTempPath(), "securead-worker-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        output.WriteLine(directory);
        await File.WriteAllBytesAsync(Path.Combine(directory, "sample.bin"), [1, 2, 3]);
        await using var reader = new IsolatedSysvolFileReader(() => HostCommand(assembly),
            TimeSpan.FromSeconds(30), new RecordingRunLog(), TimeProvider.System);

        var result = await reader.ReadFileAsync(GpoTarget.Of(Guid.NewGuid(), "offline policy", directory),
            "sample.bin", CancellationToken.None);

        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal([1, 2, 3], result.Value!.Select(value => (int)value));
    }

    [Fact]
    public async Task AWorkerIgnoringCancellationIsTerminatedAtTheDeadline()
    {
        var log = new RecordingRunLog();
        using var probe = new Probe(output, log);
        var clock = new ControlledClock();
        await using var reader = new IsolatedSysvolFileReader(FixtureCommand, TimeSpan.FromSeconds(30), probe, clock);
        reader.Watching = probe.Watch;
        using var watchdog = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var pending = reader.ReadFileAsync(Target("hang"), "sample.bin", watchdog.Token);
        await probe.Entered.Task.WaitAsync(watchdog.Token);

        clock.Expire();
        var result = await pending;

        Assert.Equal(("Capture.SysvolOperationTimedOut", true, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30), 0),
            (result.Error?.Code, Assert.Single(probe.Workers).HasExited, clock.InitialDelay,
                IsolatedSysvolFileReader.InactivityLimit, probe.CompletedOperations));
    }

    [Fact]
    public async Task UserCancellationTerminatesTheWorkerRatherThanBecomingMissingEvidence()
    {
        using var probe = new Probe(output, RunLog.Discarded);
        await using var reader = new IsolatedSysvolFileReader(FixtureCommand, TimeSpan.FromSeconds(30), probe, TimeProvider.System);
        reader.Watching = probe.Watch;
        using var stopping = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var pending = reader.ReadFileAsync(Target("hang"), "sample.bin", stopping.Token);
        await probe.Entered.Task.WaitAsync(stopping.Token);

        stopping.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        Assert.True(Assert.Single(probe.Workers).HasExited);
    }

    [Fact]
    public async Task AnEarlierRequestReplyCannotCompleteANewPolicyAfterTimeout()
    {
        using var probe = new Probe(output, RunLog.Discarded);
        var clock = new ControlledClock();
        await using var reader = new IsolatedSysvolFileReader(FixtureCommand, TimeSpan.FromSeconds(30), probe, clock);
        reader.Watching = probe.Watch;
        using var watchdog = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var first = reader.ReadFileAsync(Target("hang"), "sample.bin", watchdog.Token);
        await probe.Entered.Task.WaitAsync(watchdog.Token);
        clock.Expire();
        await first;

        var next = await reader.ReadFileAsync(Target("stale"), "sample.bin", watchdog.Token);

        Assert.Equal(("Capture.SysvolWorkerFailed", 2), (next.Error?.Code, probe.Workers.Count));
    }

    [Fact]
    public async Task ActualProgressRenewsTheInactivityDeadline()
    {
        using var probe = new Probe(output, RunLog.Discarded);
        var clock = new ControlledClock();
        await using var reader = new IsolatedSysvolFileReader(FixtureCommand, TimeSpan.FromSeconds(30), probe, clock);
        reader.Watching = probe.Watch;
        using var watchdog = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var result = await reader.ReadFileAsync(Target("progress"), "sample.bin", watchdog.Token);

        Assert.Equal((true, 4, TimeSpan.FromSeconds(30)), (result.IsSuccess, clock.Renewals, clock.RenewedDelay));
    }

    [Fact]
    public async Task OperationStartIsFlushedWithIdentityPathAndCountsBeforeTheWorkerReturns()
    {
        var directory = Path.Combine(Path.GetTempPath(), "securead-worker-log-" + Guid.NewGuid().ToString("N"));
        output.WriteLine(directory);
        using var file = RunLogFile.Open(directory, "test", TimeProvider.System).Value!;
        using var probe = new Probe(output, file);
        await using var reader = new IsolatedSysvolFileReader(FixtureCommand, TimeSpan.FromSeconds(30), probe, TimeProvider.System);
        reader.Watching = probe.Watch;
        using var stopping = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var target = Target("hang");
        var pending = reader.ReadFileAsync(target, "sample.bin", stopping.Token);
        await probe.Entered.Task.WaitAsync(stopping.Token);

        await using var stream = new FileStream(BundleLayout.RunLogPath(directory), FileMode.Open,
            FileAccess.Read, FileShare.ReadWrite, 4096, FileOptions.Asynchronous);
        using var textReader = new StreamReader(stream);
        var text = await textReader.ReadToEndAsync();
        stopping.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);

        var line = Assert.Single(text.Split('\n').Where(line => line.Contains("operation=GetAttributes", StringComparison.Ordinal)));
        Assert.Contains(target.GpoGuid.ToString("D"), line, StringComparison.Ordinal);
        Assert.Contains(target.FileSysPath + "\\sample.bin", line, StringComparison.Ordinal);
        Assert.Contains("elapsedSeconds=", line, StringComparison.Ordinal);
        Assert.Contains("items=0", line, StringComparison.Ordinal);
        Assert.Contains("bytes=0", line, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WindowsMetadataCallsAndEnumerationReportTheirActualProgress()
    {
        var directory = Path.Combine(Path.GetTempPath(), "securead-worker-metadata-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(directory, "child"));
        output.WriteLine(directory);
        await File.WriteAllBytesAsync(Path.Combine(directory, "sample.bin"), [1]);
        await File.WriteAllBytesAsync(Path.Combine(directory, "child", "nested.bin"), [2]);
        var log = new RecordingRunLog();
        await using var reader = new IsolatedSysvolFileReader(() => HostCommand("securead-cli.dll"), TimeSpan.FromSeconds(30), log, TimeProvider.System);
        var observed = new List<SysvolIoEvent>();
        reader.Watching = (progress, _) => observed.Add(progress);
        var target = GpoTarget.Of(Guid.NewGuid(), "offline metadata", directory);

        var acl = await reader.ReadSecurityDescriptorAsync(target, "", CancellationToken.None);
        var files = await reader.EnumerateRelativeFilesAsync(target, "*", CancellationToken.None);

        Assert.True(acl.IsSuccess, acl.Error?.Description);
        Assert.Equal(["child\\nested.bin", "sample.bin"], files.Value!.OrderBy(value => value, StringComparer.Ordinal));
        Assert.Equal(["GetAttributes:Started", "GetAttributes:Completed", "GetAccessControl:Started", "GetAccessControl:Completed"],
            observed.Where(progress => progress.Operation is "GetAttributes" or "GetAccessControl")
                .Select(progress => progress.Operation + ":" + progress.State));
        Assert.Equal(3, observed.Last(progress => progress.Operation == "EnumerateFiles").Items);
    }

    [Fact]
    public Task ADisappearedPolicyRootDoesNotBecomeAnEmptyFileListing() =>
        VerifyDisappearedRootAsync((reader, target) => reader.EnumerateRelativeFilesAsync(target, "*", CancellationToken.None));

    [Fact]
    public Task ADisappearedPolicyRootDoesNotBecomeAnEmptyDirectoryListing() =>
        VerifyDisappearedRootAsync((reader, target) => reader.EnumerateRelativeDirectoriesAsync(target, CancellationToken.None));

    private async Task VerifyDisappearedRootAsync(
        Func<IsolatedSysvolFileReader, GpoTarget, Task<Result<IReadOnlyList<string>>>> enumerate)
    {
        var directory = Path.Combine(Path.GetTempPath(), "securead-worker-disappearance-" + Guid.NewGuid().ToString("N"));
        var policyPath = Path.Combine(directory, "policy");
        Directory.CreateDirectory(policyPath);
        output.WriteLine(directory);
        await using var reader = new IsolatedSysvolFileReader(() => HostCommand("securead-cli.dll"),
            TimeSpan.FromSeconds(30), new RecordingRunLog(), TimeProvider.System);
        var target = GpoTarget.Of(Guid.NewGuid(), "offline disappearance", policyPath);
        var root = await reader.ReadSecurityDescriptorAsync(target, "", CancellationToken.None);
        Assert.True(root.IsSuccess, root.Error?.Description);
        Assert.NotNull(root.Value);

        // Deliberate fault injection into this test's own folder, not evidence cleanup.
        Directory.Delete(policyPath);
        var result = await enumerate(reader, target);

        Assert.Equal((false, "Capture.SysvolUnreadable", policyPath),
            (result.IsSuccess, result.Error?.Code, result.Error?.Context));
    }

    private static GpoTarget Target(string behavior) => GpoTarget.Of(Guid.NewGuid(), behavior,
        @"\\offline.invalid\SYSVOL\example.com\Policies\{00000000-0000-0000-0000-000000000001}");

    private static ProcessStartInfo FixtureCommand() => new(Path.Combine(AppContext.BaseDirectory,
        "SysvolTestWorker", "SecureAD.Sysvol.TestWorker.exe"));

    private sealed class ControlledClock : TimeProvider
    {
        private TriggerTimer? _timer;
        internal int Renewals => _timer?.Renewals ?? 0;
        internal TimeSpan InitialDelay { get; private set; }
        internal TimeSpan RenewedDelay => _timer?.Delay ?? TimeSpan.Zero;
        internal void Expire() => (_timer ?? throw new InvalidOperationException("No inactivity timer was armed.")).Fire();
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            InitialDelay = dueTime;
            _timer = new TriggerTimer(callback, state, dueTime);
            return _timer;
        }

        private sealed class TriggerTimer(TimerCallback callback, object? state, TimeSpan dueTime) : ITimer
        {
            private bool _disposed;
            internal int Renewals { get; private set; }
            internal TimeSpan Delay { get; private set; } = dueTime;
            internal void Fire()
            {
                if (!_disposed)
                    callback(state);
            }
            public bool Change(TimeSpan dueTime, TimeSpan period) { Renewals++; Delay = dueTime; return !_disposed; }
            public void Dispose() => _disposed = true;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }

    private sealed class Probe(ITestOutputHelper output, IRunLog sink) : IRunLog, IDisposable
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal List<Process> Workers { get; } = [];
        internal int CompletedOperations { get; private set; }

        // Watches the reader's progress events rather than its log. These arrive whether or not
        // the operation was slow enough to be written down, so the harness no longer depends on
        // how much the product chooses to record.
        internal void Watch(SysvolIoEvent progress, int? workerPid)
        {
            if (progress.State == "Completed")
                CompletedOperations++;
            if (progress.Operation != "GetAttributes" || progress.State != "Started" || workerPid is not { } pid)
                return;
            if (!Workers.Any(worker => worker.Id == pid))
            {
                var worker = Process.GetProcessById(pid);
                _ = worker.SafeHandle;
                Workers.Add(worker);
            }
            Entered.TrySetResult();
        }

        public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail) =>
            sink.Note(phase, message, detail);

        public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail) => sink.Record(phase, error, detail);

        public void Dispose()
        {
            foreach (var worker in Workers)
            {
                if (!worker.HasExited)
                {
                    output.WriteLine($"Stopping retained fixture worker {worker.Id}.");
                    worker.Kill(entireProcessTree: true);
                    worker.WaitForExit(5000);
                }
                worker.Dispose();
            }
        }
    }

    private static ProcessStartInfo HostCommand(string assembly)
    {
        var start = new ProcessStartInfo("dotnet");
        start.ArgumentList.Add("exec");
        start.ArgumentList.Add("--runtimeconfig");
        start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "SecureAD.Next.Tests.runtimeconfig.json"));
        start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, assembly));
        return start;
    }
}
