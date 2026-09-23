using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using SecureAD.Kernel;

namespace SecureAD.Audit.Sysvol;

/// <summary>Contains Windows SMB acquisition in a worker that cannot write the evidence database.</summary>
public sealed class IsolatedSysvolFileReader : ISysvolFileReader, IAsyncDisposable
{
    /// <summary>The owner's provisional per-operation inactivity limit, recorded under P-221.</summary>
    public static TimeSpan InactivityLimit => TimeSpan.FromSeconds(30);

    /// <summary>
    /// How long an operation must take before it is worth a line of its own.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Written because the log stopped being readable.</b> The first production capture reached
    /// 200 MB of <c>run.log</c> with several domains still to go: every operation wrote at least
    /// three lines - one before the request and one per worker progress event - each carrying ten
    /// details including the full UNC path. Against a forest of roughly 4,000 policies, where a
    /// single policy costs twenty to sixty operations, that is on the order of half a million lines
    /// saying that something ordinary happened quickly.
    /// </para>
    /// <para>
    /// <b>A second, quieter cost.</b> Those writes are synchronous and go to the same disk the
    /// capture is reading onto, so the account of the work was competing with the work.
    /// </para>
    /// <para>
    /// One second, because a descriptor read on a healthy share is a few milliseconds and anything
    /// near a second is worth a look. Nothing below it is silently lost: the rollup below counts
    /// every operation, and a failure is recorded whatever it cost.
    /// </para>
    /// </remarks>
    public static TimeSpan WorthALine => TimeSpan.FromSeconds(1);

    /// <summary>
    /// How many operations pass between rollup lines.
    /// </summary>
    /// <remarks>
    /// Liveness without volume. A capture that writes nothing for an hour is indistinguishable
    /// from one that has stopped, which is the reason the per-event lines existed at all; a line
    /// every thousand operations keeps that signal at about four hundred lines for the whole
    /// forest rather than half a million.
    /// </remarks>
    private const long RollupEvery = 1_000;

    /// <summary>
    /// Raised for every worker progress event, whether or not it is written to the log.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A seam, because the log stopped being one.</b> Progress events used to reach observers
    /// only by being written down, so anything that needed to know an operation had begun - the
    /// test harness waiting to identify the worker process, most of all - had to watch the log.
    /// That made log volume load-bearing, and quietening the log would have hung those waits
    /// rather than failed them, which is the least useful way for something to break.
    /// </para>
    /// <para>
    /// This carries every event regardless of the reduction, so what is observed no longer depends
    /// on what is recorded. It is deliberately not an <c>event</c>: there is exactly one supervisor
    /// per reader and the ordering matters.
    /// </para>
    /// </remarks>
    internal Action<SysvolIoEvent, int?>? Watching { get; set; }

    private readonly SysvolWorkerConnection _worker;
    private readonly TimeSpan _inactivityLimit;
    private readonly IRunLog _log;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private bool _ready;
    private bool _disposed;
    private long _nextId;
    private long _completedOperations;
    private long _rolledUpAt;
    private long _slowOperations;
    private long _totalBytes;
    private int? _diagnosticPid;

    /// <summary>Creates a supervisor; worker startup and shutdown have separate bounded waits.</summary>
    /// <param name="command">How to launch the acquisition-only host.</param>
    /// <param name="inactivityLimit">How long an operation may make no progress.</param>
    /// <param name="log">The run's flushed operational log.</param>
    /// <param name="time">The inactivity-deadline and diagnostic clock.</param>
    public IsolatedSysvolFileReader(
        Func<ProcessStartInfo> command, TimeSpan inactivityLimit, IRunLog log, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(inactivityLimit, TimeSpan.Zero);
        _worker = new SysvolWorkerConnection(command, TimeSpan.FromSeconds(5));
        _inactivityLimit = inactivityLimit;
        _log = log;
        _time = time;
    }

    /// <inheritdoc/>
    public async Task<Result<byte[]?>> ReadFileAsync(GpoTarget target, string relativePath, CancellationToken cancellationToken)
    {
        var result = await AcquireAsync(target, SysvolRequestKind.ReadFile, relativePath, cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? Result<byte[]?>.Success(result.Value!.Bytes) : result.Error!;
    }

    /// <inheritdoc/>
    public async Task<Result<byte[]?>> ReadSecurityDescriptorAsync(GpoTarget target, string relativePath, CancellationToken cancellationToken)
    {
        var result = await AcquireAsync(target, SysvolRequestKind.ReadSecurityDescriptor, relativePath, cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? Result<byte[]?>.Success(result.Value!.Bytes) : result.Error!;
    }

    /// <inheritdoc/>
    public async Task<Result<IReadOnlyList<string>>> EnumerateRelativeFilesAsync(GpoTarget target, string searchPattern, CancellationToken cancellationToken)
    {
        var result = await AcquireAsync(target, SysvolRequestKind.EnumerateFiles, searchPattern, cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? Result<IReadOnlyList<string>>.Success(result.Value!.Paths!) : result.Error!;
    }

    /// <inheritdoc/>
    public async Task<Result<IReadOnlyList<string>>> EnumerateRelativeDirectoriesAsync(GpoTarget target, CancellationToken cancellationToken)
    {
        var result = await AcquireAsync(target, SysvolRequestKind.EnumerateDirectories, "*", cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? Result<IReadOnlyList<string>>.Success(result.Value!.Paths!) : result.Error!;
    }

    private async Task<Result<SysvolWorkerMessage>> AcquireAsync(
        GpoTarget target, SysvolRequestKind kind, string path, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(path);
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        await _gate.WaitAsync(lifetime.Token).ConfigureAwait(false);
        var started = _time.GetTimestamp();
        var operationStarted = started;
        var limit = _inactivityLimit;
        var id = ++_nextId;
        var latest = new SysvolIoEvent(kind.ToString(),
            kind is SysvolRequestKind.EnumerateFiles or SysvolRequestKind.EnumerateDirectories
                ? target.FileSysPath : SmbSysvolFileReader.Combine(target.FileSysPath, path), "Started", 0, 0);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_ready)
                _diagnosticPid = null;
            if (_worker.Blocked)
            {
                var unavailable = SysvolText.Error("SysvolWorkerUnavailable", "WorkerUnavailable", latest.Path);
                Record(unavailable, Details(target, latest, started, id));
                return unavailable;
            }
            if (!_ready)
            {
                using var startup = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                startup.CancelAfter(TimeSpan.FromSeconds(30));
                await _worker.StartAsync(startup.Token).ConfigureAwait(false);
                _diagnosticPid = _worker.ProcessId;
                var hello = await SysvolWire.ReceiveAsync<SysvolWorkerMessage>(_worker.Pipe, startup.Token).ConfigureAwait(false);
                if (hello.RequestId != 0 || hello.Progress?.Operation != "WorkerReady" || hello.Finished)
                    throw new InvalidDataException(SysvolText.Get("ProtocolInvalid"));
                _ready = true;

                // Once per worker, not once per operation. Starting one is a real event and rare;
                // announcing every request was half of what made the log unreadable.
                Note("Started", Details(target, latest with { Operation = "StartWorker" }, started, id));
            }

            limit = _inactivityLimit;
            latest = latest with { Operation = kind.ToString() };
            var lastLineAt = _time.GetTimestamp();
            var first = true;
            using var inactivity = new CancellationTokenSource(_inactivityLimit, _time);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token, inactivity.Token);
            await SysvolWire.SendAsync(_worker.Pipe, new SysvolRequest(id, kind, target, path), deadline.Token).ConfigureAwait(false);
            while (true)
            {
                var response = await SysvolWire.ReceiveAsync<SysvolWorkerMessage>(_worker.Pipe, deadline.Token).ConfigureAwait(false);
                deadline.Token.ThrowIfCancellationRequested();
                if (response.RequestId != id)
                    throw new InvalidDataException(SysvolText.Get("ProtocolInvalid"));
                if (response.Progress is { } progress)
                {
                    if (response.Finished || progress.Items < latest.Items || progress.Bytes < latest.Bytes
                        || progress.State is not ("Started" or "Completed" or "Progress")
                        || progress.State == "Progress" && progress.Items == latest.Items && progress.Bytes == latest.Bytes)
                        throw new InvalidDataException(SysvolText.Get("ProtocolInvalid"));
                    if (progress.State == "Started")
                        operationStarted = _time.GetTimestamp();
                    latest = progress;
                    inactivity.CancelAfter(_inactivityLimit);
                    if (progress.State == "Completed")
                        _completedOperations++;
                    Watching?.Invoke(progress with { Path = latest.Path }, _diagnosticPid);

                    // One line as an operation begins, then silence unless it drags.
                    //
                    // The opening line is kept deliberately: it is flushed before the worker
                    // returns, so a capture that looks frozen can be diagnosed by reading the log
                    // and seeing which policy and path are in flight. A hung operation produces no
                    // further events, so a purely time-based rule would never write that line.
                    //
                    // After that, the clock decides. Note that "Started" is NOT once per operation:
                    // a file read reports it once per 64 KB chunk, so keeping every one of them
                    // would have left a large file writing a line per chunk - the same unbounded
                    // volume, moved rather than removed. What goes is everything ordinary and
                    // quick: the repeated chunk reports and the "Completed" line that says only
                    // that a normal thing finished, which the rollup counts instead.
                    if (progress.State == "Completed")
                        continue;
                    if (!first && _time.GetElapsedTime(lastLineAt) < WorthALine)
                        continue;
                    first = false;
                    lastLineAt = _time.GetTimestamp();
                    Note(progress.State, Details(target, progress, operationStarted, id));
                    continue;
                }
                if (!response.Finished)
                    throw new InvalidDataException(SysvolText.Get("ProtocolInvalid"));
                if (response.Error is { } error)
                {
                    Record(error, Details(target, latest with { State = "Failed" }, started, id));
                    return error;
                }
                if (kind is SysvolRequestKind.EnumerateFiles or SysvolRequestKind.EnumerateDirectories && response.Paths is null)
                    throw new InvalidDataException(SysvolText.Get("ProtocolInvalid"));
                NoteCompletion(target, latest with { Operation = kind.ToString(), State = "Completed" }, started, id);
                return response;
            }
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
        {
            await StopWorkerAsync().ConfigureAwait(false);
            Note("Cancelled", Details(target, latest with { State = "Cancelled" }, started, id));
            throw;
        }
        catch (OperationCanceledException)
        {
            await StopWorkerAsync().ConfigureAwait(false);
            var timeout = SysvolText.Error("SysvolOperationTimedOut", "TimedOut", latest.Path,
                latest.Operation, latest.Path, limit.TotalSeconds);
            Record(timeout, Details(target, latest with { State = "TimedOut" }, operationStarted, id));
            return timeout;
        }
        catch (Exception error) when (error is IOException or InvalidDataException or Win32Exception or JsonException)
        {
            await StopWorkerAsync().ConfigureAwait(false);
            var failed = SysvolText.Error("SysvolWorkerFailed", "WorkerFailed", latest.Path, latest.Path, error.Message);
            Record(failed, Details(target, latest with { State = "Failed" }, started, id));
            return failed;
        }
        finally
        {
            _gate.Release();
        }
    }

    private IReadOnlyList<RunLogDetail> Details(GpoTarget target, SysvolIoEvent progress, long started, long id) =>
    [
        new("gpo", target.GpoGuid.ToString("D")), new("policy", target.DisplayName),
        new("uncPath", progress.Path), new("operation", progress.Operation), new("state", progress.State),
        new("request", id.ToString(CultureInfo.InvariantCulture)),
        new("workerPid", _diagnosticPid?.ToString(CultureInfo.InvariantCulture) ?? "none"),
        new("elapsedSeconds", _time.GetElapsedTime(started).TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture)),
        new("items", progress.Items.ToString(CultureInfo.InvariantCulture)),
        new("bytes", progress.Bytes.ToString(CultureInfo.InvariantCulture)),
        new("completedOperations", _completedOperations.ToString(CultureInfo.InvariantCulture)),
    ];

    /// <summary>
    /// Accounts for a completed operation, writing a line only if it earned one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three things have to survive the reduction, and each is handled here. <b>Nothing may be
    /// silently lost</b> - every operation is counted whether or not it is written, so the rollup
    /// total is the true total and a reader can subtract to see what went unremarked. <b>Anything
    /// unusual must still be visible</b> - a slow operation gets its own line with its full
    /// detail, because the reason to read this log at all is usually that something was slow.
    /// <b>A running capture must not look like a stopped one</b> - hence the periodic rollup.
    /// </para>
    /// <para>
    /// Failures are not routed through here at all; they go to <see cref="Record"/> unchanged.
    /// Reducing the log must never reduce the account of what went wrong.
    /// </para>
    /// </remarks>
    private void NoteCompletion(GpoTarget target, SysvolIoEvent completed, long started, long id)
    {
        _totalBytes += completed.Bytes;
        var elapsed = _time.GetElapsedTime(started);
        if (elapsed >= WorthALine)
        {
            _slowOperations++;
            Note("SlowOperation", Details(target, completed, started, id));
        }

        if (_completedOperations - _rolledUpAt < RollupEvery)
            return;

        _rolledUpAt = _completedOperations;
        Note("Rollup",
        [
            new("completedOperations", _completedOperations.ToString(CultureInfo.InvariantCulture)),
            new("slowOperations", _slowOperations.ToString(CultureInfo.InvariantCulture)),
            new("bytes", _totalBytes.ToString(CultureInfo.InvariantCulture)),
            new("policy", target.DisplayName),
            new("workerPid", _diagnosticPid?.ToString(CultureInfo.InvariantCulture) ?? "none"),
        ]);
    }

    private void Note(string key, IReadOnlyList<RunLogDetail> details) =>
        WriteLog(() => _log.Note("Capture", SysvolText.Get(key), details));

    private void Record(AuditError error, IReadOnlyList<RunLogDetail> details) =>
        WriteLog(() => _log.Record("Capture", error, details));

    private static void WriteLog(Action write)
    {
        try { write(); }
        catch (IOException error)
        {
            // A log-storage failure is not unreadable SMB evidence and must not enter the
            // transport's IOException-to-acquisition-failure path above.
            throw new InvalidOperationException(SysvolText.Get("LogFailed"), error);
        }
    }

    private async Task StopWorkerAsync()
    {
        var pid = _worker.ProcessId;
        _diagnosticPid = pid;
        _ready = false;
        var stopped = await _worker.StopAsync().ConfigureAwait(false);
        IReadOnlyList<RunLogDetail> details =
        [new("workerPid", pid?.ToString(CultureInfo.InvariantCulture) ?? "none"),
         new("stopped", stopped.ToString()), new("cause", _worker.StopFailure ?? "")];
        if (stopped)
            Note("WorkerStopped", details);
        else
            Record(SysvolText.Error("SysvolWorkerUnavailable", "WorkerUnavailable", ""), details);
    }

    /// <summary>Withdraws the session and bounds worker cleanup, including after cancellation.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;
        _disposed = true;
        _lifetime.Cancel();
        await _gate.WaitAsync().ConfigureAwait(false);
        try { await StopWorkerAsync().ConfigureAwait(false); }
        finally
        {
            _gate.Release();
            _gate.Dispose();
            _lifetime.Dispose();
        }
    }
}
