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
            Note("Started", Details(target, latest, started, id));
            if (!_ready)
            {
                limit = TimeSpan.FromSeconds(30);
                latest = latest with { Operation = "StartWorker" };
                Note("Started", Details(target, latest, started, id));
                using var startup = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                startup.CancelAfter(TimeSpan.FromSeconds(30));
                await _worker.StartAsync(startup.Token).ConfigureAwait(false);
                _diagnosticPid = _worker.ProcessId;
                var hello = await SysvolWire.ReceiveAsync<SysvolWorkerMessage>(_worker.Pipe, startup.Token).ConfigureAwait(false);
                if (hello.RequestId != 0 || hello.Progress?.Operation != "WorkerReady" || hello.Finished)
                    throw new InvalidDataException(SysvolText.Get("ProtocolInvalid"));
                _ready = true;
            }

            limit = _inactivityLimit;
            latest = latest with { Operation = kind.ToString() };
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
                Note("Completed", Details(target, latest with { Operation = kind.ToString(), State = "Completed" }, started, id));
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
