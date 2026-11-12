using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using SecureAD.Kernel;

namespace SecureAD.Measure;

internal sealed class EnterpriseBaselineObservation : IRunLog, IDisposable
{
    private readonly object _gate = new();
    private readonly StreamWriter _writer;
    private readonly MeterListener _listener = new();
    private readonly CancellationTokenSource _samplingStop = new();
    private readonly CancellationTokenSource _stopping;
    private readonly Process _process = Process.GetCurrentProcess();
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly string _output;
    private readonly long _memoryLimit;
    private readonly Task _sampling;
    private readonly List<EnterpriseStageObservation> _stages = [];
    private readonly Dictionary<string, long> _verifications = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _nameLookups = new(StringComparer.Ordinal);
    private readonly HashSet<string> _nameLookupSources = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _gpoPreparations = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _nativePreparations = new(StringComparer.Ordinal);
    private ExceptionDispatchInfo? _samplingFailure;
    private string _stage = "Preparing";
    private TimeSpan? _memoryExceeded;
    private int _resourceSamples;
    private bool _disposed;

    internal EnterpriseBaselineObservation(string output, long physicalMemoryBytes, CancellationTokenSource stopping,
        string? nameLookupDirectory = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(physicalMemoryBytes);
        _output = Path.GetFullPath(output);
        _stopping = stopping;
        _memoryLimit = Math.Min(48L * 1024 * 1024 * 1024, physicalMemoryBytes / 4 * 3);
        _writer = new StreamWriter(new FileStream(Path.Combine(output, "observations.jsonl"),
            FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
        var lookupDirectory = nameLookupDirectory is null ? null : Path.GetFullPath(nameLookupDirectory);
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == "SecureAD.Evidence.Readback"
                && (instrument.Name == "store.verifications"
                    || lookupDirectory is not null && instrument.Name is "evidence.name_lookup" or "evidence.gpo_preparation"))
                listener.EnableMeasurementEvents(instrument);
            if (lookupDirectory is not null
                && (instrument.Meter.Name == "SecureAD.Evidence.WqlParser" && instrument.Name == "wql.native_parses"
                    || instrument.Meter.Name == "SecureAD.Kernel.GroupPolicy" && instrument.Name == "registry.instruction_decodes"))
                listener.EnableMeasurementEvents(instrument);
        };
        _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            if (instrument.Name is "wql.native_parses" or "registry.instruction_decodes")
            {
                lock (_gate)
                    _nativePreparations[instrument.Name] = checked(_nativePreparations.GetValueOrDefault(instrument.Name) + value);
                return;
            }
            if (instrument.Name is "evidence.name_lookup" or "evidence.gpo_preparation")
            {
                string? operation = null;
                string? source = null;
                string? directory = null;
                foreach (var tag in tags)
                {
                    if (tag.Key == "operation") operation = tag.Value as string;
                    if (tag.Key == "source") source = tag.Value as string;
                    if (tag.Key == "bundle") directory = tag.Value as string;
                }
                if (operation is null || source is null || directory is null)
                    throw new InvalidDataException("A name-lookup observation lacks its operation or source.");
                if (!string.Equals(directory, lookupDirectory, StringComparison.OrdinalIgnoreCase)) return;
                lock (_gate)
                {
                    var target = instrument.Name == "evidence.name_lookup" ? _nameLookups : _gpoPreparations;
                    target[operation] = checked(target.GetValueOrDefault(operation) + value);
                    _nameLookupSources.Add(source);
                }
                return;
            }
            foreach (var tag in tags)
            {
                if (tag.Value is not string path || !path.StartsWith(_output + Path.DirectorySeparatorChar,
                        StringComparison.OrdinalIgnoreCase)) continue;
                lock (_gate)
                {
                    var relative = Path.GetRelativePath(_output, path);
                    _verifications[relative] = checked(_verifications.GetValueOrDefault(relative) + value);
                    Write(new { Event = "store-verification-attempt", Stage = _stage, Path = relative, Count = value,
                        ElapsedMs = _clock.Elapsed.TotalMilliseconds });
                }
                break;
            }
        });
        _listener.Start();
        _sampling = Task.Run(SampleAsync);
    }

    internal IReadOnlyList<EnterpriseStageObservation> Stages { get { lock (_gate) return _stages.ToArray(); } }
    internal IReadOnlyDictionary<string, long> Verifications
    {
        get { lock (_gate) return new Dictionary<string, long>(_verifications, StringComparer.OrdinalIgnoreCase); }
    }
    internal IReadOnlyDictionary<string, long> NameLookups
    {
        get { lock (_gate) return new Dictionary<string, long>(_nameLookups, StringComparer.Ordinal); }
    }
    internal IReadOnlyList<string> NameLookupSources
    {
        get { lock (_gate) return _nameLookupSources.Order(StringComparer.Ordinal).ToArray(); }
    }
    internal IReadOnlyDictionary<string, long> GpoPreparations
    {
        get { lock (_gate) return new Dictionary<string, long>(_gpoPreparations, StringComparer.Ordinal); }
    }
    internal IReadOnlyDictionary<string, long> NativePreparations
    {
        get { lock (_gate) return new Dictionary<string, long>(_nativePreparations, StringComparer.Ordinal); }
    }
    internal int ResourceSamples { get { lock (_gate) return _resourceSamples; } }
    internal CancellationToken Token => _stopping.Token;

    internal T Measure<T>(string name, Func<T> work) =>
        MeasureAsync(name, () => Task.FromResult(work())).GetAwaiter().GetResult();

    internal async Task<T> MeasureAsync<T>(string name, Func<Task<T>> work)
    {
        _samplingFailure?.Throw();
        Token.ThrowIfCancellationRequested();
        _process.Refresh();
        var started = Stopwatch.GetTimestamp();
        var allocated = GC.GetTotalAllocatedBytes(true);
        var cpu = _process.TotalProcessorTime;
        lock (_gate)
        {
            _stage = name;
            Write(new { Event = "stage-start", Stage = name, ElapsedMs = _clock.Elapsed.TotalMilliseconds });
        }
        var succeeded = false;
        try
        {
            var result = await work();
            _samplingFailure?.Throw();
            Token.ThrowIfCancellationRequested();
            succeeded = true;
            return result;
        }
        finally
        {
            _process.Refresh();
            var observation = new EnterpriseStageObservation(name, succeeded,
                Stopwatch.GetElapsedTime(started).TotalMilliseconds,
                GC.GetTotalAllocatedBytes(true) - allocated, (_process.TotalProcessorTime - cpu).TotalMilliseconds);
            lock (_gate)
            {
                _stages.Add(observation);
                Write(new { Event = "stage-finish", Observation = observation });
                _stage = "BetweenStages";
            }
        }
    }

    public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail)
    {
        lock (_gate) Write(new { Event = "run-note", Stage = _stage, Phase = phase, Message = message, Detail = detail,
            ElapsedMs = _clock.Elapsed.TotalMilliseconds });
    }

    public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail)
    {
        lock (_gate) Write(new { Event = "run-error", Stage = _stage, Phase = phase, Error = error, Detail = detail,
            ElapsedMs = _clock.Elapsed.TotalMilliseconds });
    }

    private async Task SampleAsync()
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(100));
        try
        {
            var samples = 0;
            do
            {
                _process.Refresh();
                var elapsed = _clock.Elapsed;
                var privateBytes = _process.PrivateMemorySize64;
                _memoryExceeded = privateBytes > _memoryLimit ? _memoryExceeded ?? elapsed : null;
                string? stop = elapsed >= TimeSpan.FromHours(24) ? "24-hour command ceiling" : null;
                if (_memoryExceeded is { } since && elapsed - since >= TimeSpan.FromSeconds(10))
                    stop = "sustained private-memory safety ceiling";
                if (samples++ % 10 == 0)
                {
                    var drive = new DriveInfo(Path.GetPathRoot(_output)
                        ?? throw new InvalidDataException("Output has no local drive root."));
                    if (drive.AvailableFreeSpace < 32L * 1024 * 1024 * 1024) stop = "32-GiB free-space reserve";
                    long bytes = 0;
                    var transientFiles = 0;
                    foreach (var path in Directory.EnumerateFiles(_output, "*", SearchOption.AllDirectories))
                    {
                        var file = new FileInfo(path);
                        if (file.Exists) bytes = checked(bytes + file.Length);
                        else transientFiles++;
                    }
                    if (bytes > 192L * 1024 * 1024 * 1024) stop = "192-GiB owned scratch ceiling";
                    lock (_gate) Write(new { Event = "scratch-sample", Bytes = bytes, TransientFiles = transientFiles,
                        ElapsedMs = elapsed.TotalMilliseconds });
                }
                lock (_gate)
                {
                    Write(new { Event = "resource-sample", Stage = _stage, ElapsedMs = elapsed.TotalMilliseconds,
                        PrivateBytes = privateBytes, WorkingSetBytes = _process.WorkingSet64,
                        ProcessLifetimePeakWorkingSetBytes = _process.PeakWorkingSet64,
                        CpuMs = _process.TotalProcessorTime.TotalMilliseconds,
                        ManagedAllocatedBytes = GC.GetTotalAllocatedBytes(false),
                        Gen0 = GC.CollectionCount(0), Gen1 = GC.CollectionCount(1), Gen2 = GC.CollectionCount(2) });
                    _resourceSamples++;
                    if (stop is not null) Write(new { Event = "safety-stop", Reason = stop });
                }
                if (stop is not null) { _stopping.Cancel(); return; }
            } while (await timer.WaitForNextTickAsync(_samplingStop.Token));
        }
        catch (OperationCanceledException) when (_samplingStop.IsCancellationRequested) { }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _samplingFailure = ExceptionDispatchInfo.Capture(error);
            Console.Error.WriteLine("Measurement observation failed: " + error);
            _stopping.Cancel();
        }
    }

    private void Write(object value) => _writer.WriteLine(JsonSerializer.Serialize(value));

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _samplingStop.Cancel();
        _sampling.GetAwaiter().GetResult();
        _listener.Dispose();
        _writer.Dispose();
        _samplingStop.Dispose();
        _process.Dispose();
        _samplingFailure?.Throw();
    }
}

internal sealed record EnterpriseStageObservation(string Stage, bool Succeeded, double ElapsedMs,
    long ManagedAllocatedBytes, double CpuMs);
