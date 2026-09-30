using System.Globalization;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

/// <summary>Reports judging activity independently of the worker completing an object or rule.</summary>
internal sealed class JudgingStatus : IProgress<JudgingRun.JudgingProgress>, IDisposable
{
    internal static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);
    internal static readonly TimeSpan DetailInterval = TimeSpan.FromMinutes(5);
    private readonly object _gate = new();
    private readonly object _outputGate = new();
    private readonly IRunLog _log;
    private readonly IProgress<JudgingRun.JudgingProgress> _progress;
    private readonly TimeProvider _time;
    private readonly Func<PostPassMemory> _memory;
    private PostPassDiagnostics? _postPass;
    private readonly ITimer _timer;
    private readonly long _started;
    private readonly Dictionary<string, RuleTotals> _rules = new(StringComparer.Ordinal);
    private JudgingPhase _phase = JudgingPhase.PreparingInputs;
    private string _operation = "PreparingInputs";
    private string? _rule;
    private long _operationStarted;
    private long _lastCompleted;
    private long _objects;
    private long _lastReportedObjects;
    private long _lastDetail;
    private long _lastAccounting;
    private bool _disposed;
    private bool _loggingFailed;

    private sealed class RuleTotals
    {
        internal double CompletedMs;
        internal int Judged;
        internal int NotApplicable;
    }

    private sealed record RuleSnapshot(string Rule, double CompletedMs, int Judged, int NotApplicable);

    internal JudgingStatus(IRunLog log, IProgress<JudgingRun.JudgingProgress> progress, TimeProvider time,
        Func<PostPassMemory>? memory = null)
    {
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(progress);
        ArgumentNullException.ThrowIfNull(time);
        _log = log;
        _progress = progress;
        _time = time;
        _memory = memory ?? PostPassMemory.Read;
        _started = _operationStarted = _lastCompleted = _lastDetail = _lastAccounting = time.GetTimestamp();
        _timer = time.CreateTimer(_ => Tick(), null, Interval, Interval);
    }

    internal Guid AttemptId { get; } = Guid.NewGuid();

    internal void RecordBuildIdentity() => WriteDiagnostic(log => JudgingBuildIdentity.Write(log, AttemptId));

    internal void RecordGeneration(Guid generation, string evidenceSeal, Guid? derivation) => WriteDiagnostic(log =>
        log.Note("Judge", "judging generation",
        [
            new("attempt", AttemptId.ToString("D")), new("generation", generation.ToString("D")),
            new("evidenceSeal", evidenceSeal), new("derivationGeneration", derivation?.ToString("D") ?? "none"),
        ]));

    internal PostPassDiagnostics BeginPostPass(string stage, Guid generation)
    {
        PostPassDiagnostics diagnostic;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_postPass is not null) throw new InvalidOperationException("Post-pass diagnostics must not overlap.");
            _postPass = diagnostic = new(this, stage, generation, _time, _memory);
        }
        diagnostic.Report("started");
        return diagnostic;
    }

    internal void EndPostPass(PostPassDiagnostics diagnostic)
    {
        lock (_gate)
            if (ReferenceEquals(_postPass, diagnostic)) _postPass = null;
    }

    internal void WriteDiagnostic(Action<IRunLog> write)
    {
        lock (_outputGate)
        {
            lock (_gate)
                if (_disposed || _loggingFailed) return;
            try { write(_log); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                lock (_gate) _loggingFailed = true;
                System.Diagnostics.Trace.TraceError("Judging diagnostic logging disabled: {0}", error);
            }
        }
    }

    /// <summary>Forwards screen progress without making log scheduling depend on it.</summary>
    public void Report(JudgingRun.JudgingProgress value)
    {
        lock (_gate)
        {
            if (_phase != value.Phase)
            {
                _phase = value.Phase;
                _operation = value.Phase.ToString();
                _rule = null;
                _operationStarted = _time.GetTimestamp();
            }
        }
        _progress.Report(value);
    }

    internal void BeginOperation(string operation)
    {
        lock (_gate)
        {
            _operation = operation;
            _rule = null;
            _operationStarted = _time.GetTimestamp();
        }
    }

    internal void BeginRule(string rule)
    {
        lock (_gate)
        {
            _operation = "rules";
            _rule = rule;
            _operationStarted = _time.GetTimestamp();
            if (!_rules.ContainsKey(rule)) _rules.Add(rule, new());
        }
    }

    internal void EndRule(string rule, TimeSpan elapsed, int judged, int notApplicable)
    {
        lock (_gate)
        {
            var totals = _rules[rule];
            totals.CompletedMs = elapsed.TotalMilliseconds;
            totals.Judged = judged;
            totals.NotApplicable = notApplicable;
            _rule = null;
            _operationStarted = _time.GetTimestamp();
        }
    }

    internal void CompleteObject(long objects)
    {
        lock (_gate)
        {
            _objects = objects;
            _lastCompleted = _time.GetTimestamp();
        }
    }

    // Called only by the worker: its existing Stopwatch totals are never read by the timer.
    internal bool AccountingDue()
    {
        var now = _time.GetTimestamp();
        if (_time.GetElapsedTime(_lastAccounting, now) < DetailInterval) return false;
        _lastAccounting = now;
        return true;
    }

    private void Tick()
    {
        // A slow log must not queue overlapping writes or prevent the worker updating its state.
        if (!Monitor.TryEnter(_outputGate)) return;
        try
        {
            JudgingPhase phase;
            string operation;
            string? activeRule;
            long objects, delta;
            double elapsedMs, operationMs, sinceCompletedMs;
            RuleSnapshot[]? details;
            PostPassDiagnostics? postPass;
            lock (_gate)
            {
                if (_disposed || _loggingFailed) return;
                var now = _time.GetTimestamp();
                phase = _phase;
                operation = _operation;
                activeRule = _rule;
                objects = _objects;
                delta = objects - _lastReportedObjects;
                _lastReportedObjects = objects;
                elapsedMs = _time.GetElapsedTime(_started, now).TotalMilliseconds;
                operationMs = _time.GetElapsedTime(_operationStarted, now).TotalMilliseconds;
                sinceCompletedMs = _time.GetElapsedTime(_lastCompleted, now).TotalMilliseconds;
                details = _time.GetElapsedTime(_lastDetail, now) >= DetailInterval
                    ? _rules.Select(pair => new RuleSnapshot(pair.Key, pair.Value.CompletedMs,
                        pair.Value.Judged, pair.Value.NotApplicable)).ToArray() : null;
                if (details is not null) _lastDetail = now;
                postPass = _postPass;
            }

            _log.Note("Judge", "judging status",
            [
                new("phase", phase.ToString()), new("operation", operation),
                new("rule", activeRule ?? "none"), new("objects", Number(objects)),
                new("sinceLast", Number(delta)), new("elapsedMs", Number(elapsedMs)),
                new("operationMs", Number(operationMs)), new("sinceObjectCompletedMs", Number(sinceCompletedMs)),
            ]);
            postPass?.Report();
            lock (_gate)
                if (_disposed || _loggingFailed) return;
            if (details is null) return;
            foreach (var item in details.OrderByDescending(item => item.CompletedMs + (item.Rule == activeRule ? operationMs : 0)))
            {
                _log.Note("Judge", "rule work so far",
                [
                    new("rule", item.Rule), new("completedMs", Number(item.CompletedMs)),
                    new("activeMs", Number(item.Rule == activeRule ? operationMs : 0)),
                    new("judged", Number(item.Judged)), new("notAbout", Number(item.NotApplicable)),
                    new("objects", Number(objects)),
                ]);
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            // An unavailable log cannot crash a timer thread (and therefore the entire audit).
            // Keep the failure visible on the diagnostic channel, then stop periodic attempts.
            lock (_gate) _loggingFailed = true;
            System.Diagnostics.Trace.TraceError("Judging status logging disabled: {0}", error);
        }
        finally
        {
            Monitor.Exit(_outputGate);
        }
    }

    /// <summary>Stops reporting and waits for any in-flight log write before the log may be closed.</summary>
    public void Dispose()
    {
        lock (_gate) _disposed = true;
        _timer.Dispose();
        // A queued callback checks _disposed; one already writing must finish before we return.
        lock (_outputGate) { }
    }

    private static string Number(double value) => value.ToString("F0", CultureInfo.InvariantCulture);
}
