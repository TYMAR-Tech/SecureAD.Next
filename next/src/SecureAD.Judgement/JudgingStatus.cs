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
    private Guid? _generation;
    private string? _evidenceSeal;
    private Guid? _derivation;
    private PathRequesterWorkPhase? _requesterPhase;
    private PublicationState _publication;
    private Action<IRunLog>? _deferredFailure;
    private long _operationStarted;
    private long _lastCompleted;
    private long _objects;
    private long _lastReportedObjects;
    private long _lastDetail;
    private long _lastAccounting;
    private bool _disposed;
    private bool _loggingFailed;
    private readonly Dictionary<PostPassDiagnostics, long> _requesterAnswers = [];

    private enum PublicationState { NotStarted, Unconfirmed, Published }

    private sealed class RuleTotals
    {
        internal double CompletedMs;
        internal int Judged;
        internal int NotApplicable;
    }

    private sealed record RuleSnapshot(string Rule, double CompletedMs, int Judged, int NotApplicable);

    internal JudgingStatus(IRunLog log, IProgress<JudgingRun.JudgingProgress> progress, TimeProvider time,
        Func<PostPassMemory> memory)
    {
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(progress);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(memory);
        _log = log;
        _progress = progress;
        _time = time;
        _memory = memory;
        _started = _operationStarted = _lastCompleted = _lastDetail = _lastAccounting = time.GetTimestamp();
        _timer = time.CreateTimer(_ => Tick(), null, Interval, Interval);
    }

    internal Guid AttemptId { get; } = Guid.NewGuid();

    internal IRunLog DiagnosticLog => new DiagnosticSink(this);

    private sealed class DiagnosticSink(JudgingStatus owner) : IRunLog
    {
        public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail) =>
            owner.WriteDiagnostic(log => log.Note(phase, message, detail));

        public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail) =>
            owner.WriteDiagnostic(log => log.Record(phase, error, detail));
    }

    internal void RecordBuildIdentity() => WriteDiagnostic(log => JudgingBuildIdentity.Write(log, AttemptId));

    internal void RecordGeneration(Guid generation, string evidenceSeal, Guid? derivation)
    {
        lock (_gate)
        {
            _generation = generation;
            _evidenceSeal = evidenceSeal;
            _derivation = derivation;
        }
        WriteDiagnostic(log => log.Note("Judge", "judging generation",
        [
            new("attempt", AttemptId.ToString("D")), new("generation", generation.ToString("D")),
            new("evidenceSeal", evidenceSeal), new("derivationGeneration", derivation?.ToString("D") ?? "none"),
        ]));
    }

    internal void PublicationCompleted()
    {
        lock (_gate) _publication = PublicationState.Published;
    }

    // Used as an always-false exception filter: record before scopes unwind, then preserve the
    // original exception and stack. The CLR also ignores exceptions thrown by a failing log here.
    internal bool RecordException(Exception error, bool cancellationRequested)
    {
        var cancelled = error is OperationCanceledException;
        var detail = TerminalDetails(cancelled ? "Cancelled" : "Failed");
        detail.Add(new("cancellationRequested", cancellationRequested.ToString(CultureInfo.InvariantCulture)));
        detail.Add(new("exceptionType", error.GetType().FullName ?? error.GetType().Name));
        detail.Add(new("exceptionMessage", error.Message));
        detail.Add(new("exception", error.ToString()));
        Action<IRunLog> write = cancelled
            ? log => log.Note("Judge", "judging cancelled", detail)
            : log => log.Record("Judge", AuditError.Create(ErrorCategory.Evidence,
                "JudgingException", ErrorSeverity.Failed,
                "The judging operation ended with an exception. See the recorded failure details.",
                AttemptId.ToString("D")), detail);
        // A filter still holds the failing scopes' locks. Do not wait for a reporter which may
        // itself be waiting for such a lock; retain the context and flush it after unwinding.
        if (!Monitor.TryEnter(_outputGate))
        {
            lock (_gate) _deferredFailure ??= write;
            return false;
        }
        try { WriteDiagnostic(write); }
        finally { Monitor.Exit(_outputGate); }
        return false;
    }

    internal void RecordRefusal(AuditError error)
    {
        try
        {
            var detail = TerminalDetails("Failed");
            detail.Add(new("errorContext", error.Context ?? "none"));
            WriteDiagnostic(log => log.Record("Judge", error, detail));
        }
        catch (Exception)
        {
            // A broken diagnostic sink must not replace the failure result already being returned.
        }
    }

    private List<RunLogDetail> TerminalDetails(string outcome)
    {
        lock (_gate)
            return
            [
                new("attempt", AttemptId.ToString("D")), new("outcome", outcome),
                new("generation", _generation?.ToString("D") ?? "none"),
                new("evidenceSeal", _evidenceSeal ?? "none"),
                new("derivationGeneration", _derivation?.ToString("D") ?? "none"),
                new("phase", _phase.ToString()), new("operation", _operation),
                new("requesterPhase", _requesterPhase?.ToString() ?? "none"),
                new("rule", _rule ?? "none"), new("objects", Number(_objects)),
                new("publication", _publication.ToString()),
                new("elapsedMs", Number(_time.GetElapsedTime(_started).TotalMilliseconds)),
            ];
    }

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
            _requesterPhase = value.RequesterPhase;
            if (value.Phase == JudgingPhase.PublishingJudgement)
                _publication = PublicationState.Unconfirmed;
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

    internal void Work(PostPassDiagnostics diagnostic, JudgingWorkUnit unit, long completed)
    {
        JudgingRun.JudgingProgress value;
        lock (_gate)
        {
            if (_disposed) return;
            if (unit == JudgingWorkUnit.RequesterAssessments)
            {
                // Only distinct stored answers count here, never membership prerequisites or routes.
                _requesterAnswers[diagnostic] = completed;
                completed = _requesterAnswers.Values.Sum();
            }
            value = new(_objects)
            {
                Phase = _phase, RequesterPhase = _requesterPhase, JudgementGenerationId = _generation,
                WorkCompleted = completed, WorkUnit = unit,
            };
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
        Action<IRunLog>? deferred;
        lock (_gate)
        {
            _disposed = true;
            deferred = _deferredFailure;
            _deferredFailure = null;
        }
        _timer.Dispose();
        // A queued callback checks _disposed; one already writing must finish before we return.
        lock (_outputGate)
        {
            if (deferred is null) return;
            try { deferred(_log); }
            catch (Exception)
            {
                // Disposal is on the original exception's path; diagnostic failure cannot replace it.
            }
        }
    }

    private static string Number(double value) => value.ToString("F0", CultureInfo.InvariantCulture);
}
