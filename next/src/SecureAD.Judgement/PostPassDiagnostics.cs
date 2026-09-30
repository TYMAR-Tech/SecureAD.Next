using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

// Execution progress is not permission, capture, or security-analysis completeness.
internal sealed class PostPassDiagnostics(JudgingStatus owner, string stage, Guid generation,
    TimeProvider time, Func<PostPassMemory> memory) : IDisposable
{
    private readonly object _gate = new();
    private readonly long _started = time.GetTimestamp();
    private readonly Dictionary<string, double> _parts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _counters = new(StringComparer.Ordinal);
    private string? _part;
    private long _partStarted;
    private bool _completed;
    private bool _disposed;

    private sealed record PartSnapshot(string Name, double CompletedMs, double ActiveMs);
    private sealed record Snapshot(string Outcome, string? ActivePart, double ElapsedMs,
        PartSnapshot[] Parts, KeyValuePair<string, long>[] Counters);

    internal void Part(string name)
    {
        lock (_gate)
        {
            var now = time.GetTimestamp();
            ClosePart(now);
            _part = name;
            _partStarted = now;
            _parts.TryAdd(name, 0);
        }
    }

    internal void Counter(string name, long value)
    {
        lock (_gate) _counters[name] = value;
    }

    internal void Targets(long total)
    {
        lock (_gate)
        {
            _counters["targetsTotal"] = total;
            _counters["targetsProcessed"] = 0;
            _counters["targetsCompleted"] = 0;
            _counters["targetsUnavailable"] = 0;
        }
    }

    internal void TargetFinished(bool available = true)
    {
        lock (_gate)
        {
            _counters["targetsProcessed"]++;
            _counters[available ? "targetsCompleted" : "targetsUnavailable"]++;
        }
    }

    internal IProgress<OwnershipScopeProgress> ScopeProgress => new ScopeObserver(this);

    private sealed class ScopeObserver(PostPassDiagnostics diagnostic) : IProgress<OwnershipScopeProgress>
    {
        public void Report(OwnershipScopeProgress value)
        {
            lock (diagnostic._gate)
            {
                diagnostic._counters["scopeTargetsVisited"] = value.VisitedTargets;
                diagnostic._counters["scopeRelationsExamined"] = value.ExaminedRelations;
                diagnostic._counters["scopeTargetsIncluded"] = value.IncludedTargets;
            }
        }
    }

    internal void Complete()
    {
        lock (_gate) _completed = true;
    }

    internal void Report(string outcome = "running")
    {
        Snapshot snapshot;
        lock (_gate)
        {
            if (_disposed) return;
            snapshot = Read(outcome, time.GetTimestamp());
        }
        Write(snapshot);
    }

    private void ClosePart(long now)
    {
        if (_part is null) return;
        _parts[_part] += time.GetElapsedTime(_partStarted, now).TotalMilliseconds;
        _part = null;
    }

    private Snapshot Read(string outcome, long now) => new(outcome, _part,
        time.GetElapsedTime(_started, now).TotalMilliseconds,
        _parts.Select(pair => new PartSnapshot(pair.Key, pair.Value,
            pair.Key == _part ? time.GetElapsedTime(_partStarted, now).TotalMilliseconds : 0)).ToArray(),
        _counters.ToArray());

    private void Write(Snapshot snapshot) => owner.WriteDiagnostic(log =>
    {
        var sample = memory();
        var accounted = snapshot.Parts.Sum(part => part.CompletedMs + part.ActiveMs);
        var detail = new List<RunLogDetail>
        {
            new("generation", generation.ToString("D")), new("stage", stage),
            new("kind", "execution-only"), new("outcome", snapshot.Outcome),
            new("activePart", snapshot.ActivePart ?? "none"), new("elapsedMs", Number(snapshot.ElapsedMs)),
            new("accountedMs", Number(accounted)), new("unaccountedMs", Number(snapshot.ElapsedMs - accounted)),
            new("memoryKind", "process-snapshot-not-peak"), new("memoryStatus", sample.Status),
            new("workingSetBytes", Optional(sample.WorkingSetBytes)), new("privateBytes", Optional(sample.PrivateBytes)),
            new("managedEstimatedBytes", Number(sample.ManagedBytes)), new("processAllocatedBytes", Number(sample.AllocatedBytes)),
            new("processGen0", Number(sample.Gen0)), new("processGen1", Number(sample.Gen1)), new("processGen2", Number(sample.Gen2)),
        };
        detail.AddRange(snapshot.Counters.Select(pair => new RunLogDetail(pair.Key, Number(pair.Value))));
        log.Note("Judge", "post-pass status", detail);
        foreach (var part in snapshot.Parts)
            log.Note("Judge", "post-pass part",
            [
                new("generation", generation.ToString("D")), new("stage", stage), new("outcome", snapshot.Outcome),
                new("part", part.Name), new("completedMs", Number(part.CompletedMs)), new("activeMs", Number(part.ActiveMs)),
            ]);
    });

    public void Dispose()
    {
        Snapshot snapshot;
        lock (_gate)
        {
            if (_disposed) return;
            var now = time.GetTimestamp();
            if (_completed) ClosePart(now);
            snapshot = Read(_completed ? "completed" : "interrupted", now);
            _disposed = true;
        }
        owner.EndPostPass(this);
        Write(snapshot);
    }

    private static string Optional(long? value) => value.HasValue ? Number(value.Value) : "unavailable";
    private static string Number(double value) => value.ToString("F0", CultureInfo.InvariantCulture);
}

internal sealed record PostPassMemory(long? WorkingSetBytes, long? PrivateBytes, long ManagedBytes,
    long AllocatedBytes, int Gen0, int Gen1, int Gen2, string Status)
{
    internal static PostPassMemory Read()
    {
        long? working = null, committed = null;
        var status = "available";
        try
        {
            using var process = Process.GetCurrentProcess();
            process.Refresh();
            working = process.WorkingSet64;
            committed = process.PrivateMemorySize64;
        }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException or NotSupportedException)
        {
            status = "unavailable:" + error.GetType().Name;
        }
        return new(working, committed, GC.GetTotalMemory(false), GC.GetTotalAllocatedBytes(false),
            GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2), status);
    }
}
