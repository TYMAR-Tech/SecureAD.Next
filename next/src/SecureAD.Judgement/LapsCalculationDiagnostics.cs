using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace SecureAD.Judgement;

internal static class LapsCalculationDiagnostics
{
    private static readonly Meter Meter = new("SecureAD.Judgement.LapsCalculation");
    private static readonly Histogram<double> Elapsed = Meter.CreateHistogram<double>("laps.work_ms", "ms");
    private static readonly Counter<long> Work = Meter.CreateCounter<long>("laps.work");
    [ThreadStatic] private static string? _directory;
    [ThreadStatic] private static string? _area;

    internal static bool IsActive => _directory is not null && Elapsed.Enabled;

    internal static Scope Begin(string directory)
    {
        if (!Elapsed.Enabled && !Work.Enabled) return default;
        var previous = _directory;
        var previousArea = _area;
        _directory = directory;
        _area = "calculation";
        return new("calculation", directory, previous, true, previousArea);
    }

    internal static Scope Measure(string operation)
    {
        if (_directory is not { } directory || !Elapsed.Enabled) return default;
        var previousArea = _area;
        _area = operation;
        return new(operation, directory, null, false, previousArea);
    }

    internal static void RecordCurrentSelection(double milliseconds)
    {
        if (_directory is { } directory && Elapsed.Enabled)
            Elapsed.Record(milliseconds, new("bundle", directory), new("operation", "current-selection/" + _area));
    }

    internal static void Count(string operation, long count)
    {
        if (_directory is { } directory && Work.Enabled)
            Work.Add(count, new("bundle", directory), new("operation", operation));
    }

    // Calculation is synchronous; the context ends even when cancellation or a source check throws.
    internal readonly struct Scope(string operation, string directory, string? previous, bool root,
        string? previousArea) : IDisposable
    {
        private readonly long _started = Elapsed.Enabled ? Stopwatch.GetTimestamp() : 0;

        public void Dispose()
        {
            try
            {
                if (_started != 0)
                    Elapsed.Record(Stopwatch.GetElapsedTime(_started).TotalMilliseconds,
                        new("bundle", directory), new("operation", operation));
            }
            finally
            {
                if (root || _started != 0) _area = previousArea;
                if (root) _directory = previous;
            }
        }
    }
}
