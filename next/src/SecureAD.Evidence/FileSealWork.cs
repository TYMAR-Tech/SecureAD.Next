using System.Diagnostics;
using System.Globalization;
using SecureAD.Kernel;

namespace SecureAD.Evidence;

internal enum FileSealPart { OpenData, ReadData, HashData, FinishHash, CloseData, EncodeSeal, WriteSeal }

internal sealed class FileSealWork(TimeProvider time)
{
    private readonly long _started = time.GetTimestamp();
    private readonly long[] _ticks = new long[7];
    private FileSealPart? _active;
    private FileSealPart? _failed;
    private long _partStarted;
    private long _maxReadTicks;
    private long _maxHashTicks;

    internal long ReadCalls { get; private set; }
    internal long BytesRead { get; private set; }
    internal long BytesHashed { get; private set; }

    internal void Begin(FileSealPart part)
    {
        _active = part;
        _partStarted = time.GetTimestamp();
    }

    internal void End()
    {
        if (_active is not { } part) return;
        var ticks = time.GetElapsedTime(_partStarted).Ticks;
        _ticks[(int)part] += ticks;
        if (part == FileSealPart.ReadData) _maxReadTicks = Math.Max(_maxReadTicks, ticks);
        if (part == FileSealPart.HashData) _maxHashTicks = Math.Max(_maxHashTicks, ticks);
        _active = null;
    }

    internal void RecordInterruptedPart()
    {
        _failed ??= _active;
        End();
    }

    internal void Reading() => ReadCalls = checked(ReadCalls + 1);
    internal void Read(int count) => BytesRead = checked(BytesRead + count);
    internal void Hashed(int count) => BytesHashed = checked(BytesHashed + count);

    internal void Report(IRunLog log, AnalysisStoreKind? kind, Guid? generation, string outcome) =>
        Report(log, kind, generation, outcome, null);

    internal void Report(IRunLog log, AnalysisStoreKind? kind, Guid? generation, string outcome, string? artifact)
    {
        var total = time.GetElapsedTime(_started);
        var phase = kind switch
        {
            AnalysisStoreKind.Judgement => "Judge",
            AnalysisStoreKind.Derivation => "Derive",
            _ => "Capture",
        };
        try
        {
            log.Note(phase, "file sealing",
            [
                new("artifact", artifact ?? kind?.ToString() ?? "Evidence"),
                new("generation", generation?.ToString("D") ?? "none"),
                new("outcome", outcome), new("failedPart", _failed?.ToString() ?? "none"),
                new("totalMs", Number(total.TotalMilliseconds)),
                new("openDataMs", Milliseconds(FileSealPart.OpenData)),
                new("readDataMs", Milliseconds(FileSealPart.ReadData)),
                new("hashDataMs", Milliseconds(FileSealPart.HashData)),
                new("finishHashMs", Milliseconds(FileSealPart.FinishHash)),
                new("closeDataMs", Milliseconds(FileSealPart.CloseData)),
                new("encodeSealMs", Milliseconds(FileSealPart.EncodeSeal)),
                new("writeSealMs", Milliseconds(FileSealPart.WriteSeal)),
                new("unaccountedMs", Number(total.TotalMilliseconds - TimeSpan.FromTicks(_ticks.Sum()).TotalMilliseconds)),
                new("readCalls", ReadCalls.ToString(CultureInfo.InvariantCulture)),
                new("bytesRead", BytesRead.ToString(CultureInfo.InvariantCulture)),
                new("bytesHashed", BytesHashed.ToString(CultureInfo.InvariantCulture)),
                new("maxReadMs", Number(TimeSpan.FromTicks(_maxReadTicks).TotalMilliseconds)),
                new("maxHashMs", Number(TimeSpan.FromTicks(_maxHashTicks).TotalMilliseconds)),
                new("readBufferBytes", "81920"),
                new("timingKind", "elapsed-operation-not-cpu"),
                new("timingScope", "sealing-before-log-write"),
                new("sealWriteIncludes", "open-write-close"),
            ]);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Trace.TraceError("Sealing diagnostic logging unavailable ({0}); the sealing operation is unaffected.", error.GetType().Name);
        }
    }

    private string Milliseconds(FileSealPart part) => Number(TimeSpan.FromTicks(_ticks[(int)part]).TotalMilliseconds);
    private static string Number(double value) => value.ToString("0.###", CultureInfo.InvariantCulture);
}
