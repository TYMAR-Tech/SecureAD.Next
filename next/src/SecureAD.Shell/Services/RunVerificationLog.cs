using System.Globalization;
using System.IO;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Shell.Services;

/// <summary>Writes what opening a saved run cost into that run's own log, one line per file.</summary>
/// <remarks>
/// Production returns only a run's log and summary, so this is how a measurement learns whether the time
/// went into reading the disk or computing the checksum: every file's size, how long its check took, and
/// when each answer arrived relative to the others (the checks overlap).
/// </remarks>
internal sealed class RunVerificationLog : IDisposable
{
    private const string Phase = "Verify";
    private readonly RunLogFile? _file;
    private readonly IRunLog _log;
    private long _verifiedBytes;

    internal RunVerificationLog(string directory)
    {
        var opened = Directory.Exists(directory)
            ? RunLogFile.Open(directory, "saved-run verification", TimeProvider.System)
            : Result<RunLogFile>.Failure(AuditError.Create(ErrorCategory.Shell, "VerificationLogUnavailable",
                ErrorSeverity.Degraded, "The selected run directory does not exist.", directory));
        _file = opened.IsSuccess ? opened.Value : null;
        _log = _file ?? RunLog.Discarded;
        _log.Note(Phase, "saved run opened; verifying every file once",
        [
            new("run", Path.GetFullPath(directory)),
            .. NavigationDiagnostics.BuildIdentity(),
        ]);
    }

    internal void Checked(ProtectedFileCheck check)
    {
        var details = new List<RunLogDetail>
        {
            new("role", check.Role.ToString()),
            new("file", check.FileName),
            new("bytes", check.Bytes.ToString(CultureInfo.InvariantCulture)),
            new("outcome", check.Outcome.ToString()),
            new("startedMs", Milliseconds(check.Started)),
            new("finishedMs", Milliseconds(check.Finished)),
        };
        if (check.Hashed is { } hashed)
        {
            details.Add(new("hashMs", Milliseconds(hashed)));
            if (hashed > TimeSpan.Zero) details.Add(new("megabytesPerSecond", Rate(check.Bytes, hashed)));
        }
        if (check.Outcome == ProtectedFileCheckOutcome.Verified) Interlocked.Add(ref _verifiedBytes, check.Bytes);
        if (check.Outcome == ProtectedFileCheckOutcome.Failed)
            _log.Record(Phase, AuditError.Create(ErrorCategory.Evidence, "SavedRunFileUnverified", ErrorSeverity.Failed,
                check.Failure ?? "The file did not verify.", check.FileName), details);
        else _log.Note(Phase, "file verified", details);
    }

    internal void Finished(ProtectedRunVerification summary)
    {
        var verified = Interlocked.Read(ref _verifiedBytes);
        _log.Note(Phase, "saved run verified",
        [
            new("files", summary.Files.ToString(CultureInfo.InvariantCulture)),
            new("verified", summary.Verified.ToString(CultureInfo.InvariantCulture)),
            new("failed", summary.Unverified.ToString(CultureInfo.InvariantCulture)),
            new("verifiedBytes", verified.ToString(CultureInfo.InvariantCulture)),
            new("wallMs", Milliseconds(summary.Elapsed)),
            new("sumOfFileMs", Milliseconds(summary.Hashed)),
            new("megabytesPerSecond", summary.Elapsed > TimeSpan.Zero ? Rate(verified, summary.Elapsed) : "0"),
        ]);
        foreach (var problem in summary.Problems) _log.Note(Phase, "run product could not be selected", [new("detail", problem)]);
    }

    internal void Stopped() =>
        _log.Note(Phase, "verification stopped before it finished because the run was closed", []);

    internal void Unavailable(Exception error) =>
        _log.Note(Phase, "verification could not run", [new("detail", error.Message)]);

    public void Dispose() => _file?.Dispose();

    private static string Milliseconds(TimeSpan value) => value.TotalMilliseconds.ToString("F1", CultureInfo.InvariantCulture);

    private static string Rate(long bytes, TimeSpan time) =>
        (bytes / 1048576.0 / time.TotalSeconds).ToString("F1", CultureInfo.InvariantCulture);
}
