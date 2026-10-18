using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using SecureAD.Kernel;

namespace SecureAD.Evidence;

/// <summary>
/// The run log, written to <see cref="BundleLayout.RunLogFileName"/> beside the evidence.
/// </summary>
/// <remarks>
/// <para>
/// <b>Text, in columns, because the reader is a person.</b> A timestamp and a level in fixed
/// positions so an eye can run down them, the error code alone on its line as the thing to grep
/// for, and detail as <c>name=value</c> underneath. Per
/// <c>docs/decisions/0088-a-run-writes-a-log.md</c>, which records why this is not JSON: nothing
/// reads these programmatically, and a record needing a tool to be legible fails the standard
/// <c>0029</c> sets for a run that ended badly.
/// </para>
/// <para>
/// <b>Every line is flushed as it is written.</b> The run this logs may take hours and may be
/// killed part way through, and a log that buffered would lose exactly the lines explaining why. The
/// cost is a write per line.
/// </para>
/// <para>
/// <b>The file is shared for reading while it is open.</b> An operator watching a long capture can
/// tail it, which is most of the point of writing it as it goes rather than at the end.
/// </para>
/// <para>
/// <b>Opening appends and announces itself.</b> One bundle's log is written by the capture, then the
/// derivation, then the judging, and a bundle may be derived again later - so each session opens
/// with a banner naming itself and the time, and a reader can tell one from the next.
/// </para>
/// <para>
/// <b>Several logs can be open on one run's file at once, and every write goes to the file's current
/// end.</b> A saved run's browsing keeps one log open per click until the click's result is on screen,
/// and the pass that checks the run's files keeps another open while it works, so they overlap. Each
/// log used to remember its own end of the file, and what it wrote next landed on top of another
/// log's lines: a lab run lost three of its ten per-file verification records and cut a click's lines
/// in two. The logs open on one file in this process now share one lock and seek to the end under it,
/// so a record - a headline and its description - is written whole and in order. Two processes
/// writing one run's log at once are not covered; the stages that write it run one after another.
/// </para>
/// </remarks>
public sealed class RunLogFile : IRunLog, IDisposable
{
    /// <summary>How wide the level column is: <c>ERROR</c> is the longest.</summary>
    private const int LevelWidth = 5;

    /// <summary>
    /// How wide the phase column is. A longer phase name is not truncated - it pushes the message
    /// right on that line only, because a shortened phase name is a fact lost to tidiness.
    /// </summary>
    private const int PhaseWidth = 22;

    /// <summary>Where a continued line starts, so wrapped detail lines up under the message.</summary>
    private const int Continuation = 20 + 2 + LevelWidth + 2 + PhaseWidth + 2;

    /// <summary>The lock every log open on one file shares, found by the file's full path.</summary>
    private static readonly ConcurrentDictionary<string, Lock> AppendGates = new(StringComparer.OrdinalIgnoreCase);

    private readonly FileStream _stream;
    private readonly StreamWriter _writer;
    private readonly TimeProvider _time;
    private readonly Lock _gate;

    private RunLogFile(FileStream stream, StreamWriter writer, Lock gate, TimeProvider time)
    {
        _stream = stream;
        _writer = writer;
        _gate = gate;
        _time = time;
    }

    /// <summary>
    /// Opens the log in <paramref name="bundleDirectory"/>, appending to whatever is there.
    /// </summary>
    /// <param name="bundleDirectory">The run's directory. Created if it is not there yet.</param>
    /// <param name="session">
    /// What this stretch of the log is: the words a reader sees in the banner. The phase names on
    /// each line are finer than this - <c>capture</c>, <c>deriving</c>, <c>judging</c>.
    /// </param>
    /// <param name="time">Where the timestamps come from.</param>
    /// <returns>The log, or why it could not be opened.</returns>
    public static Result<RunLogFile> Open(
        string bundleDirectory,
        string session,
        TimeProvider time)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(session);
        ArgumentNullException.ThrowIfNull(time);

        try
        {
            Directory.CreateDirectory(bundleDirectory);

            var path = Path.GetFullPath(BundleLayout.RunLogPath(bundleDirectory));
            var stream = new FileStream(
                path,
                FileMode.Append,
                FileAccess.Write,
                FileShare.ReadWrite);

            var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
            {
                AutoFlush = true,
            };

            var log = new RunLogFile(stream, writer, AppendGates.GetOrAdd(path, static _ => new Lock()), time);
            log.Banner(session);
            return log;
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
        {
            // A log that cannot be opened must not stop the run it was going to describe. The
            // caller decides what to do; every one of them carries on with RunLog.Discarded,
            // because losing the account of a capture is not a reason to lose the capture.
            return Result<RunLogFile>.Failure(AuditError.Create(
                ErrorCategory.Evidence,
                "RunLogUnwritable",
                ErrorSeverity.Degraded,
                $"The run's log could not be opened in '{bundleDirectory}': {failure.Message} The "
                + "run itself is unaffected, but it will not leave an account of what it did.",
                bundleDirectory));
        }
    }

    /// <inheritdoc/>
    public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(phase);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        ArgumentNullException.ThrowIfNull(detail);

        Write("INFO", phase, message, further: null, detail);
    }

    /// <inheritdoc/>
    public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(phase);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(detail);

        // The level comes from the error rather than from the caller. An error already knows how
        // much it matters, and a caller free to choose could log a failure as a note.
        var level = error.Severity == ErrorSeverity.Failed ? "ERROR" : "WARN";

        // The code goes on the headline and the description underneath: the code is the stable
        // thing to search for, and burying it behind a sentence makes it unfindable.
        Write(level, phase, error.Code, further: error.Description, detail);
    }

    /// <summary>Closes the file, leaving everything written where it is.</summary>
    public void Dispose() => _writer.Dispose();

    private void Banner(string session)
    {
        lock (_gate)
        {
            AtEndOfFile();
            _writer.WriteLine();
            _writer.WriteLine($"==== {Stamp()}  {session} ====");
        }
    }

    private void Write(
        string level,
        string phase,
        string headline,
        string? further,
        IReadOnlyList<RunLogDetail> detail)
    {
        var line = new StringBuilder()
            .Append(Stamp())
            .Append("  ")
            .Append(level.PadRight(LevelWidth))
            .Append("  ")
            .Append(phase.PadRight(PhaseWidth))
            .Append("  ")
            .Append(headline);

        // THE DETAIL STAYS ON THE HEADLINE, and that is the whole reason this format was chosen
        // over one a machine reads. A line found by searching for sid=S-1-5-32-544 has to say when
        // it happened and which phase it was, or the search returns an orphan and the operator has
        // to go hunting upwards for the context. The description is the one thing pushed onto its
        // own line: it is prose, it is long, and nobody greps for it.
        if (detail.Count > 0)
            line.Append(' ').Append(Detail(detail));

        lock (_gate)
        {
            AtEndOfFile();
            _writer.WriteLine(line);

            if (!string.IsNullOrWhiteSpace(further))
                _writer.WriteLine(new string(' ', Continuation) + further);
        }
    }

    /// <summary>
    /// Moves to where the file ends now, which another log open on this run may have moved since this one
    /// last wrote. Called under the shared lock, so nothing is written between the move and the write.
    /// </summary>
    private void AtEndOfFile() => _stream.Seek(0, SeekOrigin.End);

    private string Stamp() =>
        _time.GetUtcNow().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>
    /// The detail pairs, as <c>name=value</c> separated by spaces.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The quoting rule lives here and nowhere else.</b> A distinguished name carries both spaces
    /// and equals signs, so an unquoted <c>object=CN=Some Group,OU=X</c> cannot be read back
    /// unambiguously - and the values this log names are mostly distinguished names.
    /// </para>
    /// <para>
    /// <b>A backslash is written as it stands rather than doubled, and that is a deliberate
    /// departure from logfmt.</b> The first real run wrote
    /// <c>bundle="C:\\Users\\ba.admin\\Downloads\\SecureAD"</c>, and this log will be full of
    /// Windows paths. Doubling every separator is precisely the decoding <c>0088</c> chose text over
    /// JSON to avoid. The cost is one theoretical ambiguity - a value ending in a backslash, which
    /// would look like an escaped quote - and no distinguished name, SID, domain or bundle path
    /// ends in one.
    /// </para>
    /// </remarks>
    private static string Detail(IReadOnlyList<RunLogDetail> detail) =>
        string.Join(' ', detail.Select(d => d.Name + "=" + Quoted(d.Value)));

    private static string Quoted(string value)
    {
        if (value.Length > 0 && !value.Any(NeedsQuoting))
            return value;

        return "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
    }

    private static bool NeedsQuoting(char c) =>
        char.IsWhiteSpace(c) || c is '=' or '"';
}
