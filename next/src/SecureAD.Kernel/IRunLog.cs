namespace SecureAD.Kernel;

/// <summary>
/// Where a run says what it is doing, and what went wrong while it did.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists because the product had no logging at all, and a real defect cost a day for
/// it.</b> Stage 2a stopped on a multi-domain forest with
/// <c>UNIQUE constraint failed: sid_identity.sid_id</c> and nothing else - no run, no phase, and no
/// hint which of four thousand principals it was about. Every fact needed to explain it existed at
/// the moment it threw and none of it was written down. See
/// <c>docs/decisions/0088-a-run-writes-a-log.md</c>.
/// </para>
/// <para>
/// <b>It takes notes and errors, and nothing grades a note.</b> <see cref="Note"/> is a fact about
/// what the run is doing; <see cref="Record"/> is an <see cref="AuditError"/> that already knows how
/// much it matters. There is deliberately no way to log an informational failure, because there is
/// no such thing - and no second severity vocabulary beside <see cref="ErrorSeverity"/>, which
/// already answers that question.
/// </para>
/// <para>
/// <b>It is a required collaborator wherever it is taken, never an optional one.</b> The
/// predecessor's performance log was optional and therefore unused, which is the defect gate 1 is
/// named for. A caller with nowhere to write passes <see cref="RunLog.Discarded"/>, whose name says
/// somebody chose it.
/// </para>
/// </remarks>
public interface IRunLog
{
    /// <summary>
    /// Writes a fact about what the run is doing.
    /// </summary>
    /// <param name="phase">The phase this happened in, as that phase names itself.</param>
    /// <param name="message">What happened, in a sentence an operator can read.</param>
    /// <param name="detail">
    /// Anything worth naming - a count, a domain, a distinguished name. Empty where there is
    /// nothing to add.
    /// </param>
    void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail);

    /// <summary>
    /// Writes a failure, at the severity the failure itself carries.
    /// </summary>
    /// <param name="phase">The phase this happened in.</param>
    /// <param name="error">The failure, which already knows its own code and severity.</param>
    /// <param name="detail">Anything worth naming beyond what the error carries.</param>
    void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail);
}

/// <summary>
/// One named value on a log line: <c>sid=S-1-5-32-544</c>.
/// </summary>
/// <remarks>
/// <b>A pair rather than a formatted string, so the formatting rule has one owner.</b> A caller that
/// built its own <c>"sid=" + sid</c> would be deciding how a value containing a space or an equals
/// sign is written, and a distinguished name contains both. The log writes it, once, the same way
/// every time.
/// </remarks>
/// <param name="Name">What the value is. Lower case, no spaces, stable across runs.</param>
/// <param name="Value">The value, however it is spelled. Quoted by the writer when it needs to be.</param>
public readonly record struct RunLogDetail(string Name, string Value);

/// <summary>
/// The logs a caller can choose when it has nowhere to write.
/// </summary>
public static class RunLog
{
    /// <summary>
    /// A log that keeps nothing.
    /// </summary>
    /// <remarks>
    /// <b>For a test, or a caller that genuinely has no run to write beside.</b> Named and passed
    /// explicitly rather than reachable by leaving an argument out: the difference between this and
    /// a defaulted null is that somebody typed it, which is the whole of what gate 1 asks for.
    /// </remarks>
    public static IRunLog Discarded { get; } = new NothingKept();

    private sealed class NothingKept : IRunLog
    {
        public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail)
        {
        }

        public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail)
        {
        }
    }
}
