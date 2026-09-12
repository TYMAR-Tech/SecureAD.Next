using SecureAD.Kernel;

namespace SecureAD.Next.Tests.Capture;

/// <summary>
/// A run log that keeps what it was given, so a test can read back what a run said about itself.
/// </summary>
/// <remarks>
/// <para>
/// <b>It exists because a log nobody reads back is a log nobody notices has stopped being
/// written.</b> The lines capture writes are what an operator will have when a multi-hour run
/// against a nine-domain forest stops at hour two, and there is no second chance to collect them.
/// Asserting on them is the only thing that keeps them there.
/// </para>
/// <para>
/// <b>It keeps the detail as pairs rather than as a formatted line</b>, so a test asks whether a
/// fact was recorded rather than whether it was spelled a particular way. How a name and a value
/// become text belongs to <c>RunLogFile</c> and is checked there.
/// </para>
/// </remarks>
internal sealed class RecordingRunLog : IRunLog
{
    /// <summary>Every note, in the order it was written.</summary>
    public List<(string Phase, string Message, IReadOnlyList<RunLogDetail> Detail)> Notes { get; } =
        [];

    /// <summary>Every failure, in the order it was written.</summary>
    public List<(string Phase, AuditError Error, IReadOnlyList<RunLogDetail> Detail)> Errors { get; } =
        [];

    public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail) =>
        Notes.Add((phase, message, detail));

    public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail) =>
        Errors.Add((phase, error, detail));

    /// <summary>
    /// The notes whose message is <paramref name="message"/>, in order.
    /// </summary>
    public IReadOnlyList<IReadOnlyList<RunLogDetail>> Saying(string message) =>
        [.. Notes.Where(n => n.Message == message).Select(n => n.Detail)];

    /// <summary>
    /// The value recorded under <paramref name="name"/>, or null where nothing was.
    /// </summary>
    /// <remarks>
    /// Null rather than an empty string, because a detail that was never written and one written
    /// empty are different failures - the first is a line that lost a fact, the second is a fact
    /// the run could not establish.
    /// </remarks>
    public static string? Value(IReadOnlyList<RunLogDetail> detail, string name)
    {
        ArgumentNullException.ThrowIfNull(detail);

        foreach (var item in detail)
        {
            if (item.Name == name)
                return item.Value;
        }

        return null;
    }
}
