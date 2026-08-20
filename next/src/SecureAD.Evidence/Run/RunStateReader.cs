using SecureAD.Kernel;

namespace SecureAD.Evidence.Run;

/// <summary>
/// A run's state, and the sentence explaining it where there is one to explain.
/// </summary>
/// <param name="State">What became of the run.</param>
/// <param name="Detail">
/// Why, in words an operator can act on, or null where the state speaks for itself. A sealed run
/// needs no explanation; a failed or damaged one does.
/// </param>
public sealed record RunStateObservation(RunState State, string? Detail);

/// <summary>
/// Decides a run's state by looking at its bundle directory.
/// </summary>
/// <remarks>
/// <para>
/// The order of the checks is the decision, not an implementation choice, and it is recorded in
/// <c>docs/decisions/0028-one-run-state-vocabulary.md</c>. A finished bundle outranks everything,
/// so a stale outcome file left beside good evidence cannot make a successful run look like a
/// failed one. A recorded outcome outranks the liveness test, because a run that said why it
/// stopped has told us more than the file system can.
/// </para>
/// <para>
/// <b>Liveness is asked of the file system.</b> If nothing can take the partial evidence file
/// exclusively, something is writing it and a run is alive. The operating system releases handles
/// when a process dies, whatever killed it, so this needs no cleanup - unlike a heartbeat or a
/// recorded process identifier, which need tidying up at exactly the moment nothing is running to
/// tidy them. The check opens and closes; it never writes, because opening a bundle must not alter
/// it.
/// </para>
/// <para>
/// <b>A directory holding none of these files is not a run</b>, and is refused rather than given a
/// state. The predecessor caught every exception and returned one sentinel, so a corrupt database
/// and a directory that was never a run both reported <i>required run metadata is missing</i> -
/// which is a claim about a run that does not exist.
/// </para>
/// </remarks>
public static class RunStateReader
{
    /// <summary>
    /// Observes the run in <paramref name="bundleDirectory"/>.
    /// </summary>
    /// <param name="bundleDirectory">A directory inside the run library.</param>
    /// <returns>
    /// The state and its explanation, or a failure when the directory is not a run at all.
    /// </returns>
    public static Result<RunStateObservation> Observe(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        if (!Directory.Exists(bundleDirectory))
        {
            return NotARun(bundleDirectory, "There is no such directory.");
        }

        if (File.Exists(BundleLayout.EvidencePath(bundleDirectory)))
        {
            var seal = BundleSealing.Verify(bundleDirectory);

            return seal.MayBeOpened
                ? Observed(RunState.Sealed, detail: null)
                : Observed(RunState.Damaged, seal.Detail);
        }

        var outcome = RunOutcomeFile.Read(bundleDirectory);
        if (!outcome.IsSuccess)
        {
            return Observed(RunState.Damaged, outcome.Error.Description);
        }

        if (outcome.Value is { } ended)
        {
            return Observed(
                ended.Outcome == RunOutcome.Failed ? RunState.Failed : RunState.Cancelled,
                ended.Detail);
        }

        var partial = BundleLayout.PartialPath(bundleDirectory);
        if (!File.Exists(partial))
        {
            return NotARun(
                bundleDirectory,
                "It holds neither finished evidence nor a run in progress.");
        }

        return IsBeingWritten(partial)
            ? Observed(RunState.InProgress, detail: null)
            : Observed(
                RunState.Interrupted,
                "The run stopped without recording why, and nothing is writing to it.");
    }

    /// <summary>
    /// Whether something still holds <paramref name="partialPath"/>. Opens and closes; never
    /// writes.
    /// </summary>
    private static bool IsBeingWritten(string partialPath)
    {
        try
        {
            using var _ = new FileStream(
                partialPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None);

            return false;
        }
        catch (IOException)
        {
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            // The file cannot be opened for a reason that is not a writer holding it. Reporting a
            // run as in progress on this evidence would be a guess, and the honest reading of "we
            // could not look" is not "somebody is working".
            return false;
        }
    }

    private static Result<RunStateObservation> Observed(RunState state, string? detail) =>
        new RunStateObservation(state, detail);

    private static Result<RunStateObservation> NotARun(string directory, string why) =>
        AuditError.Create(
            ErrorCategory.Evidence,
            "NotARunDirectory",
            ErrorSeverity.Failed,
            $"This is not a run. {why}",
            directory);
}
