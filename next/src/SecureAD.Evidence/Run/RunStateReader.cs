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
/// <param name="RecordedUtc">
/// The moment the run recorded for itself, or null where it recorded none. A sealed run says when
/// it completed and a run that ended badly says when it stopped; a run that was interrupted, or one
/// still being written, never got to say anything. Null is not a missing value to be filled in with
/// something plausible - it is the statement that this run did not record when it happened.
/// </param>
public sealed record RunStateObservation(
    RunState State, string? Detail, DateTimeOffset? RecordedUtc);

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
/// <para>
/// <b>Nothing here hashes evidence.</b> This is asked of every run each time the Home list is
/// drawn, so a check that reads whole files makes the library cost proportional to the evidence in
/// it - which with one production bundle present was minutes, on every navigation back to Home.
/// <see cref="RunState.Sealed"/> therefore means the run finished and left evidence and a seal, not
/// that the seal was checked; <see cref="BundleReader.Open(string, CancellationToken)"/> checks it
/// when the run is opened, per <c>docs/decisions/0020-the-seal-detects-corruption-not-tampering.md</c>,
/// which requires exactly one verification held for the lifetime of the opened file.
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

        if (File.Exists(BundleLayout.EvidencePath(bundleDirectory))
            && !File.Exists(BundleLayout.CaptureManifestPath(bundleDirectory) + ".partial"))
        {
            var root = AnalysisStoreLifecycle.ResolveCapture(bundleDirectory);
            if (!root.IsSuccess) return Observed(RunState.Damaged, root.Error.Description, recordedUtc: null);
            // The seal is READ but not CHECKED, and the difference is the whole of this change.
            // Reading it parses a few hundred bytes and catches the two faults that need no
            // evidence at all: no seal, or a seal this build cannot understand. Checking it means
            // hashing the whole evidence file - 1,266 ms per 1.73 GB, measured - and this runs once
            // per run every time the Home list is drawn, which is nine occasions including every
            // navigation back to Home. docs/decisions/0020 already requires the verdict to be held
            // for the lifetime of the opened file and not repeated per screen, so hashing here was
            // a defect against that decision rather than a stricter reading of it. Whether the
            // bytes still match their seal is answered in BundleReader.Open, which is where the
            // evidence is about to be believed.
            var sealPath = BundleLayout.SealPath(bundleDirectory);

            if (!File.Exists(sealPath))
            {
                return Observed(
                    RunState.Damaged,
                    "This run's evidence has no seal beside it, so it cannot be checked when it "
                    + "is opened. Restore it or discard it - running again will not repair it.",
                    recordedUtc: null);
            }

            // A malformed seal must not degrade to "nobody sealed this", per 0019. The two have
            // different causes and the detail has to say which.
            if (BundleSealing.ReadSeal(sealPath) is null)
            {
                return Observed(
                    RunState.Damaged,
                    "This run's seal cannot be read, so its evidence cannot be checked when it is "
                    + "opened. Restore it or discard it - running again will not repair it.",
                    recordedUtc: null);
            }

            return Observed(
                RunState.Sealed,
                detail: null,
                RunCompletionReader.CompletedUtc(bundleDirectory));
        }

        var outcome = RunOutcomeFile.Read(bundleDirectory);
        if (!outcome.IsSuccess)
        {
            return Observed(RunState.Damaged, outcome.Error.Description, recordedUtc: null);
        }

        if (outcome.Value is { } ended)
        {
            return Observed(
                ended.Outcome == RunOutcome.Failed ? RunState.Failed : RunState.Cancelled,
                ended.Detail,
                ended.EndedUtc);
        }

        var partial = BundleLayout.PartialPath(bundleDirectory);
        if (!File.Exists(partial) && File.Exists(BundleLayout.CaptureManifestPath(bundleDirectory) + ".partial"))
            partial = BundleLayout.EvidencePath(bundleDirectory);
        if (!File.Exists(partial))
        {
            return NotARun(
                bundleDirectory,
                "It holds neither finished evidence nor a run in progress.");
        }

        return IsBeingWritten(partial)
            ? Observed(RunState.InProgress, detail: null, recordedUtc: null)
            : Observed(
                RunState.Interrupted,
                "The run stopped without recording why, and nothing is writing to it.",
                recordedUtc: null);
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

    private static Result<RunStateObservation> Observed(
        RunState state, string? detail, DateTimeOffset? recordedUtc) =>
        new RunStateObservation(state, detail, recordedUtc);

    private static Result<RunStateObservation> NotARun(string directory, string why) =>
        AuditError.Create(
            ErrorCategory.Evidence,
            "NotARunDirectory",
            ErrorSeverity.Failed,
            $"This is not a run. {why}",
            directory);
}
