using SecureAD.Kernel;

namespace SecureAD.Evidence.Run;

/// <summary>
/// Turns a <see cref="RunState"/> into the text stored in a bundle, and back.
/// </summary>
/// <remarks>
/// <para>
/// The names are here rather than at each call site because of what happened when they were not.
/// In the predecessor the strings were private to the writer while four readers matched bare
/// literals, so renaming one changed what was written without changing what was read - and the
/// library funnelled the now-unrecognised value into its in-progress state. A sealed run degraded
/// silently and vanished from every picker that filtered on sealed. Nothing failed; the runs
/// simply stopped being there.
/// </para>
/// <para>
/// <b>An unrecognised name is a failure, never a default.</b> The plausible cause is a bundle
/// written by a later version of this product, and the honest answer is that this version cannot
/// read it. Choosing a state instead means guessing, and the guess is invisible.
/// </para>
/// <para>
/// This is the run vocabulary only. Phase, checkpoint and coverage states are separate
/// vocabularies that will share words with this one, and they are deliberately not collected here:
/// a type holding all of them invites a reader of one column to match a constant belonging to
/// another.
/// </para>
/// </remarks>
public static class RunStateNames
{
    private static readonly Dictionary<RunState, string> Names = new()
        {
            [RunState.InProgress] = "InProgress",
            [RunState.Sealed] = "Sealed",
            [RunState.Failed] = "Failed",
            [RunState.Cancelled] = "Cancelled",
            [RunState.Interrupted] = "Interrupted",
            [RunState.Damaged] = "Damaged",
        };

    /// <summary>The text stored in a bundle for <paramref name="state"/>.</summary>
    /// <param name="state">The state to write down.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// A state was added to <see cref="RunState"/> without a name to store it under. A defect in
    /// this product rather than an outcome of a run, so it throws.
    /// </exception>
    public static string Persist(RunState state) =>
        Names.TryGetValue(state, out var name)
            ? name
            : throw new ArgumentOutOfRangeException(
                nameof(state),
                state,
                "This run state has no persisted name, so a run in it could not be written down.");

    /// <summary>
    /// Reads a stored state back.
    /// </summary>
    /// <param name="persisted">The text found in the bundle.</param>
    /// <returns>
    /// The state, or a failure naming what was found. Never a default: see the remarks on this
    /// type for what defaulting cost the predecessor.
    /// </returns>
    public static Result<RunState> Read(string? persisted)
    {
        if (string.IsNullOrWhiteSpace(persisted))
        {
            return AuditError.Create(
                ErrorCategory.Evidence,
                "RunStateMissing",
                ErrorSeverity.Failed,
                "This bundle records no run state, so there is no way to tell whether its run "
                + "finished.",
                context: null);
        }

        foreach (var (state, name) in Names)
        {
            if (string.Equals(name, persisted, StringComparison.Ordinal))
            {
                return state;
            }
        }

        return AuditError.Create(
            ErrorCategory.Evidence,
            "RunStateUnrecognised",
            ErrorSeverity.Failed,
            $"This bundle records its run state as '{persisted}', which this version of the "
            + "product does not recognise. It was most likely written by a later version.",
            persisted);
    }
}
