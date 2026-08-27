namespace SecureAD.Derivation;

/// <summary>
/// What became of one derivation run.
/// </summary>
/// <remarks>
/// The same four states a judging has, and for the same reasons. A reader of a named
/// <c>derivation.db</c> should never see <see cref="Running"/> or <see cref="Failed"/>: deriving
/// writes to a partial file and renames only once every phase has finished, so those two live in a
/// file no reader asks for.
/// </remarks>
public enum DerivationRunState
{
    /// <summary>Deriving started and has not finished. Found in a partial file only.</summary>
    Running,

    /// <summary>Every phase succeeded.</summary>
    Completed,

    /// <summary>
    /// Deriving finished and at least one phase did not, so some derived facts are absent or
    /// partial.
    /// </summary>
    /// <remarks>
    /// <b>This is not a lesser kind of success.</b> A rule resting on a closure produced by a
    /// degraded run has not established a clean result, and the missing input has to travel with
    /// the answer rather than being flattened into an empty set.
    /// </remarks>
    CompletedDegraded,

    /// <summary>
    /// The coordinator itself failed, so the run has no answer to offer at all.
    /// </summary>
    Failed,
}

/// <summary>
/// What became of one phase within a derivation.
/// </summary>
public enum DerivationPhaseOutcome
{
    /// <summary>The phase ran and derived everything it set out to.</summary>
    Succeeded,

    /// <summary>
    /// The phase ran but could not finish some part of its work, most often because a budget was
    /// reached or the capture did not cover something it needed.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="Failed"/> because the facts it did derive are sound and usable.
    /// What is not sound is treating the result as complete.
    /// </remarks>
    Degraded,

    /// <summary>The phase threw, and produced nothing that can be trusted.</summary>
    Failed,

    /// <summary>
    /// The phase never started, because something it needed had already failed.
    /// </summary>
    /// <remarks>
    /// <b>A row is written for it rather than the row being absent</b>, for the reason the judgement
    /// store writes one for a rule that did not run: a phase that never ran is a fact about the
    /// derivation, and absence cannot state it. Without this, a store holding no closure because the
    /// pass failed and a store holding none because the forest has no nesting look identical.
    /// </remarks>
    DidNotRun,
}
