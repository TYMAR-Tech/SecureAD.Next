namespace SecureAD.Judgement;

/// <summary>
/// What became of a judging run as a whole.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="Failed"/> and an interrupted <see cref="Running"/> are not the same thing</b>, and
/// a store that could not tell them apart would present a coordinator that never started as a
/// judging that produced no findings. The first is a defect in this product; the second is a claim
/// about a customer's directory.
/// </para>
/// <para>
/// <b>A reader of a finished store should never see <see cref="Running"/> or <see cref="Failed"/>.</b>
/// Judging writes to unique, unselected generation files and selects their sealed root only after
/// every scheduled rule has finished, so neither state is offered by a completed root.
/// </para>
/// </remarks>
public enum JudgementRunState
{
    /// <summary>
    /// One or more scheduled rules has no terminal execution record, which includes the process
    /// having been killed mid-run.
    /// </summary>
    Running,

    /// <summary>Every scheduled rule reached a terminal, non-degraded result.</summary>
    Completed,

    /// <summary>
    /// Every scheduled rule reached a terminal result, but one or more was
    /// <see cref="RuleExecutionOutcome.Indeterminate"/>, <see cref="RuleExecutionOutcome.Error"/>
    /// or <see cref="RuleExecutionOutcome.DidNotRun"/>.
    /// </summary>
    /// <remarks>
    /// <b>This is not a lesser kind of success.</b> A judging where a rule could not read its
    /// declared inputs has not established that the forest is clean of what that rule looks for,
    /// and anything presenting this beside <see cref="Completed"/> without saying which is which
    /// has made the claim the product exists to refuse.
    /// </remarks>
    CompletedDegraded,

    /// <summary>The coordinator itself failed - scheduling, sealing or recording the result.</summary>
    Failed,
}

/// <summary>
/// What became of one rule within a judging run.
/// </summary>
/// <remarks>
/// <b>Three of the four are not failures of the product.</b> A rule that could not read what it
/// declared, or that was never scheduled, has said nothing about the forest - and saying nothing is
/// a legitimate outcome that must not be rendered as having found nothing.
/// </remarks>
public enum RuleExecutionOutcome
{
    /// <summary>The rule ran and reached a verdict on every object it was offered.</summary>
    Succeeded,

    /// <summary>
    /// The rule ran, and on one or more objects could not reach a verdict because a declared input
    /// was not captured.
    /// </summary>
    /// <remarks>
    /// A rule that executed but could not read its required inputs is not a successful clean
    /// evaluation. Which attributes were missing, and on how many objects, is recorded beside this
    /// so the answer is actionable rather than merely honest.
    /// </remarks>
    Indeterminate,

    /// <summary>The rule threw. Other rules continue; this one has no verdict.</summary>
    Error,

    /// <summary>
    /// The rule was scheduled and never executed.
    /// </summary>
    /// <remarks>
    /// Recorded rather than left absent, because an absent row cannot distinguish a rule that was
    /// never scheduled from one that was scheduled and skipped.
    /// </remarks>
    DidNotRun,
}
