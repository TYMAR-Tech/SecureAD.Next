using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.Services;

/// <summary>
/// What a judging produced, in the shell's own words.
/// </summary>
/// <remarks>
/// <b>Findings counted by severity rather than handed over.</b> A judging of a large forest produces
/// more findings than a completion screen can show, and the screen that follows a run reports how
/// many of each kind there were. The findings themselves are read from the store by the screen that
/// lists them, which is the only thing that should be holding them.
/// </remarks>
/// <param name="State">What became of the judging.</param>
/// <param name="ObjectsJudged">Unique captured objects streamed through judging, not the sum of per-rule evaluations.</param>
/// <param name="Findings">How many findings there were, by severity.</param>
/// <param name="CouldNotDecide">
/// What stopped a rule reaching a verdict, and on how many objects, worst first.
/// <para>
/// <b>Carried rather than counted into one number.</b> "At least one rule could not reach a
/// verdict" tells an operator that something is missing and nothing about what to do; the same
/// screen saying <i>Microsoft's documentation disagrees about this group</i> tells him to stop
/// looking at his forest. The distinction only became expressible when rules gained a vocabulary
/// for an unresolved derived fact, per <c>docs/decisions/0091</c>.
/// </para>
/// </param>
internal sealed record JudgingOutcome(
    JudgementRunState State,
    long ObjectsJudged,
    IReadOnlyDictionary<Severity, int> Findings,
    IReadOnlyList<UnresolvedCount> CouldNotDecide)
{
    /// <summary>
    /// What the requester scan covered, read from the store, or null where no requester product was
    /// written.
    /// </summary>
    /// <remarks>
    /// <b>Carried so the screen cannot mistake "not asked" for "nothing found".</b> Requester
    /// answers are separate from findings and from rule completion: a judging can finish every rule
    /// while the requester scan never ran, and an operator told only that judging completed would
    /// read that as a forest where nobody can add themselves to anything.
    /// </remarks>
    public SelfMembershipSummary? Requesters { get; init; }
}

/// <summary>One thing that stopped a rule deciding, and how far it reached.</summary>
/// <param name="Reason">What was missing or undecided, in the operator's words.</param>
/// <param name="ObjectsAffected">How many objects it left unjudged.</param>
internal sealed record UnresolvedCount(string Reason, int ObjectsAffected);

/// <summary>
/// Judging a sealed bundle, from a window.
/// </summary>
/// <remarks>
/// <para>
/// <b>A seam for the same reason <see cref="ICaptureLauncher"/> is one.</b> The audit screen can be
/// tested for what it asks to be judged, and for what it does with progress and refusals, without a
/// bundle on disk or hours of judging.
/// </para>
/// <para>
/// <b>Judging follows a capture without being asked for.</b> The owner's shape, 2026-08-26: it runs
/// automatically and the operator is offered the results at the end. That is why this has no
/// <c>CanJudge</c> and no confirmation - the decision to judge was the decision to audit.
/// </para>
/// </remarks>
internal interface IJudgingLauncher
{
    /// <summary>
    /// Judges the bundle in <paramref name="bundleDirectory"/> and writes the judgement beside it.
    /// </summary>
    /// <param name="bundleDirectory">The sealed bundle to judge.</param>
    /// <param name="progress">
    /// Told how many objects have been judged so far. Required rather than optional, per gate 1 and
    /// for the reason it records: the predecessor's progress reporting went unused by being
    /// something a caller could forget.
    /// </param>
    /// <param name="cancellationToken">Stops the judging, leaving any earlier judgement intact.</param>
    /// <returns>What the judging produced, or why it could not be done at all.</returns>
    Task<Result<JudgingOutcome>> RunAsync(
        string bundleDirectory,
        IProgress<JudgingRun.JudgingProgress> progress,
        CancellationToken cancellationToken);
}
