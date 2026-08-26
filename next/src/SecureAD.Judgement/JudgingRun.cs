using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

/// <summary>
/// Judging a sealed bundle: read every object once, offer it to every rule, and write what they
/// concluded beside the evidence.
/// </summary>
/// <remarks>
/// <para>
/// <b>One pass over the bundle, not one per rule.</b> The evidence is read sequentially and each
/// object is offered to every scheduled rule while it is in hand. Judging forty rules therefore
/// costs the same read as judging one, and adding a rule costs comparisons rather than another walk
/// of the forest.
/// </para>
/// <para>
/// <b>A rule that throws loses only itself.</b> It is recorded as
/// <see cref="RuleExecutionOutcome.Error"/>, offered no further objects, and the rules beside it
/// carry on. Its findings are discarded, because a rule that failed part way through has no verdict
/// and its partial output would read as a complete one.
/// </para>
/// <para>
/// <b>Nothing here decides what a run means.</b> The outcome of each rule follows from what it did,
/// and the state of the run follows from those outcomes, in
/// <see cref="JudgementWriter.Complete"/>. A coordinator that could name the state would be able to
/// call a judging complete while a rule had read nothing.
/// </para>
/// </remarks>
public static class JudgingRun
{
    /// <summary>
    /// Judges the bundle in <paramref name="bundleDirectory"/> and writes the judgement beside it.
    /// </summary>
    /// <remarks>
    /// Replaces any judgement already there, and only at the end: a judging that fails part way
    /// leaves the previous answer intact rather than replacing it with a partial one.
    /// </remarks>
    /// <param name="bundleDirectory">The bundle to judge.</param>
    /// <param name="rules">The rules to run. Each is recorded whatever becomes of it.</param>
    /// <param name="startedUtc">When judging started.</param>
    /// <param name="evaluationAsOf">
    /// The reference time temporal rules are evaluated against, recorded so that the same sealed
    /// evidence gives the same answer next year.
    /// </param>
    /// <returns>What became of the run, or why it could not be judged at all.</returns>
    public static Result<JudgementRunState> Judge(
        string bundleDirectory,
        IReadOnlyList<IRule> rules,
        DateTimeOffset startedUtc,
        DateTimeOffset evaluationAsOf)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(rules);

        var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(bundleDirectory));

        if (seal is null || string.IsNullOrWhiteSpace(seal.Hash))
        {
            return Failure(
                "EvidenceSealUnreadable",
                $"There is no readable evidence seal in '{bundleDirectory}', so a judgement written "
                + "here could not say which capture it was made against. A judgement that cannot "
                + "name its evidence is not one this product will write.",
                bundleDirectory);
        }

        var opened = BundleReader.Open(bundleDirectory);
        if (!opened.IsSuccess)
            return Result<JudgementRunState>.Failure(opened.Error!);

        using var bundle = opened.Value!;
        using var writer = JudgementWriter.Create(
            bundleDirectory, seal.Hash, startedUtc, evaluationAsOf);

        var tallies = rules.Select(r => new Tally(r)).ToList();

        foreach (var subject in bundle.StreamObjects().Objects)
        {
            foreach (var tally in tallies)
                tally.Offer(subject);
        }

        foreach (var tally in tallies)
            writer.Write(tally.ToExecution());

        writer.Complete(DateTimeOffset.UtcNow);

        return tallies.All(t => t.Outcome == RuleExecutionOutcome.Succeeded)
            ? JudgementRunState.Completed
            : JudgementRunState.CompletedDegraded;
    }

    private static Result<JudgementRunState> Failure(
        string reason, string description, string context) =>
        Result<JudgementRunState>.Failure(
            AuditError.Create(
                ErrorCategory.Evidence, reason, ErrorSeverity.Failed, description, context));

    /// <summary>
    /// What one rule has made of the objects offered to it so far.
    /// </summary>
    /// <remarks>
    /// <b>Counted as it goes rather than derived at the end.</b> The objects are streamed and gone,
    /// so anything not counted while an object is in hand cannot be recovered without reading the
    /// bundle again.
    /// </remarks>
    private sealed class Tally(IRule rule)
    {
        private readonly List<Finding> _findings = [];
        private readonly Dictionary<string, int> _missing = new(StringComparer.OrdinalIgnoreCase);

        private int _judged;
        private int _notJudged;
        private string? _error;

        public RuleExecutionOutcome Outcome =>
            _error is not null ? RuleExecutionOutcome.Error
            : _notJudged > 0 ? RuleExecutionOutcome.Indeterminate
            : RuleExecutionOutcome.Succeeded;

        /// <summary>
        /// Offers one object to the rule, unless it has already thrown.
        /// </summary>
        /// <param name="subject">The object to judge.</param>
        public void Offer(ObjectAttributes subject)
        {
            if (_error is not null)
                return;

            RuleVerdict verdict;

            try
            {
                verdict = rule.Judge(subject);
            }
            catch (Exception error) when (error is not OutOfMemoryException
                                              and not StackOverflowException)
            {
                // A rule is code, and code has defects. One that throws is a fact about this
                // product rather than about the forest, and it must not take the rules beside it
                // down - so it is recorded, its partial findings are dropped, and it is offered
                // nothing further.
                _error = error.ToString();
                _findings.Clear();
                _judged = 0;
                _notJudged = 0;
                _missing.Clear();
                return;
            }

            if (verdict.IsComplete)
            {
                _judged++;
                _findings.AddRange(verdict.Findings);
                return;
            }

            _notJudged++;

            foreach (var attribute in verdict.InputsNotCaptured)
                _missing[attribute] = _missing.GetValueOrDefault(attribute) + 1;
        }

        public RuleExecution ToExecution() =>
            _error is not null
                ? RuleExecution.Threw(rule.Definition, _error)
                : new RuleExecution(
                    rule.Definition,
                    Outcome,
                    _judged,
                    _notJudged,
                    [.. _missing
                        .OrderBy(m => m.Key, StringComparer.OrdinalIgnoreCase)
                        .Select(m => new MissingInput(m.Key, m.Value))],
                    _findings,
                    null);
    }
}
