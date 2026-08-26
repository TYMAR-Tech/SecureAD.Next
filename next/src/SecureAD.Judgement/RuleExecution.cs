using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>
/// One attribute a rule declared it reads that was not captured, and how many objects it cost.
/// </summary>
/// <remarks>
/// The count is objects the rule could not reach a verdict on <i>because of this attribute</i>. An
/// object missing two declared attributes is counted against both, so these do not sum to
/// <see cref="RuleExecution.ObjectsNotJudged"/> and are not meant to.
/// </remarks>
/// <param name="Attribute">The LDAP display name the rule declared.</param>
/// <param name="ObjectsAffected">How many objects lacked it.</param>
public sealed record MissingInput(string Attribute, int ObjectsAffected);

/// <summary>
/// Everything one rule did to one bundle: what it found, what it could not read, and what became
/// of it.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the unit the judgement store commits.</b> A rule's findings and the record of its
/// execution are written in one transaction, so a killed process cannot leave findings with nothing
/// saying which rule produced them, and cannot lose the rules that already finished.
/// </para>
/// <para>
/// <b>It is built whole before it is written</b>, which means a rule's findings are held in memory
/// until it finishes. That is affordable because a rule produces findings in the hundreds or
/// thousands where capture produces objects in the millions - and it is what makes the atomic write
/// simple enough to be obviously correct. If a rule ever produces enough findings to matter, this
/// is the thing to revisit.
/// </para>
/// </remarks>
/// <param name="Definition">The rule, as it was when it ran.</param>
/// <param name="Outcome">What became of it.</param>
/// <param name="ObjectsJudged">Objects it reached a verdict on.</param>
/// <param name="ObjectsNotJudged">Objects it could not reach a verdict on.</param>
/// <param name="MissingInputs">The declared attributes that were absent, and on how many objects.</param>
/// <param name="Findings">What it found. Empty is meaningful only beside <paramref name="Outcome"/>.</param>
/// <param name="Error">Why it threw, when it did. Null otherwise.</param>
public sealed record RuleExecution(
    RuleDefinition Definition,
    RuleExecutionOutcome Outcome,
    int ObjectsJudged,
    int ObjectsNotJudged,
    IReadOnlyList<MissingInput> MissingInputs,
    IReadOnlyList<Finding> Findings,
    string? Error)
{
    /// <summary>
    /// A rule that ran and reached a verdict on everything it was offered.
    /// </summary>
    /// <remarks>
    /// Named for the verdict rather than for success, because <c>Result</c> owns the vocabulary of
    /// operations succeeding and failing. A rule reaching every verdict is not an operation
    /// succeeding: the operation succeeds whenever the rule runs to completion, including when it
    /// concludes it cannot tell.
    /// </remarks>
    /// <param name="definition">The rule.</param>
    /// <param name="objectsJudged">How many objects it judged.</param>
    /// <param name="findings">What it found, if anything.</param>
    public static RuleExecution Judged(
        RuleDefinition definition, int objectsJudged, IReadOnlyList<Finding> findings) =>
        new(definition, RuleExecutionOutcome.Succeeded, objectsJudged, 0, [], findings, null);

    /// <summary>
    /// A rule that ran and could not reach a verdict on everything, because declared inputs were
    /// not captured.
    /// </summary>
    /// <param name="definition">The rule.</param>
    /// <param name="objectsJudged">How many objects it did judge.</param>
    /// <param name="objectsNotJudged">How many it could not.</param>
    /// <param name="missingInputs">Which declared attributes were absent.</param>
    /// <param name="findings">What it found on the objects it could judge.</param>
    public static RuleExecution Indeterminate(
        RuleDefinition definition,
        int objectsJudged,
        int objectsNotJudged,
        IReadOnlyList<MissingInput> missingInputs,
        IReadOnlyList<Finding> findings) =>
        new(
            definition,
            RuleExecutionOutcome.Indeterminate,
            objectsJudged,
            objectsNotJudged,
            missingInputs,
            findings,
            null);

    /// <summary>
    /// A rule that threw. Its findings are discarded, because a rule that failed part way through
    /// has no verdict and its partial output would read as a complete one.
    /// </summary>
    /// <param name="definition">The rule.</param>
    /// <param name="error">What went wrong.</param>
    public static RuleExecution Threw(RuleDefinition definition, string error) =>
        new(definition, RuleExecutionOutcome.Error, 0, 0, [], [], error);

    /// <summary>
    /// A rule that was scheduled and never executed.
    /// </summary>
    /// <param name="definition">The rule.</param>
    public static RuleExecution DidNotRun(RuleDefinition definition) =>
        new(definition, RuleExecutionOutcome.DidNotRun, 0, 0, [], [], null);

    /// <summary>
    /// Whether this rule said anything about the forest at all.
    /// </summary>
    /// <remarks>
    /// False for three of the four outcomes. A caller counting findings must consult this first,
    /// because no findings from a rule that never reached a verdict is not the same as no findings
    /// from one that did.
    /// </remarks>
    public bool ReachedEveryVerdict => Outcome == RuleExecutionOutcome.Succeeded;
}
