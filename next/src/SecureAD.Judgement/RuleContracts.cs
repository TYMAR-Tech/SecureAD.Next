using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>
/// What one rule made of one object: what it found, and what it could not read.
/// </summary>
/// <remarks>
/// <para>
/// <b>An empty list of findings means two different things and this type keeps them apart.</b>
/// Either the object is fine, or the rule was handed an object missing something it declared it
/// needed. Returning a bare list makes those identical, and <c>docs/decisions/0002</c> forbids
/// rendering an unavailable answer as an empty result.
/// </para>
/// <para>
/// <b>This is an execution contract and therefore belongs to Judgement.</b> Evidence owns the
/// durable <see cref="RuleDefinition"/> and <see cref="Finding"/> records. Judgement owns offering
/// inputs to executable rules and deciding whether a verdict was reached. This placement also lets a
/// later rule consume Derivation without making Evidence reference the component built above it.
/// </para>
/// </remarks>
/// <param name="Findings">What was found. Empty when there was nothing to say.</param>
/// <param name="InputsNotCaptured">
/// Declared attributes this object did not carry, so the rule could not reach a verdict on it.
/// Empty when everything the rule needed was present.
/// </param>
/// <param name="Unresolved">
/// Why a derived fact could not settle the question, when that is what stopped the rule. Empty
/// where nothing derived was in doubt.
/// </param>
public sealed record RuleVerdict(
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<string> InputsNotCaptured,
    IReadOnlyList<UnresolvedInput> Unresolved)
{
    /// <summary>A verdict reached with everything the rule asked for.</summary>
    /// <param name="findings">What was found, if anything.</param>
    public static RuleVerdict Judged(IReadOnlyList<Finding> findings) => new(findings, [], []);

    /// <summary>No verdict, because the object did not carry what the rule declared it reads.</summary>
    /// <param name="missing">The declared attributes that were absent.</param>
    public static RuleVerdict CouldNotJudge(IReadOnlyList<string> missing) => new([], missing, []);

    /// <summary>
    /// No verdict, because a derived fact did not settle the question - it was never derived, or
    /// Microsoft's own documentation does not agree about it.
    /// </summary>
    /// <remarks>
    /// <b>Kept apart from an uncaptured attribute deliberately.</b> Reporting a disputed catalogue
    /// claim as a missing attribute would tell an operator the capture failed, and send him to look
    /// at his forest for a defect that is in Microsoft's documentation. <c>docs/decisions/0091</c>
    /// requires the two to stay distinct.
    /// </remarks>
    /// <param name="unresolved">What was undecided, and why.</param>
    public static RuleVerdict CouldNotResolve(IReadOnlyList<UnresolvedInput> unresolved) =>
        new([], [], unresolved);

    /// <summary>
    /// Whether the rule had everything it declared it needed. False means silence here is not a
    /// statement that the object is clean.
    /// </summary>
    public bool IsComplete => InputsNotCaptured.Count == 0 && Unresolved.Count == 0;
}

/// <summary>
/// Executable judgement logic: what a rule is, and what it makes of one captured object.
/// </summary>
/// <remarks>
/// <para>
/// <b>Execution belongs above both Evidence and Derivation.</b> Today's rules need only one captured
/// object. A derived-fact rule will need inputs from both stores. Judgement is the layer allowed to
/// coordinate those inputs; Evidence must not reference Derivation, and Derivation must never see a
/// rule.
/// </para>
/// <para>
/// <b>A rule declares the derived facts it reads, and is never handed less than it declared.</b>
/// <see cref="RuleDefinition.RequiredDerivedFacts"/> is empty for a rule that reads only the
/// captured object, and such a rule is unaffected by any of this. A rule that names a kind is not
/// offered a judging whose derivation is absent or belongs to different evidence - <c>JudgingRun</c>
/// refuses the run instead, per <c>docs/decisions/0091</c>, because a per-object "could not judge"
/// repeated across a forest is a wall of nothing an operator has to decode.
/// </para>
/// </remarks>
public interface IRule
{
    /// <summary>What this rule is, as durable data.</summary>
    RuleDefinition Definition { get; }

    /// <summary>What this rule makes of one object, and what it could not read to decide.</summary>
    /// <param name="subject">The object to judge.</param>
    RuleVerdict Judge(ObjectAttributes subject);

    /// <summary>
    /// What this rule makes of one object, given the reference time and the derived facts it
    /// declared.
    /// </summary>
    /// <remarks>
    /// Defaulted to the single-object method, so a rule reading only captured attributes implements
    /// one method and is offered the package it never asked for without noticing it.
    /// </remarks>
    /// <param name="subject">The object to judge.</param>
    /// <param name="context">
    /// The reference time, and the derived facts - which are empty for an Evidence-only judging.
    /// </param>
    RuleVerdict Judge(ObjectAttributes subject, JudgingContext context) => Judge(subject);
}
