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
public sealed record RuleVerdict(
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<string> InputsNotCaptured)
{
    /// <summary>A verdict reached with everything the rule asked for.</summary>
    /// <param name="findings">What was found, if anything.</param>
    public static RuleVerdict Judged(IReadOnlyList<Finding> findings) => new(findings, []);

    /// <summary>No verdict, because the object did not carry what the rule declared it reads.</summary>
    /// <param name="missing">The declared attributes that were absent.</param>
    public static RuleVerdict CouldNotJudge(IReadOnlyList<string> missing) => new([], missing);

    /// <summary>
    /// Whether the rule had everything it declared it needed. False means silence here is not a
    /// statement that the object is clean.
    /// </summary>
    public bool IsComplete => InputsNotCaptured.Count == 0;
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
/// The single-object method is retained unchanged in this seam-only move. A wider declared-input
/// package is a later decision and must not be smuggled into this ownership correction.
/// </para>
/// </remarks>
public interface IRule
{
    /// <summary>What this rule is, as durable data.</summary>
    RuleDefinition Definition { get; }

    /// <summary>What this rule makes of one object, and what it could not read to decide.</summary>
    /// <param name="subject">The object to judge.</param>
    RuleVerdict Judge(ObjectAttributes subject);
}
