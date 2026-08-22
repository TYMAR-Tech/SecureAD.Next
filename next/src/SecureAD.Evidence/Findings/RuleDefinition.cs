namespace SecureAD.Evidence.Findings;

/// <summary>
/// What a rule is, as data: its identity, its wording and the evidence it needs.
/// </summary>
/// <remarks>
/// <para>
/// <b>The catalogue is data and the logic is code</b>, per <c>docs/decisions/0010</c>. This type
/// is the data half. What a rule looks for lives in an <see cref="IRule"/> implementation; what a
/// rule <i>is</i> lives here, where it can be read, listed and compared without running anything.
/// </para>
/// <para>
/// <b><see cref="RequiredAttributes"/> is the reason this type exists at all.</b> The predecessor
/// kept every rule's inputs in one hand-maintained dictionary of sixty-four entries, held in the
/// findings service and separate from the rules themselves. A rule added without an entry fell
/// through to a heuristic default and was then stamped coverage-complete on a bundle where its
/// actual inputs were never captured. Its own review called that the single most consequential
/// structural problem in the branch, and described it exactly: not a missing feature, but a wrong
/// answer stated confidently.
/// </para>
/// <para>
/// So a rule declares its inputs here, beside itself, and
/// <c>RuleDefinitionTests.EveryRuleDeclaresTheDataItReads</c> fails the build when one declares
/// none. <c>docs/decisions/0083</c> decides this, and the point of failing the build rather than
/// defaulting is that an absent verdict is loud where a clean verdict is not.
/// </para>
/// </remarks>
/// <param name="Id">The permanent identifier, such as <c>SEC-011</c>. Never reused, per 0024.</param>
/// <param name="Name">What this rule is called, in the words a report uses.</param>
/// <param name="Severity">How serious a finding from this rule is. Fixed here, per 0066.</param>
/// <param name="Version">The version of this rule's logic. Recorded on a finding, outside its identity.</param>
/// <param name="RequiredAttributes">
/// Every attribute this rule reads, by LDAP display name. Declaring none fails the build.
/// </param>
public sealed record RuleDefinition(
    string Id,
    string Name,
    Severity Severity,
    int Version,
    IReadOnlyList<string> RequiredAttributes)
{
    /// <summary>
    /// Whether this definition says what the rule reads.
    /// </summary>
    /// <remarks>
    /// False is not a shrug. <c>docs/decisions/0083</c> makes an undeclared rule fail the build,
    /// because a rule whose inputs nobody wrote down is stamped coverage-complete on a bundle that
    /// never carried them. <c>RuleDeclarationTests</c> is where that failure happens.
    /// </remarks>
    public bool IsComplete => RequiredAttributes.Count > 0;
}

/// <summary>
/// What one rule made of one object: what it found, and what it could not read.
/// </summary>
/// <remarks>
/// <para>
/// <b>An empty list of findings means two different things and this type keeps them apart.</b>
/// Either the object is fine, or the rule was handed an object missing something it declared it
/// needed. Returning a bare list makes those identical, and <c>docs/decisions/0002</c> forbids
/// rendering an unavailable answer as an empty result - the predecessor's version of this mistake
/// stamped rules coverage-complete on bundles that never carried their inputs.
/// </para>
/// <para>
/// <b>This is what declaring inputs buys.</b> Because a rule names the attributes it reads, it can
/// say exactly which of them the object did not carry, rather than falling silent.
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
/// A rule: what it is, and what it makes of one object.
/// </summary>
/// <remarks>
/// <para>
/// <b>One object at a time, deliberately.</b> Both delegation rules decide from a single object's
/// own attributes, and a rule that cannot reach beyond the object it was handed cannot quietly
/// acquire a dependency it never declared. A rule that genuinely needs the forest - anything
/// resting on group membership, for instance - needs a wider shape than this and a decision to go
/// with it, rather than being smuggled in through a captured field.
/// </para>
/// <para>
/// <b>Returning nothing is the normal case.</b> Most objects are fine, and a rule says so by
/// yielding no finding rather than by yielding a finding that says nothing is wrong.
/// </para>
/// </remarks>
public interface IRule
{
    /// <summary>What this rule is, as data.</summary>
    RuleDefinition Definition { get; }

    /// <summary>
    /// What this rule makes of one object, and what it could not read to decide.
    /// </summary>
    /// <param name="subject">The object to judge.</param>
    RuleVerdict Judge(EvidenceObject subject);
}
