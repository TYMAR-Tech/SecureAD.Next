namespace SecureAD.Evidence.Findings;

/// <summary>
/// What a rule is, as data: its identity, its wording and the evidence it needs.
/// </summary>
/// <remarks>
/// <para>
/// <b>The catalogue is data and the logic is code</b>, per <c>docs/decisions/0010</c>. This is the
/// data half. Rule execution belongs to <c>SecureAD.Judgement</c>; identity, wording, severity and
/// declared captured inputs stay here because they are durable data written into findings and the
/// judgement store. Keeping that split means Evidence describes what a rule was without depending
/// on the component that executes it.
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
/// <param name="SubjectClasses">
/// The object classes this rule is about, by LDAP display name. Declaring none fails the build.
/// </param>
/// <param name="RequiredAttributes">
/// Every attribute this rule reads, by LDAP display name. Declaring none fails the build.
/// </param>
/// <param name="RequiredDerivedFacts">
/// Every kind of derived fact this rule reads, by name. Empty for a rule that reads only the
/// captured object, which is most of them.
/// <para>
/// <b>Named here rather than on the executable rule</b> so it travels with the rest of what a rule
/// declares, and so a stored judgement can say what its rules needed. Held as text because Evidence
/// owns durable rule data and must not reference the component above it that names the kinds.
/// </para>
/// <para>
/// <b>Required rather than defaulted</b>, per gate 1. Writing an empty list is a rule author saying
/// this rule reads only the captured object; a default would let one be added that quietly says
/// nothing, and a rule whose derived inputs nobody wrote down is the failure
/// <c>docs/decisions/0083</c> exists to prevent - stamped coverage-complete on a bundle that never
/// carried what it needed.
/// </para>
/// </param>
public sealed record RuleDefinition(
    string Id,
    string Name,
    Severity Severity,
    int Version,
    IReadOnlyList<string> SubjectClasses,
    IReadOnlyList<string> RequiredAttributes,
    IReadOnlyList<string> RequiredDerivedFacts)
{
    /// <summary>
    /// Whether this definition says what the rule is about and what it reads.
    /// </summary>
    /// <remarks>
    /// False is not a shrug. <c>docs/decisions/0083</c> makes an undeclared rule fail the build,
    /// because a rule whose inputs nobody wrote down is stamped coverage-complete on a bundle that
    /// never carried them. <c>RuleDeclarationTests</c> is where that failure happens.
    /// </remarks>
    public bool IsComplete => SubjectClasses.Count > 0 && RequiredAttributes.Count > 0;

    /// <summary>
    /// Whether this rule is about <paramref name="subject"/> at all.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Not applicable is not the same as could not judge, and conflating them was a real
    /// defect.</b> An organisational unit has no <c>userAccountControl</c> because it is not an
    /// account, not because the capture missed it. Judged against a real forest on 2026-08-26, the
    /// delegation rules reported 6,279 of 8,361 objects as unreadable on exactly that account -
    /// three objects in four - which would have told an operator forever that every judging was
    /// degraded and the findings were a floor.
    /// </para>
    /// <para>
    /// <b>The class is matched against every value of <c>objectClass</c></b>, which carries the
    /// whole inheritance chain: a computer arrives as <c>top; person; organizationalPerson; user;
    /// computer</c>. So a rule declaring <c>user</c> sees computers too, which is what the schema
    /// means by a computer being a kind of user.
    /// </para>
    /// <para>
    /// <b>An empty list means every object, not no object.</b> A rule that declares no class is one
    /// whose subject is the directory itself rather than a kind of account - ownership and
    /// permission rules apply to organizational units, containers, certificate templates and
    /// policies alike, and enumerating every class a forest might hold would be a list that is
    /// wrong the moment somebody extends the schema.
    /// </para>
    /// <para>
    /// <b>This was the other reading until 2026-09-05, and it silently switched three rules off.</b>
    /// <c>SEC-060</c>, <c>SEC-031</c> and <c>SEC-032</c> all declare no class because their
    /// specifications say <i>every object</i>. Against <c>ad.lab</c> each judged <b>zero</b> objects
    /// and counted all 8,378 as not applicable, while 3,139 tests stayed green - every rule test
    /// calls <c>Judge</c> directly and so never reaches this method. Three rules were registered,
    /// documented, and measured nothing. Recorded as <c>F-S45-4</c>.
    /// </para>
    /// </remarks>
    /// <param name="subject">The object being considered.</param>
    public bool IsAbout(ObjectAttributes subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        if (SubjectClasses.Count == 0)
            return true;

        return AttributeReading.AllText(subject, "objectClass")
            .Any(c => SubjectClasses.Contains(c, StringComparer.OrdinalIgnoreCase));
    }
}
