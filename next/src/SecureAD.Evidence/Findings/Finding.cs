namespace SecureAD.Evidence.Findings;

/// <summary>
/// How serious a finding is, fixed by its rule.
/// </summary>
/// <remarks>
/// <para>
/// <b>Four levels, and the fifth was removed on purpose.</b> The predecessor defined an
/// <c>Info</c> level and none of its sixty-two rule cards used it. A level that survives sixty-two
/// attempts to find a use is being kept for a rule that does not exist, while sitting in every
/// legend, filter and sort order a reader has to learn. Decided by <c>docs/decisions/0081</c>.
/// </para>
/// <para>
/// <b>A rule fixes this, not a customer.</b> <c>docs/decisions/0066</c> puts severity in the
/// catalogue and <c>docs/decisions/0082</c> refuses customer tuning of it, because lowering a
/// severity is quieter than accepting a finding - an acceptance leaves something behind and a
/// lowered severity leaves nothing at all.
/// </para>
/// </remarks>
public enum Severity
{
    /// <summary>A minor concern, recorded so it is not lost.</summary>
    Low,

    /// <summary>Worth attention in the ordinary course of work.</summary>
    Medium,

    /// <summary>A significant weakness that should be addressed promptly.</summary>
    High,

    /// <summary>Severe. Someone should look at this today.</summary>
    Critical,
}

/// <summary>
/// What kind of thing a finding is about.
/// </summary>
/// <remarks>
/// <b>A kind and a key, never a security identifier.</b> <c>docs/decisions/0023</c> settles this:
/// findings about containers, policies and other things without a SID must not be wedged into a
/// column that assumes one. The predecessor required a <c>SubjectSid</c> on every finding, which
/// is why its rules fail closed on any subject that has none.
/// </remarks>
public enum FindingSubjectKind
{
    /// <summary>A user, computer or service account.</summary>
    Account,
}

/// <summary>
/// Who or what a finding is about, as a kind and a key.
/// </summary>
/// <param name="Kind">What sort of thing this is.</param>
/// <param name="Key">
/// The stable key for that kind. For an account this is its <c>sAMAccountName</c>, which is what
/// an administrator will recognise in a report.
/// </param>
public sealed record FindingSubject(FindingSubjectKind Kind, string Key);

/// <summary>
/// The evidence behind a finding, in a shape the finding's kind declares.
/// </summary>
/// <remarks>
/// <para>
/// <b>There is deliberately no free-form context field here.</b> The predecessor carried
/// <c>ContextJson</c>, a schemaless string with an informally reserved key namespace, and three
/// separate components read keys out of it that no type declared. The helper that recovered edge
/// identity from it parsed the blob and swallowed every exception, so a malformed value silently
/// downgraded an edge action to a principal action with no diagnostic at all - a wrong answer
/// rather than an error.
/// </para>
/// <para>
/// Deriving from this costs a type per kind of finding. That is the price, and
/// <c>docs/decisions/0080</c> decides it is worth paying up front where it is visible rather than
/// at the third reader of an undeclared key.
/// </para>
/// </remarks>
public abstract record FindingEvidence;

/// <summary>
/// One thing the product found, about one object, under one rule.
/// </summary>
/// <remarks>
/// <para>
/// <b>Identity is the rule, the subject and the object</b>, per <c>docs/decisions/0023</c>. The
/// object is identified by <c>objectGUID</c>, which is immutable in Active Directory and survives
/// both rename and move, so the same finding is recognisable months later and an acceptance made
/// against it stays attached.
/// </para>
/// <para>
/// <b><see cref="RuleVersion"/> is recorded beside the finding and is not part of its identity.</b>
/// Tightening a rule's logic must not orphan every acceptance ever made against it.
/// </para>
/// <para>
/// <b><see cref="Coverage"/> is carried because a finding that is absent has more than one
/// explanation</b>, and they are not interchangeable. A run that could not read where something
/// lived has not established that it is clean.
/// </para>
/// <para>
/// <b><see cref="DomainFqdn"/> and <see cref="ObjectClass"/> are stored rather than looked up.</b>
/// A findings grid shows them in every row, and the evidence they come from is in another database
/// that a judgement must never write to and should not be reading fifty times to paint one page.
/// The object is in hand when a rule fires, so they cost nothing to record and are what was true
/// when the judging ran - which is what a judgement is about. The predecessor joined for these; it
/// could, because its findings and its objects shared one file.
/// </para>
/// </remarks>
/// <param name="RuleId">The rule that produced this, such as <c>SEC-011</c>.</param>
/// <param name="RuleVersion">The version of the rule's logic that produced it.</param>
/// <param name="Severity">How serious this is, taken from the rule.</param>
/// <param name="Subject">Who or what this is about.</param>
/// <param name="ObjectGuid">The object this is about.</param>
/// <param name="DistinguishedName">Where the object was, for a reader who needs to find it.</param>
/// <param name="DomainFqdn">The domain the object was in, for grouping and filtering.</param>
/// <param name="ObjectClass">What kind of object it was, as the directory named it.</param>
/// <param name="Detail">What was found, said plainly enough to act on.</param>
/// <param name="Coverage">Whether the evidence behind this was complete.</param>
/// <param name="Evidence">The values this rests on, in the shape this kind of finding declares.</param>
public sealed record Finding(
    string RuleId,
    int RuleVersion,
    Severity Severity,
    FindingSubject Subject,
    Guid ObjectGuid,
    string DistinguishedName,
    string DomainFqdn,
    string ObjectClass,
    string Detail,
    EvidenceCompleteness Coverage,
    FindingEvidence Evidence);
