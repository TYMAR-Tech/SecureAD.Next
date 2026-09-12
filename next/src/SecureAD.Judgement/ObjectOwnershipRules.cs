using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>
/// Deciding which of the two ownership rules an object belongs to.
/// </summary>
/// <remarks>
/// <b>The two rules cover disjoint sets, and that is the whole reason this exists.</b>
/// <c>SEC-031</c> reports ordinary objects at <c>Low</c>; <c>SEC-032</c> reports objects
/// <c>AdminSDHolder</c> protects at <c>High</c>. If both reported the same object, an operator would
/// see one problem twice at two severities and have to work out they were the same thing.
/// </remarks>
internal enum ProtectedObjectAnswer
{
    /// <summary>The object is protected, so SEC-032 owns it.</summary>
    Protected,

    /// <summary>The object is not protected, so SEC-031 owns it.</summary>
    NotProtected,

    /// <summary>Nothing settled it, so neither rule may report and both must refuse.</summary>
    Unknown,
}

/// <summary>
/// Whether an object is one <c>AdminSDHolder</c> protects, which decides which ownership rule
/// speaks about it.
/// </summary>
internal static class ProtectedObjectReading
{
    public static ProtectedObjectAnswer Answer(
        ObjectAttributes subject, StoredProtectedPrincipalDerivation protection)
    {
        // A partial closure can make a protected object look unprotected, which would move it from
        // the High rule to the Low one and understate it. Checked before the object's own facts.
        if (!protection.IsComplete)
            return ProtectedObjectAnswer.Unknown;

        if (SidTextOf(subject) is not { } sid)
        {
            // An object with no readable SID cannot be looked up. It is not "not protected".
            return ProtectedObjectAnswer.Unknown;
        }

        var scope = Sid.IsBuiltinDomain(sid) ? subject.DomainFqdn : null;

        if (protection.Lookup(sid, scope) is not { } fact)
        {
            // MOST OBJECTS ARE NOT PRINCIPALS AT ALL. An organizational unit, a container or a
            // Group Policy object carries no objectSid, so the closure holds no fact about it and
            // it is genuinely not protected rather than unknown. That case is answered above by
            // the SID being absent; reaching here means the object HAS a SID the closure never
            // evaluated, which is a gap rather than an answer.
            return ProtectedObjectAnswer.Unknown;
        }

        return fact.Evaluation switch
        {
            ProtectedPrincipalEvaluation.Protected => ProtectedObjectAnswer.Protected,
            ProtectedPrincipalEvaluation.NotProtected => ProtectedObjectAnswer.NotProtected,
            _ => ProtectedObjectAnswer.Unknown,
        };
    }

    /// <summary>
    /// Why <see cref="Answer"/> came to <see cref="ProtectedObjectAnswer.Unknown"/>, in the
    /// vocabulary an operator reads.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Every branch of <see cref="Answer"/> that returns Unknown has an arm here</b>, and they
    /// are written in the same order for the reason the two rules share a body: two places deciding
    /// one question is two chances to disagree. An incomplete closure and an unread identifier are
    /// facts about this run that another run may fix; a primary-group-only route and a disputed
    /// catalogue claim are not, and telling an operator to capture again over either wastes his
    /// afternoon.
    /// </para>
    /// <para>
    /// <b>The derivation's own reason is preferred wherever it recorded one.</b> It knows whether
    /// the principal was blocked at a primary-group edge or by Microsoft contradicting itself;
    /// this rule does not, and guessing would put a wrong instruction on the screen.
    /// </para>
    /// </remarks>
    /// <param name="subject">The object being judged.</param>
    /// <param name="protection">The derived facts offered to the rule.</param>
    public static UnresolvedReason UnknownReason(
        ObjectAttributes subject, StoredProtectedPrincipalDerivation protection)
    {
        if (!protection.IsComplete)
            return ProtectedPrincipalReading.ReasonFor(protection.StatedLimits);

        if (SidTextOf(subject) is not { } sid)
            return UnresolvedReason.IdentityUnreadable;

        var scope = Sid.IsBuiltinDomain(sid) ? subject.DomainFqdn : null;

        // A SID the closure never evaluated is a gap in the derivation rather than a fact about
        // this object, and NotDerived is the one instruction that fits it.
        return protection.Lookup(sid, scope) is { } fact
            ? ProtectedPrincipalReading.ReasonFor(fact.UnknownReasons)
            : UnresolvedReason.NotDerived;
    }

    /// <summary>
    /// The object's own security identifier, or null where it carries none or none could be read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>An object with no SID is not a failure.</b> Organizational units, containers and Group
    /// Policy objects have none, and they are the commonest subjects of the ownership rules.
    /// </para>
    /// <para>
    /// <b>Read from bytes and never as text, which is how the directory stores it.</b> This read it
    /// as text until 2026-09-05, and <see cref="AttributeReading.Text"/> returns null for a binary
    /// attribute - so <i>every</i> object in the forest looked like it had no identifier, every
    /// object was therefore treated as unprotected, and <c>SEC-032</c> could not fire at all. The
    /// paragraph above made the wrong answer look deliberate. Found by planting a protected object
    /// in the lab and watching <c>SEC-031</c> report it instead. Recorded as <c>F-S45-6</c>.
    /// </para>
    /// </remarks>
    public static string? SidTextOf(ObjectAttributes subject) =>
        subject.Attributes
            .Where(a => string.Equals(
                a.LdapDisplayName, "objectSid", StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a.Values)
            .Select(v => v.Bytes is null ? null : Sid.ToText(v.Bytes))
            .FirstOrDefault(s => s is not null);

    /// <summary>
    /// Whether an object without a security identifier can be treated as unprotected.
    /// </summary>
    /// <remarks>
    /// <b>It can, and this is the one place that says so.</b> <c>AdminSDHolder</c> protects
    /// principals - accounts and groups - by stamping their descriptors. An object that is not a
    /// principal cannot be in the protected set, so absence of a SID is an answer rather than a
    /// gap. Without this, every organizational unit in the forest would be refused by both rules
    /// and the ownership question would go unanswered across most of the directory.
    /// </remarks>
    public static bool HasNoSecurityIdentifier(ObjectAttributes subject) =>
        SidTextOf(subject) is null;
}

/// <summary>
/// SEC-031 - an object is owned by somebody who is not an administrator.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it says in one sentence.</b> <i>This object's owner can rewrite its permissions whenever
/// they like, and its owner is not an administrator.</i>
/// </para>
/// <para>
/// <b>Why an administrator would not otherwise see it.</b> Ownership is not in the permission list.
/// An administrator can review every entry on an object, find nothing wrong, and miss that the owner
/// can replace the whole list at will.
/// </para>
/// <para>
/// <b>This reports latent authority. It is not evidence of abuse and must never be worded as if it
/// were.</b> The ordinary sequence is that somebody was allowed to create an object, they created
/// it, they became its owner, and it stayed that way for years. Nobody did anything wrong at any
/// point.
/// </para>
/// <para>
/// <b>Specified in</b>
/// docs/layers/judgement/rules/SEC-031-object-owned-by-a-non-administrator.md.
/// </para>
/// </remarks>
public sealed class ObjectOwnedByNonAdministrator : IRule
{
    private const string RuleId = "SEC-031";

    private const int RuleVersion = 3;

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        RuleId,
        "An object is owned by somebody who is not an administrator",
        Severity.Low,
        Version: RuleVersion,
        SubjectClasses: [],
        RequiredAttributes: ["objectClass"],
        RequiredDerivedFacts:
        [
            nameof(DerivedFactKind.ProtectedPrincipals),
            nameof(DerivedFactKind.PrincipalExpansion),
        ]);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException(
            "SEC-031 reads derived facts and must be offered them. Judging refuses a bundle that "
            + "cannot supply them, so reaching this is a defect rather than a missing derivation.");

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context) =>
        OwnershipRuleBody.Judge(
            subject, context, RuleId, RuleVersion, Severity.Low, wantProtected: false);
}

/// <summary>
/// SEC-032 - an object <c>AdminSDHolder</c> protects is owned by somebody who is not an
/// administrator.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it says in one sentence, and why it is a different sentence from SEC-031's.</b>
/// <i>Somebody who is not an administrator owns an object the directory protects because it confers
/// privilege, and can therefore rewrite that object's permissions.</i> That is a route to privilege
/// rather than latent authority over one object.
/// </para>
/// <para>
/// <b>The severity rests on timing rather than on durability, and that is a correction
/// (<c>F-S45-7</c>).</b> This rule shipped at <c>High</c> on the argument that <c>AdminSDHolder</c>
/// re-stamping rewrites the DACL and leaves the owner alone, so the exposure persists. <b>The lab
/// disproved it on 2026-09-05</b>: a planted protected object's owner was set to an ordinary user,
/// captured as such, and had been restored to <c>Domain Admins</c> an hour later with nobody
/// touching it. SDProp resets the owner as well as the permissions, which is the reading the Event
/// 4780 article supports where Appendix C does not.
/// </para>
/// <para>
/// <b>The rule survives the correction because what it detects is still true and still worth
/// reporting - but it is a different claim.</b> A protected object with a non-administrative owner
/// at capture time means either the ownership changed within roughly the last hour, or SDProp is
/// not running. The second is a domain-wide failure of a control nobody is watching. <c>Medium</c>
/// rather than <c>High</c> - the owner's decision of 2026-09-05 - because the exposure is
/// self-healing within the hour, and rather than <c>Low</c> because the owner expects this to be
/// vanishingly rare in a healthy domain, so any hit deserves attention.
/// </para>
/// <para>
/// <b>The finding is timing-dependent, which no other rule in the tree is.</b> It can appear in one
/// run and be gone from the next with nothing having been fixed. <see cref="Detail"/> says so in
/// the text an operator reads, because one who investigates and finds the owner already restored
/// will otherwise conclude the rule is broken.
/// </para>
/// <para>
/// <b>Why it is a second rule rather than a second severity.</b> The owner's decision of
/// 2026-09-05. Two rules are two things an operator can sort, filter and accept independently,
/// where one rule with mixed levels is a single row they must open to understand. It is also the
/// cheaper shape: severity stays fixed on the rule card and no shared interface changes.
/// </para>
/// <para>
/// <b>Specified in</b>
/// docs/layers/judgement/rules/SEC-032-protected-object-owned-by-a-non-administrator.md.
/// </para>
/// </remarks>
public sealed class ProtectedObjectOwnedByNonAdministrator : IRule
{
    private const string RuleId = "SEC-032";

    private const int RuleVersion = 3;

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        RuleId,
        "A protected object is owned by somebody who is not an administrator",
        Severity.Medium,
        Version: RuleVersion,
        SubjectClasses: [],
        RequiredAttributes: ["objectClass"],
        RequiredDerivedFacts:
        [
            nameof(DerivedFactKind.ProtectedPrincipals),
            nameof(DerivedFactKind.PrincipalExpansion),
        ]);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException(
            "SEC-032 reads derived facts and must be offered them. Judging refuses a bundle that "
            + "cannot supply them, so reaching this is a defect rather than a missing derivation.");

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context) =>
        OwnershipRuleBody.Judge(
            subject, context, RuleId, RuleVersion, Severity.Medium, wantProtected: true);
}

/// <summary>
/// The body both ownership rules share, written once.
/// </summary>
/// <remarks>
/// <b>The two rules differ in two values and nothing else</b> - which objects they cover, and what
/// severity and wording they carry. Writing the logic twice would mean two chances to get the
/// owner-rights condition wrong, and that condition is the one that decides whether the finding is
/// true at all.
/// </remarks>
internal static class OwnershipRuleBody
{
    public static RuleVerdict Judge(
        ObjectAttributes subject,
        JudgingContext context,
        string ruleId,
        int ruleVersion,
        Severity severity,
        bool wantProtected)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);

        if (context.ProtectedPrincipals is not { } protection)
        {
            return RuleVerdict.CouldNotResolve([new UnresolvedInput(
                DerivedFactKind.ProtectedPrincipals, UnresolvedReason.NotDerived)]);
        }

        // WHICH RULE OWNS THIS OBJECT, decided before anything about its owner is read. An object
        // that is not this rule's is not a gap in the evidence and must not be refused - it is the
        // other rule's business entirely.
        var protectedAnswer = ProtectedObjectReading.HasNoSecurityIdentifier(subject)
            ? ProtectedObjectAnswer.NotProtected
            : ProtectedObjectReading.Answer(subject, protection);

        if (protectedAnswer is ProtectedObjectAnswer.Unknown)
        {
            // Neither rule may speak. Reporting at Low an object that might be protected would
            // understate it; staying silent would hide it.
            //
            // THE REASON IS READ FROM THE DERIVATION RATHER THAN ASSUMED. This said
            // MembershipIncomplete for every cause until 2026-09-11, which renders as "capturing
            // every domain in the forest would settle it" - advice that is wrong for both causes a
            // lab run actually produces. A domain controller reaching Domain Controllers only
            // through primaryGroupID, and a group Microsoft's own pages disagree about, are neither
            // of them fixed by capturing anything. ProtectedPrincipalReading.ReasonFor already
            // draws exactly this distinction for SEC-021 and SEC-030; this path simply never asked
            // it. Recorded as F-S46-1.
            return RuleVerdict.CouldNotResolve([new UnresolvedInput(
                DerivedFactKind.ProtectedPrincipals, ProtectedObjectReading.UnknownReason(subject, protection))]);
        }

        var isProtected = protectedAnswer is ProtectedObjectAnswer.Protected;

        if (isProtected != wantProtected)
            return RuleVerdict.Judged([]);

        var decision = ObjectOwnershipReading.Decide(subject, context);

        switch (decision.Outcome)
        {
            case ObjectOwnershipOutcome.OwnerIsNotAdministrative:
                break;

            // A real answer: the owner is administrative, or cannot rewrite the list. Judged rather
            // than refused - this is knowledge, not ignorance.
            case ObjectOwnershipOutcome.OwnerIsAdministrative:
            case ObjectOwnershipOutcome.OwnerHoldsNoImplicitRights:
                return RuleVerdict.Judged([]);

            default:
                return RuleVerdict.CouldNotResolve([new UnresolvedInput(
                    DerivedFactKind.ProtectedPrincipals,
                    decision.Reason ?? UnresolvedReason.NotDerived)]);
        }

        if (subject.ObjectGuid is not { } objectGuid)
            return RuleVerdict.CouldNotJudge(["objectGUID"]);

        var evidence = decision.Evidence!;

        return RuleVerdict.Judged(
        [
            new Finding(
                ruleId,
                ruleVersion,
                severity,

                // THE SUBJECT IS THE OBJECT ITSELF, not the owner. The claim is about this object's
                // exposure, and an acceptance recorded against it should mean "this object's
                // ownership is known and accepted" rather than "this person may own anything".
                new FindingSubject(
                    FindingSubjectKind.DirectoryObject, subject.DistinguishedName),
                objectGuid,
                subject.DistinguishedName,
                subject.DomainFqdn ?? string.Empty,
                evidence.ObjectClass,
                Detail(evidence, isProtected),
                subject.Completeness,
                evidence),
        ]);
    }

    /// <summary>What the operator is told.</summary>
    /// <remarks>
    /// <para>
    /// <b>Worded as a capability and never as an accusation.</b> The commonest cause is that the
    /// owner created the object. An operator who reads this as evidence of malicious delegation
    /// will waste a day and then stop trusting the rule.
    /// </para>
    /// <para>
    /// <b>The protected wording says something different from the unprotected wording, and the
    /// difference is the point (<c>F-S45-7</c>).</b> An earlier version told the operator that a
    /// protected object's ownership was durable because <c>AdminSDHolder</c> re-stamping leaves
    /// the owner alone. <b>That is false</b>: SDProp resets the owner too, observed in the lab on
    /// 2026-09-05. So on a protected object this condition cannot persist past the next SDProp
    /// pass, and its presence in a capture means one of two things - the change happened within
    /// roughly the last hour, or SDProp is not running. The detail must say so, because an
    /// operator who investigates and finds the owner already back to <c>Domain Admins</c> will
    /// conclude the rule is broken unless it told them to expect that.
    /// </para>
    /// </remarks>
    private static string Detail(ObjectOwnershipEvidence evidence, bool isProtected)
    {
        var subject = isProtected
            ? "This object is protected by AdminSDHolder, and its owner"
            : "This object's owner";

        var who = evidence.IsOrphaned
            ? $"{evidence.Display}, an account that no longer exists,"
            : $"{evidence.Display}";

        var consequence = evidence.IsOrphaned
            ? "no permission review shows this, and nobody can be asked to hand ownership over "
              + "because the account is gone"
            : "no permission review shows this";

        var caveat = evidence.IsComplete
            ? string.Empty
            : " The membership walk behind this did not finish, so the owner may hold "
              + "administrative rights through a group it did not reach.";

        var timing = isProtected
            ? " AdminSDHolder restores the owner of a protected object roughly every hour, so "
              + "this should not have lasted: either it was changed within about the last hour, "
              + "or AdminSDHolder is not running. Check which before assuming it is harmless - "
              + "the owner may already have been restored by the time you look."
            : string.Empty;

        return $"{subject} {who} is not an administrative principal. An owner can rewrite an "
            + $"object's permissions at any time and {consequence}.{caveat}{timing}";
    }
}
