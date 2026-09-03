using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>
/// SEC-030 - an object carrying the AdminSDHolder marker whose protection nothing establishes,
/// while its DACL still refuses inheritance.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this reports, in one sentence.</b> An object that looks like it used to be a privileged
/// account - <c>adminCount</c> is 1 and its permissions still refuse to inherit from the
/// organisational unit it sits in - while nothing in the captured evidence says AdminSDHolder
/// protects it today. Microsoft describes the state in
/// <see href="https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory">
/// Reducing the Active Directory Attack Surface</see>: when an account leaves a protected group the
/// attribute stays behind, SDProp stops maintaining the object, and it still does not inherit. The
/// practical consequence is that permissions delegated on its container never reach it.
/// </para>
/// <para>
/// <b>Both halves are read, and the marker never stands in for the ACL.</b> <c>adminCount</c> is a
/// marker, not proof of current state - the
/// <see href="https://learn.microsoft.com/windows/win32/adschema/a-admincount">Admin-Count</see>
/// schema page records <c>System-Only: False</c>, so the directory does not reserve it to itself,
/// and nothing in a captured value says who set it or when. So the security descriptor is read as
/// well, and <c>SE_DACL_PROTECTED</c> must actually be set. Inferring the ACL from the marker is
/// <c>10.1</c> in the specification: what the predecessor did.
/// </para>
/// <para>
/// <b>Nothing here recomputes protection.</b> Whether a principal is protected was settled once in
/// Derivation under <c>docs/decisions/0089</c> and <c>0090</c>, with its basis and the membership
/// path that decided it. This rule reads that answer and does not re-derive it, which is why a
/// catalogue claim moving from <c>Unverified</c> to <c>Established</c> would change what this rule
/// reports without changing a line of it.
/// </para>
/// <para>
/// <b>A doubt is never reported as a finding.</b> Every case the specification lists as unknown -
/// no SID, an unreadable descriptor, incomplete membership, an unread forest mask, a primary-group
/// route, a disputed or unverified catalogue claim - returns <see cref="RuleVerdict.CouldNotResolve"/>
/// and says which. A caveated positive would still accuse an object of being unprotected when the
/// missing evidence might have proved the opposite, and an operator does not read caveats before
/// acting on a list.
/// </para>
/// </remarks>
public sealed class AdminCountWithoutProtection : IRule
{
    /// <summary>What the rule reads, declared per <c>docs/decisions/0083</c>.</summary>
    /// <remarks>
    /// <b>Deleted objects are not among these, and cannot be.</b> Capture does not read
    /// <c>isDeleted</c> (<c>F-S20-1</c>), so no bundle carries a tombstone to judge. Every tombstone
    /// has a non-inheriting DACL as a consequence of deletion rather than of misconfiguration, so
    /// this rule would say nothing useful about one even if it could see it. See
    /// <c>docs/decisions/0091</c>, and <c>P-108</c> and <c>P-109</c> for what was deferred and what
    /// catches the real risk.
    /// </remarks>
    private static readonly string[] Reads = ["objectSid", "adminCount", "objectClass"];

    /// <summary>
    /// Which classes this is about.
    /// </summary>
    /// <remarks>
    /// The <c>Admin-Count</c> schema page names <c>Group</c> and <c>User</c> as the classes it is
    /// used in, and a computer is a kind of user in the schema, so it arrives here too - which is
    /// wanted, because a domain controller's computer account is exactly the sort of object this
    /// condition lands on.
    /// </remarks>
    private static readonly string[] Subjects = ["user", "group", "computer"];

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        "SEC-030",
        "Protected-account marker without current protection",
        Severity.Medium,
        Version: 1,
        Subjects,
        Reads,
        [nameof(DerivedFactKind.ProtectedPrincipals)]);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException(
            "SEC-030 reads derived facts and must be offered them. Judging refuses a bundle that "
            + "cannot supply them, so reaching this is a defect rather than a missing derivation.");

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);

        // Cheapest discriminator first, and the one that ends most objects. An object without the
        // marker is outside this rule entirely - N10 and N11 - and is not a gap in the evidence.
        var adminCount = AttributeReading.UnsignedInteger(subject, "adminCount");
        if (adminCount is not 1)
            return RuleVerdict.Judged([]);

        if (context.ProtectedPrincipals is not { } protection)
            return ProtectedPrincipalReading.Unresolved(UnresolvedReason.NotDerived);

        // U3. A partial closure can make a protected object look unprotected, which is the failure
        // 10.7 names. Checked before the object's own facts, because no per-object answer can be
        // trusted while the graph behind it is incomplete.
        if (!protection.IsComplete)
            return ProtectedPrincipalReading.Unresolved(ProtectedPrincipalReading.ReasonFor(protection.StatedLimits));

        if (SidTextOf(subject) is not { } sid)
            return ProtectedPrincipalReading.Unresolved(UnresolvedReason.IdentityUnreadable);

        // Scoped the way the derivation keyed it: a built-in SID belongs to its domain, everything
        // else is already unique. Getting this wrong would merge every domain's BUILTIN groups into
        // one, which is the defect 0087 exists to prevent.
        var scope = Sid.IsBuiltinDomain(sid) ? subject.DomainFqdn : null;

        if (protection.Lookup(sid, scope) is not { } fact)
            return ProtectedPrincipalReading.Unresolved(UnresolvedReason.NotDerived);

        switch (fact.Evaluation)
        {
            // P1 and P2 are the only way out of here with a finding.
            case ProtectedPrincipalEvaluation.NotProtected:
                break;

            // N1 to N8. The object is protected, in its own right or through membership, so the
            // marker is consistent and there is nothing to report.
            case ProtectedPrincipalEvaluation.Protected:
                return RuleVerdict.Judged([]);

            // U5 to U9. The derivation declined to call it either way and said why; that reason is
            // carried through rather than being flattened into a verdict.
            default:
                return ProtectedPrincipalReading.Unresolved(ProtectedPrincipalReading.ReasonFor(fact.UnknownReasons));
        }

        // U2. Read only once the protection question is settled, because an unreadable descriptor
        // on an object that turns out to be protected is not a doubt about anything.
        if (context.Permissions is null)
            return ProtectedPrincipalReading.Unresolved(UnresolvedReason.SecurityDescriptorUnreadable);

        var permissions = context.Permissions(subject.DistinguishedName);

        if (permissions is null || permissions.DaclState is DaclState.Unreadable)
            return ProtectedPrincipalReading.Unresolved(UnresolvedReason.SecurityDescriptorUnreadable);

        // N9. The marker is inconsistent, but the condition this rule reports is the non-inheriting
        // ACL, and that is absent. Section 3 keeps it out of SEC-030 rather than reporting a
        // weaker version of the finding.
        if (!permissions.IsDaclProtected)
            return RuleVerdict.Judged([]);

        if (subject.ObjectGuid is not { } objectGuid)
            return ProtectedPrincipalReading.Unresolved(UnresolvedReason.IdentityUnreadable);

        var name = AttributeReading.Text(subject, "sAMAccountName") ?? subject.DistinguishedName;
        var objectClass = AttributeReading.LastText(subject, "objectClass") ?? string.Empty;

        return RuleVerdict.Judged(
        [
            new Finding(
                Definition.Id,
                Definition.Version,
                Definition.Severity,
                new FindingSubject(FindingSubjectKind.Account, name),
                objectGuid,
                subject.DistinguishedName,
                DnHelper.DnToFqdn(subject.DistinguishedName),
                objectClass,
                Detail(name),
                subject.Completeness,
                new AdminCountWithoutProtectionEvidence(sid)),
        ]);
    }

    /// <summary>What the operator is told.</summary>
    /// <remarks>
    /// <b>It states the consequence and refuses the history.</b> The evidence cannot establish that
    /// the object was ever privileged, who set the marker, or when inheritance was disabled - so
    /// none of that is claimed. What it can say is what is true now: SDProp no longer maintains the
    /// object, and delegated permissions on its container do not reach it.
    /// </remarks>
    private static string Detail(string name) =>
        $"{name} carries adminCount=1 and its permissions still refuse to inherit, but the captured "
        + "evidence does not establish that AdminSDHolder protects it now. SDProp no longer "
        + "maintains it, and permissions delegated on the container it sits in do not reach it. This "
        + "does not prove it was ever privileged, or that clearing the marker is safe: read its "
        + "permissions first.";

    /// <summary>
    /// The object's SID in canonical text, or null where it carried none this build can decode.
    /// </summary>
    /// <remarks>
    /// Read from bytes rather than text because that is how the directory stores it and how
    /// <c>MembershipNestingPass</c> keyed the derivation. Taking a text value here would fail to
    /// match a dictionary built from bytes, and the object would look absent rather than unmatched.
    /// </remarks>
    private static string? SidTextOf(ObjectAttributes subject) =>
        subject.Attributes
            .Where(a => string.Equals(
                a.LdapDisplayName, "objectSid", StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a.Values)
            .Select(v => v.Bytes is null ? null : Sid.ToText(v.Bytes))
            .FirstOrDefault(s => s is not null);

}
