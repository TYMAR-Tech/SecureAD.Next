using System.Collections.Frozen;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>
/// SEC-027 - a security principal carrying a privileged identifier in its SID history.
/// </summary>
/// <remarks>
/// <para>
/// <b>What SID history does.</b> An account moved between domains is issued a new identifier, and
/// the old one is kept in <c>sIDHistory</c>. That is not a historical note. Microsoft, <i>Security
/// identifiers</i>: when the user signs in, "all these SIDs are returned to the authentication
/// client, and they're included in the user's access token… any one of the SIDs in the access token
/// (including one of the SIDs in the <c>SIDHistory</c> property), can allow or deny the user
/// access." <i>Using DsAddSidHistory</i> puts the consequence plainly: doing this "effectively
/// grants to the destination principal access to all resources accessible to the source principal."
/// </para>
/// <para>
/// <b>Why that matters, in Microsoft's words.</b> Defender for Identity, <i>Unsecure SID History
/// attributes</i>: "a nonsensitive account in a domain can contain the Enterprise Admin SID in its
/// SID History from another domain in the Active Directory forest, thus 'elevating' access for the
/// user account to an effective Domain Admin in all domains in the forest."
/// </para>
/// <para>
/// <b>Why an administrator cannot find this himself.</b> Membership is a link between two objects -
/// the group's <c>member</c> and the account's <c>memberOf</c>. A SID in <c>sIDHistory</c> creates
/// no such link, so listing that group's members, at any depth, will not name this account. The
/// privilege is real and the membership listing is empty.
/// </para>
/// <para>
/// <b>What the customer can therefore mitigate.</b> A standing privilege escalation that survives
/// every review of group membership. The remedy is Microsoft's own, from the same assessment:
/// identify the value with <c>Get-ADUser -Properties SidHistory</c> and remove it with
/// <c>Set-ADUser -Remove @{SIDHistory='S-1-5-21-…'}</c>. The wording below says that and no more -
/// the value may be the only reason the account can still reach resources whose permissions were
/// never re-stamped after the migration.
/// </para>
/// <para>
/// <b>All three classes are reported identically</b>, decided by the owner on 2026-09-02. The schema
/// puts <c>sIDHistory</c> on <c>Security-Principal</c>, so a group and a computer carry it exactly as
/// a user does, and no Microsoft source ranks them differently. The class travels in the finding
/// instead.
/// </para>
/// <para>
/// <b>What this rule cannot see, and why that is stated rather than hidden.</b> It ranks a value by
/// its relative identifier, which only works for the identifiers Microsoft documents. A custom group
/// that was privileged in the old domain has an ordinary, sequentially issued identifier - nothing in
/// the number says so - and what made it dangerous was what that domain's resources granted it. If
/// that domain is gone, which is the ordinary case after a migration, no tool reading this forest can
/// recover it. So the rule is bounded, the boundary is in its About text and its guidance rather than
/// only in a document, and the unranked values travel in the evidence so an operator is never shown a
/// filtered view of the account.
/// </para>
/// <para>
/// Specified in <c>docs/layers/judgement/rules/SEC-027-privileged-sid-history.md</c>.
/// </para>
/// </remarks>
public sealed class PrivilegedSidHistory : IRule
{
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        "SEC-027",
        "Privileged identifier carried in SID history",
        Severity.High,
        Version: 1,
        SubjectClasses: ["user", "computer", "group"],
        RequiredAttributes: ["sIDHistory", "objectSid", "objectClass"],
        RequiredDerivedFacts: []);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var history = AttributeReading.SidsOf(subject, "sIDHistory");

        // An object carrying no SID history is the ordinary case and is genuinely clean. This is the
        // one place the rule must not name a missing attribute: doing so would report an unread
        // input against very nearly every object in the forest, which reads as a broken capture.
        if (history.IsAbsent)
            return RuleVerdict.Judged([]);

        var matches = Matched(history.Sids);

        // Nothing privileged among the values that were read, and at least one value that was not.
        // The rule cannot say this object is clean, because the thing it is looking for could be in
        // the value it could not decode. Silence here would be a claim of completeness the evidence
        // does not support (decisions 0002 and 0086).
        if (matches.Count == 0)
        {
            return history.IsComplete
                ? RuleVerdict.Judged([])
                : RuleVerdict.CouldNotJudge(["sIDHistory"]);
        }

        if (subject.ObjectGuid is not { } objectGuid)
            return RuleVerdict.Judged([]);

        // A privileged identifier was found, so the finding is true whether or not every other value
        // was readable - and reporting it beside the count of what could not be read tells an
        // operator more than falling silent would. What must not happen is the partial answer being
        // presented as a complete one, which is what IsComplete on the evidence is for.
        var objectSid = AttributeReading.SidsOf(subject, "objectSid").Sids.FirstOrDefault();
        var name = AttributeReading.Text(subject, "sAMAccountName") ?? subject.DistinguishedName;
        var objectClass = AttributeReading.LastText(subject, "objectClass") ?? string.Empty;

        var evidence = new PrivilegedSidHistoryEvidence(
            objectSid, history.Sids, matches, history.UnreadableValues);

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
                Wording(name, objectSid, evidence),
                subject.Completeness,
                evidence),
        ]);
    }

    /// <summary>
    /// The history values this product treats as privileged.
    /// </summary>
    /// <remarks>
    /// The decision and the name both come from <see cref="PrivilegedSidCatalogue"/>, which
    /// <c>JudgementReader</c> also asks when it reconstructs a stored finding - so a finding read
    /// back cannot disagree with the rule that wrote it.
    /// </remarks>
    private static IReadOnlyList<PrivilegedSidHistoryMatch> Matched(IReadOnlyList<string> history) =>
    [
        .. history
            .Select(value => (Value: value, Name: PrivilegedSidCatalogue.PrivilegedName(value)))
            .Where(v => v.Name is not null)
            .Select(v => new PrivilegedSidHistoryMatch(
                v.Value,
                Sid.RelativeIdentifier(v.Value) ?? 0,
                v.Name!)),
    ];

    /// <summary>
    /// What an operator reads: what is true, why it is not visible elsewhere, and what to do.
    /// </summary>
    /// <remarks>
    /// <b>It states the action and what it may break, and never that the customer is then safe.</b>
    /// Removing the value can take away access the account still depends on, because permissions
    /// left over from the migration may name only the old identifier.
    /// </remarks>
    private static string Wording(
        string name, string? objectSid, PrivilegedSidHistoryEvidence evidence)
    {
        var carried = string.Join(
            ", ",
            evidence.Matches.Select(m => $"{m.Name} ({m.Sid})"));

        var ownDomain = Sid.IssuingDomain(objectSid);
        var fromElsewhere = ownDomain is not null && evidence.Matches.All(m =>
            !string.Equals(
                Sid.IssuingDomain(m.Sid),
                ownDomain,
                StringComparison.OrdinalIgnoreCase));

        var origin = fromElsewhere ? " issued by another domain" : string.Empty;

        var unranked = evidence.UnrankedValues.Count;
        var others = unranked == 0
            ? string.Empty
            : $" The account carries {unranked} further SID history "
                + $"{(unranked == 1 ? "value" : "values")} that this product cannot rank, because "
                + "what they were granted lives in the domain that issued them.";

        var unreadable = evidence.IsComplete
            ? string.Empty
            : $" A further {evidence.UnreadableValues} "
                + $"{(evidence.UnreadableValues == 1 ? "value was" : "values were")} present but "
                + "could not be read, so this account may carry more than is listed here.";

        return $"{name} carries a privileged identifier in its SID history{origin}: {carried}. "
            + "Every value in SID history is placed in the account's access token at sign-in and "
            + "grants access exactly as membership of that group would, but it appears in no group "
            + "membership listing, so a review of that group's members will not show this account. "
            + "Confirm the value is still required, then remove it with "
            + "Set-ADUser -Remove @{SIDHistory='…'}. Removing it may take away access the account "
            + "still relies on, if permissions left behind by the migration name only the old "
            + "identifier."
            + others
            + unreadable;
    }
}
