using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;

namespace SecureAD.Judgement;

/// <summary>
/// SEC-022 - an account that does not require Kerberos pre-authentication.
/// </summary>
/// <remarks>
/// <para>
/// <b>What pre-authentication is for.</b> Normally an account proves it knows its own password
/// before the key distribution centre will answer, by encrypting a timestamp with a key derived from
/// that password. Turning that requirement off means the centre answers anybody who asks.
/// </para>
/// <para>
/// <b>Why that matters, in Microsoft's words.</b> Defender for Identity, <i>Suspected AS-REP
/// Roasting attack</i> (external ID 2412): attackers "detect accounts with their Kerberos
/// preauthentication disabled and send AS-REQ requests without the encrypted timestamp. In response
/// they receive AS-REP messages with TGT data, which may be encrypted with an insecure algorithm
/// such as RC4, and save them for later use in an offline password cracking attack." <b>No
/// credentials of any kind are needed to start this</b>, which is what separates it from
/// kerberoasting and is why the severity here is High.
/// </para>
/// <para>
/// <b>What the customer can therefore mitigate.</b> Defender for Identity, <i>Unsecure account
/// attributes</i>, gives the remedy verbatim: remove "Don't require Kerberos preauthentication" from
/// the account properties, because "removing this setting requires a Kerberos pre-authentication for
/// the account resulting in improved security." The wording below says that and no more.
/// </para>
/// <para>
/// <b>The bit is Microsoft's and was read from three of its pages.</b> <c>0x400000</c> is
/// <c>ADS_UF_DONT_REQUIRE_PREAUTH</c>, "this account does not require Kerberos preauthentication for
/// logon", in the <c>ADS_USER_FLAG_ENUM</c> enumeration, the <c>User-Account-Control</c> schema page
/// and the UserAccountControl troubleshooting article, which also gives the decimal 4194304. It is
/// pinned beside the other flags by <c>UserAccountControlWording</c>.
/// </para>
/// <para>
/// <b>Nothing is excluded, and that is a decision rather than an oversight.</b> The predecessor
/// dropped disabled accounts and krbtgt. No Microsoft source says a key distribution centre refuses
/// an AS-REQ for a disabled account, so that exclusion would rest on a belief this product cannot
/// evidence - and silently dropping a real misconfiguration is the more expensive mistake. The
/// disabled state travels in the evidence instead, so an operator sees it and decides.
/// </para>
/// </remarks>
public sealed class NoKerberosPreauthentication : IObjectRule
{
    /// <summary>
    /// <c>ADS_UF_DONT_REQUIRE_PREAUTH</c>: this account does not require Kerberos
    /// pre-authentication for logon.
    /// </summary>
    internal const uint DontRequirePreauth = 0x00400000;

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        "SEC-022",
        "Kerberos pre-authentication not required",
        Severity.High,
        Version: 1,
        SubjectClasses: ["user", "computer"],
        RequiredAttributes: ["userAccountControl", "objectClass"],
        RequiredDerivedFacts: []);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var missing = Definition.RequiredAttributes
            .Where(a => !AttributeReading.HasTextValue(subject, a))
            .ToArray();

        if (missing.Length > 0)
            return RuleVerdict.CouldNotJudge(missing);

        if (subject.ObjectGuid is not { } objectGuid)
            return RuleVerdict.Judged([]);

        // A value that is present but not a number is not an absent value. Saying "not captured"
        // here would send an operator to look at his capture for a fault that is in the directory.
        if (AttributeReading.UnsignedInteger(subject, "userAccountControl") is not { } control)
            return RuleVerdict.CouldNotJudge(["userAccountControl"]);

        if ((control & DontRequirePreauth) == 0)
            return RuleVerdict.Judged([]);

        var name = AttributeReading.Text(subject, "sAMAccountName") ?? subject.DistinguishedName;
        var objectClass = AttributeReading.LastText(subject, "objectClass") ?? string.Empty;
        var evidence = new UserAccountControlEvidence(control);

        // The disabled state changes what an operator should do first, so it belongs in the sentence
        // rather than only in the stored evidence, which no one reads at a glance.
        var disabled = evidence.IsDisabled
            ? " The account is currently disabled, which lowers the urgency but not the need to "
                + "clear the setting, because re-enabling it would restore the exposure."
            : string.Empty;

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
                $"{name} does not require Kerberos pre-authentication, so anyone on the network "
                    + "can ask a domain controller for material encrypted from this account's "
                    + "password and crack it offline, without needing any credentials first. "
                    + "Clear \"Do not require Kerberos preauthentication\" on the account."
                    + disabled,
                subject.Completeness,
                evidence),
        ]);
    }
}
