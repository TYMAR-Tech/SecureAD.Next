using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;

namespace SecureAD.Judgement;

/// <summary>
/// The three rules that report a <c>userAccountControl</c> flag weakening an account's credential.
/// </summary>
/// <remarks>
/// <para>
/// <b>One Microsoft assessment, three rules, one file.</b> SEC-028, SEC-029 and SEC-033 are rows of
/// the same table in Defender for Identity's <i>Unsecure account attributes</i>, and all three read
/// one bit of one attribute. Keeping them together is what keeps their reasoning from drifting
/// apart, which is what happened to the predecessor's four near-identical account lists.
/// </para>
/// <para>
/// <b>Three rules rather than one combined finding, deliberately.</b> Microsoft groups them; this
/// product does not, because acceptance is per finding (<c>docs/decisions/0080</c>,
/// <c>0023</c>). An operator must be able to accept "this legacy device genuinely needs DES"
/// without also accepting "this account has no password", and one finding covering both would make
/// that impossible.
/// </para>
/// <para>
/// Specified in docs/layers/judgement/rules/SEC-028-029-033-unsecure-account-flags.md.
/// </para>
/// </remarks>
internal static class UnsecureAccountFlagRules
{
    /// <summary>
    /// <c>INTERDOMAIN_TRUST_ACCOUNT</c>: an account representing a trust with another domain.
    /// </summary>
    /// <remarks>
    /// <c>0x0800</c>, decimal 2048, from Microsoft's list of property flags. Used only by SEC-028,
    /// and only because Microsoft documents these accounts as carrying <c>PASSWD_NOTREQD</c> by
    /// design.
    /// </remarks>
    internal const uint InterdomainTrustAccount = 0x00000800;

    /// <summary>
    /// Judges one object against one flag, or explains why it could not.
    /// </summary>
    /// <remarks>
    /// <b>The shape is <see cref="NoKerberosPreauthentication"/>'s, and the reasoning with it.</b>
    /// A missing attribute is an unread input rather than a zero; an attribute that is present but
    /// not a number is also not a zero, because reading it as one would silently report the account
    /// as fine.
    /// </remarks>
    internal static RuleVerdict Judge(
        ObjectAttributes subject,
        RuleDefinition definition,
        uint flag,
        Func<string, UserAccountControlEvidence, string> wording,
        bool excludeTrustAccounts = false)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var missing = definition.RequiredAttributes
            .Where(a => !AttributeReading.HasTextValue(subject, a))
            .ToArray();

        if (missing.Length > 0)
            return RuleVerdict.CouldNotJudge(missing);

        if (subject.ObjectGuid is not { } objectGuid)
            return RuleVerdict.Judged([]);

        if (AttributeReading.UnsignedInteger(subject, "userAccountControl") is not { } control)
            return RuleVerdict.CouldNotJudge(["userAccountControl"]);

        if ((control & flag) == 0)
            return RuleVerdict.Judged([]);

        // Microsoft: "A Windows trust account is exempt from having a password through PASSWD_NOTREQD
        // ... because trust objects don't use the traditional password policy", and the flag "is set
        // on INTERDOMAIN_TRUST_ACCOUNT accounts by default". Reporting them would be a finding
        // against every trust in the forest, all of them by design and all of them false.
        //
        // Read from the object's own bit rather than its name or its container, because those are
        // conventions and this is the directory's own statement about what the object is.
        if (excludeTrustAccounts && (control & InterdomainTrustAccount) != 0)
            return RuleVerdict.Judged([]);

        var name = AttributeReading.Text(subject, "sAMAccountName") ?? subject.DistinguishedName;
        var objectClass = AttributeReading.LastText(subject, "objectClass") ?? string.Empty;
        var evidence = new UserAccountControlEvidence(control);

        return RuleVerdict.Judged(
        [
            new Finding(
                definition.Id,
                definition.Version,
                definition.Severity,
                new FindingSubject(FindingSubjectKind.Account, name),
                objectGuid,
                subject.DistinguishedName,
                DnHelper.DnToFqdn(subject.DistinguishedName),
                objectClass,
                wording(name, evidence),
                subject.Completeness,
                evidence),
        ]);
    }

    /// <summary>
    /// The sentence added when the account is disabled, shared by all three rules.
    /// </summary>
    /// <remarks>
    /// The flag survives re-enabling, so a disabled account is dormant rather than safe. Saying so
    /// changes what an operator does first, which is why it belongs in the wording and not only in
    /// the stored evidence.
    /// </remarks>
    internal static string DisabledNote(UserAccountControlEvidence evidence) =>
        evidence.IsDisabled
            ? " The account is currently disabled, which lowers the urgency but not the need to "
                + "clear the setting, because re-enabling it would restore the exposure."
            : string.Empty;
}

/// <summary>
/// SEC-028 - an account that is not required to have a password.
/// </summary>
/// <remarks>
/// <para>
/// <b>Microsoft's own worked example of the assessment.</b> <i>Unsecure account attributes</i>: "if
/// the <b>PasswordNotRequired</b> attribute is enabled, an attacker can easily access the account.
/// This is especially risky if the account has privileged access to other resources."
/// </para>
/// <para>
/// <b>What the flag actually does.</b> <c>PASSWD_NOTREQD</c> - "No password is required" - exempts
/// the account from the domain's minimum password length, so it may hold an empty password. The
/// domain's password policy is still in force and still says otherwise; this account is simply not
/// subject to that part of it, and nothing on the policy screen shows that.
/// </para>
/// <para>
/// <b>Trust accounts are excluded, and that is Microsoft's statement rather than this product's
/// judgement.</b> See <see cref="UnsecureAccountFlagRules.InterdomainTrustAccount"/>.
/// </para>
/// </remarks>
public sealed class PasswordNotRequired : IRule
{
    /// <summary><c>PASSWD_NOTREQD</c>: no password is required.</summary>
    internal const uint PasswordNotRequiredFlag = 0x00000020;

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        "SEC-028",
        "Account not required to have a password",
        Severity.High,
        Version: 1,
        SubjectClasses: ["user", "computer"],
        RequiredAttributes: ["userAccountControl", "objectClass"],
        RequiredDerivedFacts: []);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        UnsecureAccountFlagRules.Judge(
            subject,
            Definition,
            PasswordNotRequiredFlag,
            (name, evidence) =>
                $"{name} is not required to have a password, so it may have none at all and the "
                + "domain's minimum password length does not apply to it. Anyone able to reach "
                + "authentication could sign in as this account without knowing anything. Clear "
                + "\"Password not required\" on the account, then set a password on it."
                + UnsecureAccountFlagRules.DisabledNote(evidence),
            excludeTrustAccounts: true);
}

/// <summary>
/// SEC-029 - an account whose password is stored so that it can be decrypted.
/// </summary>
/// <remarks>
/// <para>
/// <b>What is stored is the password, not a hash of it.</b> With
/// <c>ENCRYPTED_TEXT_PWD_ALLOWED</c> set, the directory keeps a reversibly encrypted copy, so
/// whoever reaches it recovers the password itself rather than something that must be attacked
/// first. Microsoft's stated reason for removing the setting is exactly that: "Removing this
/// setting prevents easy decryption of the account's password."
/// </para>
/// <para>
/// <b>Clearing the flag is not the whole remedy, and the wording says so.</b> The stored value
/// remains until the password is changed, so an operator who clears the flag and stops has left the
/// recoverable copy where it was.
/// </para>
/// </remarks>
public sealed class ReversiblePasswordEncryption : IRule
{
    /// <summary><c>ENCRYPTED_TEXT_PWD_ALLOWED</c>: the user can send an encrypted password.</summary>
    internal const uint ReversibleEncryption = 0x00000080;

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        "SEC-029",
        "Password stored using reversible encryption",
        Severity.High,
        Version: 1,
        SubjectClasses: ["user", "computer"],
        RequiredAttributes: ["userAccountControl", "objectClass"],
        RequiredDerivedFacts: []);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        UnsecureAccountFlagRules.Judge(
            subject,
            Definition,
            ReversibleEncryption,
            (name, evidence) =>
                $"{name} has its password stored using reversible encryption, so the directory "
                + "holds a copy that can be decrypted back to the password itself rather than a "
                + "hash that would have to be attacked. Clear \"Store password using reversible "
                + "encryption\" on the account and then change its password - clearing the setting "
                + "alone leaves the recoverable copy in place until the password changes."
                + UnsecureAccountFlagRules.DisabledNote(evidence));
}

/// <summary>
/// SEC-033 - an account restricted to DES encryption for Kerberos.
/// </summary>
/// <remarks>
/// <para>
/// <c>USE_DES_KEY_ONLY</c> - "Restrict this principal to use only Data Encryption Standard (DES)
/// encryption types for keys." Microsoft's stated reason for removing it: "Removing this setting
/// enables the use of stronger encryption algorithms."
/// </para>
/// <para>
/// <b>Medium rather than High, and the reasoning is in the rule document.</b> The credential still
/// has to be attacked, where SEC-028 leaves an account that may need no credential and SEC-029
/// stores a recoverable one. This is a degraded protection rather than an absent one.
/// </para>
/// <para>
/// <b>The flag is usually present because something could not do better</b>, so the wording asks
/// what authenticates as the account before the setting is cleared.
/// </para>
/// </remarks>
public sealed class DesEncryptionOnly : IRule
{
    /// <summary><c>USE_DES_KEY_ONLY</c>: restrict this principal to DES encryption types.</summary>
    internal const uint DesKeyOnly = 0x00200000;

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        "SEC-033",
        "Account restricted to DES encryption",
        Severity.Medium,
        Version: 1,
        SubjectClasses: ["user", "computer"],
        RequiredAttributes: ["userAccountControl", "objectClass"],
        RequiredDerivedFacts: []);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        UnsecureAccountFlagRules.Judge(
            subject,
            Definition,
            DesKeyOnly,
            (name, evidence) =>
                $"{name} is restricted to DES encryption for Kerberos, a cipher that has been "
                + "broken for years, so tickets encrypted for this account are far cheaper to "
                + "attack than they should be. Clear \"Use Kerberos DES encryption types for this "
                + "account\". The setting is usually present because something authenticating as "
                + "this account could not do better, so establish what that is first."
                + UnsecureAccountFlagRules.DisabledNote(evidence));
}
