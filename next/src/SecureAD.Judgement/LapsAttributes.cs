using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>
/// The attribute names and class test the two LAPS rules share, and what a schema answer means to
/// them.
/// </summary>
/// <remarks>
/// <para>
/// <b>Its own type, because gate 4's exemption is granted per type.</b> A compiled table of
/// constants living inside a rule would exempt the rule's judging along with the table -
/// <c>PrivilegedSidCatalogue</c> is separate from <c>PrivilegedSidHistory</c> for exactly this
/// reason, and <c>GpoClientSideExtensionCatalog</c> was split out of
/// <c>GpoClientSideExtensions</c> in August for the same one.
/// </para>
/// <para>
/// <b>Shared by both rules so that they cannot disagree about the population they divide.</b>
/// SEC-091 reports a machine carrying neither timestamp and SEC-094 one carrying only the legacy
/// value. If the two spelled an attribute name differently, or tested the class differently, a
/// machine could be reported by both or by neither, and nothing would say so.
/// </para>
/// </remarks>
public static class LapsAttributes
{
    /// <summary>
    /// <c>msLAPS-PasswordExpirationTime</c>: Microsoft's own signal that a machine is managed by
    /// Windows LAPS.
    /// </summary>
    public const string WindowsLapsExpiration = "msLAPS-PasswordExpirationTime";

    /// <summary>
    /// <c>ms-Mcs-AdmPwdExpirationTime</c>: the legacy Microsoft LAPS timestamp, which no migration
    /// step ever clears.
    /// </summary>
    public const string LegacyLapsExpiration = "ms-Mcs-AdmPwdExpirationTime";

    /// <summary>
    /// <c>msLAPS-Password</c>: the Windows LAPS password in clear text, written only when
    /// <c>ADPasswordEncryptionEnabled</c> is off.
    /// </summary>
    /// <remarks>
    /// Microsoft's schema reference gives this attribute a <c>SearchFlags</c> value of 904, whose
    /// constituent bits include <c>fCONFIDENTIAL</c> - which is what makes reading it need
    /// <c>CONTROL_ACCESS</c> as well as <c>READ_PROPERTY</c>.
    /// </remarks>
    public const string WindowsLapsPassword = "msLAPS-Password";

    /// <summary>
    /// <c>msLAPS-EncryptedPassword</c>: where Windows LAPS writes the password instead when
    /// encryption is on, which Microsoft both recommends and defaults to.
    /// </summary>
    /// <remarks>
    /// <b>Watched because omitting it would report a well-configured estate as clean.</b> The
    /// password is in one attribute or the other and never both, so a rule matching only
    /// <see cref="WindowsLapsPassword"/> finds nothing on a forest following Microsoft's advice -
    /// while a broad principal holds read access to the attribute actually carrying the secret.
    /// Reading it is not the same as reading the password: decryption is governed by the
    /// <c>ADPasswordEncryptionPrincipal</c> policy setting and never by the access control list.
    /// </remarks>
    public const string WindowsLapsEncryptedPassword = "msLAPS-EncryptedPassword";

    /// <summary>
    /// <c>ms-Mcs-AdmPwd</c>: the legacy Microsoft LAPS password, always in clear text.
    /// </summary>
    public const string LegacyLapsPassword = "ms-Mcs-AdmPwd";

    /// <summary>
    /// The class both rules judge, tested as the object's <i>most derived</i> class.
    /// </summary>
    /// <remarks>
    /// <b>A computer's <c>objectClass</c> contains "user".</b> The chain is
    /// <c>top, person, organizationalPerson, user, computer</c>, so a rule asking whether "computer"
    /// is present is safe in this direction - but the reverse test is not, and reading the last
    /// value is what keeps a group managed service account, whose chain continues past
    /// <c>computer</c>, from being judged as an ordinary machine.
    /// </remarks>
    private const string JudgedClass = "computer";

    /// <summary>
    /// <c>ADS_UF_ACCOUNTDISABLE</c>. A disabled computer account has no live machine behind it.
    /// </summary>
    private const uint AccountDisabled = 0x2;

    /// <summary>
    /// Whether the computer account is disabled, which takes it out of both LAPS rules.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Decided by the owner on 2026-09-03, and the forest is what raised it.</b> The first
    /// <c>ad.lab</c> run reported <c>CN=BADC,CN=Computers,DC=ad,DC=lab</c> and
    /// <c>CN=PHDC,CN=Computers,DC=ad,DC=lab</c> at Medium, telling an operator to deploy Windows
    /// LAPS to them. Both carry <c>userAccountControl</c> 4098 - a workstation trust account that is
    /// disabled - and both are leftovers from machines since promoted into child domains. There is
    /// no running machine, so there is no local administrator password for anything to rotate and
    /// the advice cannot be followed.
    /// </para>
    /// <para>
    /// <b>This departs from <c>SEC-021</c>, which reports a disabled account, and the difference is
    /// real.</b> A disabled <i>user</i> account still carries a service name and a password, so
    /// re-enabling it restores the exposure exactly. A disabled <i>computer</i> account is not a
    /// dormant exposure: the exposure this rule reports lives on the machine's local security
    /// database, and a stale account in the directory has no machine attached to it.
    /// </para>
    /// <para>
    /// <b>What it costs, recorded rather than hidden.</b> A machine that is temporarily disabled -
    /// switched off for a month, or awaiting rebuild - is genuinely unmanaged and is now silent.
    /// The judgement is that a stale account is far commoner than a temporarily disabled live one,
    /// and that unfollowable advice on the common case is worse than silence on the rare one. The
    /// stale accounts themselves are a real finding of a different kind, and are a punch-list item
    /// rather than something smuggled into a LAPS rule.
    /// </para>
    /// </remarks>
    /// <param name="subject">The object being judged.</param>
    public static bool IsDisabled(ObjectAttributes subject) =>
        (AttributeReading.UnsignedInteger(subject, "userAccountControl") & AccountDisabled) != 0;

    /// <summary>
    /// What a rule may do about an attribute, given what this forest's schema said about it.
    /// </summary>
    public enum Readability
    {
        /// <summary>
        /// The attribute exists here and is not withheld, so its absence on an object is a fact
        /// about that object and may be reported.
        /// </summary>
        Reportable,

        /// <summary>
        /// This forest's schema has no such attribute, so no object in it can carry a value.
        /// Absence is not evidence about any machine and the rule must stay silent - reporting
        /// would report the whole estate for the state of its schema.
        /// </summary>
        NotInThisForest,

        /// <summary>
        /// The forest withholds it, or nobody read the schema. Absence proves nothing, so the rule
        /// says it could not judge rather than saying nothing is wrong.
        /// </summary>
        Withheld,
    }

    /// <summary>
    /// Whether an absent value may be treated as a fact about the machine.
    /// </summary>
    /// <param name="visibility">What the derivation read out of the schema partition.</param>
    /// <param name="ldapDisplayName">The attribute.</param>
    public static Readability Judgeability(
        StoredAttributeVisibility visibility, string ldapDisplayName)
    {
        ArgumentNullException.ThrowIfNull(visibility);

        return visibility.Answer(ldapDisplayName) switch
        {
            AttributeVisibilityAnswer.Readable => Readability.Reportable,
            AttributeVisibilityAnswer.NotInSchema => Readability.NotInThisForest,
            _ => Readability.Withheld,
        };
    }

    /// <summary>Whether this object is a computer, by its most derived class.</summary>
    /// <param name="subject">The object being judged.</param>
    public static bool IsComputer(ObjectAttributes subject) =>
        string.Equals(ClassOf(subject), JudgedClass, StringComparison.OrdinalIgnoreCase);

    /// <summary>The object's most derived class, or the empty string where none was captured.</summary>
    /// <param name="subject">The object being judged.</param>
    public static string ClassOf(ObjectAttributes subject) =>
        AttributeReading.LastText(subject, "objectClass") ?? string.Empty;
}
