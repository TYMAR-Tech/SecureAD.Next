using System.Globalization;

namespace SecureAD.Kernel.Security;

/// <summary>
/// One flag of <c>userAccountControl</c>: the bit, the identifier Microsoft documents it under, and
/// what it means said plainly.
/// </summary>
/// <param name="Bit">The bit, as Learn's table gives it.</param>
/// <param name="Identifier">
/// The name Microsoft documents the bit under, so a reader can check this against Learn. That is
/// the <c>iads.h</c> name where one exists; <c>PARTIAL_SECRETS_ACCOUNT</c> has none, because it is
/// published only on KB 305144 and never reached the <c>ADS_USER_FLAG_ENUM</c> enumeration.
/// </param>
/// <param name="Wording">What the flag says about the account.</param>
public sealed record UserAccountControlFlag(uint Bit, string Identifier, string Wording);

/// <summary>
/// What an account's <c>userAccountControl</c> value says, one flag at a time.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the one place a bit becomes a word.</b> A wrong bit is the defect that cannot be seen:
/// it does not throw and it does not look odd, it renders as a confident <i>Disabled</i> beside an
/// account that is enabled, and an operator has no reason to doubt it. So the table below is
/// transcribed from Learn's own table at
/// <c>learn.microsoft.com/windows/win32/adschema/a-useraccountcontrol</c>, carries the
/// <c>iads.h</c> identifier of every entry so that it can be checked against Learn without reading
/// this code, and is asserted bit by bit by <c>UserAccountControlWordingTests</c>.
/// </para>
/// <para>
/// <b>A bit with no word is kept, not dropped.</b> Learn documents <c>0x4000</c> and <c>0x8000</c>
/// as unused and says nothing about <c>0x4</c>, and a directory is free to hold a bit this build was
/// written before. Discarding those would let this type report a complete reading of a value it did
/// not completely read - so <see cref="UnwordedBits"/> carries them and
/// <see cref="FlagsAreComplete"/> says whether there were any.
/// </para>
/// <para>
/// <b>Nothing here is a judgement.</b> <c>DONT_REQUIRE_PREAUTH</c> is worded as what it is and not
/// as a risk; whether it matters is a question for the classifier, on the reader's terms and
/// separately.
/// </para>
/// </remarks>
/// <param name="Value">The value as the directory holds it.</param>
/// <param name="Flags">The flags that are set, in ascending bit order.</param>
/// <param name="UnwordedBits">
/// The bits that are set and that this build has no word for. Zero when every set bit was worded.
/// </param>
public sealed record UserAccountControlWording(
    uint Value,
    IReadOnlyList<UserAccountControlFlag> Flags,
    uint UnwordedBits)
{
    /// <summary>
    /// Every flag Microsoft documents, in ascending bit order.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>0x00000004</c> is absent from Learn's table, and <c>0x00004000</c> and <c>0x00008000</c>
    /// are listed there as not used. None of the three is worded here, which is why a value setting
    /// one of them arrives with an unworded bit rather than silently as nothing.
    /// </para>
    /// <para>
    /// <b><c>PARTIAL_SECRETS_ACCOUNT</c> is here because two Microsoft pages were not enough.</b>
    /// adschema and <c>ADS_USER_FLAG_ENUM</c> agree on twenty-one flags and both descend from
    /// <c>iads.h</c> - one lineage read twice, which reads like corroboration and is not. KB 305144
    /// is maintained separately and publishes a twenty-second bit, <c>0x04000000</c>, marking a
    /// read-only domain controller. Without it an RODC's account rendered a raw hexadecimal number
    /// where a sentence belongs. Found 2026-08-21; this is the <c>F-S44-2</c> fault, and the only
    /// thing that caught it was a source outside the family.
    /// </para>
    /// <para>
    /// <b><c>ADS_UF_LOCKOUT</c> and <c>ADS_UF_PASSWORD_EXPIRED</c> are not current state, and both
    /// say so.</b> Microsoft names them in one sentence: in a Windows Server 2003 domain the two
    /// "have been replaced with a new attribute called <c>ms-DS-User-Account-Control-Computed</c>".
    /// Reading either out of a stored <c>userAccountControl</c> answers a question the directory
    /// stopped keeping the answer to there. Lockout is the worse of the two, because the obvious
    /// fallback is wrong as well - Learn's <c>Lockout-Time</c> remarks say the value "may be non
    /// zero, yet the account is not locked out", and only <c>lockoutTime</c> plus the domain's
    /// <c>Lockout-Duration</c> decides.
    /// </para>
    /// <para>
    /// The password entry was already caveated and the lockout entry was not, which is what marked
    /// it as an oversight rather than a decision. Corrected per <c>S-57</c> finding <c>#23</c>;
    /// the wording is deliberately the same shape as its pair so the next reader sees them treated
    /// alike.
    /// </para>
    /// <para>
    /// <b><c>ADS_UF_SERVER_TRUST_ACCOUNT</c> says domain controller, and Microsoft supports it.</b>
    /// The two ADSI pages - adschema and <c>ADS_USER_FLAG_ENUM</c> - describe <c>0x00002000</c> as a
    /// computer account for a <i>backup</i> domain controller, which is Windows NT vocabulary. KB
    /// 305144 words the same bit as "a computer account for a domain controller that is a member of
    /// this domain", which is what a current forest actually holds and what an administrator reading
    /// the report is looking at. The wording here follows that page deliberately; do not "correct"
    /// it to the older sentence.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<UserAccountControlFlag> Documented { get; } =
    [
        new(0x00000001, "ADS_UF_SCRIPT", "The logon script is executed."),
        new(0x00000002, "ADS_UF_ACCOUNTDISABLE", "The account is disabled."),
        new(0x00000008, "ADS_UF_HOMEDIR_REQUIRED", "The home directory is required."),
        new(
            0x00000010,
            "ADS_UF_LOCKOUT",
            "The account is locked out. Microsoft replaced this bit with "
            + "msDS-User-Account-Control-Computed, and lockoutTime answers only once the domain's "
            + "Lockout-Duration has been added to it."),
        new(0x00000020, "ADS_UF_PASSWD_NOTREQD", "No password is required."),
        new(0x00000040, "ADS_UF_PASSWD_CANT_CHANGE", "The user cannot change the password."),
        new(
            0x00000080,
            "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED",
            "The user can send an encrypted password."),
        new(
            0x00000100,
            "ADS_UF_TEMP_DUPLICATE_ACCOUNT",
            "This account is for a user whose primary account is in another domain. It gives "
            + "access to this domain, but not to any domain that trusts this domain. Also known "
            + "as a local user account."),
        new(0x00000200, "ADS_UF_NORMAL_ACCOUNT", "This is a typical user account."),
        new(
            0x00000800,
            "ADS_UF_INTERDOMAIN_TRUST_ACCOUNT",
            "This is a permit to trust account for a domain that trusts other domains."),
        new(
            0x00001000,
            "ADS_UF_WORKSTATION_TRUST_ACCOUNT",
            "This is a computer account for a computer that is a member of this domain."),
        new(
            0x00002000,
            "ADS_UF_SERVER_TRUST_ACCOUNT",
            "This is a computer account for a domain controller of this domain."),
        new(
            0x00010000,
            "ADS_UF_DONT_EXPIRE_PASSWD",
            "The password for this account never expires."),
        new(0x00020000, "ADS_UF_MNS_LOGON_ACCOUNT", "This is an MNS logon account."),
        new(0x00040000, "ADS_UF_SMARTCARD_REQUIRED", "The user must log on using a smart card."),
        new(
            0x00080000,
            "ADS_UF_TRUSTED_FOR_DELEGATION",
            "The service running under this account is trusted for Kerberos delegation, and can "
            + "impersonate a client that asks it for service."),
        new(
            0x00100000,
            "ADS_UF_NOT_DELEGATED",
            "This account's security context is not delegated to a service, even one trusted for "
            + "delegation."),
        new(
            0x00200000,
            "ADS_UF_USE_DES_KEY_ONLY",
            "This principal is restricted to Data Encryption Standard keys."),
        new(
            0x00400000,
            "ADS_UF_DONT_REQUIRE_PREAUTH",
            "This account does not require Kerberos pre-authentication to log on."),
        new(
            0x00800000,
            "ADS_UF_PASSWORD_EXPIRED",
            "The password has expired. The directory computes this from pwdLastSet and the domain "
            + "policy."),
        new(
            0x01000000,
            "ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION",
            "This account is enabled for delegation, and a service running under it can "
            + "authenticate as a client to other servers."),
        new(
            0x04000000,
            "PARTIAL_SECRETS_ACCOUNT",
            "This is a read-only domain controller account."),
    ];

    /// <summary>
    /// Whether every bit that is set was one this build has a word for.
    /// </summary>
    /// <remarks>
    /// False does not mean the reading is wrong; it means it is partial, and a screen showing
    /// flags without saying so would be claiming the account holds only what is listed.
    /// </remarks>
    public bool FlagsAreComplete => UnwordedBits == 0;

    /// <summary>
    /// Reads a stored <c>userAccountControl</c> value, or null when the text is not one.
    /// </summary>
    /// <remarks>
    /// The directory stores this as a decimal string of a 32-bit unsigned value. Text that is not
    /// one is not worded into anything: null sends the caller back to the stored form, which is a
    /// true statement about a value nobody can interpret, where a zero would be a false one.
    /// </remarks>
    /// <param name="stored">The value as the bundle holds it.</param>
    public static UserAccountControlWording? Of(string? stored)
    {
        if (!uint.TryParse(stored, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
            return null;

        var flags = Documented.Where(f => (value & f.Bit) != 0).ToArray();
        var worded = flags.Aggregate(0u, (mask, flag) => mask | flag.Bit);

        return new UserAccountControlWording(value, flags, value & ~worded);
    }
}
