using SecureAD.Audit.Capture;
using Xunit;
using SecureAD.Kernel.Capture;

namespace SecureAD.Next.Tests.Capture;

/// <summary>
/// The product reads <b>permissions on</b> credential material. It never reads the credential.
///
/// <para>
/// This became load-bearing on 2026-08-11, when the owner decided that who may read a BitLocker
/// recovery key is a question the product should answer. It is answered from the access control
/// list on the <c>msFVE-RecoveryInformation</c> object, which is a child of the computer object
/// (<see href="https://learn.microsoft.com/windows/win32/adschema/c-msfve-recoveryinformation">ms-FVE-RecoveryInformation
/// class</see>) - and never from <c>msFVE-RecoveryPassword</c>, which is the 48-digit key itself.
/// </para>
/// <para>
/// <b>Why this is a guard rather than a note.</b> The two are one line apart in the same object, and
/// the reasoning that puts the object in scope reads, at a glance, like reasoning that puts its
/// attributes in scope. A later session adding "just the recovery GUID, for correlation" is one
/// slip from a bundle that holds every BitLocker key in the estate - a signed, exportable file that
/// customers forward to auditors and insurers. An audit tool that collects credentials is not a
/// degraded audit tool; it is a different and much worse kind of software.
/// </para>
/// <para>
/// The list is deliberately wider than anything anyone has proposed capturing. A forbidden name that
/// nobody wanted costs nothing; a missing one costs everything.
/// </para>
/// </summary>
public sealed class CredentialAttributeGuardTests
{
    /// <summary>
    /// Attributes that are, or directly yield, authentication material. Named by
    /// <c>lDAPDisplayName</c>, matched without regard to case.
    ///
    /// <para>
    /// Verified against Microsoft's schema reference: <c>unicodePwd</c>,
    /// <c>supplementalCredentials</c> (<i>"the encrypted version of the user's password"</i>),
    /// <c>msDS-ManagedPassword</c> (<i>"a blob that contains the clear-text previous and current
    /// password"</i>), <c>msFVE-RecoveryPassword</c>, <c>msFVE-KeyPackage</c>, and
    /// <c>msKds-RootKeyData</c>, which is the key the whole group-managed-service-account scheme
    /// derives from and the object of the Golden gMSA attack. The password-history and LAPS names
    /// come from those products' own documentation rather than from this session's reading, and are
    /// included because the cost of a wrong entry here is zero.
    /// </para>
    /// </summary>
    private static readonly string[] NeverCaptured =
    [
        "unicodePwd",
        "dBCSPwd",
        "ntPwdHistory",
        "lmPwdHistory",
        "supplementalCredentials",
        "msDS-ManagedPassword",
        "msFVE-RecoveryPassword",
        "msFVE-KeyPackage",
        "msKds-RootKeyData",
        "ms-Mcs-AdmPwd",
        "msLAPS-Password",
        "msLAPS-EncryptedPassword",
        "msLAPS-EncryptedPasswordHistory",
        "msLAPS-EncryptedDSRMPassword",
        "msLAPS-EncryptedDSRMPasswordHistory",
    ];

    [Fact]
    public void TheCatalogueNeverRequestsACredential()
    {
        var forbidden = NeverCaptured.ToHashSet(StringComparer.OrdinalIgnoreCase);

        var offenders = CapturedAttributeCatalog.All
            .Where(a => forbidden.Contains(a.LdapDisplayName))
            .Select(a => "  " + a.LdapDisplayName)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "The catalogue requests attributes that are authentication material. This product "
            + "reads permissions on credential objects and never the credentials themselves. A "
            + "bundle is sealed, exportable, and forwarded by customers to auditors and insurers; "
            + "one holding recovery keys or password hashes is not a degraded audit tool but a "
            + "different and much worse kind of software:"
            + Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// The scanner self-test. Without it this passes by checking an empty catalogue against a list,
    /// or a catalogue against an empty list, and reporting a clean bill either way.
    /// </summary>
    [Fact]
    public void TheGuardHasBothACatalogueAndAListToCheckItAgainst()
    {
        Assert.True(CapturedAttributeCatalog.All.Count > 0, "The catalogue requests nothing.");
        Assert.True(NeverCaptured.Length > 0, "The forbidden list is empty.");
        Assert.Contains("msFVE-RecoveryPassword", NeverCaptured);
        Assert.Contains("unicodePwd", NeverCaptured);
    }

    /// <summary>
    /// The guard is shown to work against the exact mistake it exists for: the attribute that sits
    /// on the object the product now deliberately audits. A list narrowed until it no longer names
    /// this fails here.
    /// </summary>
    [Theory]
    [InlineData("msFVE-RecoveryPassword")]
    [InlineData("msFVE-KeyPackage")]
    [InlineData("msDS-ManagedPassword")]
    [InlineData("unicodePwd")]
    [InlineData("ms-Mcs-AdmPwd")]
    [InlineData("msLAPS-Password")]
    [InlineData("msLAPS-EncryptedPassword")]
    public void TheGuardStillForbidsTheOnesItWasWrittenFor(string attribute)
    {
        Assert.Contains(attribute, NeverCaptured, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The LAPS half of the same decision, and the reason the three LAPS names above were pinned on
    /// 2026-08-13 rather than left implicit.
    ///
    /// <para>
    /// S-23 put <c>ms-Mcs-AdmPwdExpirationTime</c> and <c>msLAPS-PasswordExpirationTime</c> into
    /// the catalogue, because SEC-091 and SEC-092 cannot be answered without them. Those names
    /// differ from the password attributes beside them by a suffix. An owner decision of the same
    /// day is that a LAPS password value is never requested, so the mistake this guards against is
    /// no longer hypothetical: it is a five-character edit away, in a file that now legitimately
    /// mentions LAPS.
    /// </para>
    /// </summary>
    [Fact]
    public void TheCatalogueTakesTheLapsTimestampAndNotTheLapsPassword()
    {
        var computer = CapturedAttributeCatalog.AttributesJustifiedBy("computer");

        Assert.Contains(computer, a => a.LdapDisplayName == "msLAPS-PasswordExpirationTime");
        Assert.Contains(computer, a => a.LdapDisplayName == "ms-Mcs-AdmPwdExpirationTime");

        Assert.DoesNotContain(computer, a => a.LdapDisplayName == "msLAPS-Password");
        Assert.DoesNotContain(computer, a => a.LdapDisplayName == "ms-Mcs-AdmPwd");
        Assert.DoesNotContain(
            computer,
            a => a.LdapDisplayName.Contains("EncryptedPassword", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The other side of the same decision, and the reason the guard is not simply "do not capture
    /// anything on that object". The BitLocker recovery object's own access control list is what
    /// answers who may read the key, and it arrives with every object because the security
    /// descriptor is universal.
    /// </summary>
    [Fact]
    public void ThePermissionsOnACredentialObjectAreStillCaptured()
    {
        var attributes = CapturedAttributeCatalog.AttributesJustifiedBy("msFVE-RecoveryInformation");

        Assert.Contains(attributes, a => a.LdapDisplayName == "nTSecurityDescriptor");
        Assert.DoesNotContain(attributes, a => a.LdapDisplayName.StartsWith("msFVE-", StringComparison.OrdinalIgnoreCase));
    }
}
