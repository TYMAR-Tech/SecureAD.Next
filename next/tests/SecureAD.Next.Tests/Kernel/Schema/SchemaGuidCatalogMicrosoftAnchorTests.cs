using SecureAD.Kernel.Schema;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Schema;

/// <summary>
/// Every shipped catalogue entry, pinned to the value Microsoft publishes for it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> <c>SchemaGuidCatalogTests</c> checks the catalogue thoroughly and
/// checks almost none of its content: every GUID parses, every GUID is lowercase, no name
/// repeats, every kind is represented. All of that is structure. The one content assertion,
/// <c>WhenARuleSpecificationNamesAGuid_ThenTheCatalogueAgreesWithIt</c>, reads from internal rule
/// specifications - and rule specs name dangerous rights, so an entry was anchored if and only if
/// it was dangerous. The ordinary entries had no anchor of any kind, and eleven of them were
/// wrong. This test is the anchor they lacked.
/// </para>
/// <para>
/// <b>Keyed by GUID and kind together.</b> Two GUIDs legitimately mean two things -
/// <c>bf9679c0</c> is both the <c>Self-Membership</c> validated write and the <c>member</c>
/// attribute, and <c>72e39547</c> is both <c>Validated-DNS-Host-Name</c> and the
/// <c>DNS-Host-Name-Attributes</c> property set. A test that flattened this to a GUID-to-name map
/// would call both a duplicate and force one of them out of the table.
/// </para>
/// <para>
/// <b>The field differs by kind, and reading the wrong one manufactures a false finding.</b>
/// Extended rights, validated writes and property sets publish <c>Rights-GUID</c>; attributes
/// publish <c>System-Id-Guid</c>; classes publish <c>Schema-Id-Guid</c>. Each row below was taken
/// from the field belonging to its own kind.
/// </para>
/// <para>
/// <b>Three entries Microsoft does not publish.</b> <c>msDS-KeyCredentialLink</c>,
/// <c>ms-Mcs-AdmPwd</c> and <c>msLAPS-Password</c> have no page in the AD Schema reference and no
/// GUID in MS-ADTS. The LAPS pair are schema extensions rather than base schema, so there is no
/// general claim for Microsoft to make about them. Their rows are pinned to the shipped value to
/// stop it drifting unnoticed, but the shipped value is a convenience: capture reads every
/// schema-partition object carrying a <c>schemaIDGUID</c>, and the captured layer wins, so in any
/// run that read the schema the forest's own answer is the one used.
/// </para>
/// <para>
/// <b>ms-Mcs-AdmPwd is the weakest row here.</b> Legacy LAPS extends the schema without a fixed
/// <c>schemaIDGUID</c> in every deployment path, so this GUID may not be constant across forests.
/// It is pinned as a regression guard on the shipped table, not as a claim about any given forest.
/// SEC-090 reads this attribute, so the fallback being wrong would be a miss rather than noise.
/// </para>
/// </remarks>
public sealed class SchemaGuidCatalogMicrosoftAnchorTests
{
    private static SchemaGuidCatalog Catalog => SchemaGuidCatalog.Embedded;

    /// <summary>
    /// Each row is a value Microsoft publishes, taken from the AD Schema reference page for that
    /// entry, read from the GUID field belonging to its kind.
    /// </summary>
    [Theory]
    [InlineData(SchemaGuidKind.ExtendedRight, "Abandon-Replication", "ee914b82-0a98-11d1-adbb-00c04fd8d5cd")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Add-GUID", "440820ad-65b4-11d1-a3da-0000f875ae0d")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Allocate-Rids", "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Allowed-To-Authenticate", "68b1d179-0d15-4d4f-ab71-46152e79a7bc")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Apply-Group-Policy", "edacfd8f-ffb3-11d1-b41d-00a0c968f939")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Certificate-Enrollment", "0e10c968-78fb-11d2-90d4-00c04f79dc55")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Change-Infrastructure-Master", "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Create-Inbound-Forest-Trust", "e2a36dc9-ae17-47c3-b58b-be34c55ba633")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Do-Garbage-Collection", "fec364e0-0a98-11d1-adbb-00c04fd8d5cd")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Domain-Administer-Server", "ab721a52-1e2f-11d0-9819-00aa0040529b")]
    [InlineData(SchemaGuidKind.ExtendedRight, "DS-Check-Stale-Phantoms", "69ae6200-7f46-11d2-b9ad-00c04f79f805")]
    [InlineData(SchemaGuidKind.ExtendedRight, "DS-Clone-Domain-Controller", "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e")]
    [InlineData(SchemaGuidKind.ExtendedRight, "DS-Install-Replica", "9923a32a-3607-11d2-b9be-0000f87a36b2")]
    [InlineData(SchemaGuidKind.ExtendedRight, "DS-Query-Self-Quota", "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc")]
    [InlineData(SchemaGuidKind.ExtendedRight, "DS-Replication-Get-Changes", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")]
    [InlineData(SchemaGuidKind.ExtendedRight, "DS-Replication-Get-Changes-All", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")]
    [InlineData(SchemaGuidKind.ExtendedRight, "DS-Replication-Get-Changes-In-Filtered-Set", "89e95b76-444d-4c62-991a-0facbeda640c")]
    [InlineData(SchemaGuidKind.ExtendedRight, "DS-Replication-Manage-Topology", "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2")]
    [InlineData(SchemaGuidKind.ExtendedRight, "DS-Replication-Monitor-Topology", "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96")]
    [InlineData(SchemaGuidKind.ExtendedRight, "DS-Replication-Synchronize", "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Enable-Per-User-Reversibly-Encrypted-Password", "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Generate-RSoP-Logging", "b7b1b3de-ab09-4242-9e30-9980e5d322f7")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Generate-RSoP-Planning", "b7b1b3dd-ab09-4242-9e30-9980e5d322f7")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Manage-Optional-Features", "7c0e2a7c-a419-48e4-a995-10180aad54dd")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Migrate-SID-History", "ba33815a-4f93-4c76-87f3-57574bff8109")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Recalculate-Hierarchy", "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Recalculate-Security-Inheritance", "62dd28a8-7f46-11d2-b9ad-00c04f79f805")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Receive-As", "ab721a56-1e2f-11d0-9819-00aa0040529b")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Run-Protect-Admin-Groups-Task", "7726b9d5-a4b4-4288-a6b2-dce952e80a7f")]
    [InlineData(SchemaGuidKind.ExtendedRight, "SAM-Enumerate-Entire-Domain", "91d67418-0135-4acc-8d79-c08e857cfbec")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Send-As", "ab721a54-1e2f-11d0-9819-00aa0040529b")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Send-To", "ab721a55-1e2f-11d0-9819-00aa0040529b")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Unexpire-Password", "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501")]
    [InlineData(SchemaGuidKind.ExtendedRight, "Update-Password-Not-Required-Bit", "280f369c-67c7-438e-ae98-1d46f3c6f541")]
    [InlineData(SchemaGuidKind.ExtendedRight, "User-Change-Password", "ab721a53-1e2f-11d0-9819-00aa0040529b")]
    [InlineData(SchemaGuidKind.ExtendedRight, "User-Force-Change-Password", "00299570-246d-11d0-a768-00aa006e0529")]
    [InlineData(SchemaGuidKind.ValidatedWrite, "Self-Membership", "bf9679c0-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.ValidatedWrite, "Validated-DNS-Host-Name", "72e39547-7b18-11d1-adef-00c04fd8d5cd")]
    [InlineData(SchemaGuidKind.ValidatedWrite, "Validated-MS-DS-Additional-DNS-Host-Name", "80863791-dbe9-4eb8-837e-7f0ab55d9ac7")]
    [InlineData(SchemaGuidKind.ValidatedWrite, "Validated-MS-DS-Behavior-Version", "d31a8757-2447-4545-8081-3bb610cacbf2")]
    [InlineData(SchemaGuidKind.ValidatedWrite, "Validated-SPN", "f3a64788-5306-11d1-a9c5-0000f80367c1")]
    [InlineData(SchemaGuidKind.PropertySet, "DNS-Host-Name-Attributes", "72e39547-7b18-11d1-adef-00c04fd8d5cd")]
    [InlineData(SchemaGuidKind.PropertySet, "Domain-Other-Parameters", "b8119fd0-04f6-4762-ab7a-4986c76b3f9a")]
    [InlineData(SchemaGuidKind.PropertySet, "Domain-Password", "c7407360-20bf-11d0-a768-00aa006e0529")]
    [InlineData(SchemaGuidKind.PropertySet, "Email-Information", "e45795b2-9455-11d1-aebd-0000f80367c1")]
    [InlineData(SchemaGuidKind.PropertySet, "General-Information", "59ba2f42-79a2-11d0-9020-00c04fc2d3cf")]
    [InlineData(SchemaGuidKind.PropertySet, "Membership", "bc0ac240-79a9-11d0-9020-00c04fc2d4cf")]
    [InlineData(SchemaGuidKind.PropertySet, "MS-TS-GatewayAccess", "ffa6f046-ca4b-4feb-b40d-04dfee722543")]
    [InlineData(SchemaGuidKind.PropertySet, "Personal-Information", "77b5b886-944a-11d1-aebd-0000f80367c1")]
    [InlineData(SchemaGuidKind.PropertySet, "Private-Information", "91e647de-d96f-4b70-9557-d63ff4f3ccd8")]
    [InlineData(SchemaGuidKind.PropertySet, "Public-Information", "e48d0154-bcf8-11d1-8702-00c04fb96050")]
    [InlineData(SchemaGuidKind.PropertySet, "RAS-Information", "037088f8-0ae1-11d2-b422-00a0c968f939")]
    [InlineData(SchemaGuidKind.PropertySet, "Terminal-Server-License-Server", "5805bc62-bdc9-4428-a5e2-856a0f4c185e")]
    [InlineData(SchemaGuidKind.PropertySet, "User-Account-Restrictions", "4c164200-20c0-11d0-a768-00aa006e0529")]
    [InlineData(SchemaGuidKind.PropertySet, "User-Logon", "5f202010-79a5-11d0-9020-00c04fc2d4cf")]
    [InlineData(SchemaGuidKind.PropertySet, "Web-Information", "e45795b3-9455-11d1-aebd-0000f80367c1")]
    [InlineData(SchemaGuidKind.Attribute, "adminCount", "bf967918-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "description", "bf967950-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "displayName", "bf967953-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "distinguishedName", "bf9679e4-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "dNSHostName", "72e39547-7b18-11d1-adef-00c04fd8d5cd")]
    [InlineData(SchemaGuidKind.Attribute, "gPLink", "f30e3bbe-9ff0-11d1-b603-0000f80367c1")]
    [InlineData(SchemaGuidKind.Attribute, "homeDirectory", "bf967985-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "homeDrive", "bf967986-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "lastLogonTimestamp", "c0e20a04-0e5a-4ff3-9482-5efeaecd7060")]
    [InlineData(SchemaGuidKind.Attribute, "lockoutTime", "28630ebf-41d5-11d1-a9c1-0000f80367c1")]
    [InlineData(SchemaGuidKind.Attribute, "member", "bf9679c0-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "memberOf", "bf967991-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "msDS-AllowedToActOnBehalfOfOtherIdentity", "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79")]
    [InlineData(SchemaGuidKind.Attribute, "msDS-AllowedToDelegateTo", "800d94d7-b7a1-42a1-b14d-7cae1423d07f")]
    [InlineData(SchemaGuidKind.Attribute, "msDS-ResultantPSO", "b77ea093-88d0-4780-9a98-911f8e8b1dca")]
    [InlineData(SchemaGuidKind.Attribute, "nTSecurityDescriptor", "bf9679e3-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "objectClass", "bf9679e5-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "objectGUID", "bf9679e7-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "objectSid", "bf9679e8-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "pwdLastSet", "bf967a0a-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "sAMAccountName", "3e0abfd0-126a-11d0-a060-00aa006c33ed")]
    [InlineData(SchemaGuidKind.Attribute, "scriptPath", "bf9679a8-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "servicePrincipalName", "f3a64788-5306-11d1-a9c5-0000f80367c1")]
    [InlineData(SchemaGuidKind.Attribute, "sIDHistory", "17eb4278-d167-11d0-b002-0000f80367c1")]
    [InlineData(SchemaGuidKind.Attribute, "unicodePwd", "bf9679e1-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "userAccountControl", "bf967a68-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.Attribute, "userPrincipalName", "28630ebb-41d5-11d1-a9c1-0000f80367c1")]
    [InlineData(SchemaGuidKind.ObjectClass, "computer", "bf967a86-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.ObjectClass, "contact", "5cb41ed0-0e4c-11d0-a286-00aa003049e2")]
    [InlineData(SchemaGuidKind.ObjectClass, "container", "bf967a8b-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.ObjectClass, "domain", "19195a5a-6da0-11d0-afd3-00c04fd930c9")]
    [InlineData(SchemaGuidKind.ObjectClass, "group", "bf967a9c-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.ObjectClass, "groupPolicyContainer", "f30e3bc2-9ff0-11d1-b603-0000f80367c1")]
    [InlineData(SchemaGuidKind.ObjectClass, "msDS-GroupManagedServiceAccount", "7b8b558a-93a5-4af7-adca-c017e67f1057")]
    [InlineData(SchemaGuidKind.ObjectClass, "msDS-ManagedServiceAccount", "ce206244-5827-4a86-ba1c-1c0c386c1b64")]
    [InlineData(SchemaGuidKind.ObjectClass, "nTDSDSA", "f0f8ffab-1191-11d0-a060-00aa006c33ed")]
    [InlineData(SchemaGuidKind.ObjectClass, "organizationalUnit", "bf967aa5-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.ObjectClass, "pKICertificateTemplate", "e5209ca2-3bba-11d2-90cc-00c04fd91ab1")]
    [InlineData(SchemaGuidKind.ObjectClass, "printQueue", "bf967aa8-0de6-11d0-a285-00aa003049e2")]
    [InlineData(SchemaGuidKind.ObjectClass, "user", "bf967aba-0de6-11d0-a285-00aa003049e2")]
    public void WhenMicrosoftPublishesAnEntry_ThenTheCatalogueAgreesWithIt(
        SchemaGuidKind kind, string ldapName, string microsoftGuid)
    {
        AssertPinned(kind, ldapName, microsoftGuid);
    }

    /// <summary>
    /// Two control access rights absent from the AD Schema reference but carried, with both name
    /// and GUID, in MS-ADTS 5.1.3.2.1.
    /// </summary>
    [Theory]
    [InlineData(SchemaGuidKind.ExtendedRight, "Certificate-AutoEnrollment", "a05b8cc2-17bc-4802-a710-e7c15ab866a2")]
    [InlineData(SchemaGuidKind.ExtendedRight, "DS-Validated-Write-Computer", "9b026da6-0d3c-465c-8bee-5199d7165cba")]
    public void WhenOnlyMsAdtsPublishesAnEntry_ThenTheCatalogueAgreesWithIt(
        SchemaGuidKind kind, string ldapName, string microsoftGuid)
    {
        AssertPinned(kind, ldapName, microsoftGuid);
    }

    /// <summary>
    /// The three entries Microsoft publishes nowhere. Pinned so the shipped fallback cannot drift
    /// silently; see this class's remarks for why that is all these rows can be.
    /// </summary>
    [Theory]
    [InlineData(SchemaGuidKind.Attribute, "msDS-KeyCredentialLink", "5b47d60f-6090-40b2-9f37-2a4de88f3063")]
    [InlineData(SchemaGuidKind.Attribute, "ms-Mcs-AdmPwd", "2e0e4a88-f5fa-11df-b3af-001fc000a000")]
    [InlineData(SchemaGuidKind.Attribute, "msLAPS-Password", "53c5be7e-5403-4013-a04b-b22e05d0e3c1")]
    public void WhenMicrosoftPublishesNothing_ThenTheShippedFallbackStillDoesNotDrift(
        SchemaGuidKind kind, string ldapName, string shippedGuid)
    {
        AssertPinned(kind, ldapName, shippedGuid);
    }

    /// <summary>
    /// <c>DS-Replication-Get-Changes-All-Extended</c> is not an extended right. It is absent from
    /// Microsoft's <i>Extended Rights</i> index, and the GUID the catalogue published under that
    /// name belongs to <c>Do-Garbage-Collection</c>. <c>ClassifyExtendedRight</c> matches names
    /// exactly against <c>DangerousExtendedRights</c> and <c>ReplicationRights</c>, and the
    /// invented name was in neither, so this was a display defect rather than a verdict one - but
    /// a name nobody can look up is a name nobody can check.
    /// </summary>
    [Fact]
    public void WhenANameWasInvented_ThenTheCatalogueDoesNotDefineIt()
    {
        Assert.Null(Catalog.GuidFor("DS-Replication-Get-Changes-All-Extended"));
    }

    /// <summary>
    /// Every shipped entry is named by a row above. Without this, an entry added later inherits
    /// the exact gap this test exists to close - unanchored, and wrong until somebody notices.
    /// </summary>
    [Fact]
    public void WhenAnEntryIsShipped_ThenAPinnedRowNamesIt()
    {
        var pinned = PinnedKeys();

        var unpinned = SchemaGuidCatalog.Embedded.Entries
            .Where(e => !pinned.Contains((e.Guid.ToLowerInvariant(), e.Kind)))
            .Select(e => $"{e.Kind} {e.LdapName} {e.Guid}")
            .OrderBy(d => d, StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            unpinned.Length == 0,
            "These catalogue entries are not pinned to a published value:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, unpinned));
    }

    /// <summary>
    /// The catalogue holds exactly the pinned rows and nothing else. Guards the direction the
    /// previous test cannot: a pinned entry quietly dropped from the table.
    /// </summary>
    [Fact]
    public void WhenARowIsPinned_ThenTheCatalogueShipsIt()
    {
        var shipped = SchemaGuidCatalog.Embedded.Entries
            .Select(e => (e.Guid.ToLowerInvariant(), e.Kind))
            .ToHashSet();

        var missing = PinnedKeys()
            .Where(k => !shipped.Contains(k))
            .Select(k => $"{k.Item2} {k.Item1}")
            .OrderBy(d => d, StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            missing.Length == 0,
            "These pinned entries are not in the catalogue:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, missing));
    }

    private static void AssertPinned(SchemaGuidKind kind, string ldapName, string expectedGuid)
    {
        var byName = Catalog.FindByLdapName(ldapName);

        Assert.True(
            byName is not null,
            $"The catalogue has no entry called '{ldapName}'.");

        Assert.Equal(expectedGuid, byName!.Guid);
        Assert.Equal(kind, byName.Kind);

        // Looked up the other way as well, because a GUID that resolves to the right name is not
        // the same fact as a name that resolves to the right GUID once a GUID means two things.
        var byGuid = Catalog.FindByGuid(expectedGuid);

        Assert.Contains(byGuid, e => e.Kind == kind && e.LdapName == ldapName);
    }

    private static HashSet<(string, SchemaGuidKind)> PinnedKeys() =>
    [
        ("ee914b82-0a98-11d1-adbb-00c04fd8d5cd", SchemaGuidKind.ExtendedRight),
        ("440820ad-65b4-11d1-a3da-0000f875ae0d", SchemaGuidKind.ExtendedRight),
        ("1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd", SchemaGuidKind.ExtendedRight),
        ("68b1d179-0d15-4d4f-ab71-46152e79a7bc", SchemaGuidKind.ExtendedRight),
        ("edacfd8f-ffb3-11d1-b41d-00a0c968f939", SchemaGuidKind.ExtendedRight),
        ("0e10c968-78fb-11d2-90d4-00c04f79dc55", SchemaGuidKind.ExtendedRight),
        ("cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd", SchemaGuidKind.ExtendedRight),
        ("e2a36dc9-ae17-47c3-b58b-be34c55ba633", SchemaGuidKind.ExtendedRight),
        ("fec364e0-0a98-11d1-adbb-00c04fd8d5cd", SchemaGuidKind.ExtendedRight),
        ("ab721a52-1e2f-11d0-9819-00aa0040529b", SchemaGuidKind.ExtendedRight),
        ("69ae6200-7f46-11d2-b9ad-00c04f79f805", SchemaGuidKind.ExtendedRight),
        ("3e0f7e18-2c7a-4c10-ba82-4d926db99a3e", SchemaGuidKind.ExtendedRight),
        ("9923a32a-3607-11d2-b9be-0000f87a36b2", SchemaGuidKind.ExtendedRight),
        ("4ecc03fe-ffc0-4947-b630-eb672a8a9dbc", SchemaGuidKind.ExtendedRight),
        ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", SchemaGuidKind.ExtendedRight),
        ("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", SchemaGuidKind.ExtendedRight),
        ("89e95b76-444d-4c62-991a-0facbeda640c", SchemaGuidKind.ExtendedRight),
        ("1131f6ac-9c07-11d1-f79f-00c04fc2dcd2", SchemaGuidKind.ExtendedRight),
        ("f98340fb-7c5b-4cdb-a00b-2ebdfa115a96", SchemaGuidKind.ExtendedRight),
        ("1131f6ab-9c07-11d1-f79f-00c04fc2dcd2", SchemaGuidKind.ExtendedRight),
        ("05c74c5e-4deb-43b4-bd9f-86664c2a7fd5", SchemaGuidKind.ExtendedRight),
        ("b7b1b3de-ab09-4242-9e30-9980e5d322f7", SchemaGuidKind.ExtendedRight),
        ("b7b1b3dd-ab09-4242-9e30-9980e5d322f7", SchemaGuidKind.ExtendedRight),
        ("7c0e2a7c-a419-48e4-a995-10180aad54dd", SchemaGuidKind.ExtendedRight),
        ("ba33815a-4f93-4c76-87f3-57574bff8109", SchemaGuidKind.ExtendedRight),
        ("0bc1554e-0a99-11d1-adbb-00c04fd8d5cd", SchemaGuidKind.ExtendedRight),
        ("62dd28a8-7f46-11d2-b9ad-00c04f79f805", SchemaGuidKind.ExtendedRight),
        ("ab721a56-1e2f-11d0-9819-00aa0040529b", SchemaGuidKind.ExtendedRight),
        ("7726b9d5-a4b4-4288-a6b2-dce952e80a7f", SchemaGuidKind.ExtendedRight),
        ("91d67418-0135-4acc-8d79-c08e857cfbec", SchemaGuidKind.ExtendedRight),
        ("ab721a54-1e2f-11d0-9819-00aa0040529b", SchemaGuidKind.ExtendedRight),
        ("ab721a55-1e2f-11d0-9819-00aa0040529b", SchemaGuidKind.ExtendedRight),
        ("ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501", SchemaGuidKind.ExtendedRight),
        ("280f369c-67c7-438e-ae98-1d46f3c6f541", SchemaGuidKind.ExtendedRight),
        ("ab721a53-1e2f-11d0-9819-00aa0040529b", SchemaGuidKind.ExtendedRight),
        ("00299570-246d-11d0-a768-00aa006e0529", SchemaGuidKind.ExtendedRight),
        ("bf9679c0-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.ValidatedWrite),
        ("72e39547-7b18-11d1-adef-00c04fd8d5cd", SchemaGuidKind.ValidatedWrite),
        ("80863791-dbe9-4eb8-837e-7f0ab55d9ac7", SchemaGuidKind.ValidatedWrite),
        ("d31a8757-2447-4545-8081-3bb610cacbf2", SchemaGuidKind.ValidatedWrite),
        ("f3a64788-5306-11d1-a9c5-0000f80367c1", SchemaGuidKind.ValidatedWrite),
        ("72e39547-7b18-11d1-adef-00c04fd8d5cd", SchemaGuidKind.PropertySet),
        ("b8119fd0-04f6-4762-ab7a-4986c76b3f9a", SchemaGuidKind.PropertySet),
        ("c7407360-20bf-11d0-a768-00aa006e0529", SchemaGuidKind.PropertySet),
        ("e45795b2-9455-11d1-aebd-0000f80367c1", SchemaGuidKind.PropertySet),
        ("59ba2f42-79a2-11d0-9020-00c04fc2d3cf", SchemaGuidKind.PropertySet),
        ("bc0ac240-79a9-11d0-9020-00c04fc2d4cf", SchemaGuidKind.PropertySet),
        ("ffa6f046-ca4b-4feb-b40d-04dfee722543", SchemaGuidKind.PropertySet),
        ("77b5b886-944a-11d1-aebd-0000f80367c1", SchemaGuidKind.PropertySet),
        ("91e647de-d96f-4b70-9557-d63ff4f3ccd8", SchemaGuidKind.PropertySet),
        ("e48d0154-bcf8-11d1-8702-00c04fb96050", SchemaGuidKind.PropertySet),
        ("037088f8-0ae1-11d2-b422-00a0c968f939", SchemaGuidKind.PropertySet),
        ("5805bc62-bdc9-4428-a5e2-856a0f4c185e", SchemaGuidKind.PropertySet),
        ("4c164200-20c0-11d0-a768-00aa006e0529", SchemaGuidKind.PropertySet),
        ("5f202010-79a5-11d0-9020-00c04fc2d4cf", SchemaGuidKind.PropertySet),
        ("e45795b3-9455-11d1-aebd-0000f80367c1", SchemaGuidKind.PropertySet),
        ("bf967918-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("bf967950-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("bf967953-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("bf9679e4-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("72e39547-7b18-11d1-adef-00c04fd8d5cd", SchemaGuidKind.Attribute),
        ("f30e3bbe-9ff0-11d1-b603-0000f80367c1", SchemaGuidKind.Attribute),
        ("bf967985-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("bf967986-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("c0e20a04-0e5a-4ff3-9482-5efeaecd7060", SchemaGuidKind.Attribute),
        ("28630ebf-41d5-11d1-a9c1-0000f80367c1", SchemaGuidKind.Attribute),
        ("bf9679c0-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("bf967991-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79", SchemaGuidKind.Attribute),
        ("800d94d7-b7a1-42a1-b14d-7cae1423d07f", SchemaGuidKind.Attribute),
        ("b77ea093-88d0-4780-9a98-911f8e8b1dca", SchemaGuidKind.Attribute),
        ("bf9679e3-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("bf9679e5-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("bf9679e7-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("bf9679e8-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("bf967a0a-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("3e0abfd0-126a-11d0-a060-00aa006c33ed", SchemaGuidKind.Attribute),
        ("bf9679a8-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("f3a64788-5306-11d1-a9c5-0000f80367c1", SchemaGuidKind.Attribute),
        ("17eb4278-d167-11d0-b002-0000f80367c1", SchemaGuidKind.Attribute),
        ("bf9679e1-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("bf967a68-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.Attribute),
        ("28630ebb-41d5-11d1-a9c1-0000f80367c1", SchemaGuidKind.Attribute),
        ("bf967a86-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.ObjectClass),
        ("5cb41ed0-0e4c-11d0-a286-00aa003049e2", SchemaGuidKind.ObjectClass),
        ("bf967a8b-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.ObjectClass),
        ("19195a5a-6da0-11d0-afd3-00c04fd930c9", SchemaGuidKind.ObjectClass),
        ("bf967a9c-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.ObjectClass),
        ("f30e3bc2-9ff0-11d1-b603-0000f80367c1", SchemaGuidKind.ObjectClass),
        ("7b8b558a-93a5-4af7-adca-c017e67f1057", SchemaGuidKind.ObjectClass),
        ("ce206244-5827-4a86-ba1c-1c0c386c1b64", SchemaGuidKind.ObjectClass),
        ("f0f8ffab-1191-11d0-a060-00aa006c33ed", SchemaGuidKind.ObjectClass),
        ("bf967aa5-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.ObjectClass),
        ("e5209ca2-3bba-11d2-90cc-00c04fd91ab1", SchemaGuidKind.ObjectClass),
        ("bf967aa8-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.ObjectClass),
        ("bf967aba-0de6-11d0-a285-00aa003049e2", SchemaGuidKind.ObjectClass),
        ("a05b8cc2-17bc-4802-a710-e7c15ab866a2", SchemaGuidKind.ExtendedRight),
        ("9b026da6-0d3c-465c-8bee-5199d7165cba", SchemaGuidKind.ExtendedRight),
        ("5b47d60f-6090-40b2-9f37-2a4de88f3063", SchemaGuidKind.Attribute),
        ("2e0e4a88-f5fa-11df-b3af-001fc000a000", SchemaGuidKind.Attribute),
        ("53c5be7e-5403-4013-a04b-b22e05d0e3c1", SchemaGuidKind.Attribute),
    ];
}
