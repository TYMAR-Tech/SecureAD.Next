using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using SdBytes = global::SecureAD.Next.Tests.Kernel.Security.SdBytes;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// Reading one object's permissions back out of a bundle: the owner, the four statements about the
/// DACL, the entries, and the three ways an object can have no entries at all.
/// </summary>
public sealed class ObjectPermissionsTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-permissions-" + Guid.NewGuid().ToString("N"));

    private static readonly DateTimeOffset Started = new(2026, 9, 13, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 9, 13, 11, 30, 0, TimeSpan.Zero);

    private const string DomainDn = "DC=contoso,DC=com";
    private const string AliceDn = "CN=Alice," + DomainDn;
    private const string AdminsDn = "CN=Domain Admins," + DomainDn;
    private const string AdminsSid = "S-1-5-21-1111111111-2222222222-3333333333-512";
    private const string OrphanSid = "S-1-5-21-1111111111-2222222222-3333333333-25601";

    // Well-known SIDs, and the objects Active Directory really keeps for them. The containers are
    // written out in full because the point of several of these tests is that a captured object
    // exists and is deliberately not used.
    private const string PrincipalSelfSid = "S-1-5-10";
    private const string CreatorOwnerSid = "S-1-3-0";
    private const string OwnerRightsSid = "S-1-3-4";
    private const string AuthenticatedUsersSid = "S-1-5-11";

    /// <summary><c>INHERIT_ONLY_ACE</c>, from MS-DTYP 2.4.4.1.</summary>
    private const byte InheritOnlyAce = 0x08;

    private const string WellKnownDn = "CN=WellKnown Security Principals,CN=Configuration," + DomainDn;
    private const string WellKnownSelfDn = "CN=Self," + WellKnownDn;
    private const string WellKnownAuthenticatedUsersDn = "CN=Authenticated Users," + WellKnownDn;
    private const string ForeignAuthenticatedUsersDn =
        "CN=S-1-5-11,CN=ForeignSecurityPrincipals," + DomainDn;

    // ---------------------------------------------------------------------------------------
    // An object nothing captured
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An object this bundle never saw is not an object with no permissions, and the two must not
    /// arrive as the same answer.
    /// </summary>
    [Fact]
    public void AnObjectTheBundleDoesNotHoldReadsAsNothing()
    {
        WriteBundle(writer => writer.WriteObject(ObjectAt(AliceDn)));

        Assert.Null(Read("CN=Nobody," + DomainDn));
    }

    [Fact]
    public void StreamedPermissionIdentityDoesNotDependOnAGuid()
    {
        var sharedGuid = Guid.NewGuid();
        string[] names = [AliceDn, "CN=Bob," + DomainDn, "CN=Carol," + DomainDn];
        WriteBundle(writer =>
        {
            for (var i = 0; i < names.Length; i++)
            {
                var id = writer.WriteObject(ObjectAt(names[i]) with { ObjectGuid = i == 0 ? null : sharedGuid });
                WriteDescriptor(writer, id, Descriptor(Allowing(AdminsSid, 16 + i)));
            }
        });

        using var reader = BundleReader.Open(_directory).Value;
        var index = 0;
        foreach (var subject in reader.StreamObjects().Objects)
        {
            var permissions = reader.ReadPermissions(subject.DistinguishedName)!;
            Assert.Equal(names[index], permissions.DistinguishedName);
            Assert.Equal(16 + index, Assert.Single(permissions.Entries).AccessMask);
            Assert.Equal(16 + index,
                Assert.Single(reader.ReadPermissions(subject.DistinguishedName.ToLowerInvariant())!.Entries).AccessMask);
            Assert.Null(reader.ReadPermissions("CN=Absent," + DomainDn));
            index++;
        }
        Assert.Equal(3, index);
        Assert.Equal(16, Assert.Single(reader.ReadPermissions(AliceDn)!.Entries).AccessMask);
    }

    /// <summary>
    /// The original NOCASE lookup is the compatibility oracle for ambiguous stored names.
    /// Bypassing it for a streamed row would attach a different descriptor to the same name.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AmbiguousStreamedNamesKeepTheOriginalPermissionSelection(bool sameSpelling)
    {
        var firstName = sameSpelling ? AliceDn : AliceDn.ToLowerInvariant();
        WriteBundle(writer =>
        {
            var first = writer.WriteObject(ObjectAt(firstName));
            WriteDescriptor(writer, first, Descriptor(Allowing(AdminsSid, 16)));
            var second = writer.WriteObject(ObjectAt(AliceDn));
            WriteDescriptor(writer, second, Descriptor(Denying(OrphanSid, 32)));
        });

        using var reference = BundleReader.Open(_directory).Value;
        using var reader = BundleReader.Open(_directory).Value;
        var count = 0;
        foreach (var subject in reader.StreamObjects().Objects)
        {
            var expected = reference.ReadPermissions(subject.DistinguishedName)!;
            var actual = reader.ReadPermissions(subject.DistinguishedName)!;
            Assert.Equal(expected.DistinguishedName, actual.DistinguishedName);
            Assert.Equal(expected.Entries.Select(e => (e.AceType, e.Trustee.Sid, e.AccessMask)),
                actual.Entries.Select(e => (e.AceType, e.Trustee.Sid, e.AccessMask)));
            count++;
        }
        Assert.Equal(2, count);
    }

    [Fact]
    public void StreamedNamesRetainSqliteAsciiCaseSemanticsAndEscapedValues()
    {
        string[] names = ["CN=Älice," + DomainDn, "CN=älice," + DomainDn, @"CN=Smith\, John," + DomainDn];
        WriteBundle(writer =>
        {
            for (var i = 0; i < names.Length; i++)
            {
                var id = writer.WriteObject(ObjectAt(names[i]));
                WriteDescriptor(writer, id, Descriptor(Allowing(AdminsSid, 16 + i)));
            }
        });
        using var reader = BundleReader.Open(_directory).Value;
        var index = 0;
        foreach (var subject in reader.StreamObjects().Objects)
        {
            Assert.Equal(16 + index, Assert.Single(reader.ReadPermissions(subject.DistinguishedName)!.Entries).AccessMask);
            var asciiVariant = subject.DistinguishedName.Replace("CN=", "cn=", StringComparison.Ordinal);
            Assert.Equal(16 + index, Assert.Single(reader.ReadPermissions(asciiVariant)!.Entries).AccessMask);
            index++;
        }
        Assert.Equal(3, index);
    }

    [Fact]
    public void StreamedObjectWithoutADescriptorIsNotAnAbsentObject()
    {
        WriteBundle(writer => writer.WriteObject(ObjectAt(AliceDn) with { ObjectGuid = null }));
        using var reader = BundleReader.Open(_directory).Value;
        var subject = Assert.Single(reader.StreamObjects().Objects);
        var permissions = reader.ReadPermissions(subject.DistinguishedName);
        Assert.NotNull(permissions);
        Assert.Equal(DaclState.Unreadable, permissions.DaclState);
        Assert.Null(reader.ReadPermissions("CN=Absent," + DomainDn));
        reader.Dispose();
        Assert.Throws<ObjectDisposedException>(() => reader.ReadPermissions(AliceDn));
    }

    // ---------------------------------------------------------------------------------------
    // The entries
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The entries arrive in the order the directory stored them, not the canonical order the
    /// <c>ace</c> table holds. The fixture writes an allow before a deny, which canonicalisation
    /// reverses - so a reader of the projection would see the deny first.
    /// </summary>
    /// <remarks>
    /// This test was named <c>TheEntriesAreReadInCanonicalOrder</c> and asserted only that the
    /// ordinals ran 0, 1 - which both orders satisfy, so it passed unchanged when the source
    /// swapped. Renamed and given an assertion that can tell them apart.
    /// </remarks>
    [Fact]
    public void TheEntriesAreReadInTheOrderTheDirectoryStoredThem()
    {
        WriteAliceWith(Descriptor(
            Allowing(AdminsSid, 0x000F01FF),
            Denying(OrphanSid, 0x00000010)));

        var permissions = Read(AliceDn)!;

        Assert.Equal([0, 1], permissions.Entries.Select(e => e.Ordinal));
        Assert.Equal(nameof(AceType.AccessAllowed), permissions.Entries[0].AceType);
        Assert.Equal(nameof(AceType.AccessDenied), permissions.Entries[1].AceType);
    }

    /// <summary>
    /// A DACL holding the same grant twice holds it twice. The <c>ace</c> table collapses them by
    /// <c>ace_hash</c>, which is right for comparing runs and wrong for showing evidence - measured
    /// on lab bundle <c>ad.lab-20260819-232425</c>, three entries on three objects were being
    /// discarded this way before anyone could see them.
    /// </summary>
    [Fact]
    public void TwoIdenticalEntriesAreBothShown()
    {
        WriteAliceWith(Descriptor(
            Allowing(AdminsSid, 0x000F01FF),
            Allowing(AdminsSid, 0x000F01FF)));

        Assert.Equal(2, Read(AliceDn)!.Entries.Count);
    }

    /// <summary>
    /// GUID presence comes from <c>ACE_OBJECT_TYPE_PRESENT</c>. An object ACE carrying no GUID
    /// narrows nothing and reaches exactly what its plain counterpart reaches, so a reader that
    /// inferred presence from the GUID being absent would be guessing - which <c>S-56</c> R1
    /// forbids and which the projection leaves no way to avoid.
    /// </summary>
    [Fact]
    public void AnObjectEntryCarryingNoGuidSaysTheFlagWasClear()
    {
        WriteAliceWith(Descriptor(
            Ace(AceType.AccessAllowedObject, AdminsSid, 0x00000100)));

        var entry = Read(AliceDn)!.Entries[0];

        Assert.False(entry.HasObjectType);
        Assert.False(entry.HasInheritedObjectType);
        Assert.Null(entry.ObjectTypeGuid);
    }

    [Fact]
    public void AnObjectEntryCarryingAGuidSaysTheFlagWasSet()
    {
        const string ResetPassword = "00299570-246d-11d0-a768-00aa006e0529";

        WriteAliceWith(Descriptor(
            Allowing(AdminsSid, 0x00000100) with { ObjectTypeGuid = ResetPassword }));

        Assert.True(Read(AliceDn)!.Entries[0].HasObjectType);
    }

    /// <summary>
    /// The bytes are the authority, so an error found re-reading them is reported rather than
    /// swallowed. Fewer entries than the run stored must never be silent - that is <c>#4</c>'s
    /// reasoning one layer on.
    /// </summary>
    [Fact]
    public void AnErrorFoundReReadingTheStoredBytesIsReported()
    {
        WriteAliceWith(Descriptor(Allowing(AdminsSid, 0x000F01FF)));
        TruncateTheStoredDescriptor();

        Assert.Contains(
            Read(AliceDn)!.Errors,
            message => message.StartsWith("Re-reading the stored descriptor reported:", StringComparison.Ordinal));
    }

    [Fact]
    public void AnEntryCarriesTheMaskTheDirectoryStored()
    {
        WriteAliceWith(Descriptor(Allowing(AdminsSid, 0x000F01FF)));

        var permissions = Read(AliceDn)!;

        Assert.Equal(0x000F01FF, permissions.Entries[0].AccessMask);
    }

    [Fact]
    public void AnEntryCarriesWhetherItWasInherited()
    {
        WriteAliceWith(Descriptor(Allowing(AdminsSid, 0x00000010) with { IsInherited = true }));

        var permissions = Read(AliceDn)!;

        Assert.True(permissions.Entries[0].IsInherited);
    }

    /// <summary>
    /// A denial and a grant are opposite facts, and both are stored as an entry against a trustee.
    /// </summary>
    [Fact]
    public void AnEntryCarriesItsType()
    {
        WriteAliceWith(Descriptor(Denying(OrphanSid, 0x00000010)));

        var permissions = Read(AliceDn)!;

        Assert.Equal(nameof(AceType.AccessDenied), permissions.Entries[0].AceType);
    }

    /// <summary>
    /// An entry limited to one extended right or attribute carries the GUID saying which. Losing it
    /// would turn "Reset password" into "All extended rights".
    /// </summary>
    [Fact]
    public void AnEntryLimitedToOneRightCarriesTheGuidSayingWhich()
    {
        const string ResetPassword = "00299570-246d-11d0-a768-00aa006e0529";

        WriteAliceWith(Descriptor(
            Allowing(AdminsSid, 0x00000100) with { ObjectTypeGuid = ResetPassword }));

        var permissions = Read(AliceDn)!;

        Assert.Equal(ResetPassword, permissions.Entries[0].ObjectTypeGuid);
    }

    // ---------------------------------------------------------------------------------------
    // Who the entry names
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A trustee whose object this run captured gets that object's name, matched on the SID bytes
    /// the directory sent against the SID text the entry holds.
    /// </summary>
    [Fact]
    public void ATrusteeCapturedByThisRunIsNamed()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectWithSid(AdminsDn, AdminsSid));
            var alice = writer.WriteObject(ObjectAt(AliceDn));
            WriteDescriptor(writer, alice, Descriptor(Allowing(AdminsSid, 0x000F01FF)));
        });

        var permissions = Read(AliceDn)!;

        Assert.Equal("Domain Admins", permissions.Entries[0].Trustee.Name);
    }

    [Fact]
    public void ANamedTrusteeCarriesTheDomainItWasCapturedFrom()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectWithSid(AdminsDn, AdminsSid));
            var alice = writer.WriteObject(ObjectAt(AliceDn));
            WriteDescriptor(writer, alice, Descriptor(Allowing(AdminsSid, 0x000F01FF)));
        });

        var permissions = Read(AliceDn)!;

        Assert.Equal("contoso.com", permissions.Entries[0].Trustee.DomainFqdn);
    }

    /// <summary>
    /// A SID matching nothing this run captured stays a SID. Inventing a name for it would put the
    /// wrong principal against a permission, which is worse than showing the identifier.
    /// </summary>
    [Fact]
    public void ATrusteeNothingCapturedKeepsItsIdentifierAndGainsNoName()
    {
        WriteAliceWith(Descriptor(Allowing(OrphanSid, 0x000F01FF)));

        var trustee = Read(AliceDn)!.Entries[0].Trustee;

        Assert.Equal(OrphanSid, trustee.Sid);
        Assert.Null(trustee.Name);
    }

    // ---------------------------------------------------------------------------------------
    // Well-known SIDs: named from Microsoft's table, not from whatever object happened to match
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// <c>PRINCIPAL SELF</c> means the object the permission sits on, so on Alice it is Alice.
    /// </summary>
    /// <remarks>
    /// <b>The captured <c>CN=Self</c> object is written deliberately.</b> Active Directory really
    /// does keep one, under <c>CN=WellKnown Security Principals</c>, and before the catalogue
    /// existed the ordinary lookup found it and reported <i>Self</i> as though it were a group. A
    /// test without that object in the bundle would pass whether or not the catalogue is consulted
    /// first, and would measure nothing.
    /// </remarks>
    [Fact]
    public void WhenAnEntryNamesPrincipalSelf_ThenItIsReportedAsTheObjectItself()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectWithSid(WellKnownSelfDn, PrincipalSelfSid));
            var alice = writer.WriteObject(ObjectAt(AliceDn));
            WriteDescriptor(writer, alice, Descriptor(Allowing(PrincipalSelfSid, 0x00000020)));
        });

        Assert.Equal("This object (Alice)", Read(AliceDn)!.Entries[0].Trustee.Name);
    }

    /// <summary>
    /// A placeholder holds nothing. Counting one as a holder credits a permission to a principal
    /// that does not exist, which is the whole of finding <c>F-2</c>.
    /// </summary>
    [Fact]
    public void WhenAnEntryNamesPrincipalSelf_ThenItIsNotCountedAsHoldingThePermission()
    {
        WriteAliceWith(Descriptor(Allowing(PrincipalSelfSid, 0x00000020)));

        var trustee = Read(AliceDn)!.Entries[0].Trustee;

        Assert.Equal(WellKnownSidRole.Placeholder, trustee.WellKnownRole);
        Assert.False(trustee.HoldsThePermission);
    }

    /// <summary>
    /// A well-known SID belongs to no domain. It appeared to belong to one only because the object
    /// it was named from lives in some forest's Configuration partition.
    /// </summary>
    [Fact]
    public void WhenAnEntryNamesAWellKnownSid_ThenNoDomainIsClaimedForIt()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectWithSid(WellKnownSelfDn, PrincipalSelfSid));
            var alice = writer.WriteObject(ObjectAt(AliceDn));
            WriteDescriptor(writer, alice, Descriptor(Allowing(PrincipalSelfSid, 0x00000020)));
        });

        Assert.Null(Read(AliceDn)!.Entries[0].Trustee.DomainFqdn);
    }

    /// <summary>
    /// <c>CREATOR OWNER</c> is named but never resolved: it is replaced with whoever creates a
    /// child object in future, and this bundle cannot know who that will be.
    /// </summary>
    [Fact]
    public void WhenAnEntryNamesCreatorOwner_ThenItIsNamedAsAPlaceholderAndHoldsNothing()
    {
        WriteAliceWith(Descriptor(Allowing(CreatorOwnerSid, 0x000F01FF)));

        var trustee = Read(AliceDn)!.Entries[0].Trustee;

        Assert.Equal("Creator Owner", trustee.Name);
        Assert.Equal(WellKnownSidRole.Placeholder, trustee.WellKnownRole);
        Assert.False(trustee.HoldsThePermission);
    }

    /// <summary>
    /// <c>OWNER RIGHTS</c> is in a DACL to change what ownership grants, not to grant anything to
    /// anybody, so it is not a holder either.
    /// </summary>
    [Fact]
    public void WhenAnEntryNamesOwnerRights_ThenItIsNotCountedAsHoldingThePermission()
    {
        WriteAliceWith(Descriptor(Allowing(OwnerRightsSid, 0x00020000)));

        var trustee = Read(AliceDn)!.Entries[0].Trustee;

        Assert.Equal(WellKnownSidRole.OwnerRightsQualifier, trustee.WellKnownRole);
        Assert.False(trustee.HoldsThePermission);
    }

    /// <summary>
    /// The ambiguity that made the old answer arbitrary: several captured objects carrying one
    /// well-known SID.
    /// </summary>
    /// <remarks>
    /// In one lab bundle <c>S-1-5-11</c> matched four objects - the well-known principal and three
    /// <c>ForeignSecurityPrincipals</c> entries in different domains - and the query that chose
    /// between them had no <c>ORDER BY</c>, so the domain a reader saw beside <i>Authenticated
    /// Users</i> was decided by row order. The fixture writes the foreign object <b>first</b>, so
    /// a build that consulted the captured objects would answer with it.
    /// </remarks>
    [Fact]
    public void WhenSeveralCapturedObjectsShareAWellKnownSid_ThenTheAnswerIsNotArbitrary()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectWithSid(ForeignAuthenticatedUsersDn, AuthenticatedUsersSid));
            writer.WriteObject(ObjectWithSid(WellKnownAuthenticatedUsersDn, AuthenticatedUsersSid));
            var alice = writer.WriteObject(ObjectAt(AliceDn));
            WriteDescriptor(writer, alice, Descriptor(Allowing(AuthenticatedUsersSid, 0x00020094)));
        });

        var trustee = Read(AliceDn)!.Entries[0].Trustee;

        Assert.Equal("Authenticated Users", trustee.Name);
        Assert.Null(trustee.DomainFqdn);
        Assert.True(trustee.HoldsThePermission);
    }

    /// <summary>
    /// An ordinary account is still resolved from the objects this run captured, and still holds
    /// what it is granted. The catalogue is consulted first and must not swallow everything.
    /// </summary>
    [Fact]
    public void WhenATrusteeIsNotWellKnown_ThenItIsStillResolvedFromTheCapturedObjects()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectWithSid(AdminsDn, AdminsSid));
            var alice = writer.WriteObject(ObjectAt(AliceDn));
            WriteDescriptor(writer, alice, Descriptor(Allowing(AdminsSid, 0x000F01FF)));
        });

        var trustee = Read(AliceDn)!.Entries[0].Trustee;

        Assert.Equal("Domain Admins", trustee.Name);
        Assert.Equal("contoso.com", trustee.DomainFqdn);
        Assert.Null(trustee.WellKnownRole);
        Assert.True(trustee.HoldsThePermission);
    }

    /// <summary>
    /// A trustee this run could not name still holds the permission. Not knowing who somebody is
    /// is not the same as their holding nothing, and reporting otherwise understates access.
    /// </summary>
    [Fact]
    public void WhenATrusteeCouldNotBeNamed_ThenItStillHoldsThePermission()
    {
        WriteAliceWith(Descriptor(Allowing(OrphanSid, 0x000F01FF)));

        Assert.True(Read(AliceDn)!.Entries[0].Trustee.HoldsThePermission);
    }

    // ---------------------------------------------------------------------------------------
    // OWNER RIGHTS: what qualifies the owner's ordinary control
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An <c>OWNER RIGHTS</c> entry is how an administrator stops an object's owner from being
    /// able to take it over, and the product said nothing about it at all before finding
    /// <c>F-1</c>.
    /// </summary>
    /// <remarks>
    /// <b>The access mask is zero, because that is what a real one looks like.</b> On 2026-08-20
    /// an OWNER RIGHTS entry was added to <c>OU=test01</c> in the lab with every permission
    /// unticked, and the captured descriptor holds it as <c>access_mask=0</c>. An earlier version
    /// of this test used a non-zero mask and so could not have caught an entry being dropped for
    /// granting nothing.
    /// </remarks>
    [Fact]
    public void WhenAnOwnerRightsEntryIsPresent_ThenTheObjectSaysOwnershipIsQualified()
    {
        WriteAliceWith(Descriptor(Allowing(OwnerRightsSid, 0x00000000)));

        Assert.True(Read(AliceDn)!.OwnerRightsEntryIsPresent);
    }

    /// <summary>
    /// The ordinary case. Without this the check above would pass over anything at all.
    /// </summary>
    [Fact]
    public void WhenNoOwnerRightsEntryIsPresent_ThenNothingQualifiesOwnership()
    {
        WriteAliceWith(Descriptor(Allowing(OrphanSid, 0x000F01FF)));

        Assert.False(Read(AliceDn)!.OwnerRightsEntryIsPresent);
    }

    /// <summary>
    /// An <c>OWNER RIGHTS</c> entry marked <c>INHERIT_ONLY</c> governs the objects beneath this one
    /// and grants nothing on this one, so it does not qualify this object's ownership.
    /// </summary>
    /// <remarks>
    /// <b>This is the shape an administrator will actually create.</b> Adding a permission to an
    /// organisational unit and setting <i>Applies to: descendant objects</i> sets
    /// <c>INHERIT_ONLY_ACE</c>. Counting it here would tell a reader the unit itself was hardened
    /// when only its children were - the product stating something false about the object in front
    /// of him. <c>S-56</c> R13 is the requirement this satisfies.
    /// </remarks>
    [Fact]
    public void WhenAnOwnerRightsEntryAppliesOnlyToDescendants_ThenThisObjectsOwnershipIsNotQualified()
    {
        WriteAliceWith(Descriptor(
            Allowing(OwnerRightsSid, 0x00020000) with { PropagationFlags = InheritOnlyAce }));

        Assert.False(Read(AliceDn)!.OwnerRightsEntryIsPresent);
    }

    [Fact]
    public void TheOwnerIsResolvedTheSameWayAnEntrysTrusteeIs()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectWithSid(AdminsDn, AdminsSid));
            var alice = writer.WriteObject(ObjectAt(AliceDn));
            WriteDescriptor(
                writer, alice, Descriptor(Allowing(AdminsSid, 0x000F01FF)) with
                {
                    OwnerSid = AdminsSid,
                });
        });

        var permissions = Read(AliceDn)!;

        Assert.Equal("Domain Admins", permissions.Owner!.Name);
    }

    // ---------------------------------------------------------------------------------------
    // The four statements about the DACL
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A null DACL grants everyone everything and produces no entries. A viewer that showed only
    /// the entries would render the most open object in the forest as the most closed.
    /// </summary>
    [Fact]
    public void ANullDaclIsReadAsNullRatherThanAsEmpty()
    {
        WriteAliceWith(Descriptor() with { DaclState = DaclState.Null });

        var permissions = Read(AliceDn)!;

        Assert.Equal(DaclState.Null, permissions.DaclState);
        Assert.Empty(permissions.Entries);
    }

    [Fact]
    public void AnEmptyDaclIsReadAsEmpty()
    {
        WriteAliceWith(Descriptor() with { DaclState = DaclState.Empty });

        Assert.Equal(DaclState.Empty, Read(AliceDn)!.DaclState);
    }

    /// <summary>
    /// A DACL that yielded fewer entries than it declared is genuinely present, and the shortfall
    /// has nowhere to live but this.
    /// </summary>
    [Fact]
    public void ATruncatedDaclSaysSo()
    {
        WriteAliceWith(Descriptor(Allowing(AdminsSid, 0x00000010)) with
        {
            DaclCompleteness = DaclCompleteness.Incomplete,
        });

        Assert.Equal(DaclCompleteness.Incomplete, Read(AliceDn)!.DaclCompleteness);
    }

    /// <summary>
    /// AD accumulates granted and denied rights across the whole DACL and adds a deny only for
    /// rights not already granted, so a deny placed after an allow may never apply. Normalisation
    /// sorts every DACL, so this flag is the only record that the directory held it in an order
    /// these entries no longer show.
    /// </summary>
    [Fact]
    public void ADaclTheDirectoryHeldOutOfCanonicalOrderSaysSo()
    {
        WriteAliceWith(Descriptor(Allowing(AdminsSid, 0x00000010)) with
        {
            DaclWasCanonical = false,
        });

        Assert.False(Read(AliceDn)!.DaclWasCanonical);
    }

    /// <summary>
    /// The explanation for an access control list that looks surprisingly short.
    /// </summary>
    [Fact]
    public void AnObjectRefusingInheritanceSaysSo()
    {
        WriteAliceWith(Descriptor(Allowing(AdminsSid, 0x00000010)) with
        {
            IsDaclProtected = true,
        });

        Assert.True(Read(AliceDn)!.IsDaclProtected);
    }

    /// <summary>
    /// A descriptor that could not be parsed produces no entries in exactly the way an object
    /// granting nothing does, and the errors are what tell them apart.
    /// </summary>
    [Fact]
    public void WhatWentWrongParsingTheDescriptorIsReadBack()
    {
        WriteAliceWith(Descriptor() with
        {
            DaclState = DaclState.Unreadable,
            Errors = ["The entry ran past the end of the descriptor."],
        });

        Assert.Equal(
            ["The entry ran past the end of the descriptor."], Read(AliceDn)!.Errors);
    }

    // ---------------------------------------------------------------------------------------
    // The three ways to have no descriptor
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AnObjectWhoseDescriptorWasReadSaysSo()
    {
        WriteAliceWith(Descriptor(Allowing(AdminsSid, 0x00000010)));

        Assert.Equal(DescriptorAvailability.Read, Read(AliceDn)!.Availability);
    }

    /// <summary>
    /// A fifth of a production domain returned no readable descriptor. Those objects are unknown,
    /// not empty, and the reason the run recorded is what an operator acts on.
    /// </summary>
    [Fact]
    public void AnObjectWhoseDescriptorCouldNotBeReadSaysSoAndSaysWhy()
    {
        WriteBundle(writer =>
        {
            var alice = writer.WriteObject(ObjectAt(AliceDn));
            writer.WriteUnreadableSecurityDescriptor(alice, "The controller refused the attribute.");
        });

        var permissions = Read(AliceDn)!;

        Assert.Equal(DescriptorAvailability.Unreadable, permissions.Availability);
        Assert.Equal("The controller refused the attribute.", permissions.UnreadableReason);
    }

    [Fact]
    public void AnObjectWhoseDescriptorWasNeverAttemptedSaysThatInstead()
    {
        WriteBundle(writer => writer.WriteObject(ObjectAt(AliceDn)));

        var permissions = Read(AliceDn)!;

        Assert.Equal(DescriptorAvailability.NotAttempted, permissions.Availability);
        Assert.Null(permissions.UnreadableReason);
    }

    /// <summary>
    /// An object with no descriptor makes no claim about what it grants. Reporting it as an empty
    /// DACL would report an object nobody could read as the safest object in the forest.
    /// </summary>
    [Fact]
    public void AnObjectWithNoDescriptorClaimsNothingAboutWhatItGrants()
    {
        WriteBundle(writer => writer.WriteObject(ObjectAt(AliceDn)));

        Assert.Equal(DaclState.Unreadable, Read(AliceDn)!.DaclState);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    // ---------------------------------------------------------------------------------------

    private ObjectPermissions? Read(string distinguishedName)
    {
        var opening = BundleReader.Open(_directory);
        Assert.True(opening.IsSuccess);

        using var reader = opening.Value;
        return reader.ReadPermissions(distinguishedName);
    }

    private void WriteAliceWith(AceNormalizationResult normalization) => WriteBundle(writer =>
    {
        var alice = writer.WriteObject(ObjectAt(AliceDn));
        WriteDescriptor(writer, alice, normalization);
    });

    /// <summary>
    /// Writes a descriptor with real self-relative bytes built to match the entries it declares.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The bytes used to be a placeholder and now cannot be.</b> They were
    /// <c>Encoding.UTF8.GetBytes(normalization.ToString())</c> - unique per descriptor, which was
    /// all the writer needed, since it deduplicates on their hash and stored them without looking
    /// inside. The reader now parses them, because the <c>ace</c> table is the canonical projection
    /// and <c>S-57</c> upheld that a projection cannot stand in for the stored DACL. A fixture
    /// whose bytes are not a descriptor would test nothing that happens in production.
    /// </para>
    /// <para>
    /// Built with <see cref="SdBytes"/>, which the parser's own tests use, so these fixtures and
    /// those agree about what a descriptor looks like.
    /// </para>
    /// </remarks>
    private static void WriteDescriptor(
        BundleWriter writer, long objectId, AceNormalizationResult normalization) =>
        writer.WriteSecurityDescriptor(objectId, BytesFor(normalization), normalization);

    /// <summary>
    /// The self-relative bytes a directory would have returned for <paramref name="normalization"/>.
    /// </summary>
    private static byte[] BytesFor(AceNormalizationResult normalization) =>
        SdBytes.SelfRelativeSd(
            ownerSid: normalization.OwnerSid is null ? null : Sid.ToBytes(normalization.OwnerSid),
            groupSid: normalization.GroupSid is null ? null : Sid.ToBytes(normalization.GroupSid),
            daclAces: normalization.DaclState == DaclState.Null
                ? null
                : [.. normalization.Aces.Select(AceBytes)],
            daclPresent: normalization.DaclState != DaclState.Null,
            daclProtected: normalization.IsDaclProtected);

    /// <summary>
    /// One ACE as the directory would have laid it out.
    /// </summary>
    /// <remarks>
    /// An entry carrying either GUID is written as an object ACE whatever type it declares, because
    /// a plain ACE has nowhere to put a GUID - the object-ACE body is the only layout with the
    /// flags field and the GUIDs that field describes.
    /// </remarks>
    private static byte[] AceBytes(CanonicalAce ace)
    {
        var sid = Sid.ToBytes(ace.TrusteeSid)!;
        var flags = (byte)(
            ace.InheritanceFlags | ace.PropagationFlags | (ace.IsInherited ? 0x10 : 0x00));

        var deny = ace.AceType is AceType.AccessDenied or AceType.AccessDeniedObject;
        var objectType = ace.ObjectTypeGuid is null ? (Guid?)null : Guid.Parse(ace.ObjectTypeGuid);
        var inheritedObjectType = ace.InheritedObjectTypeGuid is null
            ? (Guid?)null
            : Guid.Parse(ace.InheritedObjectTypeGuid);

        if (objectType is null && inheritedObjectType is null)
        {
            return deny
                ? SdBytes.DenyAce(sid, ace.AccessMask, flags)
                : SdBytes.AllowAce(sid, ace.AccessMask, flags);
        }

        return deny
            ? SdBytes.DenyObjectAce(sid, ace.AccessMask, objectType, inheritedObjectType, flags)
            : SdBytes.AllowObjectAce(sid, ace.AccessMask, objectType, inheritedObjectType, flags);
    }

    /// <summary>
    /// Cuts the stored descriptor short and re-seals, so the bundle is intact and its bytes no
    /// longer parse - which is what a parser change between the capturing build and this one would
    /// look like. Re-sealed because a broken seal is refused before any of this is reached.
    /// </summary>
    private void TruncateTheStoredDescriptor()
    {
        using (var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = BundleLayout.EvidencePath(_directory),
                Mode = SqliteOpenMode.ReadWrite,
                Pooling = false,
            }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText =
                "UPDATE security_descriptor SET raw_bytes = substr(raw_bytes, 1, 24)";
            command.ExecuteNonQuery();
            connection.Close();
            SqliteConnection.ClearPool(connection);
        }

        BundleSealing.Seal(
            BundleLayout.EvidencePath(_directory), BundleLayout.SealPath(_directory));
    }

    private void WriteBundle(Action<BundleWriter> write)
    {
        using var writer = BundleWriter.Create(_directory, Started);
        writer.WriteCoverage(SomeCoverage());
        write(writer);
        writer.Complete(OneDomainRead(), Finished);
    }

    private static AceNormalizationResult Descriptor(params CanonicalAce[] aces) => new(
        Guid.Empty,
        OwnerSid: null,
        GroupSid: null,
        DaclState.Present,
        IsDaclProtected: false,
        aces,
        Errors: [],
        DaclCompleteness.Complete,
        DaclWasCanonical: true);

    private static CanonicalAce Allowing(string sid, int mask) =>
        Ace(AceType.AccessAllowed, sid, mask);

    private static CanonicalAce Denying(string sid, int mask) =>
        Ace(AceType.AccessDenied, sid, mask);

    private static CanonicalAce Ace(AceType type, string sid, int mask) => new(
        type,
        sid,
        mask,
        ObjectTypeGuid: null,
        InheritedObjectTypeGuid: null,
        IsInherited: false,
        InheritanceFlags: 0,
        PropagationFlags: 0,
        ApplicationData: default,
        AceHash: $"{type}-{sid}-{mask:X8}",
        // The version this build actually produces, not a literal. It said 1 until 2026-09, while
        // AceCanonicalization.Version was 3, and nothing noticed because BundleWriter overwrote the
        // entry's claim with the build's constant on the way in - the P-3 defect. With the writer
        // recording what the entries carry, a literal 1 here writes a bundle this build cannot
        // reproduce and BundleReader correctly refuses to open it.
        CanonicalizationVersion: AceCanonicalization.Version);

    private static RunCoverage OneDomainRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration," + DomainDn, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration," + DomainDn, NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));

    private static PartitionCoverage SomeCoverage() => new(
        DomainDn,
        NamingContextKind.Domain,
        "dc01.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed,
        12,
        4200,
        3,
        [],
        false);

    private static EvidenceObject ObjectAt(string dn) =>
        new(SomeCoverage(), dn, Guid.NewGuid(), [], Started);

    private static EvidenceObject ObjectWithSid(string dn, string sid) =>
        new(
            SomeCoverage(),
            dn,
            Guid.NewGuid(),
            [
                new EvidenceAttribute(
                    "objectSid",
                    StoredAttributeCompleteness.Complete,
                    [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]),
            ],
            Started);
}
