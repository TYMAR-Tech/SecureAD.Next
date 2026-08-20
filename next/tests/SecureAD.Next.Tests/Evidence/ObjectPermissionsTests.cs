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
        Guid.Empty,
        type,
        sid,
        mask,
        ObjectTypeGuid: null,
        InheritedObjectTypeGuid: null,
        IsInherited: false,
        InheritanceFlags: 0,
        PropagationFlags: 0,
        AceHash: $"{type}-{sid}-{mask:X8}",
        CanonicalizationVersion: 1);

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
