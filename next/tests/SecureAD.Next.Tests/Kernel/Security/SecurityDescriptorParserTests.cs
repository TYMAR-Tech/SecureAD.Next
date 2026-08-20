using System.Buffers.Binary;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Parsing raw <c>nTSecurityDescriptor</c> bytes into typed owner, group, DACL state and ACEs.
///
/// <para>
/// The parser is pure binary reading with no OS calls, which is what lets the same code parse a
/// descriptor read from LDAP, from SYSVOL, and from a stored bundle.
/// </para>
/// </summary>
public sealed class SecurityDescriptorParserTests
{
    // --- Header ---

    [Fact]
    public void WhenShorterThanTheHeader_ThenParseReportsIt()
    {
        var result = SecurityDescriptorParser.Parse(new byte[10]);

        Assert.Contains(result.Errors, e => e.Contains("too short", StringComparison.Ordinal));
    }

    [Fact]
    public void WhenInputIsEmpty_ThenParseReportsIt()
    {
        var result = SecurityDescriptorParser.Parse(ReadOnlySpan<byte>.Empty);

        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void WhenSelfRelative_ThenControlFlagsAreReturned()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: []);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.NotEqual(0, result.ControlFlags);
    }

    // --- A null DACL is not an empty DACL ---
    //
    // A null DACL grants everyone full access; an empty DACL denies everyone. Collapsing the two
    // into "no ACEs" is the mistake this distinction exists to prevent, so each of the three
    // states has its own case.

    [Fact]
    public void WhenDaclPresentFlagIsClear_ThenDaclStateIsNull()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: null, daclPresent: false);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(DaclState.Null, result.DaclState);
        Assert.Empty(result.DaclAces);
    }

    [Fact]
    public void WhenDaclPresentFlagIsSetButOffsetIsZero_ThenDaclStateIsNull()
    {
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.LocalSystem, daclAces: null, daclPresent: true, forceDaclOffsetZero: true);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(DaclState.Null, result.DaclState);
    }

    [Fact]
    public void WhenDaclHasZeroAces_ThenDaclStateIsEmpty()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: []);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(DaclState.Empty, result.DaclState);
        Assert.Empty(result.DaclAces);
    }

    [Fact]
    public void WhenDaclHasAces_ThenDaclStateIsPresent()
    {
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.LocalSystem, daclAces: [SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF)]);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(DaclState.Present, result.DaclState);
        Assert.Single(result.DaclAces);
    }

    // --- Protection ---

    [Fact]
    public void WhenDaclIsProtected_ThenProtectionIsReported()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: [], daclProtected: true);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.True(result.IsDaclProtected);
    }

    [Fact]
    public void WhenDaclIsNotProtected_ThenProtectionIsNotReported()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: [], daclProtected: false);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.False(result.IsDaclProtected);
    }

    // --- Owner and group ---

    [Fact]
    public void WhenOwnerIsPresent_ThenItsSidIsParsed()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: []);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal("S-1-5-18", result.OwnerSid);
    }

    [Fact]
    public void WhenGroupIsPresent_ThenItsSidIsParsed()
    {
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.LocalSystem, groupSid: SdBytes.Administrators, daclAces: []);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal("S-1-5-32-544", result.GroupSid);
    }

    [Fact]
    public void WhenOwnerIsAbsent_ThenOwnerSidIsNull()
    {
        var sd = SdBytes.SelfRelativeSd(ownerSid: null, daclAces: []);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Null(result.OwnerSid);
    }

    [Fact]
    public void WhenOwnerIsADomainSid_ThenAllSubAuthoritiesAreRendered()
    {
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.Sid(1, 5, [21, 1234567890, 987654321, 111222333]), daclAces: []);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal("S-1-5-21-1234567890-987654321-111222333", result.OwnerSid);
        Assert.Empty(result.Errors);
    }

    // --- ACE bodies ---

    [Fact]
    public void WhenAceIsAccessAllowed_ThenTypeMaskAndTrusteeAreParsed()
    {
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.LocalSystem, daclAces: [SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF)]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.Equal(AceType.AccessAllowed, ace.AceType);
        Assert.Equal(0x000F01FF, ace.AccessMask);
        Assert.Equal("S-1-5-32-544", ace.TrusteeSid);
        Assert.Null(ace.ObjectTypeGuid);
        Assert.Null(ace.InheritedObjectTypeGuid);
    }

    [Fact]
    public void WhenAceIsAccessDenied_ThenTypeMaskAndTrusteeAreParsed()
    {
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.LocalSystem, daclAces: [SdBytes.DenyAce(SdBytes.Everyone, 0x00000004)]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.Equal(AceType.AccessDenied, ace.AceType);
        Assert.Equal(0x00000004, ace.AccessMask);
        Assert.Equal("S-1-1-0", ace.TrusteeSid);
    }

    [Fact]
    public void WhenTrusteeIsADomainSid_ThenAllSubAuthoritiesAreRendered()
    {
        var trustee = SdBytes.Sid(1, 5, [21, 1234567890, 987654321, 111222333, 1001]);
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.LocalSystem, daclAces: [SdBytes.AllowAce(trustee, 0x000F01FF)]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.Equal("S-1-5-21-1234567890-987654321-111222333-1001", ace.TrusteeSid);
    }

    [Fact]
    public void WhenSeveralAces_ThenAllAreParsedInWireOrder()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.DenyAce(SdBytes.Everyone, 0x00000004),
            SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF),
            SdBytes.AllowAce(SdBytes.LocalSystem, 0x000F01FF, aceFlags: 0x10),
        ]);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(3, result.DaclAces.Count);
        Assert.Equal(AceType.AccessDenied, result.DaclAces[0].AceType);
        Assert.Equal(AceType.AccessAllowed, result.DaclAces[1].AceType);
        Assert.True(result.DaclAces[2].IsInherited);
    }

    // --- Inheritance ---

    [Fact]
    public void WhenAceCarriesTheInheritedFlag_ThenItIsMarkedInherited()
    {
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.LocalSystem,
            daclAces: [SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF, aceFlags: 0x10)]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.True(ace.IsInherited);
    }

    [Fact]
    public void WhenAceDoesNotCarryTheInheritedFlag_ThenItIsMarkedExplicit()
    {
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.LocalSystem,
            daclAces: [SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF, aceFlags: 0x00)]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.False(ace.IsInherited);
    }

    /// <summary>
    /// The single ACE flags byte carries three unrelated things. Inheritance and propagation are
    /// separated so a later comparison can treat them independently.
    /// </summary>
    [Fact]
    public void WhenAceFlagsMixInheritanceAndPropagation_ThenTheyAreSplitApart()
    {
        // CONTAINER_INHERIT_ACE (0x02) is inheritance; INHERIT_ONLY_ACE (0x08) is propagation.
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.LocalSystem,
            daclAces: [SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF, aceFlags: 0x02 | 0x08)]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.Equal(0x02, ace.InheritanceFlags);
        Assert.Equal(0x08, ace.PropagationFlags);
    }

    // --- Object ACEs ---

    [Fact]
    public void WhenObjectAceCarriesBothGuids_ThenBothAreParsed()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowObjectAce(
                SdBytes.Administrators, 0x00000010,
                Guid.Parse("bf967aba-0de6-11d0-a285-00aa003049e2"),
                Guid.Parse("bf967a86-0de6-11d0-a285-00aa003049e2")),
        ]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.Equal(AceType.AccessAllowedObject, ace.AceType);
        Assert.Equal("bf967aba-0de6-11d0-a285-00aa003049e2", ace.ObjectTypeGuid);
        Assert.Equal("bf967a86-0de6-11d0-a285-00aa003049e2", ace.InheritedObjectTypeGuid);
    }

    [Fact]
    public void WhenObjectAceCarriesOnlyTheObjectType_ThenTheInheritedGuidIsNull()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowObjectAce(
                SdBytes.Administrators, 0x00000010,
                Guid.Parse("bf967aba-0de6-11d0-a285-00aa003049e2"),
                inheritedObjectType: null),
        ]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.Equal("bf967aba-0de6-11d0-a285-00aa003049e2", ace.ObjectTypeGuid);
        Assert.Null(ace.InheritedObjectTypeGuid);
    }

    [Fact]
    public void WhenObjectAceCarriesNeitherGuid_ThenBothAreNull()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowObjectAce(
                SdBytes.Administrators, 0x00000010,
                objectType: null, inheritedObjectType: null),
        ]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.Null(ace.ObjectTypeGuid);
        Assert.Null(ace.InheritedObjectTypeGuid);
    }

    // --- Presence is a flag, not a null check ---
    //
    // [MS-DTYP] decides whether an object ACE carries a GUID by ACE_OBJECT_TYPE_PRESENT, not by
    // what the GUID turned out to be. Reading presence off the parsed string collapses "no GUID"
    // and "the null GUID" into one answer, and they scope an entry differently. S-56 R1.

    [Fact]
    public void WhenAnObjectAceCarriesNoObjectType_ThenItReportsTheGuidAbsent()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowObjectAce(
                SdBytes.Administrators, 0x00000010,
                objectType: null, inheritedObjectType: null),
        ]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.False(ace.HasObjectType);
    }

    [Fact]
    public void WhenAnObjectAceCarriesTheNullGuid_ThenItReportsTheGuidPresent()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowObjectAce(
                SdBytes.Administrators, 0x00000010,
                objectType: Guid.Empty, inheritedObjectType: null),
        ]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.True(ace.HasObjectType);
        Assert.Equal("00000000-0000-0000-0000-000000000000", ace.ObjectTypeGuid);
    }

    /// <summary>
    /// The pair the old shape could not tell apart, asserted together so that a change collapsing
    /// them again fails here rather than somewhere that reads the result.
    /// </summary>
    [Fact]
    public void AnAbsentObjectTypeAndTheNullObjectTypeAreDistinguishable()
    {
        var absent = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowObjectAce(
                SdBytes.Administrators, 0x00000010,
                objectType: null, inheritedObjectType: null),
        ]);
        var nullGuid = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowObjectAce(
                SdBytes.Administrators, 0x00000010,
                objectType: Guid.Empty, inheritedObjectType: null),
        ]);

        var withoutGuid = Assert.Single(SecurityDescriptorParser.Parse(absent).DaclAces);
        var withNullGuid = Assert.Single(SecurityDescriptorParser.Parse(nullGuid).DaclAces);

        Assert.NotEqual(withoutGuid.HasObjectType, withNullGuid.HasObjectType);
    }

    [Fact]
    public void WhenAnObjectAceCarriesBothGuids_ThenBothAreReportedPresent()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowObjectAce(
                SdBytes.Administrators, 0x00000010,
                objectType: Guid.Parse("bf967aba-0de6-11d0-a285-00aa003049e2"),
                inheritedObjectType: Guid.Parse("bf967a86-0de6-11d0-a285-00aa003049e2")),
        ]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.True(ace.HasObjectType);
        Assert.True(ace.HasInheritedObjectType);
    }

    // --- The stored position ---
    //
    // AceNormalizer sorts the entries, so after normalisation nothing can say what order the
    // directory held them in. The ordinal is recorded while it is still known.

    [Fact]
    public void WhenSeveralAces_ThenEachCarriesTheStoredPositionItArrivedIn()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF),
            SdBytes.DenyAce(SdBytes.Everyone, 0x00000004),
            SdBytes.AllowAce(SdBytes.LocalSystem, 0x00000010),
        ]);

        var aces = SecurityDescriptorParser.Parse(sd).DaclAces;

        Assert.Equal([0, 1, 2], aces.Select(a => a.Ordinal));
        Assert.Equal("S-1-1-0", aces[1].TrusteeSid);
    }

    // --- Callback application data ---
    //
    // A conditional ACE is a callback ACE whose application data holds the condition. Dropped, an
    // entry that may not apply at all reads exactly like one that always does.

    [Fact]
    public void WhenACallbackAceCarriesApplicationData_ThenTheBytesAreKept()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            CallbackAce(0x09, SdBytes.Administrators, 0x00000010, [0x61, 0x72, 0x74, 0x78]),
        ]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.Equal(AceType.AccessAllowedCallback, ace.AceType);
        Assert.Equal<byte[]>([0x61, 0x72, 0x74, 0x78], ace.ApplicationData);
    }

    [Fact]
    public void WhenAnAceIsNotACallbackType_ThenItCarriesNoApplicationData()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF),
        ]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.Empty(ace.ApplicationData);
    }

    /// <summary>A callback ACE: a plain ACE with application data appended after the SID.</summary>
    private static byte[] CallbackAce(
        byte aceType, byte[] trusteeSid, int accessMask, byte[] applicationData)
    {
        var ace = SdBytes.SimpleAce(aceType, 0, accessMask, trusteeSid);
        var withData = new byte[ace.Length + applicationData.Length];

        ace.CopyTo(withData, 0);
        applicationData.CopyTo(withData, ace.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(withData.AsSpan(2), (ushort)withData.Length);

        return withData;
    }

    [Fact]
    public void WhenObjectAceIsAccessDeniedObject_ThenTypeAndGuidAreParsed()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            // 00299570-… is Reset Password, an extended right rather than a class.
            SdBytes.DenyObjectAce(
                SdBytes.Everyone, 0x00000100,
                Guid.Parse("00299570-246d-11d0-a768-00aa006e0529"),
                inheritedObjectType: null),
        ]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.Equal(AceType.AccessDeniedObject, ace.AceType);
        Assert.Equal("00299570-246d-11d0-a768-00aa006e0529", ace.ObjectTypeGuid);
    }

    /// <summary>
    /// GUIDs are rendered lowercase so two descriptors that differ only in case do not compare as
    /// different.
    /// </summary>
    [Fact]
    public void WhenObjectTypeGuidIsGiven_ThenItIsRenderedLowercase()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowObjectAce(
                SdBytes.Administrators, 0x00000010,
                Guid.Parse("BF967ABA-0DE6-11D0-A285-00AA003049E2"),
                inheritedObjectType: null),
        ]);

        var ace = Assert.Single(SecurityDescriptorParser.Parse(sd).DaclAces);

        Assert.Equal("bf967aba-0de6-11d0-a285-00aa003049e2", ace.ObjectTypeGuid);
    }

    // --- Base64 ---

    [Fact]
    public void WhenDescriptorIsBase64_ThenItParsesAsBytesDo()
    {
        var base64 = Convert.ToBase64String(
            SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: []));

        var result = SecurityDescriptorParser.ParseBase64(base64);

        Assert.Equal("S-1-5-18", result.OwnerSid);
        Assert.Equal(DaclState.Empty, result.DaclState);
    }

    [Fact]
    public void WhenBase64IsInvalid_ThenParseReportsIt()
    {
        var result = SecurityDescriptorParser.ParseBase64("not-valid-base64!!!");

        Assert.Contains(result.Errors, e => e.Contains("Invalid base64", StringComparison.Ordinal));
    }

    /// <summary>
    /// A descriptor that could not be decoded is not a null DACL. Per MS-ADTS 5.1.3.3.1 a null DACL
    /// grants full access to any principal that asks, so returning one from a failed decode reports
    /// the most permissive state Active Directory has - and the earlier code asserted completeness
    /// and canonical order alongside it.
    /// </summary>
    [Fact]
    public void WhenBase64IsInvalid_ThenTheDaclIsNotAConfidentNullDacl()
    {
        var result = SecurityDescriptorParser.ParseBase64("not-valid-base64!!!");

        Assert.Equal(DaclState.Unreadable, result.DaclState);
        Assert.Equal(DaclCompleteness.Unknown, result.DaclCompleteness);
        Assert.False(result.DaclWasCanonical);
    }

    [Fact]
    public void WhenTheDescriptorIsTooShortForItsHeader_ThenTheDaclIsNotAConfidentNullDacl()
    {
        var result = SecurityDescriptorParser.Parse(new byte[4]);

        Assert.Equal(DaclState.Unreadable, result.DaclState);
        Assert.Equal(DaclCompleteness.Unknown, result.DaclCompleteness);
        Assert.False(result.DaclWasCanonical);
    }

    // --- Corrupt input ---
    //
    // A descriptor read from a live directory can be malformed. Parsing must report the damage
    // rather than throwing, because one bad object must not fail a whole capture.

    [Fact]
    public void WhenDaclOffsetPointsBeyondTheDescriptor_ThenTheDaclIsUnreadableAndTheDamageIsReported()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: []);
        BinaryPrimitives.WriteInt32LittleEndian(sd.AsSpan(16), sd.Length + 100);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(DaclState.Unreadable, result.DaclState);
        Assert.Contains(result.Errors, e => e.Contains("exceeds", StringComparison.Ordinal));
    }

    [Fact]
    public void WhenAnAceIsTruncated_ThenTheDamageIsReported()
    {
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.LocalSystem, daclAces: [SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF)]);
        var truncated = sd.AsSpan(0, sd.Length - 4).ToArray();

        var result = SecurityDescriptorParser.Parse(truncated);

        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void WhenOwnerOffsetPointsAtTooFewBytes_ThenOwnerIsNullAndTheDamageIsReported()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: []);
        BinaryPrimitives.WriteInt32LittleEndian(sd.AsSpan(4), sd.Length - 3);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Null(result.OwnerSid);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void WhenDescriptorIsWellFormed_ThenNoErrorsAreReported()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.DenyAce(SdBytes.Everyone, 0x00000004),
            SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF),
        ]);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Empty(result.Errors);
        Assert.Equal(2, result.DaclAces.Count);
    }

    // --- Offsets are unsigned ---
    //
    // [MS-DTYP] 2.4.6 declares OffsetOwner, OffsetGroup, OffsetSacl and OffsetDacl as ULONG.
    // Read as Int32 they go negative above 0x7FFFFFFF, which passes a `>= Length` bounds check and
    // then throws out of the range expression that follows. Found in S-21 by reading the
    // specification; no fixture had ever produced one, because no directory does.

    [Fact]
    public void WhenDaclOffsetHasTheHighBitSet_ThenTheDamageIsReportedRatherThanThrown()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
            [SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF)]);
        BinaryPrimitives.WriteUInt32LittleEndian(sd.AsSpan(16), 0x80000014u);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(DaclState.Unreadable, result.DaclState);
        Assert.Contains(result.Errors, e => e.Contains("exceeds SD length", StringComparison.Ordinal));
    }

    [Fact]
    public void WhenOwnerOffsetHasTheHighBitSet_ThenTheDamageIsReportedRatherThanThrown()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: []);
        BinaryPrimitives.WriteUInt32LittleEndian(sd.AsSpan(4), 0x80000014u);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Null(result.OwnerSid);
        Assert.Contains(result.Errors, e => e.Contains("Owner offset", StringComparison.Ordinal));
    }

    /// <summary>
    /// An owner offset past the end used to yield a null owner and an empty error list, which
    /// reads as an object that genuinely records no owner. An owner holds WRITE_DAC implicitly,
    /// so <i>absent</i> and <i>could not be read</i> are not the same answer.
    /// </summary>
    [Fact]
    public void WhenOwnerOffsetIsPastTheEnd_ThenTheDamageIsReportedRatherThanSilentlyDropped()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: []);
        BinaryPrimitives.WriteUInt32LittleEndian(sd.AsSpan(4), (uint)sd.Length + 9000u);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Null(result.OwnerSid);
        Assert.Contains(result.Errors, e => e.Contains("Owner offset", StringComparison.Ordinal));
    }

    /// <summary>
    /// An offset of zero means the field is absent, which is legitimate and must stay silent -
    /// otherwise every descriptor without a group would report damage.
    /// </summary>
    [Fact]
    public void WhenGroupOffsetIsZero_ThenTheFieldIsAbsentAndNothingIsReported()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: []);
        BinaryPrimitives.WriteUInt32LittleEndian(sd.AsSpan(8), 0u);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Null(result.GroupSid);
        Assert.DoesNotContain(result.Errors, e => e.Contains("Group offset", StringComparison.Ordinal));
    }

    // --- A DACL nobody could read is not a DACL that denies everybody ---
    //
    // Three different situations produce zero entries and they mean different things. Two of them
    // are a statement about the object; the third is a statement about the run. Conflating the
    // third with `Empty` reported an object the product failed to read as the most locked-down
    // object in the forest. See docs/decisions/0037.

    [Fact]
    public void WhenTheDaclDeclaresEntriesAndNoneParse_ThenTheStateIsUnreadableRatherThanEmpty()
    {
        // A DACL header claiming two entries, followed by one malformed four-byte entry.
        var sd = MalformedDacl(declaredAceCount: 2, aceBytes: [0x00, 0x00, 0x04, 0x00]);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(DaclState.Unreadable, result.DaclState);
        Assert.Empty(result.DaclAces);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void WhenTheDaclHeaderCannotBeReadAtAll_ThenTheStateIsUnreadableAndCompletenessIsUnknown()
    {
        // A DACL region of four bytes: too short even to state how many entries it holds.
        var sd = TruncatedDaclHeader();

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(DaclState.Unreadable, result.DaclState);
        Assert.Equal(DaclCompleteness.Unknown, result.DaclCompleteness);
    }

    [Fact]
    public void WhenTheDaclIsGenuinelyEmpty_ThenTheStateIsEmptyAndCompletenessIsComplete()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: []);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(DaclState.Empty, result.DaclState);
        Assert.Equal(DaclCompleteness.Complete, result.DaclCompleteness);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void WhenTheDaclIsAbsent_ThenTheStateIsNullWhichGrantsEveryoneEverything()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclPresent: false);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(DaclState.Null, result.DaclState);
    }

    /// <summary>
    /// The half that a fourth state cannot express. A DACL that yielded some of what it declared is
    /// genuinely <c>Present</c>, and the shortfall has nowhere to live but here.
    /// </summary>
    [Fact]
    public void WhenTheDaclYieldsFewerEntriesThanItDeclared_ThenItStaysPresentAndSaysItIsIncomplete()
    {
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.LocalSystem,
            daclAces: [SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF)]);

        // Claim three entries where one is present. The header count is what the loop trusts.
        OverstateAceCount(sd, 3);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(DaclState.Present, result.DaclState);
        Assert.Equal(DaclCompleteness.Incomplete, result.DaclCompleteness);
        Assert.Single(result.DaclAces);
    }

    [Fact]
    public void WhenEveryDeclaredEntryParses_ThenCompletenessIsComplete()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.DenyAce(SdBytes.Everyone, 0x00000004),
            SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF),
        ]);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(DaclCompleteness.Complete, result.DaclCompleteness);
    }

    // --- The order the directory stored, recorded before it is sorted away ---
    //
    // AD examines every ACE in the DACL and adds a deny only for rights it has not already
    // granted, so an allow before a deny grants what the canonical form denies. It is not an
    // early stop at the first match. [MS-ADTS] 5.1.3.3.2. See docs/decisions/0038.

    [Fact]
    public void WhenDenyPrecedesAllow_ThenTheDaclIsRecordedAsCanonical()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.DenyAce(SdBytes.Everyone, 0x00000004),
            SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF),
        ]);

        Assert.True(SecurityDescriptorParser.Parse(sd).DaclWasCanonical);
    }

    [Fact]
    public void WhenAllowPrecedesDeny_ThenTheDaclIsRecordedAsNotCanonical()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF),
            SdBytes.DenyAce(SdBytes.Everyone, 0x00000004),
        ]);

        Assert.False(SecurityDescriptorParser.Parse(sd).DaclWasCanonical);
    }

    /// <summary>
    /// Explicit entries come before inherited ones. An inherited deny sitting ahead of an explicit
    /// allow is out of order even though deny precedes allow, and this is the case a check written
    /// only as "denies first" would miss.
    /// </summary>
    [Fact]
    public void WhenAnInheritedEntryPrecedesAnExplicitOne_ThenTheDaclIsRecordedAsNotCanonical()
    {
        const byte Inherited = 0x10;

        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.DenyAce(SdBytes.Everyone, 0x00000004, aceFlags: Inherited),
            SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF),
        ]);

        Assert.False(SecurityDescriptorParser.Parse(sd).DaclWasCanonical);
    }

    /// <summary>
    /// The limit of what this flag claims, pinned so it stays visible. <c>S-56</c> v4 R5 wants
    /// inherited entries checked in inheritance-generation order - parent, then grandparent - and
    /// that cannot be established here at all: an inherited ACE carries no depth field, so two
    /// inherited allows from different ancestors are indistinguishable and either sequence passes.
    /// </summary>
    /// <remarks>
    /// This is not a defect in the check, it is a defect in reading the flag as more than it says.
    /// Proving generation order needs ancestor descriptors, schema applicability, inheritance flags
    /// and protection boundaries, none of which one object's DACL holds. <c>0038</c>'s amendment
    /// records it, and this test exists so a later reader finds the gap asserted rather than
    /// implied.
    /// </remarks>
    [Fact]
    public void TheFlagCannotSeeInheritedGenerationOrderAndDoesNotClaimTo()
    {
        const byte Inherited = 0x10;

        var oneWay = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF, aceFlags: Inherited),
            SdBytes.AllowAce(SdBytes.Everyone, 0x00000004, aceFlags: Inherited),
        ]);

        var theOther = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowAce(SdBytes.Everyone, 0x00000004, aceFlags: Inherited),
            SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF, aceFlags: Inherited),
        ]);

        Assert.True(SecurityDescriptorParser.Parse(oneWay).DaclWasCanonical);
        Assert.True(SecurityDescriptorParser.Parse(theOther).DaclWasCanonical);
    }

    [Fact]
    public void WhenTheDaclHasOneEntry_ThenItIsCanonicalBecauseNoPairCanBeOutOfOrder()
    {
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.LocalSystem,
            daclAces: [SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF)]);

        Assert.True(SecurityDescriptorParser.Parse(sd).DaclWasCanonical);
    }

    // --- An entry whose type we do not model is skipped, not guessed at ---
    //
    // CategoryOf maps any undefined type to "not a deny", which is a fine default for a total sort
    // and a bad one for a judgement. Skipping such entries makes DaclWasCanonical mean "the entries
    // I recognised were in order", which is honest only because the entry itself survives in
    // ace.ace_type as its number - held by BundleWriterTests.

    /// <summary>
    /// Without the skip, the unmodelled entry sorts as an allow, and the deny that follows it looks
    /// like a deny after an allow - so a perfectly ordinary DACL would be reported as reordered.
    /// </summary>
    [Fact]
    public void WhenAnUnmodelledEntryPrecedesADeny_ThenTheDaclIsStillCanonical()
    {
        const byte SystemResourceAttribute = 0x12;

        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.SimpleAce(SystemResourceAttribute, 0, 0x00020000, SdBytes.Everyone),
            SdBytes.DenyAce(SdBytes.Everyone, 0x00000004),
            SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF),
        ]);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(3, result.DaclAces.Count);
        Assert.True(result.DaclWasCanonical);
    }

    /// <summary>
    /// And the skip must not hide a real reordering among the entries that are modelled.
    /// </summary>
    [Fact]
    public void WhenAnUnmodelledEntrySitsBetweenAnAllowAndADeny_ThenTheReorderingIsStillSeen()
    {
        const byte SystemResourceAttribute = 0x12;

        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.AllowAce(SdBytes.Administrators, 0x000F01FF),
            SdBytes.SimpleAce(SystemResourceAttribute, 0, 0x00020000, SdBytes.Everyone),
            SdBytes.DenyAce(SdBytes.Everyone, 0x00000004),
        ]);

        Assert.False(SecurityDescriptorParser.Parse(sd).DaclWasCanonical);
    }

    /// <summary>
    /// A DACL of nothing but unmodelled entries is canonical, vacuously. The claim is about what
    /// was understood, and nothing here was.
    /// </summary>
    [Fact]
    public void WhenEveryEntryIsUnmodelled_ThenTheDaclIsCanonicalVacuously()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces:
        [
            SdBytes.SimpleAce(0x12, 0, 0x00020000, SdBytes.Everyone),
            SdBytes.SimpleAce(0x13, 0, 0x00020000, SdBytes.Administrators),
        ]);

        var result = SecurityDescriptorParser.Parse(sd);

        Assert.Equal(2, result.DaclAces.Count);
        Assert.True(result.DaclWasCanonical);
    }

    /// <summary>
    /// The entries are still parsed and carried, which is what makes skipping them defensible.
    /// </summary>
    [Fact]
    public void AnUnmodelledEntryIsStillParsedAndKeepsItsTypeByte()
    {
        var sd = SdBytes.SelfRelativeSd(
            SdBytes.LocalSystem,
            daclAces: [SdBytes.SimpleAce(0x12, 0, 0x00020000, SdBytes.Everyone)]);

        var result = SecurityDescriptorParser.Parse(sd);

        var ace = Assert.Single(result.DaclAces);
        Assert.Equal(0x12, (byte)ace.AceType);
        Assert.False(Enum.IsDefined(ace.AceType));
    }

    /// <summary>
    /// A descriptor whose DACL region is present but shorter than the eight-byte ACL header.
    /// </summary>
    private static byte[] TruncatedDaclHeader()
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: []);
        var daclOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(sd.AsSpan(16));

        return sd.AsSpan(0, daclOffset + 4).ToArray();
    }

    /// <summary>
    /// A descriptor whose DACL header declares <paramref name="declaredAceCount"/> entries and is
    /// followed by <paramref name="aceBytes"/>, which do not parse.
    /// </summary>
    private static byte[] MalformedDacl(ushort declaredAceCount, byte[] aceBytes)
    {
        var sd = SdBytes.SelfRelativeSd(SdBytes.LocalSystem, daclAces: []);
        var daclOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(sd.AsSpan(16));

        var built = new byte[daclOffset + 8 + aceBytes.Length];
        sd.AsSpan(0, daclOffset + 8).CopyTo(built);
        aceBytes.CopyTo(built.AsSpan(daclOffset + 8));

        var dacl = built.AsSpan(daclOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(dacl[2..], (ushort)(8 + aceBytes.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(dacl[4..], declaredAceCount);

        return built;
    }

    /// <summary>Rewrites the DACL header's entry count in place.</summary>
    private static void OverstateAceCount(byte[] sd, ushort declaredAceCount)
    {
        var daclOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(sd.AsSpan(16));
        BinaryPrimitives.WriteUInt16LittleEndian(sd.AsSpan(daclOffset + 4), declaredAceCount);
    }
}
