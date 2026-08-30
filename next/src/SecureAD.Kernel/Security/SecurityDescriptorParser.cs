using System.Buffers.Binary;
using System.Text;

namespace SecureAD.Kernel.Security;

/// <summary>
/// Parses raw binary ntSecurityDescriptor bytes into <see cref="ParsedSecurityDescriptor"/>.
/// Pure binary parsing — no OS/platform calls, no ActiveDirectorySecurity, no Windows-only APIs.
/// Handles self-relative security descriptors as returned by LDAP.
/// </summary>
public static class SecurityDescriptorParser
{
    /// <summary>The version of the parsing semantics applied to stored security descriptors.</summary>
    public const int Version = 1;

    // SD header offsets (self-relative format)
    private const int HeaderSize = 20;
    private const int RevisionOffset = 0;
    private const int ControlOffset = 2;
    private const int OwnerOffset = 4;
    private const int GroupOffset = 8;
    private const int DaclOffsetField = 16;

    // Control flag bits
    private const ushort SE_DACL_PRESENT = 0x0004;
    private const ushort SE_DACL_PROTECTED = 0x1000;
    private const ushort SE_SELF_RELATIVE = 0x8000;

    // ACE flag bits
    private const byte INHERITED_ACE = 0x10;
    private const byte OBJECT_INHERIT_ACE = 0x01;
    private const byte CONTAINER_INHERIT_ACE = 0x02;
    private const byte NO_PROPAGATE_INHERIT_ACE = 0x04;
    private const byte INHERIT_ONLY_ACE = 0x08;

    // Object ACE flags (within the object ACE body)
    private const int ACE_OBJECT_TYPE_PRESENT = 0x01;
    private const int ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02;

    /// <summary>
    /// Parses a raw binary security descriptor into its components.
    /// </summary>
    /// <param name="rawSd">Raw ntSecurityDescriptor bytes (self-relative format).</param>
    /// <returns>Parsed result with owner, group, DACL state, ACEs, and any errors.</returns>
    public static ParsedSecurityDescriptor Parse(ReadOnlySpan<byte> rawSd)
    {
        var errors = new List<string>();

        if (rawSd.Length < HeaderSize)
        {
            return Undecodable(
                $"Security descriptor too short: {rawSd.Length} bytes, minimum {HeaderSize}");
        }

        var revision = rawSd[RevisionOffset];
        var headerTrustworthy = true;
        if (revision != 1)
        {
            errors.Add($"Unexpected SD revision: {revision} (expected 1)");
            headerTrustworthy = false;
        }

        var control = BinaryPrimitives.ReadUInt16LittleEndian(rawSd[ControlOffset..]);

        if ((control & SE_SELF_RELATIVE) == 0)
        {
            errors.Add("Security descriptor is not self-relative");
            headerTrustworthy = false;
        }

        // [MS-DTYP] 2.4.6 declares OffsetOwner, OffsetGroup, OffsetSacl and OffsetDacl as ULONG.
        // They are read unsigned for that reason: read as Int32, an offset with the high bit set
        // becomes negative, passes a `>= Length` bounds check, and then throws out of a range
        // expression - so a malformed descriptor crashed the parse instead of being recorded.
        var ownerOffsetValue = BinaryPrimitives.ReadUInt32LittleEndian(rawSd[OwnerOffset..]);
        var groupOffsetValue = BinaryPrimitives.ReadUInt32LittleEndian(rawSd[GroupOffset..]);
        var daclOffsetValue = BinaryPrimitives.ReadUInt32LittleEndian(rawSd[DaclOffsetField..]);

        // Parse owner SID
        var ownerSid = TryParseSidAtOffset(rawSd, ownerOffsetValue, errors, "Owner");

        // Parse group SID
        var groupSid = TryParseSidAtOffset(rawSd, groupOffsetValue, errors, "Group");

        // Parse DACL
        var isDaclProtected = (control & SE_DACL_PROTECTED) != 0;
        var daclPresent = (control & SE_DACL_PRESENT) != 0;

        if (!daclPresent || daclOffsetValue == 0)
        {
            // A genuinely absent DACL is a fact worth reporting as such - but only if the header it
            // was read from can be believed. A descriptor with the wrong revision, or one that is
            // not self-relative, has offsets that mean something else entirely, and "no DACL" read
            // out of it would be a guess presented as the most permissive state AD has.
            return headerTrustworthy
                ? new ParsedSecurityDescriptor(
                    ownerSid, groupSid, DaclState.Null, isDaclProtected, [], control, errors,
                    DaclCompleteness: DaclCompleteness.Complete, DaclWasCanonical: true)
                : new ParsedSecurityDescriptor(
                    ownerSid, groupSid, DaclState.Unreadable, isDaclProtected, [], control, errors,
                    DaclCompleteness: DaclCompleteness.Unknown, DaclWasCanonical: false);
        }

        if (daclOffsetValue >= (uint)rawSd.Length)
        {
            errors.Add($"DACL offset {daclOffsetValue} exceeds SD length {rawSd.Length}");
            return new ParsedSecurityDescriptor(
                ownerSid, groupSid, DaclState.Unreadable, isDaclProtected, [], control, errors,
                DaclCompleteness: DaclCompleteness.Unknown, DaclWasCanonical: false);
        }

        var daclSpan = rawSd[(int)daclOffsetValue..];

        // Whether the ACL header can be read at all decides everything below it. A DACL too short
        // to state its own entry count is unreadable, not empty - and reading the count as zero
        // here is exactly how the first draft of this change reported a truncated ACL as a DACL
        // that denies everybody. See docs/decisions/0037.
        const int AclHeaderSize = 8;
        var headerReadable = daclSpan.Length >= AclHeaderSize;

        if (!headerReadable)
        {
            errors.Add($"ACL too short: {daclSpan.Length} bytes, minimum {AclHeaderSize}");
            return new ParsedSecurityDescriptor(
                ownerSid, groupSid, DaclState.Unreadable, isDaclProtected, [], control, errors,
                DaclCompleteness: DaclCompleteness.Unknown, DaclWasCanonical: false);
        }

        var declaredAclSize = BinaryPrimitives.ReadUInt16LittleEndian(daclSpan[2..]);
        if (declaredAclSize < AclHeaderSize || declaredAclSize > daclSpan.Length)
        {
            errors.Add(
                $"ACL declares size {declaredAclSize} bytes, but {daclSpan.Length} bytes are "
                + "available from its offset.");
            return new ParsedSecurityDescriptor(
                ownerSid, groupSid, DaclState.Unreadable, isDaclProtected, [], control, errors,
                DaclCompleteness: DaclCompleteness.Unknown, DaclWasCanonical: false);
        }

        var declaredAceCount = BinaryPrimitives.ReadUInt16LittleEndian(daclSpan[4..]);

        var aces = ParseAcl(daclSpan[..declaredAclSize], errors);

        // Judged here because this is the last moment the entries are in the order the directory
        // stored them. AceNormalizer sorts them next, and after that nothing can tell. See
        // docs/decisions/0038.
        var daclWasCanonical = AceCanonicalization.IsCanonicalOrder(aces);

        var completeness = aces.Count == declaredAceCount
            ? DaclCompleteness.Complete
            : DaclCompleteness.Incomplete;

        var daclState = DecideDaclState(headerReadable, declaredAceCount, aces.Count);

        return new ParsedSecurityDescriptor(
            ownerSid, groupSid, daclState, isDaclProtected, aces, control, errors,
            completeness, daclWasCanonical);
    }

    /// <summary>
    /// Decides what a DACL's entry list means, given whether its header could be read, how many
    /// entries that header declared, and how many were actually parsed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Zero entries has three meanings and they are not interchangeable.</b> A header declaring
    /// none is a genuinely empty DACL, which denies everybody. A header declaring some, none of
    /// which parsed, is a DACL nobody can read - and reporting that as empty told an auditor the
    /// object was the most locked-down in the forest. So is a header that could not be read at all.
    /// That was the defect <c>docs/decisions/0037-an-unreadable-dacl-says-so.md</c> records.
    /// </para>
    /// <para>
    /// A DACL that yielded <i>some</i> of what it declared stays <see cref="DaclState.Present"/>,
    /// because it is present and that is not a lie. The shortfall is carried by
    /// <see cref="DaclCompleteness"/> instead, so this field holds a fact rather than a judgement.
    /// </para>
    /// </remarks>
    private static DaclState DecideDaclState(
        bool headerReadable, int declaredAceCount, int parsedAceCount)
    {
        if (!headerReadable)
        {
            return DaclState.Unreadable;
        }

        if (parsedAceCount > 0)
        {
            return DaclState.Present;
        }

        return declaredAceCount > 0 ? DaclState.Unreadable : DaclState.Empty;
    }

    /// <summary>
    /// The result for a descriptor that could not be decoded at all.
    /// </summary>
    /// <remarks>
    /// <b>A descriptor nobody could read is not a null DACL.</b> Per MS-ADTS 5.1.3.3.1 a NULL DACL
    /// in <c>nTSecurityDescriptor</c> grants full access to any principal that requests it, so
    /// returning <see cref="DaclState.Null"/> from a failed decode reports the most permissive
    /// state Active Directory has - and the earlier code asserted
    /// <see cref="DaclCompleteness.Complete"/> and canonical order alongside it. Every failure path
    /// comes here instead, so the outcome says what is actually known: nothing.
    /// </remarks>
    private static ParsedSecurityDescriptor Undecodable(string error) =>
        new(null, null, DaclState.Unreadable, false, [], 0, [error],
            DaclCompleteness: DaclCompleteness.Unknown, DaclWasCanonical: false);

    /// <summary>
    /// Parses a base64-encoded security descriptor string.
    /// </summary>
    public static ParsedSecurityDescriptor ParseBase64(string base64Sd)
    {
        ArgumentNullException.ThrowIfNull(base64Sd);

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(base64Sd);
        }
        catch (FormatException ex)
        {
            return Undecodable($"Invalid base64: {ex.Message}");
        }

        return Parse(bytes);
    }

    /// <summary>
    /// Parses an ACL (DACL or SACL) from its binary representation.
    /// ACL header: revision (1), padding (1), size (2), ace_count (2), padding (2) = 8 bytes.
    /// </summary>
    internal static List<ParsedAce> ParseAcl(ReadOnlySpan<byte> acl, List<string> errors)
    {
        const int AclHeaderSize = 8;
        var aces = new List<ParsedAce>();

        if (acl.Length < AclHeaderSize)
        {
            errors.Add($"ACL too short: {acl.Length} bytes, minimum {AclHeaderSize}");
            return aces;
        }

        var aceCount = BinaryPrimitives.ReadUInt16LittleEndian(acl[4..]);
        var offset = AclHeaderSize;

        for (int i = 0; i < aceCount; i++)
        {
            if (offset + 4 > acl.Length)
            {
                errors.Add($"ACE {i}: truncated ACE header at offset {offset}");
                break;
            }

            var aceType = acl[offset];
            var aceFlags = acl[offset + 1];
            var aceSize = BinaryPrimitives.ReadUInt16LittleEndian(acl[(offset + 2)..]);

            if (aceSize < 4 || offset + aceSize > acl.Length)
            {
                errors.Add($"ACE {i}: invalid size {aceSize} at offset {offset}");
                break;
            }

            var aceSpan = acl.Slice(offset, aceSize);
            var parsed = TryParseAce(aceType, aceFlags, aceSpan, errors, i);
            if (parsed is not null)
            {
                aces.Add(parsed);
            }

            offset += aceSize;
        }

        return aces;
    }

    /// <summary>
    /// Parses a single ACE from its binary representation.
    /// </summary>
    private static ParsedAce? TryParseAce(
        byte aceType, byte aceFlags, ReadOnlySpan<byte> aceData, List<string> errors, int aceIndex)
    {
        // ACE header: type (1), flags (1), size (2) = 4 bytes
        // After header: access_mask (4), then SID or object-ACE fields
        const int AceHeaderSize = 4;
        const int AccessMaskSize = 4;

        if (aceData.Length < AceHeaderSize + AccessMaskSize)
        {
            errors.Add($"ACE {aceIndex}: too short for access mask ({aceData.Length} bytes)");
            return null;
        }

        var accessMask = BinaryPrimitives.ReadInt32LittleEndian(aceData[AceHeaderSize..]);
        var isInherited = (aceFlags & INHERITED_ACE) != 0;
        var inheritanceFlags = (byte)(aceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE));
        var propagationFlags = (byte)(aceFlags & (NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE));

        // Determine if this is an object ACE type
        if (IsObjectAceType(aceType))
        {
            return TryParseObjectAce(
                aceType, aceFlags, accessMask, aceData, isInherited,
                inheritanceFlags, propagationFlags, errors, aceIndex);
        }

        // Non-object ACE: header (4) + mask (4) + SID
        var sidOffset = AceHeaderSize + AccessMaskSize;
        if (sidOffset >= aceData.Length)
        {
            errors.Add($"ACE {aceIndex}: no SID data after access mask");
            return null;
        }

        var trusteeSid = TryParseSid(aceData[sidOffset..], errors, $"ACE {aceIndex}");
        if (trusteeSid is null)
        {
            return null;
        }

        return new ParsedAce(
            AceType: (AceType)aceType,
            AceFlags: aceFlags,
            AccessMask: accessMask,
            TrusteeSid: trusteeSid,
            ObjectTypeGuid: null,
            InheritedObjectTypeGuid: null,
            IsInherited: isInherited,
            InheritanceFlags: inheritanceFlags,
            PropagationFlags: propagationFlags,
            Ordinal: aceIndex,
            ObjectFlags: 0,
            ApplicationData: ReadApplicationData(aceType, aceData, sidOffset));
    }

    /// <summary>
    /// Parses an object-type ACE (ACCESS_ALLOWED_OBJECT, ACCESS_DENIED_OBJECT, etc.).
    /// Object ACE body after header: access_mask (4), flags (4), [ObjectType GUID (16)], [InheritedObjectType GUID (16)], SID.
    /// </summary>
    private static ParsedAce? TryParseObjectAce(
        byte aceType, byte aceFlags, int accessMask, ReadOnlySpan<byte> aceData,
        bool isInherited, byte inheritanceFlags, byte propagationFlags,
        List<string> errors, int aceIndex)
    {
        const int AceHeaderSize = 4;
        const int AccessMaskSize = 4;
        const int ObjectFlagsSize = 4;
        const int GuidSize = 16;

        var bodyOffset = AceHeaderSize + AccessMaskSize;

        if (bodyOffset + ObjectFlagsSize > aceData.Length)
        {
            errors.Add($"ACE {aceIndex}: object ACE too short for object flags");
            return null;
        }

        var objectFlags = BinaryPrimitives.ReadInt32LittleEndian(aceData[bodyOffset..]);
        var currentOffset = bodyOffset + ObjectFlagsSize;

        string? objectTypeGuid = null;
        if ((objectFlags & ACE_OBJECT_TYPE_PRESENT) != 0)
        {
            if (currentOffset + GuidSize > aceData.Length)
            {
                errors.Add($"ACE {aceIndex}: object ACE too short for ObjectType GUID");
                return null;
            }
            objectTypeGuid = ParseGuid(aceData.Slice(currentOffset, GuidSize));
            currentOffset += GuidSize;
        }

        string? inheritedObjectTypeGuid = null;
        if ((objectFlags & ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0)
        {
            if (currentOffset + GuidSize > aceData.Length)
            {
                errors.Add($"ACE {aceIndex}: object ACE too short for InheritedObjectType GUID");
                return null;
            }
            inheritedObjectTypeGuid = ParseGuid(aceData.Slice(currentOffset, GuidSize));
            currentOffset += GuidSize;
        }

        if (currentOffset >= aceData.Length)
        {
            errors.Add($"ACE {aceIndex}: no SID data in object ACE");
            return null;
        }

        var trusteeSid = TryParseSid(aceData[currentOffset..], errors, $"ACE {aceIndex}");
        if (trusteeSid is null)
        {
            return null;
        }

        return new ParsedAce(
            AceType: (AceType)aceType,
            AceFlags: aceFlags,
            AccessMask: accessMask,
            TrusteeSid: trusteeSid,
            ObjectTypeGuid: objectTypeGuid,
            InheritedObjectTypeGuid: inheritedObjectTypeGuid,
            IsInherited: isInherited,
            InheritanceFlags: inheritanceFlags,
            PropagationFlags: propagationFlags,
            Ordinal: aceIndex,
            ObjectFlags: objectFlags,
            ApplicationData: ReadApplicationData(aceType, aceData, currentOffset));
    }

    /// <summary>
    /// The bytes a callback ACE carries after its trustee SID.
    /// </summary>
    /// <remarks>
    /// <b>This is what makes a conditional ACE conditional.</b> A conditional ACE is a callback ACE
    /// whose application data holds a condition evaluated during the access check; a false condition
    /// makes the entry inapplicable. Discarded, an entry that may grant nothing reads exactly like
    /// one that always grants. Only the callback types can carry it, so every other type yields
    /// empty rather than the trailing padding an ACE is allowed to have.
    /// </remarks>
    private static byte[] ReadApplicationData(
        byte aceType, ReadOnlySpan<byte> aceData, int sidOffset)
    {
        if (!IsCallbackAceType(aceType))
        {
            return [];
        }

        // The SID states its own length, and what follows it to the end of the ACE is the data.
        var subAuthorityCount = aceData[sidOffset + 1];
        var dataOffset = sidOffset + 8 + (subAuthorityCount * 4);

        return dataOffset >= aceData.Length ? [] : aceData[dataOffset..].ToArray();
    }

    private static bool IsCallbackAceType(byte aceType)
    {
        return aceType is (byte)AceType.AccessAllowedCallback
            or (byte)AceType.AccessDeniedCallback
            or (byte)AceType.AccessAllowedCallbackObject
            or (byte)AceType.AccessDeniedCallbackObject;
    }

    /// <summary>
    /// Reads a SID at a self-relative offset, recording an offset that points outside the
    /// descriptor rather than dropping it.
    /// </summary>
    /// <remarks>
    /// An offset of zero means the field is absent, which [MS-DTYP] 2.4.6 permits and which is not
    /// an error. Any other offset past the end is a malformed descriptor, and it used to produce a
    /// null owner with an empty error list - indistinguishable from an object that genuinely has
    /// no owner recorded. An owner holds WRITE_DAC implicitly, so <i>absent</i> and <i>could not be
    /// read</i> are not the same answer.
    /// </remarks>
    private static string? TryParseSidAtOffset(
        ReadOnlySpan<byte> rawSd, uint offset, List<string> errors, string context)
    {
        if (offset == 0)
        {
            return null;
        }

        if (offset >= (uint)rawSd.Length)
        {
            errors.Add($"{context} offset {offset} exceeds SD length {rawSd.Length}");
            return null;
        }

        return TryParseSid(rawSd[(int)offset..], errors, context);
    }

    /// <summary>
    /// Parses a SID from binary. SID format: revision (1), sub-authority count (1),
    /// identifier authority (6), sub-authorities (4 × count).
    /// </summary>
    internal static string? TryParseSid(ReadOnlySpan<byte> data, List<string> errors, string context)
    {
        if (data.Length < 8)
        {
            errors.Add($"{context}: SID too short ({data.Length} bytes)");
            return null;
        }

        var subAuthorityCount = data[1];
        var expectedLength = 8 + (subAuthorityCount * 4);

        if (data.Length < expectedLength)
        {
            errors.Add($"{context}: SID truncated, expected {expectedLength} bytes, got {data.Length}");
            return null;
        }

        // The formatting itself lives in Sid, because reading a bundle back has to do the same
        // thing and a second copy of a parsing rule is how two copies come to disagree. What stays
        // here is the error reporting, which is this parser's business and not that type's.
        var formatted = Sid.ToText(data);

        if (formatted is null)
            errors.Add($"{context}: SID could not be read");

        return formatted;
    }

    /// <summary>
    /// Parses a GUID from 16 bytes in mixed-endian format (as stored in Windows structures).
    /// Returns lowercase 8-4-4-4-12 format.
    /// </summary>
    internal static string ParseGuid(ReadOnlySpan<byte> data)
    {
        // Windows GUID binary layout: Data1 (4 LE), Data2 (2 LE), Data3 (2 LE), Data4 (8 bytes)
        var guid = new Guid(data);
        return guid.ToString("D").ToLowerInvariant();
    }

    private static bool IsObjectAceType(byte aceType)
    {
        return aceType is (byte)AceType.AccessAllowedObject
            or (byte)AceType.AccessDeniedObject
            or (byte)AceType.SystemAuditObject
            or (byte)AceType.AccessAllowedCallbackObject
            or (byte)AceType.AccessDeniedCallbackObject;
    }
}
