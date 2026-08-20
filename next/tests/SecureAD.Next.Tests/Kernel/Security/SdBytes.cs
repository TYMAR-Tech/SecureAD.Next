using System.Buffers.Binary;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Builds valid self-relative security-descriptor bytes for the parser tests.
///
/// <para>
/// The parser takes raw <c>nTSecurityDescriptor</c> bytes, so the only honest way to test it is to
/// hand it bytes. These builders assemble the same layout LDAP returns: a 20-byte header holding
/// offsets, then the owner SID, the group SID, and the DACL.
/// </para>
/// </summary>
internal static class SdBytes
{
    /// <summary>S-1-5-18, Local System.</summary>
    public static byte[] LocalSystem => Sid(1, 5, [18]);

    /// <summary>S-1-5-32-544, Administrators.</summary>
    public static byte[] Administrators => Sid(1, 5, [32, 544]);

    /// <summary>S-1-1-0, Everyone.</summary>
    public static byte[] Everyone => Sid(1, 1, [0]);

    /// <summary>
    /// A binary SID: revision (1), sub-authority count (1), identifier authority (6, big-endian),
    /// then the sub-authorities (4 each, little-endian).
    /// </summary>
    public static byte[] Sid(byte revision, long authority, uint[] subAuthorities)
    {
        var sid = new byte[8 + subAuthorities.Length * 4];
        sid[0] = revision;
        sid[1] = (byte)subAuthorities.Length;

        for (var i = 5; i >= 0; i--)
            sid[2 + (5 - i)] = (byte)((authority >> (i * 8)) & 0xFF);

        for (var i = 0; i < subAuthorities.Length; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(sid.AsSpan(8 + i * 4), subAuthorities[i]);

        return sid;
    }

    /// <summary>An ACCESS_ALLOWED ACE (type 0x00).</summary>
    public static byte[] AllowAce(byte[] trusteeSid, int accessMask, byte aceFlags = 0) =>
        SimpleAce(0x00, aceFlags, accessMask, trusteeSid);

    /// <summary>An ACCESS_DENIED ACE (type 0x01).</summary>
    public static byte[] DenyAce(byte[] trusteeSid, int accessMask, byte aceFlags = 0) =>
        SimpleAce(0x01, aceFlags, accessMask, trusteeSid);

    /// <summary>An ACCESS_ALLOWED_OBJECT ACE (type 0x05).</summary>
    public static byte[] AllowObjectAce(
        byte[] trusteeSid, int accessMask, Guid? objectType, Guid? inheritedObjectType,
        byte aceFlags = 0) =>
        ObjectAce(0x05, aceFlags, accessMask, trusteeSid, objectType, inheritedObjectType);

    /// <summary>An ACCESS_DENIED_OBJECT ACE (type 0x06).</summary>
    public static byte[] DenyObjectAce(
        byte[] trusteeSid, int accessMask, Guid? objectType, Guid? inheritedObjectType,
        byte aceFlags = 0) =>
        ObjectAce(0x06, aceFlags, accessMask, trusteeSid, objectType, inheritedObjectType);

    /// <summary>ACE header (4) + access mask (4) + trustee SID.</summary>
    /// <remarks>
    /// Public so a test can build an ACE of a type this product does not name. Every other builder
    /// here fixes the type byte, which is right for the named types and useless for asking what
    /// happens when an entry arrives that the parser has no member for.
    /// </remarks>
    public static byte[] SimpleAce(byte aceType, byte aceFlags, int accessMask, byte[] trusteeSid)
    {
        var size = 4 + 4 + trusteeSid.Length;
        var ace = new byte[size];
        ace[0] = aceType;
        ace[1] = aceFlags;
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2), (ushort)size);
        BinaryPrimitives.WriteInt32LittleEndian(ace.AsSpan(4), accessMask);
        trusteeSid.CopyTo(ace.AsSpan(8));
        return ace;
    }

    /// <summary>
    /// ACE header (4) + access mask (4) + object flags (4) + the GUIDs the flags say are present,
    /// then the trustee SID. A GUID that is absent occupies no bytes, which is what makes the
    /// flags load-bearing rather than decorative.
    /// </summary>
    private static byte[] ObjectAce(
        byte aceType, byte aceFlags, int accessMask, byte[] trusteeSid,
        Guid? objectType, Guid? inheritedObjectType)
    {
        var objectFlags = 0;
        var guidBytes = 0;

        if (objectType.HasValue)
        {
            objectFlags |= 0x01;
            guidBytes += 16;
        }

        if (inheritedObjectType.HasValue)
        {
            objectFlags |= 0x02;
            guidBytes += 16;
        }

        var size = 4 + 4 + 4 + guidBytes + trusteeSid.Length;
        var ace = new byte[size];
        ace[0] = aceType;
        ace[1] = aceFlags;
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2), (ushort)size);
        BinaryPrimitives.WriteInt32LittleEndian(ace.AsSpan(4), accessMask);
        BinaryPrimitives.WriteInt32LittleEndian(ace.AsSpan(8), objectFlags);

        var offset = 12;

        if (objectType.HasValue)
        {
            objectType.Value.TryWriteBytes(ace.AsSpan(offset));
            offset += 16;
        }

        if (inheritedObjectType.HasValue)
        {
            inheritedObjectType.Value.TryWriteBytes(ace.AsSpan(offset));
            offset += 16;
        }

        trusteeSid.CopyTo(ace.AsSpan(offset));
        return ace;
    }

    /// <summary>
    /// A complete self-relative security descriptor.
    /// </summary>
    /// <param name="ownerSid">Owner SID bytes, or null for no owner.</param>
    /// <param name="groupSid">Group SID bytes, or null for no group.</param>
    /// <param name="daclAces">DACL ACEs, or null for no DACL at all.</param>
    /// <param name="daclPresent">Whether SE_DACL_PRESENT is set.</param>
    /// <param name="daclProtected">Whether SE_DACL_PROTECTED is set.</param>
    /// <param name="forceDaclOffsetZero">
    /// Writes a zero DACL offset while leaving SE_DACL_PRESENT set, which is the second way a
    /// descriptor says its DACL is null.
    /// </param>
    public static byte[] SelfRelativeSd(
        byte[]? ownerSid,
        byte[]? groupSid = null,
        byte[][]? daclAces = null,
        bool daclPresent = true,
        bool daclProtected = false,
        bool forceDaclOffsetZero = false)
    {
        using var buffer = new MemoryStream();
        buffer.Write(new byte[20]);

        var ownerOffset = 0;
        if (ownerSid is not null)
        {
            ownerOffset = (int)buffer.Position;
            buffer.Write(ownerSid);
        }

        var groupOffset = 0;
        if (groupSid is not null)
        {
            groupOffset = (int)buffer.Position;
            buffer.Write(groupSid);
        }

        var daclOffset = 0;
        if (daclAces is not null && daclPresent && !forceDaclOffsetZero)
        {
            daclOffset = (int)buffer.Position;

            var aclHeaderPosition = (int)buffer.Position;
            buffer.Write(new byte[8]);

            foreach (var ace in daclAces)
                buffer.Write(ace);

            var aclSize = (int)buffer.Position - aclHeaderPosition;
            var raw = buffer.GetBuffer();
            raw[aclHeaderPosition] = 2;
            BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(aclHeaderPosition + 2), (ushort)aclSize);
            BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(aclHeaderPosition + 4), (ushort)daclAces.Length);
        }

        var sd = buffer.ToArray();
        sd[0] = 1;

        ushort control = 0x8000;
        if (daclPresent)
            control |= 0x0004;
        if (daclProtected)
            control |= 0x1000;

        BinaryPrimitives.WriteUInt16LittleEndian(sd.AsSpan(2), control);
        BinaryPrimitives.WriteInt32LittleEndian(sd.AsSpan(4), ownerOffset);
        BinaryPrimitives.WriteInt32LittleEndian(sd.AsSpan(8), groupOffset);
        BinaryPrimitives.WriteInt32LittleEndian(sd.AsSpan(12), 0);
        BinaryPrimitives.WriteInt32LittleEndian(sd.AsSpan(16), daclOffset);

        return sd;
    }
}
