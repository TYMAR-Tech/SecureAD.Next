using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace SecureAD.Kernel.Security;

/// <summary>
/// A security identifier, in the two forms this product has to move between.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists as its own type.</b> An access control entry names a trustee by SID, and the
/// bundle stores that as text. A captured object carries <c>objectSid</c> as the bytes the
/// directory sent. Putting a name against a permission means crossing between the two, and before
/// this the only code that could do it was buried inside
/// <see cref="SecurityDescriptorParser"/> - so the alternative was a second implementation of a
/// parsing rule. Two implementations of a parsing rule is how they drift, and a drifted SID parser
/// puts the wrong name against a permission.
/// </para>
/// <para>
/// <b>The format is the directory's, not this product's.</b> A SID is a revision byte, a count, a
/// six-byte big-endian authority, and that many four-byte little-endian sub-authorities. The two
/// endiannesses in one structure are not a mistake here; they are what the format is.
/// </para>
/// <para>
/// <b>The members are <c>ToText</c> and <c>ToBytes</c> rather than <c>Format</c> and
/// <c>Parse</c>.</b> <c>CONCEPT-REGISTRY.md</c> gives <i>security descriptor parsing</i> to
/// <see cref="SecurityDescriptorParser"/>, and a <c>Parse</c> here would claim a question that
/// already has an owner - the registry gate says so. The names are also the truer ones: this
/// converts one representation to another and parses no descriptor.
/// </para>
/// </remarks>
public static class Sid
{
    /// <summary>The shortest a SID can be: revision, count and authority, with no sub-authorities.</summary>
    private const int HeaderLength = 8;

    /// <summary>
    /// The only revision Microsoft defines. <c>[MS-DTYP]</c> 2.4.2.2: "This value MUST be set to
    /// 0x01."
    /// </summary>
    private const byte Revision = 0x01;

    /// <summary>
    /// The most sub-authorities a SID may carry. <c>[MS-DTYP]</c> 2.4.2.2: "The maximum number of
    /// elements allowed is 15."
    /// </summary>
    private const int MaxSubAuthorities = 15;

    /// <summary>
    /// Turns SID bytes into the <c>S-1-5-21-…</c> form, or null when the bytes are not a SID.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Null rather than an exception, and null rather than a partial answer: a truncated SID is
    /// something the directory sent that this product cannot name, and inventing a shorter SID
    /// from the bytes that did arrive would put a name against the wrong principal.
    /// </para>
    /// <para>
    /// <b>Structure is checked as well as length.</b> The bounds below make this memory-safe and
    /// say nothing about whether the bytes are a SID at all - <c>S-57</c> finding <c>#24</c>: the
    /// revision byte was read and trusted, so a structurally invalid value rendered as though it
    /// were a principal. Both values Microsoft constrains are now enforced, and neither is
    /// inferred: <see cref="Revision"/> and <see cref="MaxSubAuthorities"/> are quoted from
    /// <c>[MS-DTYP]</c> 2.4.2.2.
    /// </para>
    /// <para>
    /// <b>Nothing else is validated, deliberately.</b> The finding was upheld narrowly. A SID
    /// longer than its own count is not rejected, because the span may legitimately be a window
    /// onto a larger buffer, and the identifier authority is not range-checked, because every
    /// 48-bit value is structurally legal.
    /// </para>
    /// </remarks>
    /// <param name="bytes">The SID as the directory stores it.</param>
    public static string? ToText(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < HeaderLength)
            return null;

        if (bytes[0] != Revision)
            return null;

        var subAuthorityCount = bytes[1];
        if (subAuthorityCount > MaxSubAuthorities)
            return null;

        if (bytes.Length < HeaderLength + (subAuthorityCount * 4))
            return null;

        long authority = 0;
        for (var i = 2; i < HeaderLength; i++)
            authority = (authority << 8) | bytes[i];

        var text = new StringBuilder(64);
        text.Append("S-").Append(bytes[0]).Append('-').Append(authority);

        for (var i = 0; i < subAuthorityCount; i++)
        {
            text.Append('-');
            text.Append(BinaryPrimitives.ReadUInt32LittleEndian(bytes[(HeaderLength + (i * 4))..]));
        }

        return text.ToString();
    }

    /// <summary>
    /// Turns the <c>S-1-5-21-…</c> form back into bytes, or null when the text is not a SID.
    /// </summary>
    /// <remarks>
    /// Holds to the same two constraints as <see cref="ToText"/>, so the pair agrees about what a
    /// SID is. Accepting text here that the byte reader would refuse would let a SID round-trip
    /// into a form this product then declines to read back.
    /// </remarks>
    /// <param name="text">The SID in its written form.</param>
    public static byte[]? ToBytes(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;

        var parts = text.Split('-');

        // "S", revision, authority, and at least nothing else - a SID with no sub-authorities is
        // legal, which is why this is 3 and not 4.
        if (parts.Length < 3 || !parts[0].Equals("S", StringComparison.OrdinalIgnoreCase))
            return null;

        if (!byte.TryParse(parts[1], CultureInfo.InvariantCulture, out var revision)
            || revision != Revision
            || !long.TryParse(parts[2], CultureInfo.InvariantCulture, out var authority)
            || authority < 0
            || authority > 0xFFFFFFFFFFFF)
        {
            return null;
        }

        var subAuthorityCount = parts.Length - 3;
        if (subAuthorityCount > MaxSubAuthorities)
            return null;

        var bytes = new byte[HeaderLength + (subAuthorityCount * 4)];
        bytes[0] = revision;
        bytes[1] = (byte)subAuthorityCount;

        for (var i = 0; i < 6; i++)
            bytes[2 + i] = (byte)(authority >> (8 * (5 - i)));

        for (var i = 0; i < subAuthorityCount; i++)
        {
            if (!uint.TryParse(parts[3 + i], CultureInfo.InvariantCulture, out var subAuthority))
                return null;

            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(HeaderLength + (i * 4)), subAuthority);
        }

        return bytes;
    }

    /// <summary>
    /// The prefix every SID in the built-in domain carries. <c>[MS-DTYP]</c> 2.4.2.4 names
    /// <c>S-1-5-32</c> <c>SECURITY_BUILTIN_DOMAIN_RID</c>.
    /// </summary>
    private const string BuiltinDomainPrefix = "S-1-5-32-";

    /// <summary>
    /// The last sub-authority of a SID - its relative identifier - or null when it has none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What this is for.</b> Microsoft: "the SID of a security principal is created by
    /// concatenating the SID of the domain with a relative identifier (RID) for the account", and
    /// "the last value in the series, the RID, identifies a particular account or group relative to
    /// a domain." So the RID is the part of a SID that says <i>which</i> principal, and it is the
    /// only part that means the same thing in every domain - which is what lets
    /// <see cref="WellKnownSidCatalog.FindByRid"/> name one.
    /// </para>
    /// <para>
    /// <b>Null rather than a guess, for the same reason as <see cref="ToText"/>.</b> Text this
    /// method cannot read is not reported as RID zero, because zero is
    /// <c>SECURITY_NULL_RID</c> and a caller would act on it.
    /// </para>
    /// </remarks>
    /// <param name="text">A SID in <c>S-1-5-…</c> form.</param>
    /// <seealso href="https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers"/>
    public static int? RelativeIdentifier(string? text)
    {
        var parts = SubAuthorityParts(text);

        // A SID with no sub-authorities has no RID. S-1-1 is legal and identifies an authority
        // rather than a principal, so there is nothing here to return.
        if (parts is not { Length: > 3 })
            return null;

        return int.TryParse(parts[^1], CultureInfo.InvariantCulture, out var rid) ? rid : null;
    }

    /// <summary>
    /// A SID with its relative identifier removed - the domain that issued it - or null when it
    /// has none.
    /// </summary>
    /// <remarks>
    /// <b>Why a caller wants this.</b> Microsoft: "no two domains in an enterprise share the same
    /// domain identifier." So two SIDs sharing this prefix were issued by one domain, and two that
    /// do not were not. That is the only way to tell, from a SID alone, that a value in
    /// <c>sIDHistory</c> came from somewhere other than the account's own domain.
    /// </remarks>
    /// <param name="text">A SID in <c>S-1-5-…</c> form.</param>
    /// <seealso href="https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers"/>
    public static string? IssuingDomain(string? text)
    {
        var parts = SubAuthorityParts(text);

        return parts is not { Length: > 3 }
            ? null
            : string.Join('-', parts[..^1]);
    }

    /// <summary>
    /// The dash-separated parts of a SID, or null when the text is not one.
    /// </summary>
    /// <remarks>
    /// Validated through <see cref="ToBytes"/> rather than by a second parser, so this agrees with
    /// the rest of this type about what a SID is. A shape the byte writer would refuse must not be
    /// one this reader accepts, or a caller could rank a RID off text no other component believes.
    /// </remarks>
    private static string[]? SubAuthorityParts(string? text) =>
        ToBytes(text) is null ? null : text!.Split('-');

    /// <summary>
    /// Whether this SID belongs to the built-in domain, and so names a different principal in every
    /// domain that has one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the one range whose SIDs repeat across a forest on purpose.</b> Microsoft's
    /// <i>Security identifiers</i> is explicit that the domain identifier 32 "identifies the domain,
    /// Builtin, which exists on every computer", and that distinguishing one computer's built-in
    /// groups from another's "is never necessary, because they're local in scope". So
    /// <c>S-1-5-32-544</c> is <c>BUILTIN\Administrators</c> in every domain, and those are different
    /// groups holding different members.
    /// </para>
    /// <para>
    /// <b>Everything else is left alone, because Microsoft guarantees it.</b> A domain SID carries
    /// the issuing domain inside it - "no two domains in an enterprise share the same domain
    /// identifier" - so a domain principal is already unique forest-wide and scoping it would split
    /// one principal into several.
    /// </para>
    /// <para>
    /// <b>Asked of text rather than bytes</b> because that is the form the stores keep, and the
    /// alternative is decoding a SID twice to answer one question about its prefix.
    /// </para>
    /// </remarks>
    /// <param name="text">A SID in <c>S-1-5-…</c> form.</param>
    /// <returns>Whether the SID is in the built-in domain.</returns>
    /// <seealso href="https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers"/>
    public static bool IsBuiltinDomain(string? text) =>
        text is not null && text.StartsWith(BuiltinDomainPrefix, StringComparison.OrdinalIgnoreCase);
}
