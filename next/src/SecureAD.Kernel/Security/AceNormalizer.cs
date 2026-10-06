using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace SecureAD.Kernel.Security;

/// <summary>
/// Full ACE normalization pipeline: takes a parsed security descriptor and produces
/// canonically ordered, deduplicated ACEs with deterministic SHA-256 hashes.
/// <para>Pipeline steps:</para>
/// <list type="number">
/// <item>Expand generic rights</item>
/// <item>Normalize access mask — stored as int, no interpretation</item>
/// <item>Normalize GUID representation — already lowercase from parser</item>
/// <item>Preserve inheritance flags</item>
/// <item>Canonical ordering — Explicit Deny → Explicit Allow → Inherited Deny → Inherited Allow, then by SID/mask/GUIDs</item>
/// <item>Compute ace_hash — SHA-256 of canonical fields</item>
/// <item>Deduplicate by ace_hash</item>
/// </list>
/// Pure logic, zero OS calls.
/// </summary>
public static class AceNormalizer
{
    /// <summary>
    /// Normalizes all DACL ACEs from a parsed security descriptor for a given object.
    /// </summary>
    /// <param name="objectGuid">GUID of the AD object this SD belongs to.</param>
    /// <param name="parsed">Parsed security descriptor from <see cref="SecurityDescriptorParser"/>.</param>
    /// <returns>Normalization result with canonical ACEs, metadata, and any errors.</returns>
    public static AceNormalizationResult Normalize(Guid objectGuid, ParsedSecurityDescriptor parsed)
    {
        ArgumentNullException.ThrowIfNull(parsed);

        if (parsed.DaclState != DaclState.Present)
        {
            return new AceNormalizationResult(
                objectGuid, parsed.OwnerSid, parsed.GroupSid,
                parsed.DaclState, parsed.IsDaclProtected,
                [], [.. parsed.Errors],
                parsed.DaclCompleteness, parsed.DaclWasCanonical);
        }

        var errors = new List<string>(parsed.Errors);
        var canonicalAces = new List<CanonicalAce>();

        foreach (var ace in parsed.DaclAces)
        {
            var canonical = NormalizeAce(ace, errors);
            if (canonical is not null)
            {
                canonicalAces.Add(canonical);
            }
        }

        canonicalAces.Sort(CanonicalAceComparer.Instance);

        var deduplicated = Deduplicate(canonicalAces);

        return new AceNormalizationResult(
            objectGuid, parsed.OwnerSid, parsed.GroupSid,
            parsed.DaclState, parsed.IsDaclProtected,
            deduplicated, errors,
            parsed.DaclCompleteness, parsed.DaclWasCanonical);
    }

    /// <summary>
    /// Normalizes a single parsed ACE into canonical form.
    /// </summary>
    private static CanonicalAce? NormalizeAce(ParsedAce ace, List<string> errors)
    {
        try
        {
            // Expansion happens before hashing, so the same permission written two ways hashes once.
            var expandedMask = GenericRightsExpander.Expand(ace.AccessMask);

            var objectTypeGuid = NormalizeGuid(ace.ObjectTypeGuid);
            var inheritedObjectTypeGuid = NormalizeGuid(ace.InheritedObjectTypeGuid);

            var aceHash = ComputeAceHash(
                ace.TrusteeSid, expandedMask,
                objectTypeGuid, inheritedObjectTypeGuid,
                ace.IsInherited, ace.InheritanceFlags, ace.PropagationFlags,
                ace.AceType, ace.ApplicationData);

            return new CanonicalAce(
                AceType: ace.AceType,
                TrusteeSid: ace.TrusteeSid,
                AccessMask: expandedMask,
                ObjectTypeGuid: objectTypeGuid,
                InheritedObjectTypeGuid: inheritedObjectTypeGuid,
                IsInherited: ace.IsInherited,
                InheritanceFlags: ace.InheritanceFlags,
                PropagationFlags: ace.PropagationFlags,
                ApplicationData: ace.ApplicationData.ToArray(),
                AceHash: aceHash,
                CanonicalizationVersion: AceCanonicalization.Version);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException)
        {
            errors.Add($"ACE normalization failed for trustee {ace.TrusteeSid}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Normalizes a GUID string: ensures lowercase 8-4-4-4-12 format.
    /// Returns null if the input is null.
    /// </summary>
    internal static string? NormalizeGuid(string? guid)
    {
        if (guid is null)
            return null;

        // Parser already produces lowercase — avoid allocation when already normalized
        return string.Equals(guid, guid.ToLowerInvariant(), StringComparison.Ordinal)
            ? guid
            : guid.ToLowerInvariant();
    }

    /// <summary>
    /// Computes a deterministic SHA-256 hash from the canonical ACE fields:
    /// trustee_sid, access_mask, object_type_guid, inherited_object_type_guid,
    /// is_inherited, inheritance_flags, propagation_flags, ace_type, application_data.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>ace_type</c> was added in canonicalization version 2. Without it, an allow and a deny
    /// that were otherwise identical hashed the same and one was silently discarded by
    /// deduplication; so did a plain ACE and an object ACE carrying neither GUID. Windows defines
    /// an ACE by four things — trustee, access mask, type, and inheritance flags — and this hash
    /// covered three of them.
    /// </para>
    /// <para>
    /// <c>application_data</c> was added in canonicalization version 3, for the same failure one
    /// level down: it is what makes a conditional ACE conditional, so without it two entries
    /// granting the same rights under <i>different conditions</i> hashed the same and one was
    /// discarded before it was ever written. It is rendered as lowercase hex and is empty for every
    /// non-callback ACE type, which is the overwhelming majority. See <c>F-S58-11</c>.
    /// </para>
    /// <para>
    /// <b>The object's own GUID came out in canonicalization version 4, and that is what makes an
    /// entry storable once.</b> While it was in, the same inherited entry found on two objects
    /// hashed differently, so no two objects could ever be seen to hold one entry and every
    /// inherited entry was written again for every descendant - 294 times over, on the production
    /// capture of 2026-09-23. An entry is a trustee, a mask, a type and its inheritance; the object
    /// it was found on is a fact about where it was found, which <c>descriptor_entry</c> now
    /// records as a link. See <c>P-272</c>.
    /// </para>
    /// <para>
    /// Every version so far has been inspectable by eye against the one before it. A version 4
    /// input string is a version 3 input string with its leading <c>{object_guid}|</c> removed,
    /// which is in turn a version 2 input string plus <c>|{application_data}</c>, which is a version
    /// 1 input string plus <c>|{ace_type}</c>.
    /// </para>
    /// </remarks>
    internal static string ComputeAceHash(
        string trusteeSid,
        int accessMask,
        string? objectTypeGuid,
        string? inheritedObjectTypeGuid,
        bool isInherited,
        byte inheritanceFlags,
        byte propagationFlags,
        AceType aceType,
        ReadOnlySpan<byte> applicationData)
    {
        // Build pipe-delimited input. Realistic max is ~200 chars for the longest
        // SIDs and two GUIDs, but we avoid any fixed-size assumption.
        var input = string.Concat(
            trusteeSid, "|",
            accessMask.ToString(), "|",
            objectTypeGuid ?? "", "|",
            inheritedObjectTypeGuid ?? "", "|",
            isInherited ? "1" : "0", "|",
            inheritanceFlags.ToString(), "|",
            propagationFlags.ToString(), "|",
            ((byte)aceType).ToString(), "|",
            Convert.ToHexString(applicationData).ToLowerInvariant());

        var utf8Length = Encoding.UTF8.GetByteCount(input);
        byte[]? rented = null;
        Span<byte> utf8Buffer = utf8Length <= 512
            ? stackalloc byte[512]
            : (rented = ArrayPool<byte>.Shared.Rent(utf8Length));

        try
        {
            int bytesWritten = Encoding.UTF8.GetBytes(input.AsSpan(), utf8Buffer);
            Span<byte> hashBuffer = stackalloc byte[32]; // SHA-256 = 32 bytes
            SHA256.HashData(utf8Buffer[..bytesWritten], hashBuffer);
            return Convert.ToHexString(hashBuffer).ToLowerInvariant();
        }
        finally
        {
            if (rented is not null)
                ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <summary>
    /// Deduplicates ACEs by ace_hash, preserving the first occurrence in canonical order.
    /// </summary>
    private static List<CanonicalAce> Deduplicate(List<CanonicalAce> aces)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<CanonicalAce>(aces.Count);

        foreach (var ace in aces)
        {
            if (seen.Add(ace.AceHash))
            {
                result.Add(ace);
            }
        }

        return result;
    }

    /// <summary>
    /// Comparer for canonical ACE ordering:
    /// 1. Explicit Deny, 2. Explicit Allow, 3. Inherited Deny, 4. Inherited Allow.
    /// Within each category: trustee_sid → access_mask → object_type_guid →
    /// inherited_object_type_guid → ace_type. The ordering is total, so it does not depend on the
    /// order the ACEs arrived in.
    /// </summary>
    private sealed class CanonicalAceComparer : IComparer<CanonicalAce>
    {
        public static readonly CanonicalAceComparer Instance = new();

        public int Compare(CanonicalAce? x, CanonicalAce? y)
        {
            if (ReferenceEquals(x, y)) return 0;
            if (x is null) return -1;
            if (y is null) return 1;

            var categoryCompare = GetCategory(x).CompareTo(GetCategory(y));
            if (categoryCompare != 0) return categoryCompare;

            var sidCompare = string.Compare(x.TrusteeSid, y.TrusteeSid, StringComparison.Ordinal);
            if (sidCompare != 0) return sidCompare;

            var maskCompare = x.AccessMask.CompareTo(y.AccessMask);
            if (maskCompare != 0) return maskCompare;

            // null sorts before non-null
            var otCompare = CompareNullableString(x.ObjectTypeGuid, y.ObjectTypeGuid);
            if (otCompare != 0) return otCompare;

            var iotCompare = CompareNullableString(x.InheritedObjectTypeGuid, y.InheritedObjectTypeGuid);
            if (iotCompare != 0) return iotCompare;

            // Final tiebreak. Category already separates deny from allow, but not, say, an
            // ACCESS_ALLOWED ACE from an ACCESS_ALLOWED_OBJECT ACE carrying neither GUID. Without
            // this the two tie on every key, and List<T>.Sort is not stable, so which one came
            // first depended on the order the bytes arrived in.
            return ((byte)x.AceType).CompareTo((byte)y.AceType);
        }

        /// <summary>
        /// Maps an ACE to its canonical ordering category.
        /// 0 = Explicit Deny, 1 = Explicit Allow, 2 = Inherited Deny, 3 = Inherited Allow.
        /// </summary>
        /// <remarks>
        /// Delegates to <see cref="AceCanonicalization.CategoryOf"/>, which is where the
        /// classification lives so that this sort and the parser's judgement of whether a DACL
        /// arrived in canonical order cannot disagree. See
        /// <c>docs/decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md</c>.
        /// </remarks>
        private static int GetCategory(CanonicalAce ace) =>
            AceCanonicalization.CategoryOf(ace.AceType, ace.IsInherited);

        private static int CompareNullableString(string? a, string? b)
        {
            if (a is null && b is null) return 0;
            if (a is null) return -1;
            if (b is null) return 1;
            return string.Compare(a, b, StringComparison.Ordinal);
        }
    }
}
