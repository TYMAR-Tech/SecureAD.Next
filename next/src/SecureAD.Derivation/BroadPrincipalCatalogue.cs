using SecureAD.Kernel.Security;

namespace SecureAD.Derivation;

/// <summary>
/// The principals that are too broad to hold a sensitive right, whoever put them there.
/// </summary>
/// <remarks>
/// <para>
/// <b>Its own type, because gate 4's exemption is granted per type.</b> A compiled table of
/// constants living inside the expansion would exempt the expansion along with the table -
/// <c>PrivilegedSidCatalogue</c> is separate from <c>PrivilegedSidHistory</c> for exactly this
/// reason, and <c>LapsAttributes</c> is separate from the three rules that share it.
/// </para>
/// <para>
/// <b>Membership is decided by SID and never by name, and that is the whole point.</b> Microsoft's
/// security groups reference gives the built-in <c>Users</c> group default members of
/// <i>Authenticated Users</i> and <i>Domain Users</i>, and <c>Pre-Windows 2000 Compatible Access</c>
/// - which Microsoft says holds read access for all users and groups in the domain - may contain
/// <i>Everyone</i> and <i>Anonymous</i>. A test against the name of the principal somebody
/// delegated to would pass both of those, which is why this is applied to the fully expanded set
/// rather than to whatever the delegation names.
/// </para>
/// <para>
/// <b>What is here and what deliberately is not.</b> These are broad in every organisation, so no
/// local knowledge is needed to call them wrong - which is the constraint <c>P-123</c> records after
/// the owner's decision of 2026-09-03. A merely large group is not here: a decryptor group with
/// four hundred helpdesk staff in it may be exactly what an organisation intended, and this product
/// has no way to know. Reporting it would be the product substituting its idea of normal for the
/// customer's, which is the mistake <c>P-99</c> came from.
/// </para>
/// </remarks>
public static class BroadPrincipalCatalogue
{
    /// <summary>
    /// Absolute SIDs that are broad wherever they appear.
    /// </summary>
    /// <remarks>
    /// <b>Anonymous is here and it is not a redundancy.</b> A permission naming it is reachable
    /// without authenticating at all, so it is broader than <i>Authenticated Users</i> rather than a
    /// subset of it.
    /// </remarks>
    private static readonly IReadOnlySet<string> AbsoluteSids = PrincipalClassificationRegistry.BroadSids;

    /// <summary>
    /// Relative identifiers that are broad under any domain.
    /// </summary>
    /// <remarks>
    /// <b>Counted from a domain and not from a machine.</b> Reading a relative identifier as though
    /// it hung off anything would let 513 match under a machine SID and be called Domain Users,
    /// which is the distinction <c>DomainRelativeScope</c> exists to keep.
    /// </remarks>
    private static readonly IReadOnlySet<int> DomainRids = PrincipalClassificationRegistry.BroadRids;

    /// <summary>
    /// Whether this SID names a principal too broad to hold a sensitive right.
    /// </summary>
    /// <remarks>
    /// <b>The relative identifier is read from a SID of the right shape rather than off the end of
    /// any string</b>, because a domain-relative principal's SID differs per domain and only its
    /// last component is fixed. See <see cref="RelativeIdentifierOf"/> for what that shape is and
    /// what reading the tail alone got wrong.
    /// </remarks>
    /// <param name="sid">The SID in string form.</param>
    public static bool IsBroad(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid))
            return false;

        foreach (var absolute in AbsoluteSids)
        {
            if (string.Equals(sid, absolute, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return RelativeIdentifierOf(sid) is { } rid && DomainRids.Contains(rid);
    }

    /// <summary>
    /// Why this SID counts as broad, for a finding that has to explain itself.
    /// </summary>
    /// <remarks>
    /// <b>A finding naming only the conclusion is unusable at depth.</b> An operator told that a
    /// group is broad still has to work out which principal made it so; naming it is the difference
    /// between a finding they can act on and one they have to reproduce by hand.
    /// </remarks>
    /// <param name="sid">The SID in string form.</param>
    /// <returns>The principal's well-known name, or null where the SID is not broad.</returns>
    public static string? NameOf(string? sid)
    {
        if (!IsBroad(sid))
            return null;

        if (WellKnownSidCatalog.FindBySid(sid) is { } known)
            return known.DisplayName;

        return RelativeIdentifierOf(sid) is { } rid
            ? WellKnownSidCatalog.FindByRid(rid)?.DisplayName
            : null;
    }

    /// <summary>
    /// The relative identifier of a domain principal, or null where the SID is not one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The shape is checked, not just the tail, and a test caught this rather than review.</b>
    /// A domain SID is <c>S-1-5-21</c> followed by three sub-authorities; a principal in that domain
    /// is the same followed by a fourth, which is its relative identifier. Reading the last
    /// component of anything meant <c>S-1-5-21-513-513-513</c> - a domain whose own identifier
    /// happens to end in 513 - was reported as Domain Users, and the finding would have named a
    /// whole domain as a broad principal.
    /// </para>
    /// <para>
    /// <b>What this still cannot tell apart.</b> A machine's local SID has the same shape as a
    /// domain's, so a relative identifier counted from a machine is indistinguishable here from one
    /// counted from a domain - the distinction <c>DomainRelativeScope</c> names. It does not arise
    /// in a directory bundle, whose principals belong to domains, and it would if this were ever
    /// pointed at local security databases.
    /// </para>
    /// </remarks>
    /// <param name="sid">The SID in string form.</param>
    private static int? RelativeIdentifierOf(string sid)
    {
        var parts = sid.Split('-');

        // S, 1, 5, 21, then three sub-authorities and the relative identifier.
        if (parts.Length != 8
            || !string.Equals(parts[0], "S", StringComparison.OrdinalIgnoreCase)
            || parts[1] != "1"
            || parts[2] != "5"
            || parts[3] != "21")
        {
            return null;
        }

        return int.TryParse(
            parts[7],
            System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture,
            out var rid)
            ? rid
            : null;
    }
}
