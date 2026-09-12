namespace SecureAD.Kernel.Naming;

/// <summary>
/// Reading Active Directory distinguished names: the leaf name, the parent, and the domain.
///
/// <para>
/// A distinguished name looks like a delimited list and is not one. The comma that separates two
/// relative distinguished names may also appear inside a value, escaped &#8212;
/// <c>CN=Smith\, John,OU=Users,DC=corp,DC=local</c> names one person in one organisational unit,
/// and splitting it on <c>','</c> produces two components that do not exist. Every operation here
/// scans for an <i>unescaped</i> comma for that reason.
/// </para>
/// <para>
/// It handles the escaped form of RFC 2253 &#167;2.4 and not the quoted form. See
/// docs/layers/kernel/distinguished-names.md.
/// </para>
/// </summary>
public static class DnHelper
{
    /// <summary>
    /// The DN with its characters in reverse order, which is what makes a subtree question an
    /// indexed prefix scan.
    ///
    /// <para>
    /// A DN is written leaf-first, so every object beneath a container shares a common
    /// <i>suffix</i> - and a B-tree cannot serve <c>LIKE '%OU=Sales,DC=corp,DC=com'</c>, which is a
    /// full scan of every object in the forest. Reversed, the shared part becomes a common prefix
    /// and <c>LIKE 'moc=CD,...'</c> is a range scan. On a nine-million-object forest that is the
    /// difference between a query and a wait.
    /// </para>
    /// <para>
    /// <b>Characters rather than components</b>, which is how the predecessor did it and is worth
    /// keeping. Reversing the component order would give the same prefix property but has to parse
    /// the DN to do it, and every parse of a DN is a chance to disagree with the directory about
    /// escaping. Reversing characters cannot be wrong about a DN it never interprets, and the
    /// comparison it feeds is exact.
    /// </para>
    /// <para>
    /// It is not a normalisation and no reader should show it. The stored
    /// <c>distinguished_name</c> is what the controller said; this is an index key derived from it.
    /// </para>
    /// </summary>
    /// <param name="dn">The distinguished name, as the controller gave it.</param>
    public static string ReverseDn(string dn)
    {
        ArgumentNullException.ThrowIfNull(dn);

        return string.Create(dn.Length, dn, static (span, source) =>
        {
            for (var i = 0; i < source.Length; i++)
                span[i] = source[source.Length - 1 - i];
        });
    }

    /// <summary>
    /// The DN of the container one level up, or <c>null</c> when there is none.
    ///
    /// <para>
    /// <c>null</c> means the DN names the root of a naming context, or is absent. It is not an
    /// error, and it is what terminates a walk up the ancestor chain.
    /// </para>
    /// </summary>
    public static string? GetParentDn(string dn)
    {
        if (string.IsNullOrEmpty(dn))
            return null;

        var separatorIndex = FindUnescapedComma(dn);
        if (separatorIndex < 0)
            return null;

        var parent = dn[(separatorIndex + 1)..];
        return string.IsNullOrEmpty(parent) ? null : parent;
    }

    /// <summary>
    /// The value of the first relative distinguished name, unescaped &#8212; the name a person
    /// reads. <c>CN=Smith\, John,OU=Users</c> gives <c>Smith, John</c>.
    ///
    /// <para>
    /// Input with no attribute type is returned unchanged rather than cut, because not every
    /// string that reaches a display surface is a DN, and a truncated fragment is worse to show
    /// than the raw value.
    /// </para>
    /// </summary>
    public static string ExtractFirstRdn(string dn)
    {
        if (string.IsNullOrEmpty(dn))
            return dn;

        var eqIdx = dn.IndexOf('=', StringComparison.Ordinal);
        if (eqIdx < 0)
            return dn;

        var valueStart = eqIdx + 1;
        for (var i = valueStart; i < dn.Length; i++)
        {
            if (IsUnescapedComma(dn, i))
                return Unescape(dn[valueStart..i]);
        }

        return Unescape(dn[valueStart..]);
    }

    /// <summary>
    /// <see cref="ExtractFirstRdn(string)"/> where an absent DN is <c>null</c>.
    ///
    /// <para>
    /// The two absence conventions exist because their callers differ: a display surface that
    /// binds <c>null</c> falls back to another column, whereas one that binds an empty string
    /// renders a blank cell claiming the object has no name.
    /// </para>
    /// </summary>
    public static string? ExtractFirstRdnOrNull(string? dn)
    {
        if (string.IsNullOrEmpty(dn))
            return null;

        return ExtractFirstRdn(dn);
    }

    /// <summary>
    /// <see cref="ExtractFirstRdn(string)"/> where an absent DN is the empty string. The
    /// convention used by principal and SID resolution, which have a name column to fill either
    /// way.
    /// </summary>
    public static string ExtractNameFromDn(string? dn)
    {
        if (string.IsNullOrEmpty(dn))
            return "";

        return ExtractFirstRdn(dn);
    }

    /// <summary>
    /// The DNS name of the domain a DN belongs to: <c>OU=Users,DC=corp,DC=com</c> gives
    /// <c>corp.com</c>. Only <c>DC=</c> components contribute, and the attribute type is matched
    /// without regard to case because a DN's attribute types are case-insensitive.
    ///
    /// <para>
    /// Fewer than two domain components produce the empty string rather than a single label. A
    /// lone <c>DC=gov</c> would otherwise yield <c>"gov"</c>, which a caller hands to DNS and
    /// waits on until it times out against a domain that does not exist.
    /// </para>
    /// </summary>
    /// <exception cref="ArgumentNullException">
    /// The DN is <c>null</c>. Absent input is a caller that lost its DN, and reporting "no domain"
    /// for it would turn a defect into a routine answer.
    /// </exception>
    public static string DnToFqdn(string dn)
    {
        ArgumentNullException.ThrowIfNull(dn);

        var parts = new List<string>();
        var remaining = dn.AsSpan();

        while (remaining.Length > 0)
        {
            var commaIndex = FindUnescapedComma(remaining);
            var component = commaIndex >= 0 ? remaining[..commaIndex] : remaining;

            var trimmed = component.Trim();
            if (trimmed.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            {
                parts.Add(trimmed[3..].Trim().ToString());
            }

            if (commaIndex < 0)
                break;

            remaining = remaining[(commaIndex + 1)..];
        }

        if (parts.Count < 2)
            return string.Empty;

        return string.Join('.', parts);
    }

    /// <summary>
    /// Turns the escaped commas inside one RDN value back into the commas the value contains.
    /// </summary>
    private static string Unescape(string value) =>
        value.Contains("\\,", StringComparison.Ordinal) ? value.Replace("\\,", ",") : value;

    /// <summary>
    /// Whether the character at <paramref name="index"/> separates two components, as opposed to
    /// being a comma the value itself contains.
    /// </summary>
    private static bool IsUnescapedComma(ReadOnlySpan<char> value, int index) =>
        value[index] == ',' && (index == 0 || value[index - 1] != '\\');

    /// <summary>
    /// The index of the first component separator, or <c>-1</c> when the whole input is one
    /// component.
    /// </summary>
    private static int FindUnescapedComma(ReadOnlySpan<char> value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            if (IsUnescapedComma(value, i))
                return i;
        }

        return -1;
    }
}
