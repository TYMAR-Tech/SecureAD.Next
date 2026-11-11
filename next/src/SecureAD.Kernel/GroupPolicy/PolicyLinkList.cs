namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// One policy link read out of a container's <c>gPLink</c>.
/// </summary>
/// <param name="Order">
/// Where the link sits in the stored string, counting from one, reading left to right.
/// </param>
/// <param name="Precedence">
/// The ordinary link's priority on this container, counting from one, where one is highest.
/// MS-GPOL 3.2.5.1.5 prepends ordinary links to the processing list, so the first stored link is
/// processed last. This is not a computer's effective setting precedence.
/// </param>
/// <param name="DistinguishedName">The policy object the link names.</param>
/// <param name="Options">
/// The link's options, as the directory stores them. Not worded - see
/// <see cref="PolicyLinkList"/>.
/// </param>
public sealed record PolicyLink(
    int Order, int Precedence, string DistinguishedName, string Options);

/// <summary>
/// The policy links on one container, read out of the single string the directory keeps them in.
/// </summary>
/// <remarks>
/// <para>
/// <b>The format is <c>[LDAP://&lt;dn&gt;;&lt;options&gt;]</c>, repeated.</b> Microsoft's own
/// example of a three-link container is three of those concatenated with no separator, which is why
/// an unparsed <c>gPLink</c> on screen is one unreadable line however wide the window is.
/// </para>
/// <para>
/// <b>Order is not precedence, and the difference is the whole point of reading this.</b> Learn
/// gives an internally contradictory account of stored order. MS-GPOL 3.2.5.1.5 is the authority:
/// ordinary links are prepended to the processing list, leaving the first stored link processed
/// last and therefore highest priority. Disabled/enforced links and inherited scope still require
/// their own calculation.
/// </para>
/// <para>
/// <b>The option flags remain original text.</b> MS-GPOL 2.2.2 defines disabled and enforced bits,
/// but reading a container's stored links is not the same as calculating their reach or processing
/// order for a computer. Callers must qualify those options separately rather than replacing the
/// captured number with an inferred result.
/// </para>
/// </remarks>
/// <param name="Links">The links, in stored order.</param>
/// <param name="Errors">
/// What could not be read, one message each. A container whose <c>gPLink</c> is malformed is not a
/// container with no policies, and the two must not arrive as the same empty list.
/// </param>
public sealed record PolicyLinkList(IReadOnlyList<PolicyLink> Links, IReadOnlyList<string> Errors)
{
    /// <summary>
    /// Reads a stored <c>gPLink</c>.
    /// </summary>
    /// <param name="stored">The value as the bundle holds it, or null when there is none.</param>
    public static PolicyLinkList Of(string? stored)
    {
        var links = new List<PolicyLink>();
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(stored))
            return new PolicyLinkList(links, errors);

        var rest = stored.AsSpan().Trim();
        var order = 0;

        while (!rest.IsEmpty)
        {
            var close = rest.IndexOf(']');

            if (rest[0] != '[' || close < 0)
            {
                errors.Add(
                    $"'{rest.ToString()}' is not a bracketed link, and the rest of the value was "
                    + "not read.");
                break;
            }

            var entry = rest[1..close];
            rest = rest[(close + 1)..].Trim();
            order++;

            if (Split(entry, order, out var link, out var error))
                links.Add(link!);
            else
                errors.Add(error!);
        }

        return new PolicyLinkList(links, errors);
    }

    /// <summary>
    /// One <c>LDAP://&lt;dn&gt;;&lt;options&gt;</c> entry, without its brackets.
    /// </summary>
    /// <remarks>
    /// Split on the <b>last</b> semicolon, because a distinguished name contains them: Microsoft's
    /// own example writes the name as <c>cn=policies;cn=system;DC=corp;DC=contoso;DC=com</c>.
    /// Splitting on the first would take the options to be <c>cn=system…</c> and the policy to be
    /// <c>cn=policies</c>, which is a plausible-looking wrong answer rather than a failure.
    /// </remarks>
    private static bool Split(
        ReadOnlySpan<char> entry, int order, out PolicyLink? link, out string? error)
    {
        link = null;
        error = null;

        const string Scheme = "LDAP://";
        var separator = entry.LastIndexOf(';');

        if (separator < 0)
        {
            error = $"Link {order} carries no options: '{entry.ToString()}'.";
            return false;
        }

        var name = entry[..separator].Trim();
        var options = entry[(separator + 1)..].Trim().ToString();

        if (name.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
            name = name[Scheme.Length..];

        if (name.IsEmpty)
        {
            error = $"Link {order} names no policy object: '{entry.ToString()}'.";
            return false;
        }

        link = new PolicyLink(order, order, name.ToString(), options);
        return true;
    }
}
