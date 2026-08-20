namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// One policy link read out of a container's <c>gPLink</c>.
/// </summary>
/// <param name="Order">
/// Where the link sits in the stored string, counting from one, reading left to right.
/// </param>
/// <param name="Precedence">
/// Where the link sits in precedence, counting from one, where one wins. Microsoft: the links are
/// read left to right and <b>applied in reverse</b>, so the last one in the string is applied first
/// and the first one in the string can be overridden by every link after it.
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
/// states it plainly: the links are read left to right and applied in reverse, so the last link in
/// the string has the highest precedence. A viewer that listed them in stored order and let a
/// reader assume the first one wins would have the answer exactly backwards, which on a container
/// with two policies setting the same thing is the difference between a setting applying and not.
/// </para>
/// <para>
/// <b>The option flags are deliberately not worded.</b> A link can be disabled or enforced, and
/// both matter enormously - an enforced link cannot be blocked lower down. But Learn's page for
/// <c>gPLink</c> says only <i>a sorted list of Group Policy options, each option is a DWORD</i> and
/// does not give the values, and this product does not word a bit it has not seen documented. The
/// number is carried through to the screen as stored. This is the same refusal that kept
/// <c>WRITE_OWNER</c> from being labelled with the file system's word for it.
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
            var open = rest.IndexOf('[');
            var close = rest.IndexOf(']');

            if (open < 0 || close < open)
            {
                errors.Add(
                    $"'{rest.ToString()}' is not a bracketed link, and the rest of the value was "
                    + "not read.");
                break;
            }

            var entry = rest[(open + 1)..close];
            rest = rest[(close + 1)..];
            order++;

            if (Split(entry, order, out var link, out var error))
                links.Add(link!);
            else
                errors.Add(error!);
        }

        return new PolicyLinkList(WithPrecedence(links), errors);
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

        link = new PolicyLink(order, 0, name.ToString(), options);
        return true;
    }

    /// <summary>
    /// Numbers the links by precedence, which is the reverse of the order they are stored in.
    /// </summary>
    private static List<PolicyLink> WithPrecedence(List<PolicyLink> links) =>
        [.. links.Select(l => l with { Precedence = links.Count - l.Order + 1 })];
}
