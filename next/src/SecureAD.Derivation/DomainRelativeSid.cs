namespace SecureAD.Derivation;

/// <summary>
/// The domain part of a security identifier, for the one question several passes ask of it.
/// </summary>
/// <remarks>
/// <b>One answering type, because there were two and nearly three.</b> Identical private copies of
/// this test lived in <see cref="MembershipNestingPass"/> and <see cref="DerivationReader"/>, and
/// <c>P-163</c> needed a third in <see cref="ProtectedPrincipalDeriver"/>. Two copies of one rule
/// are two things free to disagree about whether an identifier names a domain, and the answer
/// decides whether an absent principal is an orphan or an unread one - so a disagreement would show
/// up as a live delegation reported inert. This is the defect that left the predecessor with six
/// answers to <i>is this permission dangerous</i>.
/// </remarks>
internal static class DomainRelativeSid
{
    /// <summary>
    /// The domain part of a domain-relative SID, or null where the SID is not one.
    /// </summary>
    /// <remarks>
    /// <b>Only <c>S-1-5-21-a-b-c-RID</c> names a domain.</b> A built-in identifier such as
    /// <c>S-1-5-32-544</c> and a well-known one such as <c>S-1-1-0</c> mean something in every
    /// domain and belong to none, so there is no coverage to look up and no absence to conclude
    /// anything from.
    /// </remarks>
    /// <param name="sid">The identifier to read.</param>
    internal static string? DomainOf(string sid)
    {
        ArgumentNullException.ThrowIfNull(sid);

        var parts = sid.Split('-');

        if (parts.Length != 8
            || !string.Equals(parts[0], "S", StringComparison.OrdinalIgnoreCase)
            || parts[1] != "1"
            || parts[2] != "5"
            || parts[3] != "21"
            || parts.Skip(4).Any(part => !uint.TryParse(part, out _)))
        {
            return null;
        }

        return string.Join('-', parts[..^1]);
    }
}
