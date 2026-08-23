namespace SecureAD.Audit.Capture;

/// <summary>
/// What a controller's answer said about whether there is more to send.
/// </summary>
/// <remarks>
/// Three states rather than a bookmark that is sometimes absent and sometimes empty, because the
/// three are three different facts and the difference between two of them is the whole of a paged
/// search's correctness. Written as a type for the same reason
/// <see cref="AttributeCompleteness"/> is: a caller cannot reach the entries without holding the
/// answer to "is that all of them", and cannot arrive at the wrong one by forgetting to check.
/// </remarks>
public enum PageCompleteness
{
    /// <summary>
    /// The response carried no paging control at all, so the controller did not say whether there
    /// is more.
    /// <para>
    /// <b>This is not the end of a search.</b> It is an answer that cannot say it was the last one,
    /// and reading it as one is how part of a forest is reported as the whole of it.
    /// </para>
    /// </summary>
    NotPaged,

    /// <summary>
    /// The controller returned a bookmark, so there is more and that bookmark is what to send back.
    /// </summary>
    MoreToCome,

    /// <summary>
    /// The controller returned no bookmark, which means the search is finished:
    /// <i>"if the server doesn't return a cookie, the client must consider the paged search to be
    /// successfully complete"</i>
    /// (<see href="https://learn.microsoft.com/windows-server/identity/ad-ds/manage/how-ldap-server-cookies-are-handled">How
    /// LDAP server cookies are handled</see>).
    /// <para>
    /// It is only worth believing on a connection that could not have followed a referral. A client
    /// that did follow one reads this on its first page, wrongly, and no part of the response says
    /// so.
    /// </para>
    /// </summary>
    LastPage,
}

/// <summary>
/// One answer from a domain controller: the entries it sent, whether it has more to send, and the
/// partitions it mentioned on the way past.
/// </summary>
/// <remarks>
/// <para>
/// <b>The request is the platform's type and the answer is this one, and the asymmetry is
/// deliberate.</b> A request carries the referral policy and the paging control, so it must be a
/// real <c>SearchRequest</c> built by the one factory permitted to build one - that is what
/// <c>DirectorySearchGateTests</c> polices. An answer carries no policy; it carries facts. Keeping
/// it as this type means the rules in <c>docs/layers/audit/how-a-controller-is-read.md</c> can be exercised
/// against a controller model, which the platform's own sealed response type does not allow, and
/// the alternative was a test that inspected nothing and reported it correct.
/// </para>
/// </remarks>
/// <param name="Entries">
/// The objects this page carried, each already read as an entry. May be empty: a controller may
/// return an empty page and still report success, meaning it could not build a page this time and
/// has not finished.
/// </param>
/// <param name="Completeness">Whether the controller said there is more to send.</param>
/// <param name="PagingCookie">
/// The bookmark to send back for the next page. Meaningful only when
/// <see cref="Completeness"/> is <see cref="PageCompleteness.MoreToCome"/>, and empty otherwise.
/// </param>
/// <param name="ContinuationReferences">
/// Partitions the controller mentioned below the one searched, as LDAP URLs. They arrive even
/// though nothing is followed, and they are evidence rather than noise -
/// <see cref="ContinuationReferenceReconciliation"/> compares them against what the run planned.
/// </param>
public sealed record DirectoryPage(
    IReadOnlyList<LdapEntryReader> Entries,
    PageCompleteness Completeness,
    byte[] PagingCookie,
    IReadOnlyList<string> ContinuationReferences)
{
    /// <summary>
    /// Reads an answer as the paging control described it, so the three states are decided in one
    /// place.
    /// </summary>
    /// <remarks>
    /// This is where a channel turns "was there a paging control, and what was in it" into the
    /// distinction the loop acts on. Doing it here rather than in each channel is the point: two
    /// channels deciding separately would be two opinions about when a partition has been read.
    /// </remarks>
    /// <param name="entries">The entries the answer carried.</param>
    /// <param name="cookie">
    /// The bookmark from the paging control, or <c>null</c> if the answer carried no paging control
    /// at all.
    /// </param>
    /// <param name="continuationReferences">The references the answer carried.</param>
    public static DirectoryPage From(
        IReadOnlyList<LdapEntryReader> entries,
        byte[]? cookie,
        IReadOnlyList<string> continuationReferences)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(continuationReferences);

        var completeness =
            cookie is null ? PageCompleteness.NotPaged
            : cookie.Length == 0 ? PageCompleteness.LastPage
            : PageCompleteness.MoreToCome;

        return new DirectoryPage(entries, completeness, cookie ?? [], continuationReferences);
    }
}
