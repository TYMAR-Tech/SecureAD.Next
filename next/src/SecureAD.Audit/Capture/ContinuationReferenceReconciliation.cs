namespace SecureAD.Audit.Capture;

/// <summary>
/// What a run learned from the continuation references its searches came back with: which
/// partitions the forest mentioned that the run had not planned to read.
/// </summary>
/// <remarks>
/// <para>
/// This is finding F-S7-11, built. Turning referral chasing off stops the client following a
/// referral; it does not stop the server sending one. "If referral chasing is not enabled and a
/// subtree search is performed, the search will return all objects within the specified domain that
/// meet the search criteria. The search will <b>also return referrals</b> to any subordinate
/// domains that are direct descendants"
/// (<see href="https://learn.microsoft.com/windows/win32/ad/referrals">Referrals</see>).
/// </para>
/// <para>
/// It would be easy to discard them as noise, and they are not noise. Together they are the
/// controller's own statement of what else exists below the point searched. Comparing them against
/// the partitions the run planned to read turns a partition nobody knew about into a visible
/// coverage gap instead of silence - which matters because a forest that has grown a partition is
/// exactly the forest whose owner does not know it has one.
/// </para>
/// <para>
/// <b>The reconciliation can be blind, and says so.</b> The domain-scope control asks a controller
/// not to generate continuation referrals at all. Where it was sent and honoured, that unit
/// contributes no references, so "nothing left over" from that unit means "we asked not to be
/// told" rather than "there is nothing". <see cref="IsComplete"/> is false whenever any unit
/// suppressed them, and a report must not phrase this result as a statement about the forest
/// unless it is true. This is finding F-S7-28, and it is the reason the two halves of B4's
/// referral policy have to be understood together rather than as two independent precautions.
/// </para>
/// </remarks>
public sealed class ContinuationReferenceReconciliation
{
    private ContinuationReferenceReconciliation(
        IReadOnlyList<string> unplanned,
        IReadOnlyList<string> unreadableReferences,
        IReadOnlyList<CaptureUnit> unitsWithSuppressedReferrals)
    {
        Unplanned = unplanned;
        UnreadableReferences = unreadableReferences;
        UnitsWithSuppressedReferrals = unitsWithSuppressedReferrals;
    }

    /// <summary>
    /// Naming contexts the forest referred the run to, and that the run did not plan to read. Each
    /// is a coverage entry, never a silence.
    /// </summary>
    public IReadOnlyList<string> Unplanned { get; }

    /// <summary>
    /// References that could not be read as a naming context. Kept rather than dropped: a
    /// reference nobody could parse is not a reference to nothing.
    /// </summary>
    public IReadOnlyList<string> UnreadableReferences { get; }

    /// <summary>
    /// The units whose searches asked the controller not to generate continuation referrals, and
    /// which therefore contributed no evidence here.
    /// </summary>
    public IReadOnlyList<CaptureUnit> UnitsWithSuppressedReferrals { get; }

    /// <summary>
    /// Whether this reconciliation saw everything it would have needed to see.
    /// </summary>
    /// <remarks>
    /// False when any unit suppressed its referrals, or when a reference could not be read. An
    /// empty <see cref="Unplanned"/> with <c>IsComplete</c> false means "we cannot say", and per
    /// <c>docs/decisions/0002</c> that is never rendered as "we found none".
    /// </remarks>
    public bool IsComplete =>
        UnitsWithSuppressedReferrals.Count == 0 && UnreadableReferences.Count == 0;

    /// <summary>
    /// Compares the references received against the partitions the run planned to read.
    /// </summary>
    /// <param name="planned">Every unit the run intended to capture.</param>
    /// <param name="continuationReferences">
    /// The references the searches returned, as LDAP URLs of the form
    /// <c>ldap://host/DC=child,DC=example,DC=com</c>.
    /// </param>
    /// <param name="unitsWithSuppressedReferrals">
    /// The units whose search carried the domain-scope control, and which therefore cannot have
    /// contributed a reference.
    /// </param>
    public static ContinuationReferenceReconciliation Reconcile(
        IEnumerable<CaptureUnit> planned,
        IEnumerable<string> continuationReferences,
        IEnumerable<CaptureUnit> unitsWithSuppressedReferrals)
    {
        ArgumentNullException.ThrowIfNull(planned);
        ArgumentNullException.ThrowIfNull(continuationReferences);
        ArgumentNullException.ThrowIfNull(unitsWithSuppressedReferrals);

        var plannedContexts = planned
            .Select(u => u.NamingContext)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var unplanned = new List<string>();
        var unreadable = new List<string>();

        foreach (var reference in continuationReferences)
        {
            var namingContext = NamingContextOf(reference);

            if (namingContext is null)
            {
                unreadable.Add(reference ?? string.Empty);
                continue;
            }

            if (!plannedContexts.Contains(namingContext)
                && !unplanned.Contains(namingContext, StringComparer.OrdinalIgnoreCase))
            {
                unplanned.Add(namingContext);
            }
        }

        return new ContinuationReferenceReconciliation(
            unplanned,
            unreadable,
            unitsWithSuppressedReferrals.ToList());
    }

    /// <summary>
    /// The naming context a continuation reference points at, or <c>null</c> if the reference
    /// cannot be read as one.
    /// </summary>
    /// <remarks>
    /// A reference is an LDAP URL. Only the distinguished name in it is of interest: the host is
    /// whichever controller the referring server happened to name, and the run chooses its own.
    /// </remarks>
    private static string? NamingContextOf(string? reference)
    {
        if (string.IsNullOrWhiteSpace(reference))
        {
            return null;
        }

        if (!Uri.TryCreate(reference.Trim(), UriKind.Absolute, out var url))
        {
            return null;
        }

        var path = Uri.UnescapeDataString(url.AbsolutePath).TrimStart('/');

        // A reference may carry a filter and scope after a further '?'. Only the DN is wanted.
        var queryStart = path.IndexOf('?');
        if (queryStart >= 0)
        {
            path = path[..queryStart];
        }

        return string.IsNullOrWhiteSpace(path) ? null : path.Trim();
    }
}
