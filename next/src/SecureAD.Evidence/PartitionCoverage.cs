namespace SecureAD.Evidence;

/// <summary>
/// What one pass over one naming context on one domain controller actually read, and the grounds
/// on which the run is entitled to say it was all of it.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the only type that records coverage directly</b>, per
/// <c>docs/decisions/0035</c>. It was two: <c>PartitionCoverage</c> in capture and
/// <c>PartitionCoverageRecord</c> in the bundle, twins with identical fields, an identical
/// <see cref="IsComplete"/> and no conversion between them. Two definitions of one fact are two
/// facts the moment one of them is edited, and <c>0035</c> was written because the pair had already
/// grown a second, incompatible per-domain model beside them. Every other statement of coverage -
/// what became of a domain, what the forest mentioned that the run did not plan to read - is
/// derived from these rows and never asserted next to them.
/// </para>
/// <para>
/// <b>The existence of one of these is the claim.</b> There is no state on it saying whether the
/// partition was finished, because there is no other kind. A pass that stopped for any other reason
/// - a request that failed, a controller that answered without the paging control, an attribute
/// whose remaining values could not be fetched - produces an <c>AuditError</c> and ends the run.
/// One outcome or the other, and no third.
/// </para>
/// <para>
/// <b>The row in the bundle is opened before this exists, and that is deliberate.</b> Objects are
/// handed on as they are read and must be attributed to a partition immediately, but a pass only
/// knows what it read once it has read all of it. So <c>BundleWriter.BeginPartition</c> reserves a
/// row from what is known before the first request and <c>BundleWriter.CompletePartition</c> fills
/// in the counts from this type. A reserved row reads
/// <c>continuation_references_are_complete = 0</c> until then, and a run
/// that never completes never calls <c>BundleWriter.Complete</c>, so the database is never given
/// the name a reader opens. The guarantee moved from <i>this row cannot exist unless the claim is
/// true</i> to <i>this file cannot be read unless every claim in it is true</i>, which is the
/// guarantee the rest of the bundle already rested on. What did not change is who may make the
/// claim: only the loop can construct this, and only at the moment it is true.
/// </para>
/// <para>
/// That is the point of the type and the reason it is not a boolean on something else. "Ran without
/// throwing" is not a statement that a partition was read: a capture that reads the first page of a
/// nine-million-object forest and stops also runs without throwing, and the caller cannot tell it
/// from a partition that genuinely fitted in one page - see
/// <c>docs/next/S-12-the-capture-passes.md</c>. So the claim is made by a type that only the loop
/// can construct, at the only moment it is true.
/// </para>
/// <para>
/// <b>It is also the positive record of coverage in the bundle.</b> An object's absence means
/// something only because the partition it would have come from either has one of these or does
/// not, and per <c>docs/decisions/0002</c> that difference must never be inferred from emptiness.
/// </para>
/// <para>
/// <b>A unit is a partition and never a domain</b>, which is why this carries a naming context
/// rather than a domain name. The configuration and schema partitions belong to the forest rather
/// than to any domain, so a run that failed to read one has somewhere to say so here; expressed as
/// domain coverage it would either vanish or make a forest-wide failure look local.
/// </para>
/// </remarks>
/// <param name="NamingContextDn">
/// The distinguished name of the partition root, exactly as the controller reported it in its
/// RootDSE.
/// </param>
/// <param name="Kind">Which kind of partition it is.</param>
/// <param name="Controller">
/// The host the unit was read from. One controller per unit, chosen before the run starts, so that
/// under fail-fast a failure names one unit unambiguously.
/// </param>
/// <param name="ConnectionSecurity">
/// How well protected the connection this partition was read over turned out to be.
/// <para>
/// Recorded rather than assumed, and recorded per partition rather than once per run, because it
/// varies by controller and a run reads one controller per unit. A Windows Server 2025 controller
/// strips confidential attributes from an unencrypted search and returns no error to the client, so
/// a partition read over <see cref="ConnectionSecurityLevel.Signed"/> may be missing values that
/// nothing else in the bundle records as missing. A reader that cannot see the rung would read that
/// silence as a fact about the forest. This is <c>F-S24-1</c> option C.
/// </para>
/// </param>
/// <param name="PagesRead">
/// How many pages the controller sent, including the one that ended the search. Never zero: a
/// completed read has at least one page.
/// </param>
/// <param name="ObjectsRead">How many objects were handed on.</param>
/// <param name="AttributeBlocksFetched">
/// How many extra requests were spent finishing attributes too large for one response. Recorded
/// because it is the cost of range retrieval on a real forest, and nobody has a number for it.
/// </param>
/// <param name="ContinuationReferences">
/// The references the controller returned - pointers to partitions below the one searched, which
/// arrive even though nothing is followed.
/// </param>
/// <param name="ReferralsSuppressed">
/// Whether the domain-scope control was sent for this unit, in which case the controller was asked
/// to generate no references at all and an empty list above means nothing.
/// </param>
public sealed record PartitionCoverage(
    string NamingContextDn,
    NamingContextKind Kind,
    string Controller,
    ConnectionSecurityLevel ConnectionSecurity,
    int PagesRead,
    int ObjectsRead,
    int AttributeBlocksFetched,
    IReadOnlyList<string> ContinuationReferences,
    bool ReferralsSuppressed)
{
    /// <summary>
    /// Whether <see cref="ContinuationReferences"/> is a complete statement of what lies below the
    /// partition that was searched.
    /// </summary>
    /// <remarks>
    /// False when the domain-scope control was sent, because that control asks a controller not to
    /// generate references at all - so an empty list from such a unit means <i>we asked not to be
    /// told</i> and not <i>there is nothing</i>. Rendering the first as the second would be the
    /// product telling a customer something false, which <c>docs/decisions/0002</c> forbids. It is
    /// the same distinction <c>ContinuationReferenceReconciliation.IsComplete</c> carries, at the
    /// level of one unit rather than a run.
    ///
    /// <para>
    /// <b>It is not a statement that the partition was read.</b> It was called <c>IsComplete</c>
    /// until <c>F-S29-3</c>, and under that name it was consulted as though it were one. Nothing in
    /// a sealed bundle can carry such a statement usefully: capture is fail-fast per
    /// <c>docs/decisions/0003</c>, so a partition that was not read to the end produces no bundle at
    /// all, and a flag saying otherwise would be true on every row of every bundle forever.
    /// </para>
    /// </remarks>
    public bool ContinuationReferencesAreComplete => !ReferralsSuppressed;
}
