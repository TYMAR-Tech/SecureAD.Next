using SecureAD.Evidence;

namespace SecureAD.Audit.Capture;

/// <summary>
/// Whether everything capture asked about one object came back.
/// </summary>
/// <remarks>
/// Two states, and the second is the one that costs something to carry. An attribute is missing
/// from an entry when it was never set, and it is equally missing when the reader was not permitted
/// to see it - an attribute marked confidential in the schema is withheld silently, exactly as
/// though it had never been set. Which of the two it was is not derivable from the response, and
/// <c>docs/decisions/0002</c> forbids rendering the second as the first. So an object says that
/// something did not arrive, and whoever settles the interpretation has something to attach it to.
/// </remarks>
public enum ObjectCompleteness
{
    /// <summary>Every attribute capture asked about came back.</summary>
    Complete,

    /// <summary>
    /// At least one attribute did not come back at all. Not "the object has no value for it" -
    /// see the remarks above.
    /// </summary>
    SomeAttributesDidNotArrive,
}

/// <summary>
/// One object as capture read it: its distinguished name, and every catalogue attribute the
/// controller had something to say about.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every attribute here is finished.</b> An object is not handed on until each of its
/// range-liable attributes has been retrieved to the block the controller marked as its last, so
/// nothing downstream can be handed a prefix of a group's membership and mistake it for the
/// membership. That is enforced by construction: <see cref="Create"/> refuses an attribute still
/// carrying <see cref="AttributeCompleteness.MoreToFetch"/>.
/// </para>
/// <para>
/// <b>An attribute that never arrived is still here.</b> It appears with
/// <see cref="AttributeCompleteness.NotReturned"/> rather than being dropped, because an absent
/// attribute is not a fact about the forest - it is equally absent when it was never set and when
/// the reader was not permitted to see it, and <c>docs/decisions/0002</c> forbids rendering the
/// second as the first.
/// </para>
/// </remarks>
/// <param name="DistinguishedName">The object's distinguished name, as the controller gave it.</param>
/// <param name="Attributes">Its attributes, each with the answer to "are these all the values".</param>
public sealed record CapturedObject(
    string DistinguishedName,
    IReadOnlyList<AttributeValues> Attributes)
{
    /// <summary>
    /// Creates a captured object, refusing one with an unfinished attribute.
    /// </summary>
    /// <remarks>
    /// An <see cref="InvalidOperationException"/> rather than a failure result, because an
    /// unfinished attribute reaching here is a defect in the loop and not an outcome of a request:
    /// the loop's own contract is that it finishes an object's attribute blocks before moving on.
    /// </remarks>
    /// <param name="distinguishedName">The object's distinguished name.</param>
    /// <param name="attributes">Its attributes.</param>
    public static CapturedObject Create(
        string distinguishedName, IReadOnlyList<AttributeValues> attributes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        ArgumentNullException.ThrowIfNull(attributes);

        var unfinished = attributes
            .Where(a => a.Completeness == AttributeCompleteness.MoreToFetch)
            .Select(a => a.LdapDisplayName)
            .ToList();

        if (unfinished.Count > 0)
        {
            throw new InvalidOperationException(
                $"'{distinguishedName}' would be handed on with unfinished attributes: "
                + string.Join(", ", unfinished)
                + ". A prefix of a group's members presented as its members is the defect the "
                + "range-retrieval rule exists to remove, so an object leaves the capture loop "
                + "complete or the loop fails.");
        }

        return new CapturedObject(distinguishedName, attributes);
    }

    /// <summary>
    /// Whether every attribute capture asked about came back for this object.
    /// </summary>
    /// <remarks>
    /// Derived rather than stored, so it cannot disagree with the attributes it describes. Most
    /// objects will be <see cref="ObjectCompleteness.SomeAttributesDidNotArrive"/>, because the
    /// whole catalogue is asked for on every object and most objects have no value for most of it -
    /// which is exactly why the fact travels with the object instead of being inferred later from
    /// an empty list.
    /// </remarks>
    public ObjectCompleteness Completeness =>
        Attributes.Any(a => a.Completeness == AttributeCompleteness.NotReturned)
            ? ObjectCompleteness.SomeAttributesDidNotArrive
            : ObjectCompleteness.Complete;
}

/// <summary>
/// Where captured objects go.
/// </summary>
/// <remarks>
/// <para>
/// The loop hands each object on as it finishes it rather than returning a list, because a forest
/// partition is millions of objects and a list of them is a design that works in a lab and runs a
/// machine out of memory at a customer. What receives them is <c>BundleCaptureSink</c>, which
/// writes them through <c>BundleWriter</c> - inventory rows B9 and B10. This was the shape of the
/// hand-off and nothing else until 2026-08-14.
/// </para>
/// <para>
/// <b>The streaming is why coverage is opened before it is known.</b> An object may not be written
/// until the partition it came from has a row, and a pass only knows what it read at the end - so
/// the row is reserved first and completed after, rather than holding a partition's objects in
/// memory to satisfy the ordering. See <c>BundleWriter.BeginPartition</c>.
/// </para>
/// <para>
/// <b>It is one method and it returns nothing.</b> A sink that could refuse an object would be a
/// second place deciding what a capture contains, and <c>docs/decisions/0052</c> puts that decision
/// nowhere in capture at all.
/// </para>
/// </remarks>
public interface ICapturedObjectSink
{
    /// <summary>
    /// Says a pass over one partition is starting, before any object from it arrives.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why the sink is told rather than asked.</b> An object must be attributed to the partition
    /// it was read from at the moment it is written, and only this loop knows two things a
    /// receiver cannot work out: which rung the connection to this unit reached, and whether the
    /// domain-scope control was sent - which decides whether an empty list of continuation
    /// references means <i>there is nothing below</i> or <i>we asked not to be told</i>.
    /// </para>
    /// <para>
    /// It returns nothing, for the same reason <see cref="Receive"/> does: a sink that could refuse
    /// a partition would be a second place deciding what a capture contains.
    /// </para>
    /// </remarks>
    /// <param name="unit">The partition and the controller it is being read from.</param>
    /// <param name="connectionSecurity">The rung the connection to that controller reached.</param>
    /// <param name="referralsSuppressed">
    /// Whether the domain-scope control was sent, in which case the controller was asked to
    /// generate no continuation references at all.
    /// </param>
    void BeginPartition(
        CaptureUnit unit, ConnectionSecurityLevel connectionSecurity, bool referralsSuppressed);

    /// <summary>Takes one finished object.</summary>
    /// <param name="capturedObject">The object, with every attribute complete.</param>
    void Receive(CapturedObject capturedObject);

    /// <summary>Discards everything received for the partition attempt currently open.</summary>
    void AbortPartition();

    /// <summary>
    /// Says the pass finished, and what it read.
    /// </summary>
    /// <remarks>
    /// Called only where a partition was read whole. A pass that ended any other way produces an
    /// <c>AuditError</c> and the run stops, so a sink never has to decide what a half-read
    /// partition means.
    /// </remarks>
    /// <param name="coverage">What the pass read.</param>
    void CompletePartition(PartitionCoverage coverage);
}
