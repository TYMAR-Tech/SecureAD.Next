namespace SecureAD.Audit.Capture;

/// <summary>
/// Whether the values of one attribute, as read from one response, are all of them.
/// </summary>
/// <remarks>
/// Three states rather than two, because the third is the one a customer is harmed by. A reader
/// that only knows "some values" and "no values" reports a ten-thousand-member group as a group
/// of a thousand, calmly, and nothing downstream can tell.
/// </remarks>
public enum AttributeCompleteness
{
    /// <summary>
    /// Every value the controller holds for this attribute is here. Either it fitted in one
    /// response, or the retrieval ran to the block the controller marked as its last.
    /// </summary>
    Complete,

    /// <summary>
    /// The controller served a block and said there are more. What is here is a prefix of the
    /// attribute's values and must not be presented as the attribute's values.
    /// </summary>
    MoreToFetch,

    /// <summary>
    /// The response did not carry this attribute at all, under its own name or a ranged one.
    /// <para>
    /// <b>This is not "the object has no values for it".</b> An attribute is absent from an entry
    /// when it was never set, and it is equally absent when the caller was not permitted to see
    /// it: an attribute marked confidential in the schema is withheld from a reader lacking
    /// <c>CONTROL_ACCESS</c> on it, silently, exactly as though it had never been set
    /// (<see href="https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential">Mark
    /// an attribute as confidential</see>). Which of the two it was is not derivable from the
    /// response, and <c>docs/decisions/0002</c> forbids rendering the second as the first. So this
    /// state says what happened - the attribute did not come back - and stops there.
    /// </para>
    /// </summary>
    NotReturned,
}

/// <summary>
/// The values of one attribute as read from one response, and whether they are all of them.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row B8's answer, and docs/layers/audit/how-a-controller-is-read.md
/// was the document bound to it. The values and the statement of completeness are one type on
/// purpose: a caller cannot reach the values without the answer to "is this all of them" being in
/// its hand, which is gate 4's shape - a collection that cannot be read as an empty fact when it
/// is really an unfinished one.
/// </para>
/// <para>
/// <b>Nothing here says "these are the members".</b> Only <see cref="AttributeCompleteness.Complete"/>
/// entitles a caller to say that, and it is a value of an enum rather than the absence of an
/// error, so it cannot be arrived at by forgetting to check.
/// </para>
/// </remarks>
/// <param name="LdapDisplayName">
/// The attribute these values belong to, with any range option stripped off, so that the name is
/// the one the catalogue asked for rather than the one the wire happened to carry.
/// </param>
/// <param name="Values">
/// The values themselves, in the order the controller sent them - a <c>string</c> or a
/// <c>byte[]</c> each, as the response carried them. Multi-valued attributes are unordered in the
/// directory, so this order carries no meaning beyond being stable within one read.
/// </param>
/// <param name="Completeness">Whether these are all the values.</param>
/// <param name="NextRange">
/// The block to ask for next. Present exactly when <see cref="Completeness"/> is
/// <see cref="AttributeCompleteness.MoreToFetch"/>, so an unfinished read always carries the means
/// to finish rather than leaving a caller to compute where it got to.
/// </param>
public sealed record AttributeValues(
    string LdapDisplayName,
    IReadOnlyList<object> Values,
    AttributeCompleteness Completeness,
    AttributeRange? NextRange);
