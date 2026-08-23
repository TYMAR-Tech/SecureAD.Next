using System.DirectoryServices.Protocols;
using System.Security.Principal;
using System.Text;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;

namespace SecureAD.Audit.Capture;

/// <summary>
/// One entry as a domain controller returned it, and the rules for turning what it carries into
/// typed values.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row B8, and <c>docs/audit/how-a-controller-is-read.md</c> is the
/// document bound to it. It is one reader on purpose. The question <i>what does this attribute
/// actually say</i> is asked once, in one place, because the two things it decides - whether a
/// value is text or bytes, and whether the values are all of them - are the two things a second
/// opinion is invisible in. Bytes read as text come out as mojibake somebody notices; a
/// half-fetched membership comes out as a smaller group nobody notices.
/// </para>
/// <para>
/// <b>What it does not do.</b> It issues nothing. Range retrieval is a second request, and the one
/// place permitted to build a request is <see cref="CaptureSearchRequestFactory"/>, so what this
/// type hands back is the <i>name to ask for</i> and never a request. The loop that asks, and the
/// failure policy it obeys when a controller will not answer, are inventory rows B6 and B7.
/// </para>
/// <para>
/// <b>There is no cap on how many rounds a retrieval may take.</b> A cap that stops early and
/// returns what it has is the defect this row exists to remove: it converts a large group into a
/// small one and says nothing. What bounds the loop instead is progress - <see cref="Continue"/>
/// refuses a round that advanced by nothing - so a retrieval either finishes, or fails and says
/// so, and cannot quietly do neither.
/// </para>
/// </remarks>
public sealed class LdapEntryReader
{
    private readonly Dictionary<string, IReadOnlyList<object>> _attributes;

    private LdapEntryReader(
        string distinguishedName, Dictionary<string, IReadOnlyList<object>> attributes)
    {
        DistinguishedName = distinguishedName;
        _attributes = attributes;
    }

    /// <summary>
    /// The distinguished name of the object this entry describes. A range retrieval is a request
    /// for one attribute of one object, so the object has to travel with the values.
    /// </summary>
    public string DistinguishedName { get; }

    /// <summary>
    /// Reads an entry as it arrived from a domain controller.
    /// </summary>
    /// <remarks>
    /// The attribute names are kept exactly as the response carried them, range option and all,
    /// because the range option is the response's own statement about what it served and rewriting
    /// it here would throw away the only evidence there is.
    /// </remarks>
    /// <param name="entry">The entry from a search response.</param>
    public static LdapEntryReader ForEntry(SearchResultEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var attributes = new Dictionary<string, IReadOnlyList<object>>(StringComparer.OrdinalIgnoreCase);

        foreach (string name in entry.Attributes.AttributeNames)
        {
            var attribute = entry.Attributes[name];
            attributes[name] = attribute.Cast<object>().ToArray();
        }

        return new LdapEntryReader(entry.DistinguishedName, attributes);
    }

    /// <summary>
    /// Reads an entry from values already in hand, rather than from a live response.
    /// </summary>
    /// <remarks>
    /// This is how the reader is exercised without a directory. It is not a test hook bolted onto
    /// a production type: the rules below are about what a set of named values means, and the
    /// wire is where they came from rather than part of the question. Names are matched without
    /// case, as LDAP matches them.
    /// </remarks>
    /// <param name="distinguishedName">The object the values belong to.</param>
    /// <param name="attributes">
    /// The attribute names as a response would carry them - range option included where there is
    /// one - each with its values, a <c>string</c> or a <c>byte[]</c> apiece.
    /// </param>
    public static LdapEntryReader ForValues(
        string distinguishedName,
        IEnumerable<KeyValuePair<string, IReadOnlyList<object>>> attributes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        ArgumentNullException.ThrowIfNull(attributes);

        var byName = new Dictionary<string, IReadOnlyList<object>>(StringComparer.OrdinalIgnoreCase);

        foreach (var (name, values) in attributes)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(name);
            ArgumentNullException.ThrowIfNull(values);
            byName[name] = values;
        }

        return new LdapEntryReader(distinguishedName, byName);
    }

    /// <summary>
    /// What this entry says about one attribute, and whether that is all of it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three shapes can arrive, and the whole of this row's correctness is in telling them apart.
    /// </para>
    /// <para>
    /// <b>Under its own name.</b> The controller sent the values and had no more to send, so they
    /// are complete.
    /// </para>
    /// <para>
    /// <b>Under a ranged name</b> such as <c>member;range=0-1499</c>. The controller served a
    /// block. If the block's high bound is the wildcard the block was the last one and the read is
    /// complete; otherwise there are more values and the answer carries the block to ask for next.
    /// </para>
    /// <para>
    /// <b>Not at all.</b> Reported as <see cref="AttributeCompleteness.NotReturned"/> and never as
    /// an empty set of values, because an attribute is equally absent when it was never set and
    /// when the reader was not permitted to see it.
    /// </para>
    /// <para>
    /// <b>Whether an attribute can be ranged is not decided here.</b> It is
    /// <see cref="CapturedAttribute.Cardinality"/>, derived from the catalogue, so no attribute is
    /// ever tested by name. A hand-kept list of the attributes that need range retrieval agrees
    /// with the catalogue on the day it is written and stops agreeing silently.
    /// </para>
    /// </remarks>
    /// <param name="attribute">The catalogue entry being read.</param>
    public AttributeValues ValuesOf(CapturedAttribute attribute)
    {
        ArgumentNullException.ThrowIfNull(attribute);

        var name = attribute.LdapDisplayName;

        if (attribute.Cardinality == AttributeCardinality.MultiValued)
        {
            foreach (var (returnedName, values) in _attributes)
            {
                if (!AttributeRange.TryReadSpecifier(returnedName, out var ranged, out var range)
                    || !string.Equals(ranged, name, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                return range!.High is null
                    ? new AttributeValues(name, values, AttributeCompleteness.Complete, NextRange: null)
                    : new AttributeValues(
                        name,
                        values,
                        AttributeCompleteness.MoreToFetch,
                        range.NextAfter(Math.Max(values.Count, 1)));
            }
        }

        return _attributes.TryGetValue(name, out var plain)
            ? new AttributeValues(name, plain, AttributeCompleteness.Complete, NextRange: null)
            : new AttributeValues(
                name, [], AttributeCompleteness.NotReturned, NextRange: null);
    }

    /// <summary>
    /// Joins the next block of a range retrieval onto what has been read so far.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is where a retrieval is allowed to end and where it is not. It ends when a block comes
    /// back marked as the last; it fails when a block comes back that did not advance. It cannot
    /// end by giving up, which is the point: every outcome of this method is either all the values
    /// or a stated failure, and none of them is a shorter list presented as the answer.
    /// </para>
    /// <para>
    /// A failure here is a failure of the request under
    /// <c>docs/audit/limits-and-failures.md</c>: capture is fail-fast, and a partition it cannot read
    /// fully ends the run rather than yielding a bundle whose silences mean nothing.
    /// </para>
    /// </remarks>
    /// <param name="readSoFar">The values read up to now, which must be unfinished.</param>
    /// <param name="nextBlock">What the next request returned for the same attribute.</param>
    public static Result<AttributeValues> Continue(
        AttributeValues readSoFar, AttributeValues nextBlock)
    {
        ArgumentNullException.ThrowIfNull(readSoFar);
        ArgumentNullException.ThrowIfNull(nextBlock);

        if (readSoFar.Completeness != AttributeCompleteness.MoreToFetch)
        {
            throw new InvalidOperationException(
                $"'{readSoFar.LdapDisplayName}' was already {readSoFar.Completeness}, so there is "
                + "no next block to join onto it. Asking for one is a defect in the loop rather "
                + "than an outcome of the request.");
        }

        if (!string.Equals(
                readSoFar.LdapDisplayName,
                nextBlock.LdapDisplayName,
                StringComparison.OrdinalIgnoreCase))
        {
            return AuditError.Create(
                ErrorCategory.Capture,
                "RangeRetrievalAnsweredAboutAnotherAttribute",
                ErrorSeverity.Failed,
                $"A range retrieval of '{readSoFar.LdapDisplayName}' was answered with values of "
                + $"'{nextBlock.LdapDisplayName}'. Joining them would attribute one object's "
                + "values to another attribute, so the read stops here.",
                readSoFar.LdapDisplayName);
        }

        if (nextBlock.Completeness == AttributeCompleteness.NotReturned)
        {
            return AuditError.Create(
                ErrorCategory.Capture,
                "RangeRetrievalStoppedAnswering",
                ErrorSeverity.Failed,
                $"A block of '{readSoFar.LdapDisplayName}' was asked for and the response did not "
                + "carry the attribute at all. The controller had said there were more values, so "
                + "this is not the end of them - and the values read so far must not be reported "
                + "as the whole attribute.",
                readSoFar.LdapDisplayName);
        }

        if (nextBlock.Values.Count == 0)
        {
            return AuditError.Create(
                ErrorCategory.Capture,
                "RangeRetrievalMadeNoProgress",
                ErrorSeverity.Failed,
                $"A block of '{readSoFar.LdapDisplayName}' returned no values while more were "
                + "outstanding. Asking again would repeat the same request forever, and accepting "
                + "it would report part of the attribute as all of it.",
                readSoFar.LdapDisplayName);
        }

        var joined = new List<object>(readSoFar.Values.Count + nextBlock.Values.Count);
        joined.AddRange(readSoFar.Values);
        joined.AddRange(nextBlock.Values);

        return new AttributeValues(
            readSoFar.LdapDisplayName, joined, nextBlock.Completeness, nextBlock.NextRange);
    }

    /// <summary>Reads a value as text.</summary>
    /// <remarks>
    /// Directory text arrives as UTF-8, and is decoded strictly: a byte sequence that is not valid
    /// UTF-8 is reported rather than replaced with question marks, because a distinguished name
    /// silently corrupted is an object attributed to a container that does not hold it.
    /// </remarks>
    /// <param name="value">One value from <see cref="AttributeValues.Values"/>.</param>
    public static Result<string> AsText(object value)
    {
        ArgumentNullException.ThrowIfNull(value);

        switch (value)
        {
            case string text:
                return text;

            case byte[] bytes:
                try
                {
                    return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes);
                }
                catch (DecoderFallbackException)
                {
                    return NotThisShape(value, "text", "the bytes are not valid UTF-8");
                }

            default:
                return NotThisShape(value, "text", "the value is neither text nor bytes");
        }
    }

    /// <summary>Reads a value as raw bytes.</summary>
    /// <param name="value">One value from <see cref="AttributeValues.Values"/>.</param>
    public static Result<byte[]> AsBytes(object value)
    {
        ArgumentNullException.ThrowIfNull(value);

        return value is byte[] bytes
            ? bytes
            : NotThisShape(value, "bytes", "the value arrived as text");
    }

    /// <summary>Reads a value as a whole number.</summary>
    /// <remarks>
    /// Integers arrive as their decimal text, and the width is 64 bits because several of the
    /// attributes this product reads do not fit in 32 - <c>pwdLastSet</c> and its relatives are
    /// 100-nanosecond intervals since 1601.
    /// </remarks>
    /// <param name="value">One value from <see cref="AttributeValues.Values"/>.</param>
    public static Result<long> AsInteger(object value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var text = AsText(value);
        if (!text.IsSuccess)
        {
            return text.Error;
        }

        return long.TryParse(
            text.Value,
            System.Globalization.NumberStyles.AllowLeadingSign,
            System.Globalization.CultureInfo.InvariantCulture,
            out var number)
            ? number
            : NotThisShape(value, "a whole number", $"'{text.Value}' is not one");
    }

    /// <summary>Reads a value as a GUID, from the sixteen bytes the directory stores.</summary>
    /// <param name="value">One value from <see cref="AttributeValues.Values"/>.</param>
    public static Result<Guid> AsGuid(object value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var bytes = AsBytes(value);
        if (!bytes.IsSuccess)
        {
            return bytes.Error;
        }

        return bytes.Value.Length == 16
            ? new Guid(bytes.Value)
            : NotThisShape(value, "a GUID", $"a GUID is sixteen bytes and this is {bytes.Value.Length}");
    }

    /// <summary>
    /// Reads a value as a security identifier, returned in its string form - <c>S-1-5-21-…</c>.
    /// </summary>
    /// <remarks>
    /// The string form is what the rest of the product compares and stores. Parsing is left to the
    /// platform rather than done by hand over the byte layout: a SID misread by one byte is a
    /// permission attributed to the wrong principal, which is the same class of harm as a
    /// half-read group.
    /// </remarks>
    /// <param name="value">One value from <see cref="AttributeValues.Values"/>.</param>
    public static Result<string> AsSid(object value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var bytes = AsBytes(value);
        if (!bytes.IsSuccess)
        {
            return bytes.Error;
        }

        try
        {
            return new SecurityIdentifier(bytes.Value, 0).Value;
        }
        catch (ArgumentException)
        {
            return NotThisShape(value, "a security identifier", "the bytes are not a valid SID");
        }
    }

    private static AuditError NotThisShape(object value, string wanted, string why) =>
        AuditError.Create(
            ErrorCategory.Capture,
            "AttributeValueNotReadable",
            ErrorSeverity.Failed,
            $"A directory value could not be read as {wanted}: {why}. The value is reported as "
            + "unreadable rather than substituted, because a substituted value reads like a fact "
            + "about the forest.",
            value.GetType().Name);
}
