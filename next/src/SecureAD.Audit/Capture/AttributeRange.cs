namespace SecureAD.Audit.Capture;

/// <summary>
/// One block of an attribute's values: which values were asked for, or which came back.
/// </summary>
/// <remarks>
/// <para>
/// A domain controller will not return more than a fixed number of values for one attribute of
/// one object. The limit is a matter of the forest's LDAP policy - <c>MaxValRange</c>, 1,500 by
/// default - and it cannot be raised out of the way, because Windows Server 2008 and later impose
/// a hardcoded ceiling of 5,000 values that overrides the policy whenever the policy is set higher
/// (<see href="https://learn.microsoft.com/troubleshoot/windows-server/active-directory/domain-controller-returns-500-values-ldap-response">Windows
/// Server 2008 and newer domain controller returns only 5000 values in an LDAP response</see>,
/// whose own example is a group with more than 5,000 members yielding 5,000). Microsoft's
/// statement of what that costs a client is blunt: the results <i>"may appear truncated or
/// incomplete. In some occasions, you may not get any results."</i>
/// </para>
/// <para>
/// <b>So the values are asked for a block at a time.</b> The request names the attribute with a
/// range option after it - <c>member;range=0-999</c> - where the two numbers are zero-based
/// indexes of the first and last value wanted, and <c>*</c> in place of the second means all
/// remaining values
/// (<see href="https://learn.microsoft.com/windows/win32/adsi/attribute-range-retrieval">Attribute
/// Range Retrieval</see>). This is the only way to enumerate every value of an attribute that has
/// more of them than the server will send at once
/// (<see href="https://learn.microsoft.com/windows/win32/ad/enumerating-groups-that-contain-many-members">Enumerating
/// groups that contain many members</see>).
/// </para>
/// <para>
/// <b>How a block says it was the last one.</b> The controller answers under the ranged name it
/// actually served, and on the final block it replaces the high number with <c>*</c> rather than
/// echoing what was asked for. Microsoft states this as the difference between the requested
/// attribute string and the returned one -
/// <i>"in the second query, the attribute string would be <c>member;range=101-200</c>, but
/// GetNextColumnName will return <c>member;range=101-*</c> &#8230; if the strings are different,
/// the last block of values should be requested again with the range wildcard"</i>
/// (<see href="https://learn.microsoft.com/windows/win32/adsi/using-idirectorysearch-and-idirectoryobject-for-range-retrieval">Using
/// IDirectorySearch and IDirectoryObject for Range Retrieval</see>). That mark, and not an empty
/// block or a count, is what ends the retrieval.
/// </para>
/// <para>
/// <b>This type owns the range specifier and nothing else builds one.</b> It is a build failure
/// for the <c>;range=</c> text to appear anywhere else in the product, held by
/// <c>RangeSpecifierGateTests</c>. A second place that spells a range specifier is a second
/// opinion on where a block ends, and the visible symptom of the two disagreeing is a privileged
/// group reported smaller than it is.
/// </para>
/// </remarks>
/// <param name="Low">
/// The zero-based index of the first value in the block. Never negative.
/// </param>
/// <param name="High">
/// The zero-based index of the last value in the block, or <c>null</c> for the wildcard - which
/// on a request means "and everything after this" and on a response means "this was the last
/// block".
/// </param>
public sealed record AttributeRange(int Low, int? High)
{
    /// <summary>
    /// The text separating an attribute's name from its range option. Declared once, because the
    /// gate that forbids it elsewhere needs somewhere for it to legitimately live.
    /// </summary>
    private const string Marker = ";range=";

    /// <summary>
    /// How many values one round asks for: a thousand.
    /// </summary>
    /// <remarks>
    /// Microsoft's guidance is that the number requested should be as close to the server's
    /// maximum as possible to keep the round trips down, but that <i>"to enable an application to
    /// work correctly with all Windows servers, a maximum number of 1000 should be used"</i>
    /// (<see href="https://learn.microsoft.com/windows/win32/adsi/attribute-range-retrieval">Attribute
    /// Range Retrieval</see>). A thousand is therefore the largest number that is safe against
    /// every server rather than a compromise: asking for more risks a server that serves fewer,
    /// and a client that assumes it got what it asked for is the defect this whole component
    /// exists to remove.
    /// </remarks>
    public const int ValuesPerRound = 1000;

    /// <summary>The block a retrieval starts with: the first thousand values.</summary>
    public static AttributeRange FirstRound { get; } = new(0, ValuesPerRound - 1);

    /// <summary>
    /// The attribute name to ask for, with this range after it - for example
    /// <c>member;range=0-999</c>.
    /// </summary>
    /// <remarks>
    /// This produces a name and never a request. The one place permitted to build a search request
    /// is <see cref="CaptureSearchRequestFactory"/>, so that the referral policy is stated once;
    /// range retrieval is a second request and inherits that, rather than opening a second way to
    /// issue one.
    /// </remarks>
    /// <param name="ldapDisplayName">The attribute's name, spelled as the schema spells it.</param>
    public string SpecifierFor(string ldapDisplayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ldapDisplayName);

        var high = High is null ? "*" : High.Value.ToString();
        return $"{ldapDisplayName}{Marker}{Low}-{high}";
    }

    /// <summary>
    /// The block to ask for next, given how many values this one returned.
    /// </summary>
    /// <remarks>
    /// The next block starts where the values received end. It is expressed against the count
    /// returned rather than against <see cref="High"/> so that a controller which served fewer
    /// values than were asked for - which it is entitled to do, and which is what a lowered
    /// <c>MaxValRange</c> looks like from the client's side - is followed rather than skipped
    /// over.
    /// </remarks>
    /// <param name="valuesReceived">How many values the block actually returned. At least one.</param>
    public AttributeRange NextAfter(int valuesReceived)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(valuesReceived, 1);

        var nextLow = Low + valuesReceived;
        return new AttributeRange(nextLow, nextLow + ValuesPerRound - 1);
    }

    /// <summary>
    /// Reads the range off an attribute name a controller returned, if it carries one.
    /// </summary>
    /// <remarks>
    /// A name without a range option is not a failure and not a range of zero: it is an ordinary
    /// attribute that fitted in one response. So this answers false and says so, rather than
    /// inventing a block.
    /// </remarks>
    /// <param name="returnedName">The attribute name exactly as the entry carried it.</param>
    /// <param name="ldapDisplayName">The attribute name with the range stripped off.</param>
    /// <param name="range">The block the controller says it served.</param>
    public static bool TryReadSpecifier(
        string returnedName,
        out string ldapDisplayName,
        out AttributeRange? range)
    {
        ArgumentNullException.ThrowIfNull(returnedName);

        ldapDisplayName = returnedName;
        range = null;

        var marker = returnedName.IndexOf(Marker, StringComparison.OrdinalIgnoreCase);
        if (marker < 0)
        {
            return false;
        }

        var name = returnedName[..marker];
        var bounds = returnedName[(marker + Marker.Length)..];
        var dash = bounds.IndexOf('-');

        if (name.Length == 0 || dash <= 0)
        {
            return false;
        }

        if (!int.TryParse(bounds[..dash], out var low) || low < 0)
        {
            return false;
        }

        var highText = bounds[(dash + 1)..];
        if (highText == "*")
        {
            ldapDisplayName = name;
            range = new AttributeRange(low, null);
            return true;
        }

        if (!int.TryParse(highText, out var high) || high < low)
        {
            return false;
        }

        ldapDisplayName = name;
        range = new AttributeRange(low, high);
        return true;
    }
}
