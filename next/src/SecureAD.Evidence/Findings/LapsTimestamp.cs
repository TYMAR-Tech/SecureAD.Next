using System.Globalization;

namespace SecureAD.Evidence.Findings;

/// <summary>
/// One LAPS expiration timestamp as the directory stored it, with what it amounts to.
/// </summary>
/// <remarks>
/// <para>
/// <b>Its own type so that one decoder serves the rules and the inventory.</b> <c>SEC-091</c> and
/// <c>SEC-094</c> report a machine on the strength of a timestamp being absent, and the LAPS
/// inventory shows the same machines with the same timestamps beside the healthy ones. A second
/// decoder in the grid could call a value present that a rule called absent, and an operator
/// reading both screens would have no way to tell which was right.
/// </para>
/// <para>
/// <b>Active Directory stores these as a Windows FILETIME in a text attribute</b>, which is why the
/// raw value is carried and the date is computed rather than the other way round.
/// </para>
/// </remarks>
/// <param name="Raw">The attribute value as captured, or null where the object carried none.</param>
public sealed record LapsTimestamp(string? Raw)
{
    /// <summary>Whether this is absent, unreadable, or a date.</summary>
    /// <remarks>
    /// <b>A whitespace value counts as absent rather than unreadable.</b> It carries no date, and
    /// naming it as an undecodable value would put a gap in front of an operator that no attribute
    /// really has.
    /// </remarks>
    public LapsTimestampReading Reading =>
        string.IsNullOrWhiteSpace(Raw)
            ? LapsTimestampReading.Absent
            : ExpiresUtc is null
                ? LapsTimestampReading.Unreadable
                : LapsTimestampReading.Present;

    /// <summary>
    /// Whether something has written a timestamp here at all, decodable or not.
    /// </summary>
    /// <remarks>
    /// <b>This is what the rules decide on, and it is deliberately not the decoded date.</b> A
    /// machine whose timestamp is present but unreadable is still a machine LAPS has written to;
    /// reporting it because this build could not parse a FILETIME would be a false finding produced
    /// by our own decoder rather than by the forest.
    /// </remarks>
    public bool IsPresent => Reading is not LapsTimestampReading.Absent;

    /// <summary>When the password is next expected to rotate, where that could be decoded.</summary>
    public DateTimeOffset? ExpiresUtc => Decode(Raw);

    /// <summary>Reads one raw attribute value.</summary>
    /// <param name="raw">The value as captured, or null.</param>
    public static LapsTimestamp Of(string? raw) => new(raw);

    /// <summary>
    /// Decodes a Windows FILETIME, which is what both LAPS products write.
    /// </summary>
    /// <remarks>
    /// <b>Zero is not a date and is refused.</b> A FILETIME of 0 is the start of the epoch in 1601,
    /// which as a password expiration time means the value was written empty rather than that the
    /// password expired four centuries ago. Reporting it as a date would put an absurdity in front
    /// of an operator; reporting it as unreadable says what is true, that nothing usable is there.
    /// </remarks>
    private static DateTimeOffset? Decode(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)
            || !long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var fileTime)
            || fileTime <= 0)
        {
            return null;
        }

        try
        {
            return DateTimeOffset.FromFileTime(fileTime);
        }
        catch (ArgumentOutOfRangeException)
        {
            // A value outside the range a FILETIME can express. It came from the directory, so it
            // is reported as unreadable rather than thrown - one strange attribute must not lose a
            // finding about the machine carrying it, nor a row about it in the inventory.
            return null;
        }
    }
}
