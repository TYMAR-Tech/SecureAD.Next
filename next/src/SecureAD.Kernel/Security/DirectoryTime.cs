using System.Globalization;

namespace SecureAD.Kernel.Security;

/// <summary>
/// The two ways Active Directory stores a moment in time.
/// </summary>
/// <remarks>
/// Both are on screen on one object, so a reader that assumed either would be wrong half the time:
/// <c>pwdLastSet</c> is a 64-bit count and <c>whenCreated</c> is a string of digits, and neither is
/// recognisable as a time to anybody who has not been told which is which.
/// </remarks>
public enum DirectoryTimeFormat
{
    /// <summary>
    /// Microsoft's <c>Interval</c> syntax: 100-nanosecond units since 1601-01-01 UTC, held as a
    /// signed 64-bit number and sent as its decimal digits.
    /// </summary>
    Interval,

    /// <summary>
    /// Microsoft's <c>String(Generalized-Time)</c> syntax: <c>YYYYMMDDHHMMSS.0Z</c>, or the same
    /// with an offset from UTC in place of the <c>Z</c>.
    /// </summary>
    GeneralizedTime,
}

/// <summary>
/// What a stored directory timestamp says.
/// </summary>
/// <param name="Worded">The value in words, whether it is a moment or one of the sentinels.</param>
/// <param name="Instant">
/// The moment, or null when the value is a sentinel that does not name one.
/// </param>
/// <param name="Caveat">
/// What a reader must know before drawing a conclusion from this value, or null when there is
/// nothing to add. Not decoration: <c>lastLogonTimestamp</c> is designed to be days out of date,
/// and a stale-account judgement made without knowing that is wrong by up to a fortnight.
/// </param>
public sealed record DirectoryTimeWording(string Worded, DateTimeOffset? Instant, string? Caveat);

/// <summary>
/// Reads the timestamps this product captures, including the values that are not times at all.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the one place a stored timestamp becomes a date.</b> Every attribute below was
/// checked against its own page on Microsoft Learn on 2026-08-18, because each carries a trap that
/// does not announce itself:
/// </para>
/// <para>
/// <c>accountExpires</c> has <b>two</b> values meaning <i>never</i> - <c>0</c> and
/// <c>9223372036854775807</c> - and Learn explains why: an account created never-expiring holds the
/// maximum, and one whose expiry was removed holds zero. A reader handling only one of them renders
/// the other as a date in 1601 or in 30828, and either reads as a real expiry to an operator.
/// </para>
/// <para>
/// <c>pwdLastSet</c> of zero is not a date either. It is how the directory records <i>this password
/// must be set at the next logon</i>, and the accounts it is true of are exactly the ones an
/// auditor is looking for.
/// </para>
/// <para>
/// <c>whenCreated</c> is not a number at all but a string, and reading it as an interval would
/// produce a plausible date rather than an error.
/// </para>
/// <para>
/// <b>An age is measured against the run, never against today.</b> A bundle is sealed evidence: a
/// password last set six days before a capture is a fact about that forest, and it stays a fact
/// however long the bundle sits on a share. Measuring against the reader's own clock would make the
/// same evidence say something different every morning.
/// </para>
/// </remarks>
public static class DirectoryTime
{
    /// <summary>
    /// The zero point of Microsoft's <see cref="DirectoryTimeFormat.Interval"/> syntax.
    /// </summary>
    private static readonly DateTimeOffset Epoch = new(1601, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// The value Learn gives for an account that has never been configured to expire:
    /// <c>0x7FFFFFFFFFFFFFFF</c>.
    /// </summary>
    private const long Forever = long.MaxValue;

    /// <summary>
    /// Which of the captured attributes are timestamps, and in which of the two formats.
    /// </summary>
    /// <remarks>
    /// Held as a table rather than guessed from the value, because the guess is what goes wrong:
    /// <c>20260913090000.0Z</c> parses as a perfectly good interval and lands in the year 1666.
    /// </remarks>
    public static IReadOnlyDictionary<string, DirectoryTimeFormat> Attributes { get; } =
        new Dictionary<string, DirectoryTimeFormat>(StringComparer.OrdinalIgnoreCase)
        {
            ["pwdLastSet"] = DirectoryTimeFormat.Interval,
            ["accountExpires"] = DirectoryTimeFormat.Interval,
            ["lastLogonTimestamp"] = DirectoryTimeFormat.Interval,
            ["ms-Mcs-AdmPwdExpirationTime"] = DirectoryTimeFormat.Interval,
            ["msLAPS-PasswordExpirationTime"] = DirectoryTimeFormat.Interval,
            ["whenCreated"] = DirectoryTimeFormat.GeneralizedTime,
        };

    /// <summary>
    /// Reads one stored timestamp, or returns null when this build cannot.
    /// </summary>
    /// <remarks>
    /// Null rather than a fallback date, for the reason <c>docs/decisions/0002</c> gives: a value
    /// nobody can read is shown as it was stored, and never worded into a moment it might not mean.
    /// </remarks>
    /// <param name="ldapDisplayName">The attribute, as the catalogue names it.</param>
    /// <param name="stored">The value as the bundle holds it.</param>
    /// <param name="asOf">
    /// When the run captured the object. Ages are measured from here, so that sealed evidence says
    /// the same thing whenever it is read.
    /// </param>
    public static DirectoryTimeWording? WordTimestamp(
        string ldapDisplayName, string? stored, DateTimeOffset asOf)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ldapDisplayName);

        if (!Attributes.TryGetValue(ldapDisplayName, out var format) || string.IsNullOrWhiteSpace(stored))
            return null;

        return format == DirectoryTimeFormat.Interval
            ? FromInterval(ldapDisplayName, stored, asOf)
            : FromGeneralizedTime(ldapDisplayName, stored, asOf);
    }

    /// <summary>
    /// What a reader must know before drawing a conclusion from this attribute, whatever its value.
    /// </summary>
    private static string? CaveatFor(string ldapDisplayName) =>
        string.Equals(ldapDisplayName, "lastLogonTimestamp", StringComparison.OrdinalIgnoreCase)
            ? "This value is deliberately imprecise. A controller only updates it when the value "
              + "it holds is older than msDS-LogonTimeSyncInterval, which defaults to between 9 "
              + "and 14 days, so the account may have logged on more recently than this says."
            : null;

    private static DirectoryTimeWording? FromInterval(
        string ldapDisplayName, string stored, DateTimeOffset asOf)
    {
        if (!long.TryParse(stored, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ticks))
            return null;

        if (Sentinel(ldapDisplayName, ticks) is { } sentinel)
            return new DirectoryTimeWording(sentinel, null, CaveatFor(ldapDisplayName));

        if (ticks < 0)
            return null;

        DateTimeOffset instant;
        try
        {
            instant = Epoch.AddTicks(ticks);
        }
        catch (ArgumentOutOfRangeException)
        {
            // A value too large to be a date at all. Shown as stored rather than clamped to a
            // year that would read as a real one.
            return null;
        }

        return new DirectoryTimeWording(
            Worded(instant, asOf), instant, CaveatFor(ldapDisplayName));
    }

    /// <summary>
    /// The values of this attribute that are not moments in time.
    /// </summary>
    private static string? Sentinel(string ldapDisplayName, long ticks) =>
        (ldapDisplayName.ToLowerInvariant(), ticks) switch
        {
            // Both, per Learn: the maximum on an account never configured to expire, and zero on
            // one whose expiry was removed.
            ("accountexpires", 0 or Forever) => "Never expires",

            // Not a date. The directory records the requirement this way, and Learn adds that it
            // only takes effect on an account whose password is not set never to expire.
            ("pwdlastset", 0) =>
                "Never set. The directory uses this to mean the password must be set at the next "
                + "logon, unless the account's password is set never to expire.",

            ("lastlogontimestamp", 0 or Forever) => "No logon has been recorded",
            _ => null,
        };

    private static DirectoryTimeWording? FromGeneralizedTime(
        string ldapDisplayName, string stored, DateTimeOffset asOf)
    {
        string[] formats =
        [
            "yyyyMMddHHmmss.fZ",
            "yyyyMMddHHmmss.ffZ",
            "yyyyMMddHHmmss.fffZ",
            "yyyyMMddHHmmssZ",
            "yyyyMMddHHmmss.fzzz",
            "yyyyMMddHHmmsszzz",
        ];

        return DateTimeOffset.TryParseExact(
            stored,
            formats,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var instant)
            ? new DirectoryTimeWording(
                Worded(instant, asOf), instant, CaveatFor(ldapDisplayName))
            : null;
    }

    /// <summary>
    /// The moment, and how long before the run it was.
    /// </summary>
    /// <remarks>
    /// A date on its own makes a reader do arithmetic against a capture date they have to go and
    /// find; the age is the thing being asked for. A timestamp after the run is not corrected -
    /// it is stated, because a value in the future is a defect in the directory and hiding it
    /// would be this product covering for one.
    /// </remarks>
    private static string Worded(DateTimeOffset instant, DateTimeOffset asOf)
    {
        var date = instant.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);
        var days = (int)(asOf.ToUniversalTime().Date - instant.ToUniversalTime().Date).TotalDays;

        return days switch
        {
            < 0 => $"{date} ({-days} days after this run)",
            0 => $"{date} (the day of this run)",
            1 => $"{date} (1 day before this run)",
            _ => $"{date} ({days} days before this run)",
        };
    }
}
