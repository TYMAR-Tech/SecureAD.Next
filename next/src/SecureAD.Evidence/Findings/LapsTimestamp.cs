using System.Globalization;

namespace SecureAD.Evidence.Findings;

/// <summary>One captured expiration value and its quality, never proof that LAPS is operating.</summary>
public sealed record LapsTimestamp(string? Raw)
{
    /// <summary>The source was not exactly one text value; originals remain in captured attributes.</summary>
    public bool HasUnsupportedRepresentation { get; init; }

    public LapsTimestampReading Reading =>
        HasUnsupportedRepresentation ? LapsTimestampReading.Unreadable
        : Raw is null ? LapsTimestampReading.Absent
        : long.TryParse(Raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) && value == 0
            ? LapsTimestampReading.Zero
        : ExpiresUtc is null ? LapsTimestampReading.Unreadable
        : LapsTimestampReading.Present;

    public bool HasCapturedValue => Raw is not null || HasUnsupportedRepresentation;

    public DateTimeOffset? ExpiresUtc =>
        HasUnsupportedRepresentation ? null : Decode(Raw)?.ToUniversalTime();

    public static LapsTimestamp Of(string? raw) => new(raw);

    public static LapsTimestamp FromAttribute(ObjectAttribute? attribute)
    {
        if (attribute is null || attribute.Values.Count == 0) return new(Raw: null);
        if (attribute.Values.Count != 1) return new(Raw: null) { HasUnsupportedRepresentation = true };
        var value = attribute.Values[0];
        return new(value.Stored)
        {
            HasUnsupportedRepresentation = value.Text is null || value.Bytes is not null || value.Ordinal != 0,
        };
    }

    private static DateTimeOffset? Decode(string? raw)
    {
        if (!long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var fileTime) || fileTime <= 0)
            return null;
        try
        {
            return DateTimeOffset.FromFileTime(fileTime);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }
}
