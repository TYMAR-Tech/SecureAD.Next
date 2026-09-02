using System.Globalization;
using SecureAD.Kernel.Security;

namespace SecureAD.Evidence.Findings;

/// <summary>
/// Reading a single value off a captured object, without pretending an absence is a zero.
/// </summary>
/// <remarks>
/// <b>Null means the object did not carry it, and that is not the same as zero.</b> An account
/// with no <c>userAccountControl</c> in the bundle either had none or was refused it, and the
/// directory does not tell the two apart. Returning zero would let a rule conclude that no flags
/// are set, which is a statement the evidence does not support.
/// </remarks>
public static class AttributeReading
{
    /// <summary>The first text value of an attribute, or null when the object has none.</summary>
    /// <param name="subject">The object to read.</param>
    /// <param name="ldapDisplayName">The attribute to read.</param>
    public static string? Text(ObjectAttributes subject, string ldapDisplayName) =>
        subject.Attributes
            .FirstOrDefault(a => string.Equals(
                a.LdapDisplayName, ldapDisplayName, StringComparison.OrdinalIgnoreCase))
            ?.Values.Select(v => v.Text)
            .FirstOrDefault(t => t is not null);

    /// <summary>Every text value of an attribute, empty when the object has none.</summary>
    /// <param name="subject">The object to read.</param>
    /// <param name="ldapDisplayName">The attribute to read.</param>
    internal static IReadOnlyList<string> AllText(ObjectAttributes subject, string ldapDisplayName) =>
    [
        .. subject.Attributes
            .Where(a => string.Equals(
                a.LdapDisplayName, ldapDisplayName, StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a.Values)
            .Select(v => v.Text)
            .Where(t => t is not null)
            .Select(t => t!),
    ];

    /// <summary>Whether the object carries at least one text value for an attribute.</summary>
    /// <param name="subject">The object to read.</param>
    /// <param name="ldapDisplayName">The attribute to read.</param>
    public static bool HasTextValue(ObjectAttributes subject, string ldapDisplayName) =>
        Text(subject, ldapDisplayName) is not null;

    /// <summary>Whether any text value equals <paramref name="value"/>, without regard to case.</summary>
    /// <param name="subject">The object to read.</param>
    /// <param name="ldapDisplayName">The attribute to read.</param>
    /// <param name="value">The value to find.</param>
    public static bool ContainsText(
        ObjectAttributes subject, string ldapDisplayName, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        return AllText(subject, ldapDisplayName)
            .Contains(value, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>The last text value of an attribute, or null when the object has none.</summary>
    /// <remarks>
    /// Used for <c>objectClass</c>, whose last value is the most-derived class an operator names.
    /// </remarks>
    /// <param name="subject">The object to read.</param>
    /// <param name="ldapDisplayName">The attribute to read.</param>
    public static string? LastText(ObjectAttributes subject, string ldapDisplayName)
    {
        var values = AllText(subject, ldapDisplayName);
        return values.Count == 0 ? null : values[^1];
    }

    /// <summary>An attribute read as a 32-bit unsigned value, or null when it is not one.</summary>
    /// <param name="subject">The object to read.</param>
    /// <param name="ldapDisplayName">The attribute to read.</param>
    public static uint? UnsignedInteger(ObjectAttributes subject, string ldapDisplayName) =>
        uint.TryParse(
            Text(subject, ldapDisplayName),
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var value)
            ? value
            : null;

    /// <summary>An attribute read as a 32-bit signed value, or null when it is not one.</summary>
    /// <param name="subject">The object to read.</param>
    /// <param name="ldapDisplayName">The attribute to read.</param>
    public static int? SignedInteger(ObjectAttributes subject, string ldapDisplayName) =>
        int.TryParse(
            Text(subject, ldapDisplayName),
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var value)
            ? value
            : null;

    /// <summary>
    /// Every text value of an attribute, with a count of any the object carried without text.
    /// </summary>
    /// <remarks>
    /// The public counterpart of <see cref="AllText"/>, carrying the count so a caller can tell a
    /// complete answer from a partial one - the same reason <see cref="SidsOf"/> returns
    /// <see cref="SidReading"/> rather than a bare list.
    /// </remarks>
    /// <param name="subject">The object to read.</param>
    /// <param name="ldapDisplayName">The attribute to read.</param>
    public static TextReading TextValuesOf(ObjectAttributes subject, string ldapDisplayName)
    {
        var values = subject.Attributes
            .Where(a => string.Equals(
                a.LdapDisplayName, ldapDisplayName, StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a.Values)
            .ToList();

        if (values.Count == 0)
            return TextReading.Absent;

        return new TextReading(
            [.. values.Where(v => v.Text is not null).Select(v => v.Text!)],
            values.Count(v => v.Text is null));
    }

    /// <summary>
    /// Every value of an attribute the directory stores as a SID, with a count of any that could
    /// not be decoded.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why this is here and not in a rule.</b> <c>objectSid</c> and <c>sIDHistory</c> are
    /// captured as bytes, so anything wanting to name them must decode them, and a second decoder
    /// is a second opinion about what a value says. <c>MembershipNestingPass</c> already reads
    /// <c>sIDHistory</c> this way in Derivation; putting the reading here means a rule and a
    /// derivation cannot disagree about which principal a bundle names.
    /// </para>
    /// <para>
    /// <b>The failures are counted rather than dropped.</b> Returning only the values that decoded
    /// would let a caller report an object as clean on the strength of bytes nobody could read.
    /// <see cref="SidReading"/> carries the count so the caller can tell a complete answer from a
    /// partial one.
    /// </para>
    /// </remarks>
    /// <param name="subject">The object to read.</param>
    /// <param name="ldapDisplayName">The attribute to read.</param>
    public static SidReading SidsOf(ObjectAttributes subject, string ldapDisplayName)
    {
        var values = subject.Attributes
            .Where(a => string.Equals(
                a.LdapDisplayName, ldapDisplayName, StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a.Values)
            .ToList();

        if (values.Count == 0)
            return SidReading.Absent;

        var read = values
            .Select(v => v.Bytes is null ? null : Sid.ToText(v.Bytes))
            .ToList();

        return new SidReading(
            [.. read.Where(s => s is not null).Select(s => s!)],
            read.Count(s => s is null));
    }
}
