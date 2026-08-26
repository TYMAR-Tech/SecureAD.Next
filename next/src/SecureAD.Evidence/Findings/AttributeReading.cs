using System.Globalization;

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
internal static class AttributeReading
{
    /// <summary>The first text value of an attribute, or null when the object has none.</summary>
    /// <param name="subject">The object to read.</param>
    /// <param name="ldapDisplayName">The attribute to read.</param>
    internal static string? Text(ObjectAttributes subject, string ldapDisplayName) =>
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

    /// <summary>An attribute read as a 32-bit unsigned value, or null when it is not one.</summary>
    /// <param name="subject">The object to read.</param>
    /// <param name="ldapDisplayName">The attribute to read.</param>
    internal static uint? UnsignedInteger(ObjectAttributes subject, string ldapDisplayName) =>
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
    internal static int? SignedInteger(ObjectAttributes subject, string ldapDisplayName) =>
        int.TryParse(
            Text(subject, ldapDisplayName),
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var value)
            ? value
            : null;
}
