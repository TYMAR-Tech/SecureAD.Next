namespace SecureAD.Evidence.Findings;

/// <summary>
/// The text values read off one attribute, and whether every value was readable.
/// </summary>
/// <remarks>
/// <para>
/// <b>The same shape as <see cref="SidReading"/>, for the other storage class.</b> Both answer "what
/// did this attribute hold, and did I get all of it" - and both exist because a bare list cannot
/// distinguish <i>the object carried these three</i> from <i>the object carried four and one could
/// not be read</i>. They are separate types rather than one because the values are decoded
/// differently and a caller should not have to say which it meant.
/// </para>
/// <para>
/// <b>Text can fail to read, which is not obvious.</b> A captured value carries text or bytes, and
/// an attribute the catalogue declares as text can still arrive with a value this product has no
/// text for. Dropping those silently would let a rule report an account as carrying no service
/// names when it carried one nobody could read.
/// </para>
/// </remarks>
/// <param name="Values">The values that were read, in the order the object carried them.</param>
/// <param name="UnreadableValues">How many values were present but had no text.</param>
public sealed record TextReading(IReadOnlyList<string> Values, int UnreadableValues)
{
    /// <summary>An attribute the object did not carry at all.</summary>
    public static TextReading Absent { get; } = new([], 0);

    /// <summary>Whether every value the object carried was read.</summary>
    public bool IsComplete => UnreadableValues == 0;

    /// <summary>Whether the object carried no values for the attribute.</summary>
    /// <remarks>
    /// Distinct from an empty <see cref="Values"/>, which can also mean every value was unreadable.
    /// </remarks>
    public bool IsAbsent => Values.Count == 0 && UnreadableValues == 0;
}
