namespace SecureAD.Evidence.Findings;

/// <summary>
/// The security identifiers read off one attribute, and whether every value was readable.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the count of failures travels with the values.</b> A caller handed a bare list cannot tell
/// "the object carried these three" from "the object carried four and one could not be read", and
/// those mean opposite things: the first is a complete answer and the second is a partial one that
/// must not be presented as complete. <c>docs/decisions/0002</c> and <c>0086</c> both turn on that
/// distinction, and gate 4 exists to stop a type handing back a collection that cannot state it.
/// </para>
/// <para>
/// <b>Unreadable is not the same as absent.</b> An object carrying no values at all yields an empty
/// reading that <i>is</i> complete - it looked, and there was nothing. Only bytes that were present
/// and could not be decoded make it incomplete.
/// </para>
/// </remarks>
/// <param name="Sids">The values that were read, in the order the object carried them.</param>
/// <param name="UnreadableValues">How many values were present but could not be decoded.</param>
public sealed record SidReading(IReadOnlyList<string> Sids, int UnreadableValues)
{
    /// <summary>An attribute the object did not carry at all.</summary>
    public static SidReading Absent { get; } = new([], 0);

    /// <summary>Whether every value the object carried was read.</summary>
    public bool IsComplete => UnreadableValues == 0;

    /// <summary>Whether the object carried no values for the attribute.</summary>
    /// <remarks>
    /// Distinct from an empty <see cref="Sids"/>, which can also mean every value failed to decode.
    /// </remarks>
    public bool IsAbsent => Sids.Count == 0 && UnreadableValues == 0;
}
