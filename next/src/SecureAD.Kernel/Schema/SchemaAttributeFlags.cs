namespace SecureAD.Kernel.Schema;

/// <summary>
/// The <c>searchFlags</c> and <c>systemFlags</c> bits that decide whether an attribute can be read
/// at all.
/// </summary>
/// <remarks>
/// <para>
/// <b>A confidential attribute is withheld silently.</b> There is no error and no marker on the
/// object: the search simply returns without it. So an unprivileged run cannot tell <i>this
/// attribute is not set on this machine</i> from <i>this run was not allowed to see it</i>, and a
/// rule that reads absence as a fact about the forest would be wrong about every object in it.
/// Telling the two apart is what <c>docs/decisions/0002</c> requires, and it is answered per forest
/// from the schema partition rather than assumed.
/// </para>
/// <para>
/// <b>These constants are the rule's external anchor.</b> Per <c>F-S44-2</c> and the
/// <i>Anchoring</i> section of <c>building-a-rule.md</c>, a constant a rule names must be checked
/// against something outside this repository. Both values are Microsoft's, from
/// <see href="https://learn.microsoft.com/windows/win32/adschema/a-searchflags">Search-Flags</see>:
/// <i>"128 (0x00000080) | Mark attribute as confidential. Ignored for base schema attributes
/// (systemFlags=0x10)."</i>
/// </para>
/// <para>
/// <b>The second half of that sentence is why <see cref="BaseSchemaObject"/> is here.</b> A base
/// schema attribute carrying bit 128 is <i>not</i> confidential - the directory ignores the bit -
/// so a check reading the bit alone would report a readable attribute as withheld and silence a
/// rule that had every right to speak. The LAPS attributes are schema extensions and so are not
/// affected, which was confirmed rather than assumed: read from the <c>ad.lab</c> schema partition
/// on 2026-09-03, all four LAPS attributes returned an empty <c>systemFlags</c>.
/// </para>
/// </remarks>
public static class SchemaAttributeFlags
{
    /// <summary>
    /// <c>fCONFIDENTIAL</c>: the attribute is readable only by a caller granted CONTROL_ACCESS on
    /// it, and is withheld from everybody else without a word.
    /// </summary>
    public const int Confidential = 128;

    /// <summary>
    /// The <c>systemFlags</c> bit marking a base schema object, on which
    /// <see cref="Confidential"/> is ignored.
    /// </summary>
    public const int BaseSchemaObject = 0x10;

    /// <summary>
    /// Whether this forest withholds the attribute, given what its schema partition said.
    /// </summary>
    /// <remarks>
    /// <b>Both arguments are nullable and null does not mean zero.</b> An attribute whose
    /// <c>searchFlags</c> was not captured is not an attribute known to be readable, and returning
    /// false for it would state an answer nobody read. The caller distinguishes those cases; this
    /// answers only the forests that said.
    /// </remarks>
    /// <param name="searchFlags">The attribute's <c>searchFlags</c>, or null if absent.</param>
    /// <param name="systemFlags">The attribute's <c>systemFlags</c>, or null if absent.</param>
    public static bool IsConfidential(int? searchFlags, int? systemFlags) =>
        searchFlags is { } flags
        && (flags & Confidential) != 0
        && ((systemFlags ?? 0) & BaseSchemaObject) == 0;
}
