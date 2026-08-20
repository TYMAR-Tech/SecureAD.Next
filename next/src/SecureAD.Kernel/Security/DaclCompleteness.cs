namespace SecureAD.Kernel.Security;

/// <summary>
/// Whether a DACL yielded every entry it said it held.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is an outcome and not a count.</b>
/// <c>docs/decisions/0037-an-unreadable-dacl-says-so.md</c> originally asked for the declared entry
/// count to be stored, so completeness could be a comparison. Gate 4 refused it, and was right: a
/// number on its own cannot say whether it was measured, so a header that declared zero entries and
/// a header too truncated to read would both have arrived at a caller as <c>0</c>. That is the
/// same defect the record exists to remove, one field over - and the first draft of the change
/// really did reintroduce it, reporting a truncated ACL as an empty DACL.
/// </para>
/// <para>
/// The exact numbers are not carried here. A bundle keeps the descriptor's raw bytes, so <i>three
/// of five</i> is recoverable by re-parsing, which is the same division of labour
/// <c>docs/decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md</c> makes: the
/// cheap question is queryable over a whole forest, and the exact one is answered from the evidence
/// when something actually needs it.
/// </para>
/// </remarks>
public enum DaclCompleteness
{
    /// <summary>Every entry the DACL header declared was parsed.</summary>
    Complete,

    /// <summary>
    /// The header declared more entries than were parsed. What is missing is unknown, and a missing
    /// allow entry is a permission the product will not report.
    /// </summary>
    Incomplete,

    /// <summary>
    /// The DACL header itself could not be read, so how many entries it declared is unknown. This
    /// is never reported as <see cref="Complete"/>, which is the whole reason the third member
    /// exists.
    /// </summary>
    Unknown
}
