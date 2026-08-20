namespace SecureAD.Kernel.Security;

/// <summary>
/// State of the DACL within a parsed security descriptor.
///
/// <para>
/// The distinction between <see cref="Null"/> and <see cref="Empty"/> is load-bearing and inverted:
/// both carry zero ACEs, and they mean opposite things. Collapsing them into "no ACEs" is the
/// mistake this enum exists to make impossible.
/// </para>
/// <para>
/// <b>There are three ways to hold no entries, not two.</b> <see cref="Unreadable"/> was added in
/// <c>docs/decisions/0037-an-unreadable-dacl-says-so.md</c> after the enum was found answering
/// <see cref="Empty"/> for a DACL whose entries could not be parsed - reporting an object the
/// product could not read as the most locked-down object it is possible to be.
/// </para>
/// </summary>
public enum DaclState
{
    /// <summary>DACL is present with zero or more ACEs.</summary>
    Present,

    /// <summary>DACL pointer is NULL — grants full access to everyone.</summary>
    Null,

    /// <summary>DACL is present but contains zero ACEs — denies all access.</summary>
    Empty,

    /// <summary>
    /// The DACL declared entries and none of them could be parsed — what it grants is unknown.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is not <see cref="Empty"/> and it is not <see cref="Null"/>.</b> It makes no claim
    /// about what the object grants. A consumer may not treat it as safe, and must render it as
    /// unknown rather than omitting the object - the same rule
    /// <c>docs/decisions/0004-unknown-counts-name-the-failed-phase.md</c> gives for counts, for the
    /// same reason: the word occupies the slot the answer would have taken, so its absence is
    /// visible to someone skimming.
    /// </para>
    /// <para>
    /// Set only when the DACL header declared at least one entry and none parsed. It is never
    /// inferred from the presence of errors alone, because a descriptor can carry an error and
    /// still have read every entry it declared. A DACL that parsed <i>some</i> of its entries stays
    /// <see cref="Present"/>, which is true; the shortfall is visible in the declared count instead.
    /// </para>
    /// </remarks>
    Unreadable
}
