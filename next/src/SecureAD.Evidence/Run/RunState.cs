namespace SecureAD.Evidence.Run;

/// <summary>
/// What became of a run.
/// </summary>
/// <remarks>
/// <para>
/// One vocabulary, used by the writer, the reader and the display. The predecessor had four for
/// this question with no two sharing members: seven states in memory, five persisted, five
/// presented, and two further axes beside them. Three of its members were never written down at
/// all, one collapsed into another on read, and one was reachable from a single fallback branch.
/// </para>
/// <para>
/// <b>Every member here is arrived at from something observed</b>, by the procedure
/// <see cref="RunStateReader"/> follows. That is not a courtesy. A state nothing can produce is
/// worse than an absent one, because a document naming it and a test asserting it both pass while
/// describing something that cannot happen.
/// </para>
/// <para>
/// This axis is lifecycle only. How much of the forest the run saw is <see cref="RunCoverage"/>,
/// and the two are combined only by <see cref="RunComparability"/>. The predecessor's mistake was
/// not having separate axes; it was persisting one of them and reconstructing the rest.
/// </para>
/// </remarks>
public enum RunState
{
    /// <summary>
    /// Capture or analysis is still running. Something holds the partial evidence file open.
    /// </summary>
    InProgress,

    /// <summary>
    /// The run finished and left sealed evidence behind it. The only state that may serve as a
    /// comparison baseline, and only then if every domain was read.
    /// </summary>
    /// <remarks>
    /// <b>This says the evidence and its seal are both there, not that the two still match.</b>
    /// Establishing that hashes the whole file, and this state is decided once per run every time
    /// the run library is listed - so checking here made drawing a list cost proportional to the
    /// evidence in it. <c>docs/decisions/0020-the-seal-detects-corruption-not-tampering.md</c> puts
    /// the one verification at the moment a bundle is opened and requires that it not be repeated
    /// per screen; a run whose evidence has gone bad is refused there, before anything is read off
    /// it.
    /// </remarks>
    Sealed,

    /// <summary>The run ended in an error, and recorded what it was.</summary>
    Failed,

    /// <summary>The operator stopped the run.</summary>
    Cancelled,

    /// <summary>
    /// The run stopped without recording why. Something outside the product ended it - a reboot, a
    /// disconnect, a full disk - so this is the state that sends an operator to look outside the
    /// product.
    /// </summary>
    Interrupted,

    /// <summary>
    /// The bundle is there and cannot be checked: its seal is absent or unreadable. Distinct from
    /// <see cref="Interrupted"/> because the remedy differs - restore or discard, rather than run
    /// again.
    /// </summary>
    /// <remarks>
    /// <b>Evidence that no longer matches its seal is <see cref="Sealed"/> here, not this.</b>
    /// Telling the two apart means hashing the file, which the reasons on <see cref="Sealed"/>
    /// keep out of a listing. What this catches are the faults that need no evidence read at all,
    /// and they are the ones that make a run unopenable rather than merely suspect.
    /// </remarks>
    Damaged,
}
