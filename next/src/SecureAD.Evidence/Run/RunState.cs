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
    /// The run finished, and its evidence is present with an intact seal. The only state that may
    /// serve as a comparison baseline, and only then if every domain was read.
    /// </summary>
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
    /// The bundle is there and cannot be trusted: its evidence will not open, or its seal is
    /// absent, unreadable or does not match. Distinct from <see cref="Interrupted"/> because the
    /// remedy differs - restore or discard, rather than run again.
    /// </summary>
    Damaged,
}
