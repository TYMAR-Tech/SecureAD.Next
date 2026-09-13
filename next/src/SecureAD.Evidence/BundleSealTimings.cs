namespace SecureAD.Evidence;

/// <summary>
/// How long each part of sealing a bundle took.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists because the run log stopped at the last partition and resumed at "finished".</b>
/// In a three-domain laboratory that gap was seven seconds out of fifteen - 47% of the capture,
/// entirely unaccounted for. Against 347,000 objects and 5.9 million access control entries it is
/// the part most likely to dominate, and an operator watching a capture that has read every domain
/// and then sat still for twenty minutes had no way to tell which of five things it was doing.
/// </para>
/// <para>
/// <b>Returned rather than logged from inside the writer.</b> Giving <see cref="BundleWriter"/> an
/// <c>IRunLog</c> would mean a required argument on a constructor called from ninety places, most
/// of them tests, for no behaviour any of them care about. Handing the figures back lets the run
/// driver - which already holds the log and already writes every other line - write these too.
/// </para>
/// <para>
/// <b>Why these five and not one number.</b> They fail differently and they scale differently.
/// Index building is three sorts of the entries table; the backfill passes are set-based updates
/// over every object; the checkpoint is bounded by how much the write-ahead log has accumulated;
/// the seal is a hash of the whole file, so it scales with bytes rather than rows. One figure
/// covering all of them would say a capture was slow without saying what to look at.
/// </para>
/// <para>
/// <b>It carries no completeness member, and that is the reason it holds no collection either.</b>
/// A value of this type exists only when <see cref="BundleWriter.Complete"/> returned, and that
/// happens only when all five phases ran - a phase that throws produces no bundle and no timings.
/// So an <c>IsComplete</c> here could only ever be true, which gate 4 would accept and gate 5 would
/// refuse for being unreachable as false. Between them the two gates say this should be plain data,
/// and turning the figures into log lines belongs to the run driver that writes every other line.
/// </para>
/// </remarks>
/// <param name="Commit">Committing the transaction every object was written inside.</param>
/// <param name="Indexes">
/// Building the indexes deferred until the end, three of which are on the entries table.
/// </param>
/// <param name="Backfill">
/// Resolving each object's parent and counting entries per object - two set-based passes that run
/// after the indexes because both join on a column the indexes have just created.
/// </param>
/// <param name="Checkpoint">Folding the write-ahead log back into the database.</param>
/// <param name="Seal">Hashing the finished file and writing its seal.</param>
public sealed record BundleSealTimings(
    TimeSpan Commit,
    TimeSpan Indexes,
    TimeSpan Backfill,
    TimeSpan Checkpoint,
    TimeSpan Seal)
{
    /// <summary>Everything after the last object was written.</summary>
    public TimeSpan Total => Commit + Indexes + Backfill + Checkpoint + Seal;
}
