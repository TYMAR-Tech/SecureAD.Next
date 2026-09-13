namespace SecureAD.Evidence;

/// <summary>
/// How long finishing one parallel reader's database took.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two phases rather than the five a bundle has, because a shard does only two things.</b>
/// <see cref="BundleWriter.CompleteShard"/> commits and checkpoints; it builds no indexes, runs no
/// backfill and writes no seal, all of which happen once over the merged bundle instead. A type
/// carrying five figures of which three were always zero would invite a reader to conclude that a
/// shard's index build was free.
/// </para>
/// <para>
/// <b>Separate from <see cref="BundleSealTimings"/> rather than a subset of it.</b> The two are
/// summed differently and compared differently: nine shards run at once, so their wall-clock cost
/// is the slowest rather than the total, while the bundle's five phases are strictly sequential.
/// One type for both would make that distinction invisible at the point somebody adds them up.
/// </para>
/// <para>
/// It carries no completeness member for the reason <see cref="BundleSealTimings"/> does not: a
/// value of this type exists only when the method returned, and a phase that throws produces no
/// shard and no timings. An <c>IsComplete</c> here could only ever be true.
/// </para>
/// </remarks>
/// <param name="Commit">Committing the transaction every object was written inside.</param>
/// <param name="Checkpoint">
/// Folding the write-ahead log back in, so the shard is one self-contained file the merge can open
/// without depending on its sidecar.
/// </param>
public sealed record BundleShardTimings(TimeSpan Commit, TimeSpan Checkpoint)
{
    /// <summary>Everything after this shard's last object was written.</summary>
    public TimeSpan Total => Commit + Checkpoint;
}
