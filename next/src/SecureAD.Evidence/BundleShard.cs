namespace SecureAD.Evidence;

/// <summary>
/// Which of a run's parallel readers a writer is, so that two of them can never give the same
/// number to different things.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists because of how the schema is keyed, and the alternative was a silent defect.</b>
/// Under <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c> each domain writes its own
/// database and they are merged afterwards. <c>BundleSchema</c> keys on surrogate integers -
/// <c>captured_object.object_id</c>, <c>trustee.trustee_id</c>,
/// <c>security_descriptor.descriptor_id</c>, <c>partition_coverage.coverage_id</c> - and every one
/// of them is a plain counter starting at 1. Two shards therefore each hand out 1, to different
/// entities, and a merge that copied the rows would put one domain's access control entries against
/// another domain's principal. <b>A permission reported against the wrong account</b>, in a bundle
/// that looks perfectly healthy, which is the one thing an audit tool must never do.
/// </para>
/// <para>
/// <b>Why ranges rather than remapping everything at the merge.</b> Two dimensions genuinely have
/// to be remapped, because they are genuinely shared between domains: a trustee appears in both
/// shards under one SID, and an identical security descriptor hashes the same in both. Everything
/// else is private to its shard and only needs to not collide. Remapping objects instead would mean
/// rewriting every table that references <c>object_id</c> - and one of those is the whole family of
/// per-attribute value tables, which is generated from the captured schema and is not a fixed list.
/// </para>
/// <para>
/// <b>The unsharded case is shard zero and is byte-for-byte what the product wrote before.</b>
/// <see cref="Whole"/> starts at 1, so a run that reads domains one at a time produces exactly the
/// identifiers it always did. That is deliberate: the frozen golden hashes and classifier fixtures
/// are recorded outputs of the old behaviour, and a change that quietly renumbered every object
/// would have needed every one of them edited - which under
/// <c>docs/next/README.md</c> is a finding rather than a fix.
/// </para>
/// </remarks>
public readonly record struct BundleShard
{
    /// <summary>
    /// How many identifiers each shard owns.
    /// </summary>
    /// <remarks>
    /// <b>A trillion, which is not a number anybody has to think about again.</b> The forest this is
    /// built for holds roughly 347,000 objects and 5.9 million access control entries across nine
    /// domains; the largest single number a shard could need is therefore seven orders of magnitude
    /// below this. It is sized so that no future forest makes it a question, because a range that
    /// can be overrun is a range that fails by attributing a permission to the wrong account -
    /// exactly the failure it was introduced to prevent.
    /// </remarks>
    public const long Capacity = 1_000_000_000_000L;

    private BundleShard(int index) => Index = index;

    /// <summary>Which shard this is, counting from zero.</summary>
    public int Index { get; }

    /// <summary>
    /// The identifiers this shard owns, from <see cref="FirstId"/> to <see cref="LastId"/>.
    /// </summary>
    public long FirstId => (Index * Capacity) + 1;

    /// <inheritdoc cref="FirstId"/>
    public long LastId => FirstId + Capacity - 1;

    /// <summary>
    /// The whole bundle, written by one writer. Numbers from 1, as the product always has.
    /// </summary>
    /// <remarks>
    /// This is also <c>default</c>, and that is not an accident: a caller who says nothing gets the
    /// behaviour that existed before shards did, rather than an arbitrary shard.
    /// </remarks>
    public static BundleShard Whole => default;

    /// <summary>
    /// The highest shard a run may have, above which the identifiers would overflow.
    /// </summary>
    /// <remarks>
    /// <b>Bounded by the last identifier a shard owns, not by its first.</b> Checking
    /// <see cref="FirstId"/> alone admits a shard whose <see cref="LastId"/> passes
    /// <see cref="long.MaxValue"/> and wraps negative, and <see cref="Owns"/> would then refuse
    /// every identifier that shard legitimately holds - which is the one method the merge uses to
    /// prove it is reading what it thinks it is. Unreachable with any real forest, and still wrong:
    /// this is the bound that stops identifiers colliding, so it checks the thing it is named for.
    /// </remarks>
    public static int MaxIndex => (int)(long.MaxValue / Capacity) - 1;

    /// <summary>
    /// The shard at <paramref name="index"/>, counting from zero.
    /// </summary>
    /// <param name="index">
    /// Which reader this is. Zero is <see cref="Whole"/>, so a one-domain run and an unsharded run
    /// agree.
    /// </param>
    public static BundleShard Number(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(index, MaxIndex);

        return new BundleShard(index);
    }

    /// <summary>
    /// Whether <paramref name="id"/> was handed out by this shard.
    /// </summary>
    /// <remarks>
    /// Used by the merge to prove it is reading what it thinks it is reading. A shard whose rows
    /// carry another shard's identifiers has already gone wrong, and finding that out at the merge
    /// is the last moment it is still a crash rather than a wrong answer.
    /// </remarks>
    /// <param name="id">A surrogate identifier from any of the keyed tables.</param>
    public bool Owns(long id) => id >= FirstId && id <= LastId;
}
