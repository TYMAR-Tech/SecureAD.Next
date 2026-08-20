namespace SecureAD.Evidence.Run;

/// <summary>
/// What happened when the run tried to read one of the forest-wide partitions.
/// </summary>
/// <remarks>
/// <b>Two members, where <see cref="DomainReadOutcome"/> has three.</b> There is no
/// <c>PartiallyRead</c> here and the omission is the decision. A domain is many partitions and can
/// genuinely be partly covered; the configuration partition and the schema partition are each one
/// capture unit, and a unit either completed - producing its <see cref="PartitionCoverage"/> row -
/// or failed and ended the run. A third member would describe a state capture cannot reach.
/// </remarks>
public enum ForestPartitionReadOutcome
{
    /// <summary>The partition was read in full.</summary>
    Read,

    /// <summary>The partition could not be read.</summary>
    NotRead,
}

/// <summary>
/// What became of one partition that belongs to the forest rather than to any domain.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists at all.</b> Per
/// <c>docs/decisions/0035-coverage-is-recorded-once-per-capture-unit.md</c>, a partition that
/// belongs to no domain is a run-level fact: the configuration and schema partitions are the
/// forest's, and a run that cannot read one is a failed run rather than a domain with a problem.
/// Expressed as domain coverage it would make a forest-wide failure look local; expressed nowhere -
/// which is where it was until now - a failed schema read left every domain still reporting as
/// read.
/// </para>
/// <para>
/// <b>That is not hypothetical.</b> Per
/// <c>docs/decisions/0014-capture-reads-the-schema-partition.md</c> an unread schema partition is
/// the failure that stops any permission being resolved at all, so it is precisely the one that
/// must not pass quietly.
/// </para>
/// <para>
/// A partition that could not be read must say why, because the operator's remedy depends on it and
/// a refusal that names no cause is a refusal he cannot act on. This is the same rule
/// <see cref="DomainCoverage"/> follows, for the same reason.
/// </para>
/// </remarks>
public sealed record ForestPartitionCoverage
{
    private ForestPartitionCoverage(
        string namingContextDn,
        NamingContextKind kind,
        ForestPartitionReadOutcome outcome,
        string? reason)
    {
        NamingContextDn = namingContextDn;
        Kind = kind;
        Outcome = outcome;
        Reason = reason;
    }

    /// <summary>The partition root's distinguished name.</summary>
    public string NamingContextDn { get; }

    /// <summary>Which forest-wide partition this is.</summary>
    public NamingContextKind Kind { get; }

    /// <summary>What happened when the run tried to read it.</summary>
    public ForestPartitionReadOutcome Outcome { get; }

    /// <summary>
    /// Why it was not read, in words an operator can act on. Null when <see cref="Outcome"/> is
    /// <see cref="ForestPartitionReadOutcome.Read"/>, because a partition that was read has nothing
    /// to explain.
    /// </summary>
    public string? Reason { get; }

    /// <summary>Records a forest-wide partition that was read in full.</summary>
    /// <param name="namingContextDn">The partition root's distinguished name.</param>
    /// <param name="kind">Which forest-wide partition it is.</param>
    public static ForestPartitionCoverage Read(string namingContextDn, NamingContextKind kind) =>
        new(Require(namingContextDn), ForestWide(kind), ForestPartitionReadOutcome.Read, reason: null);

    /// <summary>Records a forest-wide partition that could not be read.</summary>
    /// <param name="namingContextDn">The partition root's distinguished name.</param>
    /// <param name="kind">Which forest-wide partition it is.</param>
    /// <param name="reason">Why it could not be read.</param>
    public static ForestPartitionCoverage NotRead(
        string namingContextDn, NamingContextKind kind, string reason) =>
        new(Require(namingContextDn), ForestWide(kind), ForestPartitionReadOutcome.NotRead, Require(reason));

    /// <summary>
    /// Refuses a domain partition, which is not a forest-wide fact and has a domain to be reported
    /// against.
    /// </summary>
    /// <remarks>
    /// Recording a domain partition here would put one naming context in two coverage models at
    /// once, which is the disagreement <c>docs/decisions/0035</c> was written to end.
    /// </remarks>
    private static NamingContextKind ForestWide(NamingContextKind kind)
    {
        if (kind == NamingContextKind.Domain)
        {
            throw new ArgumentException(
                "A domain partition is not a forest-wide fact and belongs to its domain's coverage. "
                + "Recording it here would describe one naming context in two coverage models, "
                + "which is what docs/decisions/0035 exists to prevent.",
                nameof(kind));
        }

        return kind;
    }

    private static string Require(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value.Trim();
    }
}
