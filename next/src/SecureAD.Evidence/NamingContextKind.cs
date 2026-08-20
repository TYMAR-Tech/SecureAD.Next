namespace SecureAD.Evidence;

/// <summary>
/// What kind of naming context one capture unit reads.
/// </summary>
/// <remarks>
/// <para>
/// A <b>naming context</b>, also called a partition, is one of the separately held trees a domain
/// controller serves. Every forest has at least three: one per domain, one configuration partition
/// shared by the whole forest, and one schema partition.
/// </para>
/// <para>
/// <b>Why this lives in the evidence library rather than beside capture.</b> It was defined in
/// <c>SecureAD.Audit</c> until 2026-08-13, next to the capture unit whose shape it describes, and
/// the one decision that turns on it is still a capture decision: the control that asks a
/// controller not to generate continuation referrals applies to a domain root, and the
/// configuration and schema partitions are not domain roots. But per
/// <c>docs/decisions/0035</c> a capture unit is the only thing that records coverage directly, one
/// type expresses that coverage, and it is defined here. The kind is part of that record, so
/// leaving the enum on the far side of the dependency would have forced the stored kind back into
/// a bare string - which is the untyped seam the two coverage types drifted across in the first
/// place.
/// </para>
/// <para>
/// Everything else about a unit is the same whichever kind it is, which is the point - a partition
/// is a partition. Treating a unit as a <i>domain</i> rather than as a partition is the assumption
/// the paging defect grows out of, because it is what makes the other partitions look like
/// something to pass through rather than something to read on purpose. It is also what
/// <c>docs/decisions/0035</c> records failing one level up: a forest-wide partition that belongs to
/// no domain had nowhere to report a failure, so a run that could not read the schema partition
/// still reported every domain as covered.
/// </para>
/// <para>
/// <b>Which</b> naming contexts a run reads is not decided here. That is inventory row B6, and the
/// DNS application partitions are out of scope per the DNS scope decision of 2026-08-11.
/// </para>
/// </remarks>
public enum NamingContextKind
{
    /// <summary>A domain partition, whose root is a domain root.</summary>
    Domain,

    /// <summary>The forest's configuration partition. Read once per forest.</summary>
    Configuration,

    /// <summary>The forest's schema partition. Read once per forest.</summary>
    Schema,
}
