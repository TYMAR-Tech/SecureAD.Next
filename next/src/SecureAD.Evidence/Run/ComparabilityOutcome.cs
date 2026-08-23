namespace SecureAD.Evidence.Run;

/// <summary>
/// Why a comparison may or may not be made, as a closed set.
/// </summary>
/// <remarks>
/// <para>
/// Closed on purpose. Adding a situation is one entry here, after which the compiler names every
/// place that must decide what to do about it. The alternative is what the predecessor had: five
/// independent predicates in three files, so changing the rule meant finding all five, and the one
/// that was missed did not fail - it disagreed quietly.
/// </para>
/// <para>
/// The situations and their card shapes are decision <c>0027</c>, and the document
/// <c>docs/evidence/whether-two-runs-compare.md</c> is bound to this enum in both
/// directions.
/// </para>
/// </remarks>
public enum ComparabilityOutcome
{
    /// <summary>This is the first run of this forest, so there is nothing behind it.</summary>
    NoEarlierRun,

    /// <summary>
    /// There was an earlier run and it is gone. Kept apart from <see cref="NoEarlierRun"/> because
    /// <i>this is your first audit</i> and <i>somebody deleted last month's</i> call for different
    /// things from the operator.
    /// </summary>
    EarlierRunDeleted,

    /// <summary>The earlier run did not finish, so there is nothing sound to measure against.</summary>
    EarlierRunNeverCompleted,

    /// <summary>
    /// This run did not read every domain the forest reported, so any comparison would understate
    /// what changed by an unknown amount.
    /// </summary>
    ThisRunDidNotReadEveryDomain,

    /// <summary>
    /// The earlier run did not read every domain. Kept apart from
    /// <see cref="ThisRunDidNotReadEveryDomain"/> because only one of the two can be fixed by
    /// running the audit again now.
    /// </summary>
    EarlierRunDidNotReadEveryDomain,

    /// <summary>
    /// Both runs are complete and the forest itself changed shape between them - a domain
    /// decommissioned, an acquisition finished, a new domain stood up. A real comparison, reported
    /// with what only one side covered.
    /// </summary>
    ForestDomainSetDiffers,

    /// <summary>Comparable, but some graph analysis was withheld from one of the runs.</summary>
    GraphFindingsWithheld,

    /// <summary>Comparable, but the runs were produced by different major versions.</summary>
    DifferentMajorVersions,

    /// <summary>
    /// Nothing qualifies the comparison. The only outcome permitted to produce a card that says
    /// nothing changed.
    /// </summary>
    FullyComparable,
}

/// <summary>
/// The three shapes the drift card may take. The shape follows the verdict, never the counts.
/// </summary>
/// <remarks>
/// The predecessor built this card from five integers and read no compatibility verdict at all, so
/// a comparison it had <b>declined to perform</b> came back with every delta collection empty and
/// printed <i>no changes since the previous audit</i>, with the success flag set. That is
/// <i>found nothing</i> and <i>could not compute</i> rendered identically, one level above where
/// the type system reaches.
/// </remarks>
public enum DriftCardShape
{
    /// <summary>
    /// No comparison happened. The card says so, names a cause the operator can act on, and never
    /// renders as a pass.
    /// </summary>
    NoResult,

    /// <summary>
    /// A comparison happened, and something about it must be stated alongside the numbers. The
    /// qualification cannot be dismissed.
    /// </summary>
    Qualified,

    /// <summary>A comparison happened over the whole estate with nothing withheld.</summary>
    Measured,
}

/// <summary>
/// Whether two runs may be compared, why, and what the card that reports it must look like.
/// </summary>
/// <param name="Outcome">The situation, from the closed set.</param>
/// <param name="Shape">The card shape this situation requires.</param>
/// <param name="Explanation">
/// What to tell the operator, in terms of something he did or can act on.
/// </param>
public sealed record ComparabilityVerdict(
    ComparabilityOutcome Outcome,
    DriftCardShape Shape,
    string Explanation)
{
    /// <summary>
    /// Whether a comparison may be performed at all. False for every
    /// <see cref="DriftCardShape.NoResult"/> outcome, which is what makes
    /// <i>the success flag is never set on a path where no comparison occurred</i> a property of
    /// the type rather than a rule callers are asked to remember.
    /// </summary>
    public bool ComparisonMayProceed => Shape != DriftCardShape.NoResult;
}

/// <summary>
/// Whether a run may be nominated as the baseline of its forest.
/// </summary>
/// <param name="IsEligible">Whether it may.</param>
/// <param name="Explanation">Why not, or why it may.</param>
public sealed record BaselineVerdict(bool IsEligible, string Explanation);
