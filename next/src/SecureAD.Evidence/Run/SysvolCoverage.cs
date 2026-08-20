namespace SecureAD.Evidence.Run;

/// <summary>
/// How much of the Group Policy held on SYSVOL a run managed to read.
/// </summary>
/// <remarks>
/// <b>Every member is reachable, and that is the requirement rather than a nicety.</b> A coverage
/// value that can only ever say one thing is worth nothing, and SYSVOL is the single place in this
/// product where partial coverage is genuinely expected - so it is the one place the record can be
/// made to matter.
/// </remarks>
public enum SysvolReadOutcome
{
    /// <summary>Every policy the directory declared was read in full.</summary>
    Read,

    /// <summary>Some policies were read and some were not, or some were read only in part.</summary>
    PartiallyRead,

    /// <summary>The directory declared policies and none of them could be read.</summary>
    NotRead,
}

/// <summary>
/// What became of the Group Policy files on the SYSVOL share, set against the policies the
/// directory said were there.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the first read in the product that may fail without failing the run</b>, and every
/// unusual thing about this type follows from that. Per
/// <c>docs/decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md</c> capture is fail-fast: a
/// capture unit that could not be read returns before the seal, so no bundle exists describing a
/// partly read forest. <c>docs/decisions/0044</c> makes SYSVOL the single stated exception, because
/// SYSVOL is a file share, permission problems on it are ordinary, and a run that died because one
/// policy folder out of four hundred was locked would be unusable in the field.
/// </para>
/// <para>
/// <b>It is held beside the capture units, not among them.</b> The tempting shortcut is to mark the
/// domain partly read instead, and <see cref="DomainCoverage"/> says plainly why that is wrong: a
/// partly read domain counts as an outright failure, so one unreadable policy folder would make the
/// whole forest audit unusable as a baseline. That is not "the run does not fail" - it is the run
/// failing one step later, somewhere the operator cannot connect to the cause.
/// </para>
/// <para>
/// <b>Why SYSVOL is allowed to record coverage at all.</b> <c>docs/decisions/0035</c> gives that
/// right to capture units only, and <c>0044</c> widens it by exactly one condition: a thing that is
/// not a capture unit may record coverage only where its incompleteness has knowable edges. SYSVOL
/// meets it because the policy list comes from LDAP before a single file is opened, so a run that
/// could not read three folders out of four hundred knows which three, by name and GUID. A record
/// that said <i>partial</i> without naming them would fail the condition it was granted under, which
/// is why <see cref="UnreadablePolicies"/> exists and why <see cref="Of"/> will not accept a
/// nameless failure.
/// </para>
/// <para>
/// <b><see cref="RunCoverage.AllDeclaredUnitsAreComplete"/> does not consider any of this</b>, and
/// that separation is deliberate. That flag is an internal consistency check, true in every bundle
/// a reader can open; this is a value that genuinely varies and is meant to be read. Merging them
/// would turn an always-true invariant into a customer-facing verdict, which is the defect
/// <c>F-S29-3</c> was raised about.
/// </para>
/// </remarks>
public sealed record SysvolCoverage
{
    private SysvolCoverage(
        IReadOnlyList<GpoCoverage> policies,
        IReadOnlyList<GpoCoverage> unreadablePolicies,
        SysvolReadOutcome outcome)
    {
        Policies = policies;
        UnreadablePolicies = unreadablePolicies;
        Outcome = outcome;
    }

    /// <summary>
    /// What became of each policy the directory declared, ordered by display name. Every declared
    /// policy appears, read or not.
    /// </summary>
    public IReadOnlyList<GpoCoverage> Policies { get; }

    /// <summary>
    /// The policies that were not read in full, ordered by display name, so a report can name them
    /// rather than say only that something was missed.
    /// </summary>
    public IReadOnlyList<GpoCoverage> UnreadablePolicies { get; }

    /// <summary>
    /// How much of SYSVOL was read.
    /// </summary>
    /// <remarks>
    /// Derived from <see cref="Policies"/> rather than supplied, so it cannot disagree with the
    /// list it summarises. A caller cannot declare success over a set of failures.
    /// </remarks>
    public SysvolReadOutcome Outcome { get; }

    /// <summary>
    /// Whether every declared policy was read in full.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is what vouches for <see cref="Policies"/> under gate 4: a caller holding the list can
    /// tell an empty or short one from a complete one without inspecting every element. It is the
    /// same arrangement <see cref="RunCoverage.AllDeclaredUnitsAreComplete"/> has over the domain
    /// list, with one difference that matters - <b>this one genuinely varies</b>, because a SYSVOL
    /// failure does not end the run.
    /// </para>
    /// <para>
    /// It is coarser than <see cref="Outcome"/> and does not replace it. False covers both "three
    /// policies out of four hundred were missed" and "the share refused everything", and those call
    /// for different action from an operator.
    /// </para>
    /// </remarks>
    public bool AllDeclaredPoliciesAreComplete => UnreadablePolicies.Count == 0;

    /// <summary>How many policies the directory declared - the denominator.</summary>
    public int PoliciesDeclared => Policies.Count;

    /// <summary>How many of them were read in full.</summary>
    /// <remarks>
    /// Stated as well as derivable because this is the number a report puts in front of a reader -
    /// <i>397 of 400 policies were examined</i> - and a figure assembled at each call site is a
    /// figure that will eventually be assembled differently at one of them.
    /// </remarks>
    public int PoliciesRead => Policies.Count - UnreadablePolicies.Count;

    /// <summary>
    /// Sets the outcome of the SYSVOL read against the policies the directory declared.
    /// </summary>
    /// <param name="policies">
    /// What became of each declared policy. Empty is allowed and means the forest declared no
    /// policies at all, which is a fact about the forest rather than a failure.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="policies"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// A policy is null, or the same policy is reported twice.
    /// </exception>
    public static SysvolCoverage Of(IEnumerable<GpoCoverage> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);

        var ordered = policies
            .Select(RequirePolicy)
            .OrderBy(p => p.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.GpoGuid)
            .ToArray();

        RefuseDuplicates(ordered);

        var unreadable = ordered
            .Where(p => p.Outcome != GpoReadOutcome.Read)
            .ToArray();

        return new SysvolCoverage(ordered, unreadable, OutcomeOf(ordered, unreadable));
    }

    /// <summary>
    /// Reads the outcome out of the policies themselves.
    /// </summary>
    /// <remarks>
    /// <c>NotRead</c> is reserved for a forest that declared policies and yielded none of them,
    /// because that is the case an operator must act on immediately - it usually means the share
    /// itself was refused rather than one folder. A forest with no policies at all reports
    /// <c>Read</c>: there was nothing to read and nothing was missed, and calling that a failure
    /// would make every empty test forest look broken.
    /// </remarks>
    private static SysvolReadOutcome OutcomeOf(
        IReadOnlyList<GpoCoverage> policies,
        IReadOnlyList<GpoCoverage> unreadable)
    {
        if (unreadable.Count == 0)
        {
            return SysvolReadOutcome.Read;
        }

        return unreadable.Count == policies.Count && policies.All(p => p.Outcome == GpoReadOutcome.Unreadable)
            ? SysvolReadOutcome.NotRead
            : SysvolReadOutcome.PartiallyRead;
    }

    private static GpoCoverage RequirePolicy(GpoCoverage policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return policy;
    }

    private static void RefuseDuplicates(IReadOnlyList<GpoCoverage> policies)
    {
        var seen = new HashSet<Guid>();
        foreach (var policy in policies)
        {
            if (!seen.Add(policy.GpoGuid))
            {
                throw new ArgumentException(
                    $"Policy {policy.GpoGuid} was reported twice. Two outcomes for one policy means "
                    + "the capture disagrees with itself about what it read, and choosing which to "
                    + "believe is not this type's business.",
                    nameof(policies));
            }
        }
    }
}
