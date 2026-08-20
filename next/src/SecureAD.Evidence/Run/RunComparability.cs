namespace SecureAD.Evidence.Run;

/// <summary>
/// The one answer to whether a run may be used - as a comparison partner, or as the baseline of
/// its forest.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every door calls this.</b> The run library, the automatic drift summary, the compare window,
/// acceptance import and baseline marking read the same verdict, and no caller carries its own
/// predicate. A rule enforced at one door and not another is not enforced.
/// </para>
/// <para>
/// The predecessor had five, and they disagreed rather than merely repeating each other. The drift
/// path checked neither coverage nor eligibility. Two of the three library compare commands
/// checked only whether a run was sealed. The one command that did check coverage refused every
/// mismatch, including the changed-forest case its own comparison core had been deliberately
/// rewritten to permit - so an operator who decommissioned a domain lost remediation tracking
/// across the transition, and the carefully reasoned relaxation was unreachable from the only door
/// that asked. Baseline eligibility never read run state at all.
/// </para>
/// <para>
/// <b>The order of the checks is the decision</b>, recorded in
/// <c>docs/decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md</c>. The
/// first match wins, and the sequence runs from the least recoverable situation to the most: no
/// partner at all, then a partner that never finished, then evidence with a hole in it, then
/// differences that qualify rather than refuse. A run that both failed a domain and saw a changed
/// forest reports the failure, because that is the one the operator has to fix.
/// </para>
/// </remarks>
public static class RunComparability
{
    /// <summary>There is no earlier run of this forest.</summary>
    public static ComparabilityVerdict NoEarlierRun() => new(
        ComparabilityOutcome.NoEarlierRun,
        DriftCardShape.NoResult,
        "This is the first audit of this forest, so there is nothing to compare it against yet. "
        + "The next run will be measured against this one.");

    /// <summary>There was an earlier run of this forest and it is no longer in the library.</summary>
    public static ComparabilityVerdict EarlierRunDeleted() => new(
        ComparabilityOutcome.EarlierRunDeleted,
        DriftCardShape.NoResult,
        "The previous audit of this forest is no longer in the run library, so there is nothing "
        + "to compare against. Nominate another run as the baseline, or treat this run as the "
        + "new starting point.");

    /// <summary>
    /// Decides whether <paramref name="thisRun"/> may be compared against
    /// <paramref name="earlierRun"/>.
    /// </summary>
    /// <param name="thisRun">The run being reported on.</param>
    /// <param name="earlierRun">The run it would be measured against.</param>
    /// <exception cref="ArgumentException">
    /// The two runs assessed different forests. That is not a comparison with a qualification on
    /// it; it is a question nobody asked, and answering it at all would let a bundle copied in
    /// from another machine be offered as a partner for a forest it does not belong to.
    /// </exception>
    public static ComparabilityVerdict Evaluate(RunSummary thisRun, RunSummary earlierRun)
    {
        ArgumentNullException.ThrowIfNull(thisRun);
        ArgumentNullException.ThrowIfNull(earlierRun);

        if (thisRun.Profile != earlierRun.Profile)
        {
            throw new ArgumentException(
                $"These runs assessed different forests ({thisRun.Profile.ForestFqdn} and "
                + $"{earlierRun.Profile.ForestFqdn}), so there is no comparison to qualify.",
                nameof(earlierRun));
        }

        if (earlierRun.State != RunState.Sealed || earlierRun.Coverage is null)
        {
            return new ComparabilityVerdict(
                ComparabilityOutcome.EarlierRunNeverCompleted,
                DriftCardShape.NoResult,
                "The previous audit of this forest did not finish, so there is no sound record to "
                + "measure this one against. Run it again, or nominate a completed run as the "
                + "baseline.");
        }

        if (thisRun.State != RunState.Sealed || thisRun.Coverage is null)
        {
            return new ComparabilityVerdict(
                ComparabilityOutcome.ThisRunDidNotReadEveryDomain,
                DriftCardShape.NoResult,
                "This audit did not finish, so there is nothing complete enough to compare.");
        }

        if (!thisRun.Coverage.AllDeclaredUnitsAreComplete)
        {
            return new ComparabilityVerdict(
                ComparabilityOutcome.ThisRunDidNotReadEveryDomain,
                DriftCardShape.NoResult,
                "This audit could not read "
                + Name(thisRun.Coverage.IncompleteDomains)
                + " in full, so a comparison would understate what has changed by an unknown "
                + "amount. Run the audit again once the domain can be reached.");
        }

        if (!earlierRun.Coverage.AllDeclaredUnitsAreComplete)
        {
            return new ComparabilityVerdict(
                ComparabilityOutcome.EarlierRunDidNotReadEveryDomain,
                DriftCardShape.NoResult,
                "The previous audit could not read "
                + Name(earlierRun.Coverage.IncompleteDomains)
                + " in full, so it cannot be used as a baseline. Nominate a complete run as the "
                + "baseline; this audit is sound and can serve as one.");
        }

        if (thisRun.Coverage.Declared.Value != earlierRun.Coverage.Declared.Value)
        {
            return new ComparabilityVerdict(
                ComparabilityOutcome.ForestDomainSetDiffers,
                DriftCardShape.Qualified,
                "The forest itself changed between these audits: "
                + Difference(thisRun.Coverage.Declared, earlierRun.Coverage.Declared)
                + " Everything both audits covered is compared; anything only one of them covered "
                + "is reported as not assessed, which means neither fixed nor new.");
        }

        if (thisRun.GraphFindingsWithheld || earlierRun.GraphFindingsWithheld)
        {
            return new ComparabilityVerdict(
                ComparabilityOutcome.GraphFindingsWithheld,
                DriftCardShape.Qualified,
                "Some graph analysis was withheld from one of these audits, so findings that "
                + "depend on it are absent from the comparison rather than absent from the "
                + "forest.");
        }

        if (thisRun.MajorVersion != earlierRun.MajorVersion)
        {
            return new ComparabilityVerdict(
                ComparabilityOutcome.DifferentMajorVersions,
                DriftCardShape.Qualified,
                $"These audits were produced by different major versions of this product "
                + $"({earlierRun.MajorVersion} and {thisRun.MajorVersion}), which may not agree "
                + "about what counts as a finding. Differences may reflect the change of version "
                + "rather than a change in the forest.");
        }

        return new ComparabilityVerdict(
            ComparabilityOutcome.FullyComparable,
            DriftCardShape.Measured,
            "Both audits covered the whole forest with nothing withheld, so this comparison is "
            + "complete.");
    }

    /// <summary>
    /// Decides whether <paramref name="run"/> may be nominated as the baseline of its forest.
    /// </summary>
    /// <remarks>
    /// The same predicate as reaching a comparison that may proceed, which is what keeps
    /// eligibility part of the one verdict rather than a second opinion beside it. The
    /// predecessor's version read coverage and never state, so a failed run could become the
    /// baseline of a forest and then never be compared against - the compare command required a
    /// sealed baseline, so it refused forever and named no cause, because there had been no
    /// refusal to explain.
    /// </remarks>
    /// <param name="run">The run being nominated.</param>
    public static BaselineVerdict MayBeBaseline(RunSummary run)
    {
        ArgumentNullException.ThrowIfNull(run);

        // The state test is redundant while RunSummary makes "sealed with no coverage" and
        // "unfinished with coverage" unbuildable, and mutation-testing on 2026-08-12 confirmed
        // that removing it changes nothing. It is kept because the predecessor's defect was
        // precisely a coverage-only eligibility check, and because the redundancy is one
        // comparison. Do not remove the factory guard on the strength of this one, or the other.
        if (run.State != RunState.Sealed || run.Coverage is null)
        {
            return new BaselineVerdict(
                IsEligible: false,
                "This audit did not finish, so later audits cannot be measured against it.");
        }

        if (!run.Coverage.AllDeclaredUnitsAreComplete)
        {
            return new BaselineVerdict(
                IsEligible: false,
                "This audit could not read "
                + Name(run.Coverage.IncompleteDomains)
                + " in full. A baseline with a gap in it makes every later comparison understate "
                + "what changed, without saying so.");
        }

        return new BaselineVerdict(
            IsEligible: true,
            "This audit covered the whole forest, so later audits can be measured against it.");
    }

    private static string Name(IReadOnlyList<string> domains) =>
        domains.Count == 1 ? domains[0] : string.Join(", ", domains);

    private static string Difference(CoverageId now, CoverageId before)
    {
        var added = now.DeclaredDomains.Except(before.DeclaredDomains, StringComparer.Ordinal).ToArray();
        var gone = before.DeclaredDomains.Except(now.DeclaredDomains, StringComparer.Ordinal).ToArray();

        var parts = new List<string>();
        if (added.Length > 0)
        {
            parts.Add($"{Name(added)} is present now and was not before");
        }

        if (gone.Length > 0)
        {
            parts.Add($"{Name(gone)} was present before and is not now");
        }

        return parts.Count == 0
            ? "its domains are recorded differently."
            : string.Join("; ", parts) + ".";
    }
}
