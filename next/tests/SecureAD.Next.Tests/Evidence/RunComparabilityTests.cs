using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// F17 and F10 - the one answer to whether a run may be used, as a comparison partner or as a
/// baseline.
///
/// <para>
/// The predecessor answered this in five independent places - three compare commands in one view
/// model, an acceptance import filter, the drift path, and baseline eligibility - and they did not
/// merely repeat each other, they disagreed. The drift path checked neither coverage nor
/// eligibility, so a comparison the system had declined to perform rendered on the home screen as
/// <i>no changes since the previous audit</i>, with the success flag set. Baseline eligibility
/// never checked run state at all, so a failed run could be made the baseline of a forest and then
/// never compared against.
/// </para>
/// <para>
/// The states, their order and their card shapes are decision
/// <c>0027</c>. The order is asserted here because it is the part that cannot be recovered by
/// reading the outcomes.
/// </para>
/// </summary>
public sealed class RunComparabilityTests
{
    private const int Version = 4;

    private static readonly string[] TwoDomains = ["contoso.com", "eu.contoso.com"];
    private static readonly string[] ThreeDomains = ["contoso.com", "eu.contoso.com", "us.contoso.com"];

    // 1 - no earlier run exists.
    [Fact]
    public void AFirstRunHasNothingToCompareAgainst()
    {
        var verdict = RunComparability.NoEarlierRun();

        Assert.Equal(ComparabilityOutcome.NoEarlierRun, verdict.Outcome);
        Assert.Equal(DriftCardShape.NoResult, verdict.Shape);
    }

    // 2 - the earlier run was deleted. Distinct from 1 because the operator can act on it.
    [Fact]
    public void ADeletedEarlierRunIsNotTheSameAsNeverHavingOne()
    {
        var deleted = RunComparability.EarlierRunDeleted();

        Assert.Equal(ComparabilityOutcome.EarlierRunDeleted, deleted.Outcome);
        Assert.Equal(DriftCardShape.NoResult, deleted.Shape);
        Assert.NotEqual(RunComparability.NoEarlierRun().Outcome, deleted.Outcome);
    }

    // 3 - the earlier run never completed.
    [Theory]
    [InlineData(RunState.InProgress)]
    [InlineData(RunState.Failed)]
    [InlineData(RunState.Cancelled)]
    [InlineData(RunState.Interrupted)]
    [InlineData(RunState.Damaged)]
    public void AnEarlierRunThatNeverCompletedCannotBeComparedAgainst(RunState state)
    {
        var verdict = RunComparability.Evaluate(Complete(), Incomplete(state));

        Assert.Equal(ComparabilityOutcome.EarlierRunNeverCompleted, verdict.Outcome);
        Assert.Equal(DriftCardShape.NoResult, verdict.Shape);
    }

    // 4 - this run failed to read a domain.
    [Fact]
    public void ARunThatDidNotReadEveryDomainIsRefused()
    {
        var verdict = RunComparability.Evaluate(MissingADomain(), Complete());

        Assert.Equal(ComparabilityOutcome.ThisRunDidNotReadEveryDomain, verdict.Outcome);
        Assert.Equal(DriftCardShape.NoResult, verdict.Shape);
    }

    // 5 - the earlier run failed to read a domain.
    [Fact]
    public void AnEarlierRunThatDidNotReadEveryDomainIsRefused()
    {
        var verdict = RunComparability.Evaluate(Complete(), MissingADomain());

        Assert.Equal(ComparabilityOutcome.EarlierRunDidNotReadEveryDomain, verdict.Outcome);
        Assert.Equal(DriftCardShape.NoResult, verdict.Shape);
    }

    /// <summary>
    /// States 4 and 5 stay apart because only one of them is actionable today. Merging them would
    /// send an operator to re-run the wrong month.
    /// </summary>
    [Fact]
    public void TheTwoIncompleteRunOutcomesAreDistinct()
    {
        Assert.NotEqual(
            RunComparability.Evaluate(MissingADomain(), Complete()).Outcome,
            RunComparability.Evaluate(Complete(), MissingADomain()).Outcome);
    }

    // 6 - the forest changed shape. Qualified, not refused.
    [Fact]
    public void AForestThatGainedADomainIsStillComparedAndSaysSo()
    {
        var verdict = RunComparability.Evaluate(Complete(ThreeDomains), Complete(TwoDomains));

        Assert.Equal(ComparabilityOutcome.ForestDomainSetDiffers, verdict.Outcome);
        Assert.Equal(DriftCardShape.Qualified, verdict.Shape);
        Assert.True(
            verdict.ComparisonMayProceed,
            "A decommissioned domain or a finished acquisition is a legitimate change to a "
            + "forest. Refusing across it forever loses remediation tracking exactly when it is "
            + "most wanted - the relaxation the predecessor reasoned out and then made "
            + "unreachable.");
    }

    // 7 - graph findings were withheld.
    [Fact]
    public void WithheldGraphFindingsQualifyTheComparison()
    {
        var verdict = RunComparability.Evaluate(Complete(withheld: true), Complete());

        Assert.Equal(ComparabilityOutcome.GraphFindingsWithheld, verdict.Outcome);
        Assert.Equal(DriftCardShape.Qualified, verdict.Shape);
    }

    // 8 - different major versions.
    [Fact]
    public void RunsFromDifferentMajorVersionsQualifyTheComparison()
    {
        var verdict = RunComparability.Evaluate(Complete(majorVersion: 5), Complete(majorVersion: 4));

        Assert.Equal(ComparabilityOutcome.DifferentMajorVersions, verdict.Outcome);
        Assert.Equal(DriftCardShape.Qualified, verdict.Shape);
    }

    // 9 and 10 - fully compatible. Whether anything changed is the comparison's answer, not this.
    [Fact]
    public void TwoCompleteRunsOfAnUnchangedForestAreFullyComparable()
    {
        var verdict = RunComparability.Evaluate(Complete(), Complete());

        Assert.Equal(ComparabilityOutcome.FullyComparable, verdict.Outcome);
        Assert.Equal(DriftCardShape.Measured, verdict.Shape);
    }

    /// <summary>
    /// The ordering rule from <c>0027</c>, and the reason it is a decision rather than a detail. A
    /// run that both failed a domain and saw a changed forest must report the failure, because
    /// that is the one the operator has to fix. In the other order he is shown a qualified
    /// comparison quietly resting on incomplete evidence.
    /// </summary>
    [Fact]
    public void AFailedDomainIsReportedAheadOfAChangedForest()
    {
        var verdict = RunComparability.Evaluate(MissingADomain(ThreeDomains), Complete(TwoDomains));

        Assert.Equal(ComparabilityOutcome.ThisRunDidNotReadEveryDomain, verdict.Outcome);
    }

    /// <summary>
    /// An earlier run that never completed is reported ahead of this run's own coverage problem,
    /// because there is nothing to compare against at all and telling the operator to re-run this
    /// month would not help.
    /// </summary>
    [Fact]
    public void AnEarlierRunThatNeverCompletedIsReportedAheadOfThisRunsCoverage()
    {
        var verdict = RunComparability.Evaluate(MissingADomain(), Incomplete(RunState.Failed));

        Assert.Equal(ComparabilityOutcome.EarlierRunNeverCompleted, verdict.Outcome);
    }

    /// <summary>
    /// The rule <c>0026</c> states outright: the success flag is never set on a path where no
    /// comparison occurred. Asserted over the whole outcome set rather than case by case, so an
    /// outcome added later cannot slip through as a pass.
    /// </summary>
    [Fact]
    public void NoRefusedComparisonEverReportsThatItMayProceed()
    {
        foreach (var verdict in EveryVerdict())
        {
            Assert.Equal(verdict.Shape != DriftCardShape.NoResult, verdict.ComparisonMayProceed);
        }
    }

    /// <summary>
    /// Only a comparison that actually ran over the whole estate may say nothing changed. This is
    /// the defect the whole component exists to remove: a refused comparison returning empty
    /// deltas and rendering as a clean pass.
    /// </summary>
    [Fact]
    public void OnlyAFullyComparablePairIsEverMeasured()
    {
        foreach (var verdict in EveryVerdict())
        {
            if (verdict.Shape == DriftCardShape.Measured)
            {
                Assert.Equal(ComparabilityOutcome.FullyComparable, verdict.Outcome);
            }
        }
    }

    /// <summary>
    /// Every outcome must carry a sentence, because a refusal the operator cannot read is a
    /// refusal he cannot act on.
    /// </summary>
    [Fact]
    public void EveryOutcomeExplainsItself()
    {
        foreach (var verdict in EveryVerdict())
        {
            Assert.False(
                string.IsNullOrWhiteSpace(verdict.Explanation),
                $"{verdict.Outcome} has no explanation.");
        }
    }

    /// <summary>
    /// The closed set is the point of the design: every outcome must be producible, or the
    /// compiler is naming doors for a situation that cannot arise.
    /// </summary>
    [Fact]
    public void EveryOutcomeIsProducible()
    {
        var produced = EveryVerdict().Select(v => v.Outcome).Distinct().ToList();

        Assert.Equal(Enum.GetValues<ComparabilityOutcome>().Length, produced.Count);
    }

    /// <summary>
    /// Two runs of different forests are not a comparison at all. The predecessor grouped by
    /// profile in the library and then never rechecked it at the compare command.
    /// </summary>
    [Fact]
    public void RunsFromDifferentForestsAreRefused()
    {
        var other = RunSummary.OfCompletedRun(
            ProfileId.ForForest("fabrikam.com"),
            CoverageFor("fabrikam.com", ["fabrikam.com"], allRead: true),
            Version,
            graphFindingsWithheld: false,
            SecureAD.Kernel.Capture.CaptureObjectScope.Default.ExcludedClasses);

        Assert.Throws<ArgumentException>(() => RunComparability.Evaluate(Complete(), other));
    }

    // --- F10, baseline eligibility -------------------------------------------------------------

    [Fact]
    public void ACompleteSealedRunMayBeABaseline()
    {
        Assert.True(RunComparability.MayBeBaseline(Complete()).IsEligible);
    }

    /// <summary>
    /// The predecessor's baseline eligibility read coverage only, and its own summary said it
    /// decided whether a <i>sealed</i> run may serve. Neither it nor the button that invoked it
    /// checked state, so a failed run could become the baseline of a forest - after which the
    /// compare command required a sealed baseline and refused forever, naming no cause, because
    /// there had been no refusal to explain.
    /// </summary>
    [Theory]
    [InlineData(RunState.InProgress)]
    [InlineData(RunState.Failed)]
    [InlineData(RunState.Cancelled)]
    [InlineData(RunState.Interrupted)]
    [InlineData(RunState.Damaged)]
    public void ARunThatNeverCompletedMayNotBeABaseline(RunState state)
    {
        var verdict = RunComparability.MayBeBaseline(Incomplete(state));

        Assert.False(verdict.IsEligible);
        Assert.False(string.IsNullOrWhiteSpace(verdict.Explanation));
    }

    [Fact]
    public void ARunThatDidNotReadEveryDomainMayNotBeABaseline()
    {
        Assert.False(RunComparability.MayBeBaseline(MissingADomain()).IsEligible);
    }

    /// <summary>
    /// <c>0027</c> makes eligibility the same predicate as a fully comparable verdict. If the two
    /// could disagree, eligibility would be the second opinion the consolidation exists to remove.
    /// </summary>
    [Fact]
    public void EligibilityAgreesWithComparingARunAgainstItself()
    {
        foreach (var run in new[] { Complete(), MissingADomain(), Incomplete(RunState.Failed) })
        {
            var comparable = RunComparability.Evaluate(Complete(), run).Shape != DriftCardShape.NoResult;

            Assert.Equal(comparable, RunComparability.MayBeBaseline(run).IsEligible);
        }
    }

    /// <summary>
    /// What actually makes the predecessor's defect impossible here. Its baseline eligibility read
    /// coverage and never state; this type cannot express a run that has coverage and did not
    /// finish, so the coverage-only reading is unavailable rather than merely discouraged.
    ///
    /// <para>
    /// Recorded because mutation-testing on 2026-08-12 removed the state check from
    /// <c>MayBeBaseline</c> and no test failed - the factory had already made the combination
    /// unbuildable. The guard that is doing the work is this one, and it is the one to protect.
    /// </para>
    /// </summary>
    [Fact]
    public void ARunCannotClaimToBeSealedWithoutSayingWhatItRead()
    {
        Assert.Throws<ArgumentException>(
            () => RunSummary.OfUnfinishedRun(ProfileId.ForForest("contoso.com"), RunState.Sealed));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DifferentClassScopesCannotProduceAnUnqualifiedComparison(bool includeEnatelSso)
    {
        var verdict = RunComparability.Evaluate(Complete(includeEnatelSso: includeEnatelSso),
            Complete(includeEnatelSso: !includeEnatelSso));

        Assert.Equal((ComparabilityOutcome.ObjectClassScopeDiffers, DriftCardShape.Qualified),
            (verdict.Outcome, verdict.Shape));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MatchingClassScopesRemainComparable(bool includeEnatelSso)
    {
        var verdict = RunComparability.Evaluate(Complete(includeEnatelSso: includeEnatelSso),
            Complete(includeEnatelSso: includeEnatelSso));

        Assert.Equal(ComparabilityOutcome.FullyComparable, verdict.Outcome);
    }

    [Fact]
    public void ACompletedSummaryCopiesItsClassScope()
    {
        var classes = new[] { "dnsNode", "dnsZone" };
        var run = RunSummary.OfCompletedRun(ProfileId.ForForest("contoso.com"),
            CoverageFor("contoso.com", TwoDomains, allRead: true), Version, false, classes);

        classes[0] = "user";

        Assert.Equal(["dnsNode", "dnsZone"], run.ExcludedObjectClasses);
    }

    // --- helpers -------------------------------------------------------------------------------

    private static IEnumerable<ComparabilityVerdict> EveryVerdict() =>
    [
        RunComparability.NoEarlierRun(),
        RunComparability.EarlierRunDeleted(),
        RunComparability.Evaluate(Complete(), Incomplete(RunState.Failed)),
        RunComparability.Evaluate(MissingADomain(), Complete()),
        RunComparability.Evaluate(Complete(), MissingADomain()),
        RunComparability.Evaluate(Complete(ThreeDomains), Complete(TwoDomains)),
        RunComparability.Evaluate(Complete(withheld: true), Complete()),
        RunComparability.Evaluate(Complete(majorVersion: 5), Complete()),
        RunComparability.Evaluate(Complete(), Complete()),
        RunComparability.Evaluate(Complete(includeEnatelSso: true), Complete()),
    ];

    private static RunSummary Complete(
        string[]? domains = null,
        bool withheld = false,
        int majorVersion = Version,
        bool includeEnatelSso = false) =>
        RunSummary.OfCompletedRun(
            ProfileId.ForForest("contoso.com"),
            CoverageFor("contoso.com", domains ?? TwoDomains, allRead: true),
            majorVersion,
            withheld,
            SecureAD.Kernel.Capture.CaptureObjectScope.For(includeEnatelSso).ExcludedClasses);

    private static RunSummary MissingADomain(string[]? domains = null) =>
        RunSummary.OfCompletedRun(
            ProfileId.ForForest("contoso.com"),
            CoverageFor("contoso.com", domains ?? TwoDomains, allRead: false),
            Version,
            graphFindingsWithheld: false,
            SecureAD.Kernel.Capture.CaptureObjectScope.Default.ExcludedClasses);

    private static RunSummary Incomplete(RunState state) =>
        RunSummary.OfUnfinishedRun(ProfileId.ForForest("contoso.com"), state);

    private static RunCoverage CoverageFor(string forest, string[] domains, bool allRead)
    {
        var declared = CoverageId.ForDomains(forest, domains);

        var outcomes = domains
            .Select(d => d.ToLowerInvariant())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(d => d, StringComparer.Ordinal)
            .Select((d, i) => allRead || i > 0
                ? DomainCoverage.Read(d)
                : DomainCoverage.NotRead(d, "No controller answered."));

        return RunCoverage.Of(
            declared,
            outcomes,
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));
    }
}
