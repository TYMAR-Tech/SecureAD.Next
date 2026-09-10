using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class AuditPhaseReportingTests
{
    [Theory]
    [InlineData(JudgingPhase.SelectingOwnershipScope, "Selecting ownership assessment scope")]
    [InlineData(JudgingPhase.AssessingOwnership, "Assessing ownership takeover")]
    public void OwnershipPhasesUseTheApprovedLabels(JudgingPhase phase, string expected)
    {
        Assert.Equal(expected, AuditProgressViewModel.PhaseText(phase.ToString()));
    }

    [Fact]
    public void JudgingReportsPreparationWorkAndPublicationInOrder()
    {
        var directory = Bundle();
        Derive(directory);
        var reports = new Collected<JudgingRun.JudgingProgress>();
        var result = JudgingRun.Judge(directory, [], Started, Started, reports, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal(new[] { JudgingPhase.PreparingInputs, JudgingPhase.EvaluatingObjects,
            JudgingPhase.SelectingOwnershipScope, JudgingPhase.AssessingOwnership, JudgingPhase.EvaluatingRequesters,
            JudgingPhase.WritingFindings, JudgingPhase.PublishingJudgement }, reports.Values.Select(value => value.Phase).Distinct());
    }

    [Fact]
    public async Task ShellJudgingReportsUniqueObjectsRatherThanPerRuleEvaluations()
    {
        var directory = Bundle();
        Derive(directory);
        var reports = new Collected<JudgingRun.JudgingProgress>();
        var result = await new JudgingLauncher(null).RunAsync(directory, reports, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal((3L, JudgingPhase.ReadingResults), (result.Value.ObjectsJudged, reports.Values[^1].Phase));
    }

    [Fact]
    public async Task DerivationReportsSourceWritingPublicationAndReadback()
    {
        var reports = new Collected<DerivationProgress>();
        var result = await new DerivationLauncher().RunAsync(Bundle(), reports, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal(new[] { "WritingMembershipEvidence", "PublishingDerivation", "ReadingDerivedResults" },
            reports.Values.Select(value => value.Phase).Where(phase => phase is "WritingMembershipEvidence" or "PublishingDerivation" or "ReadingDerivedResults"));
    }

    private sealed class Collected<T> : IProgress<T>
    {
        public List<T> Values { get; } = [];
        public void Report(T value) => Values.Add(value);
    }
}
