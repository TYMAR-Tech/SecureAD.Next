using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Capture;
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

    /// <summary>
    /// <b>The run log must say which phase judging is in, while it is in it.</b> The owner ran a
    /// production judging for eight hours on 2026-09-24 and the log held one line - <i>Started,
    /// rules=17</i> - so there was no way to tell work from a hang, and no way to decide whether to
    /// abandon it. Every phase reaching <see cref="IProgress{T}"/> already, and none reaching the
    /// log, is what made the screen the only witness to a run that outlives any screen.
    /// </summary>
    /// <remarks>
    /// Asserted against the log rather than the progress reports on purpose: the log is the
    /// artefact that survives a cancelled run, a closed window and a machine the operator walked
    /// away from. <see cref="JudgingReportsPreparationWorkAndPublicationInOrder"/> covers the
    /// progress side, and passed throughout the eight hours that taught us this.
    /// </remarks>
    [Fact]
    public void JudgingNotesEachPhaseToTheRunLogAsItEntersIt()
    {
        var directory = Bundle();
        Derive(directory);
        var log = new RecordingRunLog();

        var result = JudgingRun.Judge(
            directory, [], Started, Started, JudgingRun.NobodyIsWatching, log, CancellationToken.None);

        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal(
            new[]
            {
                nameof(JudgingPhase.PreparingInputs),
                nameof(JudgingPhase.EvaluatingObjects),
                nameof(JudgingPhase.SelectingOwnershipScope),
                nameof(JudgingPhase.AssessingOwnership),
                nameof(JudgingPhase.EvaluatingRequesters),
                nameof(JudgingPhase.WritingFindings),
                nameof(JudgingPhase.PublishingJudgement),
            },
            log.Saying("phase").Select(detail => RecordingRunLog.Value(detail, "name")));
    }

    private sealed class Collected<T> : IProgress<T>
    {
        public List<T> Values { get; } = [];
        public void Report(T value) => Values.Add(value);
    }
}
