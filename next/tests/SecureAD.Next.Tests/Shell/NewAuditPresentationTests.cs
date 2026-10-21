using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class NewAuditPresentationTests
{
    [Fact]
    public void WizardRowDistinguishesUnaskedReadinessFromControllerRefusal()
    {
        var row = new DomainRowViewModel(Forests.Domain(), _ => Task.CompletedTask, (_, _) => { });
        var changed = new List<string?>();
        row.PropertyChanged += (_, args) => changed.Add(args.PropertyName);
        Assert.Equal("Not checked", row.ReadinessText);
        row.Problem = "Controller refused";
        Assert.Equal("Validation refused", row.ReadinessText);
        Assert.Contains(nameof(DomainRowViewModel.ReadinessText), changed);
    }

    [Fact]
    public async Task WizardRefusalIsProminentButNextCanRecheckWithoutStartingCapture()
    {
        var capture = new FakeCaptureLauncher { CheckFails = Failures.Any("Recorded DNS failure") };
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher(), capture);
        model.Screen = AuditScreen.Domains;
        await model.OpenAsync();
        Assert.True(model.HasReadinessIssues);
        Assert.Contains("Recorded DNS failure", model.FooterStatus);
        Assert.False(model.CanStart);
        Assert.True(model.ReviewCommand.CanExecute(null));
        Assert.False(model.ShowsStandaloneNotice);
        Assert.False(model.ShowsPhaseProgress);
        capture.CheckFails = null;
        await model.ReviewAsync();
        Assert.Equal(AuditScreen.Review, model.Screen);
        Assert.False(capture.WasRun);
        Assert.True(model.ShowsStartAction);
    }

    [Fact]
    public async Task WizardCaptureOnlyKeepsUnrequestedAnalysisSeparateFromSuccess()
    {
        var deriving = new FakeDerivationLauncher();
        var judging = new FakeJudgingLauncher();
        var model = AuditProgressTests.Model(deriving, judging);
        model.CaptureOnly = true;
        Assert.Equal("Start capture", model.StartLabel);
        await model.StartAsync();
        Assert.Equal((AuditOutputState.Saved, AuditOutputState.NotRequested, AuditOutputState.NotRequested),
            (model.CaptureOutput, model.DerivationOutput, model.JudgementOutput));
        Assert.Equal(("Sealed", "Not requested", "Not requested"), (model.CaptureOutputText, model.DerivationOutputText, model.JudgementOutputText));
        Assert.False(model.HasOutputLimitations);
        Assert.False(deriving.WasRun || judging.WasRun);
        Assert.False(model.ShowsRunPreparation || model.ShowsStartAction);
        Assert.Equal("View results", model.LeaveLabel);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WizardSeparateOutcomeCardsKeepDegradedAnalysisVisible(bool derivation)
    {
        var deriving = new FakeDerivationLauncher();
        var judging = new FakeJudgingLauncher();
        if (derivation) deriving.Outcome = new(DerivationRunState.CompletedDegraded, 2, 3, false);
        else judging.Outcome = new(JudgementRunState.CompletedDegraded, 2, new Dictionary<SecureAD.Evidence.Findings.Severity, int>(), []);
        var model = AuditProgressTests.Model(deriving, judging);
        await model.StartAsync();
        Assert.Equal(AuditOutputState.Saved, model.CaptureOutput);
        Assert.Equal(AuditOutputState.SavedWithLimitations, derivation ? model.DerivationOutput : model.JudgementOutput);
        Assert.Equal("Saved with limitations", derivation ? model.DerivationOutputText : model.JudgementOutputText);
        Assert.True(model.HasOutputLimitations);
    }

    [Theory]
    [InlineData("capture")]
    [InlineData("derive")]
    [InlineData("judge")]
    public async Task WizardStoppedOutputDoesNotErasePreviouslySealedEvidence(string phase)
    {
        var capture = new FakeCaptureLauncher { Cancels = phase == "capture" };
        var deriving = new FakeDerivationLauncher { Cancels = phase == "derive" };
        var judging = new FakeJudgingLauncher { Cancels = phase == "judge" };
        var model = AuditProgressTests.Model(deriving, judging, capture);
        await model.StartAsync();
        Assert.True(model.HasRunEnded);
        Assert.True(model.HasOutputLimitations);
        Assert.False(model.StopConfirmationRequested);
        Assert.Equal(phase == "capture" ? AuditOutputState.Stopped : AuditOutputState.Saved, model.CaptureOutput);
        Assert.Equal(phase == "capture" ? "Done" : "View results", model.LeaveLabel);
        Assert.Equal(phase == "derive" ? AuditOutputState.Stopped : phase == "judge" ? AuditOutputState.Saved : AuditOutputState.NotStarted, model.DerivationOutput);
        Assert.Equal(phase == "judge" ? AuditOutputState.Stopped : AuditOutputState.NotStarted, model.JudgementOutput);
        Assert.Equal(phase != "capture", model.BundleDirectory is not null);
        Assert.Equal("What this audit produced", model.StepQuestion);
        Assert.NotNull(model.ResultsNote);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WizardFailedAnalysisDoesNotBecomeSavedOutput(bool derivation)
    {
        var deriving = new FakeDerivationLauncher { Fails = derivation ? Failures.Any("derive refused") : null };
        var judging = new FakeJudgingLauncher { Fails = derivation ? null : Failures.Any("judge refused") };
        var model = AuditProgressTests.Model(deriving, judging);
        await model.StartAsync();
        Assert.Equal(AuditOutputState.Failed, derivation ? model.DerivationOutput : model.JudgementOutput);
        Assert.True(model.HasOutputLimitations);
        Assert.Equal(AuditOutputState.Saved, model.CaptureOutput);
        Assert.Equal("View results", model.LeaveLabel);
    }

    [Fact]
    public async Task WizardRetryClearsOutputCardsFromThePreviousRun()
    {
        var capture = new FakeCaptureLauncher();
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher(), capture);
        await model.StartAsync();
        Assert.Equal(AuditOutputState.Saved, model.JudgementOutput);
        capture.Cancels = true;
        await model.StartAsync();
        Assert.Equal((AuditOutputState.Stopped, AuditOutputState.NotStarted, AuditOutputState.NotStarted),
            (model.CaptureOutput, model.DerivationOutput, model.JudgementOutput));
        Assert.Null(model.BundleDirectory);
    }

    [Fact]
    public async Task WizardStopConfirmationCanBeCancelledWithoutStoppingTheRun()
    {
        var judging = new FakeJudgingLauncher();
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), judging);
        (bool Requested, bool Cleared, bool TokenCancelled, string Explanation)? seen = null;
        judging.WhileRunning = () =>
        {
            model.RequestAuditStopCommand.Execute(null);
            var requested = model.StopConfirmationRequested;
            model.KeepAuditRunningCommand.Execute(null);
            seen = (requested, !model.StopConfirmationRequested, model.Progress.Status.StartsWith("Stopping", StringComparison.Ordinal), model.StopExplanation);
        };
        await model.StartAsync();
        Assert.NotNull(seen);
        Assert.True(seen.Value.Requested && seen.Value.Cleared);
        Assert.False(seen.Value.TokenCancelled);
        Assert.Contains("already sealed", seen.Value.Explanation);
        Assert.Equal(AuditOutputState.Saved, model.JudgementOutput);
    }

    [Fact]
    public async Task WizardConfirmedStopUsesTheExistingCancellationAndPreservesEvidence()
    {
        var judging = new FakeJudgingLauncher();
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), judging);
        judging.WhileRunning = () =>
        {
            model.RequestAuditStopCommand.Execute(null);
            model.ConfirmAuditStopCommand.Execute(null);
        };
        await model.StartAsync();
        Assert.Equal(AuditOutputState.Stopped, model.JudgementOutput);
        Assert.Equal(AuditOutputState.Saved, model.CaptureOutput);
        Assert.False(model.StopConfirmationRequested);
        Assert.False(model.CanRequestAuditStop);
    }

    [Fact]
    public void WizardModeChoiceRefreshesTheStartActionLabel()
    {
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher());
        var names = new List<string?>();
        model.PropertyChanged += (_, args) => names.Add(args.PropertyName);
        model.CaptureOnly = true;
        Assert.Equal("Start capture", model.StartLabel);
        Assert.Contains(nameof(NewAuditViewModel.StartLabel), names);
        model.CaptureAndAnalyse = true;
        Assert.Equal("Start audit", model.StartLabel);
    }
}
