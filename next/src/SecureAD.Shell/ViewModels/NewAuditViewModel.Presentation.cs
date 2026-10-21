using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SecureAD.Shell.ViewModels;

internal enum AuditOutputState { NotStarted, Waiting, NotRequested, Active, Saved, SavedWithLimitations, NoOutput, Failed, Stopped }

internal sealed partial class NewAuditViewModel
{
    [ObservableProperty] private AuditOutputState _captureOutput;
    [ObservableProperty] private AuditOutputState _derivationOutput;
    [ObservableProperty] private AuditOutputState _judgementOutput;
    [ObservableProperty] private bool _stopConfirmationRequested;

    public bool HasRunOutput => CaptureOutput != AuditOutputState.NotStarted;
    public bool ShowsRunPreparation => !HasRunOutput;
    public bool ShowsRunHeading => IsOnReview && HasRunOutput;
    public bool ShowsStartAction => IsOnReview && ShowsRunPreparation;
    public bool HasRunEnded => HasRunOutput && !IsCapturing;
    public bool ShowsPhaseProgress => IsBusy || IsCapturing || HasRunOutput;
    public bool ShowsStandaloneNotice => HasNotice && !(HasReadinessIssues && Notice?.Detail == Problem);
    public bool HasReadinessIssues => IsOnDomains && !IsBusy
        && (Problem is not null || AnyDomainNeedsAttention || HasUnattestedExclusions
            || _blockingDomains.Any(domain => !Attestations().Any(attestation =>
                string.Equals(attestation.NamingContext, domain, StringComparison.OrdinalIgnoreCase))));
    public string FooterStatus => Problem ?? (IsBusy ? "Checking domain readiness. No capture has started."
        : IsCapturing ? "The authorized run is in progress. Stop does not complete its remaining work."
        : HasRunEnded ? BundleDirectory is null ? "No sealed evidence is available to open." : "Sealed evidence remains available. Review the separate analysis outcomes."
        : HasReadinessIssues ? "Next rechecks every domain before allowing the run to continue."
        : "No capture has started.");
    public string StartLabel => CaptureOnly ? "Start capture" : "Start audit";
    public string CaptureOutputText => OutputText(CaptureOutput, evidence: true);
    public string DerivationOutputText => OutputText(DerivationOutput, evidence: false);
    public string JudgementOutputText => OutputText(JudgementOutput, evidence: false);
    public bool HasOutputLimitations => HasRunEnded && new[] { CaptureOutput, DerivationOutput, JudgementOutput }
        .Any(state => state is AuditOutputState.SavedWithLimitations or AuditOutputState.NoOutput or AuditOutputState.Failed or AuditOutputState.Stopped);
    public string StopExplanation => BundleDirectory is null
        ? "Sealing has not been confirmed. Stopping is not a completed capture; the run will report what it actually produced."
        : "Evidence is already sealed and remains available. Stopping analysis does not remove it or complete unfinished checks.";

    public bool CanRequestAuditStop => IsCapturing;

    [RelayCommand(CanExecute = nameof(CanRequestAuditStop))]
    private void RequestAuditStop() => StopConfirmationRequested = true;
    [RelayCommand]
    private void KeepAuditRunning() => StopConfirmationRequested = false;
    [RelayCommand(CanExecute = nameof(CanRequestAuditStop))]
    private void ConfirmAuditStop()
    {
        StopConfirmationRequested = false;
        Stop();
    }

    private static string OutputText(AuditOutputState state, bool evidence) => state switch
    {
        AuditOutputState.NotStarted => "Not started",
        AuditOutputState.Waiting => "Waiting",
        AuditOutputState.NotRequested => "Not requested",
        AuditOutputState.Active => evidence ? "Capture / sealing in progress" : "In progress",
        AuditOutputState.Saved => evidence ? "Sealed" : "Saved",
        AuditOutputState.SavedWithLimitations => "Saved with limitations",
        AuditOutputState.NoOutput => "No sealed evidence",
        AuditOutputState.Failed => "Failed - no completed output confirmed",
        AuditOutputState.Stopped => "Stopped - completion not confirmed",
        _ => throw new ArgumentOutOfRangeException(nameof(state)),
    };

    partial void OnCaptureOutputChanged(AuditOutputState value) => AnnouncePresentation();
    partial void OnDerivationOutputChanged(AuditOutputState value) => AnnouncePresentation();
    partial void OnJudgementOutputChanged(AuditOutputState value) => AnnouncePresentation();
    partial void OnProblemChanged(string? value) => AnnouncePresentation();

    private void AnnouncePresentation()
    {
        OnPropertyChanged(nameof(HasRunOutput));
        OnPropertyChanged(nameof(ShowsRunPreparation));
        OnPropertyChanged(nameof(ShowsRunHeading));
        OnPropertyChanged(nameof(ShowsStartAction));
        OnPropertyChanged(nameof(CanRequestAuditStop));
        OnPropertyChanged(nameof(HasRunEnded));
        OnPropertyChanged(nameof(ShowsPhaseProgress));
        OnPropertyChanged(nameof(ShowsStandaloneNotice));
        OnPropertyChanged(nameof(HasReadinessIssues));
        OnPropertyChanged(nameof(FooterStatus));
        OnPropertyChanged(nameof(StartLabel));
        OnPropertyChanged(nameof(CaptureOutputText));
        OnPropertyChanged(nameof(DerivationOutputText));
        OnPropertyChanged(nameof(JudgementOutputText));
        OnPropertyChanged(nameof(HasOutputLimitations));
        OnPropertyChanged(nameof(StopExplanation));
        OnPropertyChanged(nameof(LeaveLabel));
        OnPropertyChanged(nameof(StepQuestion));
        OnPropertyChanged(nameof(ResultsNote));
        RequestAuditStopCommand.NotifyCanExecuteChanged();
        ConfirmAuditStopCommand.NotifyCanExecuteChanged();
    }
}
