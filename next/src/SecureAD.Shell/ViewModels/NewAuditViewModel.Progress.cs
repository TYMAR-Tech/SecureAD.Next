using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Kernel.Capture;
using SecureAD.Shell.Services;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class AuditCaptureRow(string name, string detail) : ObservableObject
{
    public string Name { get; } = name;
    public string Detail { get; } = detail;
    public bool HasDetail => Detail.Length != 0;
    [ObservableProperty] private string _objectsText = AuditProgressViewModel.Text("UnreportedCount");
    [ObservableProperty] private CaptureReadState _state = CaptureReadState.Waiting;
    public string Status => AuditProgressViewModel.Text("CaptureRead" + State);
    public string Mark => State switch
    {
        CaptureReadState.ReadComplete => "\u2713",
        CaptureReadState.Reading => "\u2022",
        CaptureReadState.AttemptFailed or CaptureReadState.Stopped => "!",
        _ => "\u2014",
    };

    internal void Update(IReadOnlyList<CaptureScopeProgress> scopes)
    {
        var known = scopes.Where(scope => scope.ObjectsRead.HasValue).ToArray();
        ObjectsText = known.Length == 0 ? AuditProgressViewModel.Text("UnreportedCount")
            : known.Sum(scope => scope.ObjectsRead!.Value).ToString("N0", CultureInfo.CurrentCulture);
        State = scopes.All(scope => scope.State == CaptureReadState.ReadComplete) ? CaptureReadState.ReadComplete
            : scopes.Any(scope => scope.State == CaptureReadState.Reading) ? CaptureReadState.Reading
            : scopes.Any(scope => scope.State == CaptureReadState.AttemptFailed) ? CaptureReadState.AttemptFailed
            : scopes.Any(scope => scope.State == CaptureReadState.Stopped) ? CaptureReadState.Stopped
            : CaptureReadState.Waiting;
    }

    partial void OnStateChanged(CaptureReadState value)
    {
        OnPropertyChanged(nameof(Status));
        OnPropertyChanged(nameof(Mark));
    }
}

internal sealed partial class NewAuditViewModel
{
    private CaptureProgress? _captureProgress;
    private long _captureSequence;
    private string[]? _captureInventory;
    private DerivingOutcome? _derivedSummary;
    private JudgingOutcome? _judgedSummary;
    [ObservableProperty] private bool _showsRunDetails;
    public ObservableCollection<AuditCaptureRow> CaptureRows { get; } = [];
    public bool ShowsRunSurface => IsOnReview && HasRunOutput;
    public bool ShowsWizardSteps => !IsOnReview || ShowsRunPreparation;
    public bool ShowsRunActivity => ShowsRunSurface && IsCapturing;
    public bool ShowsCaptureActivity => ShowsRunActivity && CaptureOutput == AuditOutputState.Active;
    public bool ShowsAnalysisActivity => ShowsRunActivity && CaptureOutput != AuditOutputState.Active;
    public bool ShowsReadinessProgress => IsBusy && !HasRunOutput;
    public bool ShowsPreparationNotice => ShowsRunPreparation && ShowsStandaloneNotice;
    public bool ShowsBackAction => ShowsRunPreparation && CanGoBack;
    public bool HasSealedEvidence => BundleDirectory is not null;
    public string ScreenHeading => !ShowsRunSurface ? Text("NewAuditTitle")
        : IsCapturing ? Text("RunningTitle") : Text("ResultsTitle");
    public string CaptureMark => OutputMark(CaptureOutput);
    public string DerivationMark => OutputMark(DerivationOutput);
    public string JudgementMark => OutputMark(JudgementOutput);
    public string CaptureStepText => CaptureOutput != AuditOutputState.Active ? CaptureOutputText
        : _captureProgress?.Phase == CaptureWorkPhase.Sealing ? Text("SealingShort") : Text("RunningShort");
    public string RunScopeLabel => Exclusions.Count == 0
        ? _captureProgress is not { } progress ? DomainCountLabel
            : progress.Scopes.Count(scope => scope.IsDomain) is 1 ? Text("OneRunDomain")
                : Text("RunDomains", progress.Scopes.Count(scope => scope.IsDomain))
        : Text("RunSelectedScope", _captureProgress?.Scopes.Count(scope => scope.IsDomain)
            ?? Domains.Count(domain => domain.IsIncluded), Exclusions.Count);
    private long? CapturedObjects => _captureProgress is not { } report || !report.Scopes.Any(scope => scope.ObjectsRead.HasValue)
        ? null : report.Scopes.Sum(scope => scope.ObjectsRead ?? 0);
    public string CapturedObjectsText => Number(CapturedObjects);
    public string DomainReadsText => _captureProgress is not { } report ? Text("UnreportedCount")
        : report.Scopes.Count(scope => scope.IsDomain) is 0 ? Text("NotRequestedShort")
        : Text("DomainReads", report.Scopes.Count(scope => scope.IsDomain && scope.State == CaptureReadState.ReadComplete),
            report.Scopes.Count(scope => scope.IsDomain));
    public bool HasSavedDerivation => _derivedSummary is not null
        && DerivationOutput is AuditOutputState.Saved or AuditOutputState.SavedWithLimitations;
    public bool HasSavedJudgement => _judgedSummary is not null
        && JudgementOutput is AuditOutputState.Saved or AuditOutputState.SavedWithLimitations;
    public bool HasResultMetrics => BundleDirectory is not null && (CapturedObjects.HasValue || HasSavedDerivation || HasSavedJudgement);
    public string ResultObjectsText => HasSavedJudgement ? Number(_judgedSummary!.ObjectsJudged) : CapturedObjectsText;
    public string ResultObjectsLabel => HasSavedJudgement ? Text("ObjectsProcessedShort") : Text("ObjectsReadShort");
    public string ResultPrincipalsText => HasSavedDerivation ? DerivedNumber(_derivedSummary!.Principals) : Text("UnreportedCount");
    public string ResultRelationshipsText => HasSavedDerivation ? DerivedNumber(_derivedSummary!.NestingEdges) : Text("UnreportedCount");
    public IReadOnlyList<UnresolvedCount> UnresolvedReasons => _judgedSummary?.CouldNotDecide ?? [];
    public bool HasRuleLimitations => HasSavedJudgement
        && (JudgementOutput == AuditOutputState.SavedWithLimitations || UnresolvedReasons.Count != 0);
    public bool HasCoverage => HasSavedJudgement;
    public string RuleLimitationsText => UnresolvedReasons.Count == 0
        ? Text("AnalysisLimitations") : Text("RuleLimitations");
    public string CoverageText => _judgedSummary?.Requesters is not { } requesters ? Text("ScanNotReported")
        : requesters.Discovery.Verdict == "NotStarted" ? Text("ScanNotRun") : Text("ScanCoverageRecorded");
    public string CoverageDetail => _judgedSummary is { } judged && judged.Requesters is not null
        ? Requesters(judged).Trim() : CoverageText;
    public bool HasRunError => HasRunEnded && (Notice is not null
        || new[] { CaptureOutput, DerivationOutput, JudgementOutput }
            .Any(output => output is AuditOutputState.Failed or AuditOutputState.NoOutput));
    public string ResultsSummary => BundleDirectory is null
        ? Text(CaptureOutput == AuditOutputState.Stopped ? "StoppedNoSeal" : "NoEvidenceShort")
        : WasStopped ? Text("AuditStopped")
        : new[] { DerivationOutput, JudgementOutput }.Contains(AuditOutputState.Failed) ? Text("AnalysisFailed")
        : new[] { DerivationOutput, JudgementOutput }.Contains(AuditOutputState.Stopped) ? Text("AnalysisStopped")
        : HasOutputLimitations ? Text("ResultsLimited")
        : DerivationOutput == AuditOutputState.NotRequested && JudgementOutput == AuditOutputState.NotRequested
            ? Text("EvidenceSealed") : Text("ResultsSaved");
    public string ResultsMessage => BundleDirectory is null ? Text("NoConfirmedEvidence")
        : DerivationOutput == AuditOutputState.NotRequested && JudgementOutput == AuditOutputState.NotRequested
            ? Text("AnalysisNotRequested")
        : WasStopped || HasRunError || JudgementOutput is AuditOutputState.Stopped or AuditOutputState.NoOutput or AuditOutputState.NotStarted
            ? Text("EvidenceKeptAnalysisIncomplete") : string.Empty;
    public bool HasResultsMessage => ResultsMessage.Length != 0;

    [RelayCommand]
    private void ToggleRunDetails() => ShowsRunDetails = !ShowsRunDetails;
    [RelayCommand]
    private void ShowRunDetails() => ShowsRunDetails = true;

    private void ResetRunPresentation()
    {
        _captureProgress = null;
        _captureSequence = 0;
        _captureInventory = null;
        _derivedSummary = null;
        _judgedSummary = null;
        ShowsRunDetails = false;
        CaptureRows.Clear();
        foreach (var domain in Domains.Where(domain => domain.IsIncluded))
            CaptureRows.Add(new(domain.Domain, string.Empty));
        CaptureRows.Add(new(Text("ForestData"), Text("ForestDataDetail")));
        AnnounceProgressPresentation();
    }

    internal void ApplyCaptureProgress(CaptureProgress report)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(report.Scopes);
        if (report.Sequence <= 0) throw new ArgumentException("Capture progress has no invocation sequence.", nameof(report));
        if (report.Sequence <= _captureSequence) return;
        if (!Enum.IsDefined(report.Phase) || report.PoliciesProcessed < 0 || report.PoliciesTotal < 0
            || report.PoliciesProcessed > report.PoliciesTotal)
            throw new ArgumentException("Capture progress has an invalid phase or policy count.", nameof(report));
        var inventory = report.Scopes.Select(scope =>
            $"{scope.NamingContext}\0{scope.DisplayName}\0{scope.IsDomain}").ToArray();
        if (report.Scopes.Any(scope => string.IsNullOrWhiteSpace(scope.NamingContext)
            || string.IsNullOrWhiteSpace(scope.DisplayName) || scope.ObjectsRead < 0 || !Enum.IsDefined(scope.State))
            || report.Scopes.Select(scope => scope.NamingContext).Distinct(StringComparer.OrdinalIgnoreCase).Count() != report.Scopes.Count
            || _captureInventory is not null && !_captureInventory.SequenceEqual(inventory))
            throw new ArgumentException("Capture progress changed or invalidated its selected scope.", nameof(report));
        var groups = report.Scopes.GroupBy(scope => scope.IsDomain ? scope.NamingContext : string.Empty,
            StringComparer.OrdinalIgnoreCase).Select(group => group.ToArray())
            .OrderByDescending(group => group[0].IsDomain).ToArray();
        if (_captureInventory is null)
        {
            CaptureRows.Clear();
            foreach (var group in groups)
                CaptureRows.Add(group[0].IsDomain ? new(group[0].DisplayName, string.Empty)
                    : new(Text("ForestData"), Text("ForestDataDetail")));
            _captureInventory = inventory;
        }
        _captureSequence = report.Sequence;
        _captureProgress = report;
        for (var index = 0; index < groups.Length; index++) CaptureRows[index].Update(groups[index]);
        var activity = Text("Capture" + report.Phase);
        Progress.ReportCount(activity, report.Phase == CaptureWorkPhase.PolicyFiles ? report.PoliciesProcessed : CapturedObjects,
            Text(report.Phase == CaptureWorkPhase.PolicyFiles ? "PoliciesProcessedShort" : "ObjectsReadShort"));
        AnnounceProgressPresentation();
    }

    private string DerivedNumber(long value) => _derivedSummary!.EveryPhaseThatRanSucceeded
        ? Number(value) : Text("AtLeast", Number(value));
    private static string Number(long? value) => value?.ToString("N0", CultureInfo.CurrentCulture) ?? Text("UnreportedCount");
    private static string Text(string key, params object?[] args) => AuditProgressViewModel.Text(key, args);
    private static string OutputMark(AuditOutputState output) => output switch
    {
        AuditOutputState.Saved => "\u2713",
        AuditOutputState.Active => "\u2022",
        AuditOutputState.SavedWithLimitations or AuditOutputState.Failed or AuditOutputState.NoOutput or AuditOutputState.Stopped => "!",
        _ => "\u2014",
    };

    private void AnnounceProgressPresentation()
    {
        foreach (var name in new[]
        {
            nameof(ShowsRunSurface), nameof(ShowsWizardSteps), nameof(ShowsRunActivity), nameof(ShowsCaptureActivity),
            nameof(ShowsAnalysisActivity), nameof(ShowsReadinessProgress), nameof(ShowsPreparationNotice), nameof(ShowsBackAction), nameof(HasSealedEvidence),
            nameof(ScreenHeading), nameof(CaptureMark), nameof(DerivationMark), nameof(JudgementMark), nameof(CaptureStepText),
            nameof(RunScopeLabel), nameof(CapturedObjectsText), nameof(DomainReadsText), nameof(HasSavedDerivation),
            nameof(HasSavedJudgement), nameof(HasResultMetrics), nameof(ResultObjectsText), nameof(ResultObjectsLabel),
            nameof(ResultPrincipalsText), nameof(ResultRelationshipsText), nameof(UnresolvedReasons), nameof(HasRuleLimitations),
            nameof(HasCoverage), nameof(RuleLimitationsText), nameof(CoverageText), nameof(CoverageDetail), nameof(HasRunError), nameof(ResultsSummary),
            nameof(ResultsMessage), nameof(HasResultsMessage),
        }) OnPropertyChanged(name);
    }
}
