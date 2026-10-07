using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class SavedTier0PathSectionViewModel(ObjectSectionDefinition definition) : ObjectSectionViewModel(definition)
{
    private Func<PathRiskVerdict, PathRiskPageMark?, CancellationToken, Task<Result<SavedTier0Path?>>>? _read;
    private CancellationTokenSource? _pending;
    private long _revision;
    private string? _subjectDn;
    [ObservableProperty] private string _result = SavedPathText.Get("NotRead");
    [ObservableProperty] private string _severity = "";
    [ObservableProperty] private string _detail = "";
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasRecordDetails))]
    private string _provenance = "";
    [ObservableProperty] private string _automaticChecks = SavedPathText.Get("NotRead");
    [ObservableProperty] private IReadOnlyList<string> _limitations = [];
    [ObservableProperty] private IReadOnlyList<SavedPathGroupViewModel> _groups = [];
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasRoutes))]
    private Tier0RoutePresentation? _routes;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedSteps))]
    [NotifyPropertyChangedFor(nameof(SelectedConditions))]
    private bool _showShortest;
    public bool HasRoutes => Routes is not null;
    public IReadOnlyList<SavedPathStepViewModel> SelectedSteps => Routes is null ? [] : ShowShortest ? Routes.ShortestSteps : Routes.BestSteps;
    public string SelectedConditions => Routes is null ? "" : ShowShortest ? Routes.ShortestConditions : Routes.Conditions;
    partial void OnRoutesChanged(Tier0RoutePresentation? value)
    {
        OnPropertyChanged(nameof(SelectedSteps));
        OnPropertyChanged(nameof(SelectedConditions));
    }

    public string Boundary { get; } = SavedPathText.Get("RiskBoundary");
    public string CoverageHeading { get; } = SavedPathText.Get("CoverageHeading");
    public string RecordDetailsHeading { get; } = SavedPathText.Get("RecordDetailsHeading");
    public bool HasRecordDetails => Provenance.Length > 0;
    public string Scope { get; } = SavedPathText.Get("RiskScope") + "\n" + SavedPathText.Get("CoverageScope");
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;

    public void ConfigureAsync(string subjectDn,
        Func<PathRiskVerdict, PathRiskPageMark?, CancellationToken, Task<Result<SavedTier0Path?>>> read)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectDn);
        ArgumentNullException.ThrowIfNull(read);
        CancelRead();
        _subjectDn = subjectDn;
        _read = read;
    }

    public void Read()
    {
        CancelRead();
        if (_read is not { } read) return;
        Result = SavedPathText.Get("Loading");
        var pending = new CancellationTokenSource();
        _pending = pending;
        ReadCompletion = LoadAsync(read, pending, _revision);
    }

    public void CancelRead()
    {
        _revision++;
        _pending?.Cancel();
        _pending = null;
        foreach (var group in Groups) group.Cancel();
        Groups = [];
        Result = AutomaticChecks = SavedPathText.Get("NotRead");
        Detail = Provenance = Severity = "";
        Limitations = [];
        Routes = null;
    }

    private async Task LoadAsync(
        Func<PathRiskVerdict, PathRiskPageMark?, CancellationToken, Task<Result<SavedTier0Path?>>> read,
        CancellationTokenSource pending, long revision)
    {
        try
        {
            var answer = await read(PathRiskVerdict.UnexpectedRoute, null, pending.Token);
            if (revision != _revision || pending.IsCancellationRequested) return;
            if (!answer.IsSuccess) { Refuse(answer.Error.Description); return; }
            if (answer.Value is not { } saved)
            {
                Result = SavedPathText.Get("Absent");
                Detail = SavedPathText.Get("AbsentDetail");
                return;
            }
            if (!saved.IsBound) { Refuse(SavedPathText.Get("GenerationChanged")); return; }
            if (!string.Equals(saved.Page.RequesterDn, _subjectDn, StringComparison.OrdinalIgnoreCase))
            { Refuse(SavedPathText.Get("SubjectChanged")); return; }
            if (saved.Description.State is not (JudgementRunState.Completed or JudgementRunState.CompletedDegraded))
            { Refuse(SavedPathText.Get("Unfinished")); return; }
            if (saved.Page.Group != PathRiskVerdict.UnexpectedRoute)
            { Refuse(SavedPathText.Get("InvalidEvidence")); return; }
            Apply(saved, read, revision);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error)
        {
            if (revision == _revision && !pending.IsCancellationRequested)
                Refuse(SavedPathText.Get("InvalidEvidence") + " " + error.Message);
        }
        finally
        {
            if (ReferenceEquals(_pending, pending)) _pending = null;
            pending.Dispose();
        }
    }

    private void Apply(SavedTier0Path saved,
        Func<PathRiskVerdict, PathRiskPageMark?, CancellationToken, Task<Result<SavedTier0Path?>>> read, long revision)
    {
        var description = saved.Description;
        var page = saved.Page;
        Routes = saved.Routes is { } routes ? new(routes) : null;
        Provenance = SavedPathText.Get("Generation", description.GenerationId, description.CompletedUtc,
            description.EvidenceSeal, description.DerivationGenerationId?.ToString() ?? SavedPathText.Get("NotUsed"));
        AutomaticChecks = SavedPathText.Get(page.Coverage.Availability == PathRiskAvailability.Recorded
            ? "EvaluatedSupportedQuestions" : page.Coverage.Availability.ToString());
        Result = saved.Finding is not null ? SavedPathText.Get("FindingHeading")
            : page.IsFixedTarget ? SavedPathText.Get("FixedTarget")
            : saved.Summary is null ? SavedPathText.Get("NotRequested")
            : page.Verdict switch
            {
                PathRiskReadVerdict.NotRequested => SavedPathText.Get("NotRequested"),
                PathRiskReadVerdict.InputsUnavailable => SavedPathText.Get("InputsUnavailable"),
                PathRiskReadVerdict.NoRecordedQuestions => SavedPathText.Get("NoQuestions"),
                _ => SavedPathText.Get("NoFinding"),
            };
        Detail = saved.Finding is not null ? SavedPathText.Get("FindingExplanation")
            : page.IsFixedTarget ? SavedPathText.Get("NoQuestions") : "";
        Severity = saved.Finding?.Severity.ToString() ?? "";
        var limitations = new List<string>();
        if (!page.Coverage.PathCoverage.InputsComplete) limitations.Add(SavedPathText.Get("CapturedIncomplete"));
        if (!page.Coverage.PathCoverage.AnalysisComplete) limitations.Add(SavedPathText.Get("Unsupported"));
        if (!page.Coverage.PathCoverage.ProcessingComplete) limitations.Add(SavedPathText.Get("UnfinishedProcessing"));
        if (page.Coverage.Availability == PathRiskAvailability.InputsUnavailable) limitations.Add(SavedPathText.Get("InputsUnavailable"));
        if (page.Counts.Unresolved > 0) limitations.Add(SavedPathText.Get("UnresolvedCount", page.Counts.Unresolved));
        if (description.State == JudgementRunState.CompletedDegraded) limitations.Add(SavedPathText.Get("Degraded"));
        Limitations = limitations;
        Groups = new[] { PathRiskVerdict.UnexpectedRoute, PathRiskVerdict.Unknown, PathRiskVerdict.ExpectedRoute, PathRiskVerdict.NotEstablished }
            .Where(kind => page.Counts.For(kind) > 0)
            .Select(kind => new SavedPathGroupViewModel(kind, saved, read,
                () => revision == _revision, Refuse)).ToArray();
    }

    private void Refuse(string reason)
    {
        CancelRead();
        Result = SavedPathText.Get("Unavailable");
        Detail = reason;
    }
}

internal sealed partial class SavedPathGroupViewModel : ObservableObject
{
    private readonly PathRiskVerdict _kind;
    private readonly SavedTier0Path _initial;
    private readonly Func<PathRiskVerdict, PathRiskPageMark?, CancellationToken, Task<Result<SavedTier0Path?>>> _read;
    private readonly Func<bool> _current;
    private readonly Action<string> _refuse;
    private readonly List<PathRiskPageMark?> _pages = [null];
    private CancellationTokenSource? _pending;
    private long _revision;
    private PathRiskPageMark? _next;
    [ObservableProperty] private bool _isExpanded;
    [ObservableProperty] private string _status = SavedPathText.Get("NotRead");
    [ObservableProperty] private IReadOnlyList<SavedPathQuestionViewModel> _questions = [];
    [ObservableProperty] private int _pageNumber = 1;
    [ObservableProperty] private bool _hasPrevious;
    [ObservableProperty] private bool _hasNext;

    public SavedPathGroupViewModel(PathRiskVerdict kind, SavedTier0Path initial,
        Func<PathRiskVerdict, PathRiskPageMark?, CancellationToken, Task<Result<SavedTier0Path?>>> read,
        Func<bool> current, Action<string> refuse)
    {
        _kind = kind;
        _initial = initial;
        _read = read;
        _current = current;
        _refuse = refuse;
        Heading = SavedPathText.Get("Group" + kind);
        HasQuestions = initial.Page.Counts.For(kind) > 0;
        _isExpanded = kind == PathRiskVerdict.UnexpectedRoute;
        if (_isExpanded) Apply(initial);
    }

    public string Heading { get; }
    public bool HasQuestions { get; }
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;

    partial void OnIsExpandedChanged(bool value)
    {
        Cancel();
        _pages.Clear();
        _pages.Add(null);
        PageNumber = 1;
        if (value && HasQuestions) ReadCompletion = LoadAsync(null);
    }

    public void Cancel()
    {
        _revision++;
        _pending?.Cancel();
        _pending = null;
        Questions = [];
        Status = SavedPathText.Get("NotRead");
        _next = null;
        HasPrevious = HasNext = false;
        PreviousCommand.NotifyCanExecuteChanged();
        NextCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand(CanExecute = nameof(HasNext))]
    private void Next()
    {
        if (_next is not { } next) return;
        _pages.Add(next);
        ReadCompletion = LoadAsync(next);
    }

    [RelayCommand(CanExecute = nameof(HasPrevious))]
    private void Previous()
    {
        if (_pages.Count <= 1) return;
        _pages.RemoveAt(_pages.Count - 1);
        ReadCompletion = LoadAsync(_pages[^1]);
    }

    private async Task LoadAsync(PathRiskPageMark? after)
    {
        Cancel();
        if (!_current()) return;
        Status = SavedPathText.Get("Loading");
        var revision = _revision;
        var pending = new CancellationTokenSource();
        _pending = pending;
        try
        {
            var result = await _read(_kind, after, pending.Token);
            if (revision != _revision || pending.IsCancellationRequested || !_current()) return;
            if (!result.IsSuccess) { _refuse(result.Error.Description); return; }
            if (result.Value is not { } saved || !saved.IsBound
                || saved.Description.GenerationId != _initial.Description.GenerationId
                || saved.Page.Coverage.CalculationFingerprint != _initial.Page.Coverage.CalculationFingerprint
                || saved.Page.RequesterDn != _initial.Page.RequesterDn || saved.Page.Group != _kind
                || saved.Page.Counts != _initial.Page.Counts)
            { _refuse(SavedPathText.Get("GenerationChanged")); return; }
            Apply(saved);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error)
        {
            if (revision == _revision && !pending.IsCancellationRequested && _current())
                _refuse(SavedPathText.Get("InvalidEvidence") + " " + error.Message);
        }
        finally
        {
            if (ReferenceEquals(_pending, pending)) _pending = null;
            pending.Dispose();
        }
    }

    private void Apply(SavedTier0Path saved)
    {
        Questions = saved.Page.Questions.Select(value => new SavedPathQuestionViewModel(value, saved)).ToArray();
        Status = "";
        PageNumber = _pages.Count;
        _next = saved.Page.Next;
        HasPrevious = _pages.Count > 1;
        HasNext = _next is not null;
        PreviousCommand.NotifyCanExecuteChanged();
        NextCommand.NotifyCanExecuteChanged();
    }
}
