using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Judgement;
using SecureAD.Shell.Services.Export;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class AssetsViewModel
{
    [ObservableProperty] private LapsComputerViewModel? _selectedLapsComputer;
    [ObservableProperty] private string _lapsSearchText = "";
    [ObservableProperty] private string _lapsStateFilter = LapsInventoryText.Get("AllValues");
    private readonly Stack<LapsPageMark> _lapsBack = [];
    private LapsPageMark? _lapsNext;

    public bool HasSelectedLapsComputer => SelectedLapsComputer is not null;
    public event Action<string, LapsQuery>? LapsExportRequested;
    public string LapsExportLabel => ExportText.Get("Action");
    public bool CanExportLaps => _active && ShowsLaps && HasListingResult && !HasLapsRefusal
        && BundlePath is not null && Selected is not null;
    public string LapsTitle => LapsInventoryText.Get("Title");
    public string LapsCaption => LapsInventoryText.Get("Caption");
    public IReadOnlyList<string> LapsStateChoices { get; } =
        [LapsInventoryText.Get("AllValues"), .. Enum.GetValues<LapsValuePresence>().Select(LapsInventoryText.Label)];
    public IReadOnlyList<LapsComputerViewModel> VisibleLapsComputers => LapsComputers;
    public int LapsPageNumber => _lapsBack.Count + 1;
    public bool HasMoreLaps => HasListingResult && _lapsNext is not null;
    public bool HasEarlierLaps => HasListingResult && _lapsBack.Count > 0;

    private LapsQuery LapsQuestion(string container)
    {
        LapsValuePresence? selected = null;
        if (LapsStateFilter != LapsInventoryText.Get("AllValues"))
        {
            var matches = Enum.GetValues<LapsValuePresence>()
                .Where(values => LapsInventoryText.Label(values) == LapsStateFilter).ToArray();
            if (matches.Length != 1) throw new InvalidOperationException("The selected captured-value group is not recognized.");
            selected = matches[0];
        }
        return new(container, Scope, LapsSearchText.Trim(), selected);
    }

    [RelayCommand(CanExecute = nameof(CanExportLaps))]
    private void ExportLaps()
    {
        if (LapsExportRequested is null)
            throw new InvalidOperationException("The application export presenter is not connected.");
        LapsExportRequested(BundlePath ?? throw new InvalidOperationException("No run is selected."),
            LapsQuestion(Selected?.DistinguishedName ?? throw new InvalidOperationException("No directory scope is selected.")));
    }

    [RelayCommand(CanExecute = nameof(HasMoreLaps))]
    private void NextLaps()
    {
        if (_lapsNext is not { } next) return;
        _lapsBack.Push(next);
        LoadVisible();
    }

    [RelayCommand(CanExecute = nameof(HasEarlierLaps))]
    private void PreviousLaps()
    {
        if (_lapsBack.Count == 0) return;
        _lapsBack.Pop();
        LoadVisible();
    }

    private bool CanOpenLapsComputer(LapsComputerViewModel? row) =>
        _active && ShowsLaps && !IsLoading && (row ?? SelectedLapsComputer) is not null;

    [RelayCommand(CanExecute = nameof(CanOpenLapsComputer))]
    private void OpenLapsComputer(LapsComputerViewModel? row) =>
        Open((row ?? SelectedLapsComputer ?? throw new InvalidOperationException("No LAPS computer is selected.")).DistinguishedName,
            ObjectSectionCatalog.Overview, expectedObjectGuid: null);

    partial void OnSelectedLapsComputerChanged(LapsComputerViewModel? value)
    {
        OnPropertyChanged(nameof(HasSelectedLapsComputer));
        OpenLapsComputerCommand.NotifyCanExecuteChanged();
    }

    partial void OnLapsSearchTextChanged(string value) => RefilterLaps();
    partial void OnLapsStateFilterChanged(string value) => RefilterLaps();

    private void RefilterLaps()
    {
        if (_resetting) return;
        ResetLapsPaging();
        if (ShowsLaps) LoadVisible();
    }

    private void ResetLapsPaging()
    {
        _lapsBack.Clear();
        _lapsNext = null;
        AnnounceLaps();
    }

    private void AnnounceLaps()
    {
        OnPropertyChanged(nameof(CanExportLaps));
        ExportLapsCommand.NotifyCanExecuteChanged();
        OnPropertyChanged(nameof(VisibleLapsComputers));
        OnPropertyChanged(nameof(LapsPageNumber));
        OnPropertyChanged(nameof(HasMoreLaps));
        OnPropertyChanged(nameof(HasEarlierLaps));
        NextLapsCommand.NotifyCanExecuteChanged();
        PreviousLapsCommand.NotifyCanExecuteChanged();
    }

    private void ResetLapsFilters()
    {
        _lapsSearchText = "";
        _lapsStateFilter = LapsInventoryText.Get("AllValues");
        OnPropertyChanged(nameof(LapsSearchText));
        OnPropertyChanged(nameof(LapsStateFilter));
        ResetLapsPaging();
    }
}
