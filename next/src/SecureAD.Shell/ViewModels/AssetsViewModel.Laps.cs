using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Judgement;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class AssetsViewModel
{
    [ObservableProperty] private LapsComputerViewModel? _selectedLapsComputer;
    [ObservableProperty] private string _lapsSearchText = "";
    [ObservableProperty] private string _lapsStateFilter = "All states";
    private readonly Stack<LapsPageMark> _lapsBack = [];
    private LapsPageMark? _lapsNext;

    public bool HasSelectedLapsComputer => SelectedLapsComputer is not null;
    public IReadOnlyList<string> LapsStateChoices { get; } =
        ["All states", "Not managed", "Windows LAPS", "Legacy LAPS", "Migrated", "Unexpected"];
    public IReadOnlyList<LapsComputerViewModel> VisibleLapsComputers => LapsComputers;
    public int LapsPageNumber => _lapsBack.Count + 1;
    public bool HasMoreLaps => HasListingResult && _lapsNext is not null;
    public bool HasEarlierLaps => HasListingResult && _lapsBack.Count > 0;

    private LapsQuery LapsQuestion(string container) => new(container, Scope, LapsSearchText.Trim(), LapsStateFilter switch
    {
        "All states" => null,
        "Not managed" => LapsManagement.NotManaged,
        "Windows LAPS" => LapsManagement.WindowsLaps,
        "Legacy LAPS" => LapsManagement.LegacyLaps,
        "Migrated" => LapsManagement.Migrated,
        "Unexpected" => LapsManagement.Unexpected,
        _ => throw new InvalidOperationException("The selected LAPS state is not recognized."),
    });

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
            ObjectSectionCatalog.Overview);

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
        _lapsStateFilter = "All states";
        OnPropertyChanged(nameof(LapsSearchText));
        OnPropertyChanged(nameof(LapsStateFilter));
        ResetLapsPaging();
    }
}
