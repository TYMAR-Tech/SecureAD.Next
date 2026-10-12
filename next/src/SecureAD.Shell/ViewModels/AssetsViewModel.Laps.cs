using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class AssetsViewModel
{
    [ObservableProperty] private LapsComputerViewModel? _selectedLapsComputer;
    [ObservableProperty] private string _lapsSearchText = "";
    [ObservableProperty] private string _lapsStateFilter = "All states";

    public bool HasSelectedLapsComputer => SelectedLapsComputer is not null;
    public IReadOnlyList<string> LapsStateChoices { get; } =
        ["All states", "Not managed", "Windows LAPS", "Legacy LAPS", "Migrated", "Unexpected"];
    public IReadOnlyList<LapsComputerViewModel> VisibleLapsComputers
    {
        get
        {
            var search = LapsSearchText.Trim();
            return LapsComputers.Where(row =>
                (search.Length == 0 || row.Name.Contains(search, StringComparison.OrdinalIgnoreCase)
                    || row.Domain.Contains(search, StringComparison.OrdinalIgnoreCase))
                && (LapsStateFilter == "All states" || row.Management == LapsStateFilter)).ToArray();
        }
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

    partial void OnLapsSearchTextChanged(string value) => ApplyLapsFilters();
    partial void OnLapsStateFilterChanged(string value) => ApplyLapsFilters();

    private void ApplyLapsFilters()
    {
        OnPropertyChanged(nameof(VisibleLapsComputers));
        if (SelectedLapsComputer is null || !VisibleLapsComputers.Contains(SelectedLapsComputer))
            SelectedLapsComputer = VisibleLapsComputers.FirstOrDefault();
    }

    private void ResetLapsFilters()
    {
        _lapsSearchText = "";
        _lapsStateFilter = "All states";
        OnPropertyChanged(nameof(LapsSearchText));
        OnPropertyChanged(nameof(LapsStateFilter));
        ApplyLapsFilters();
    }
}
