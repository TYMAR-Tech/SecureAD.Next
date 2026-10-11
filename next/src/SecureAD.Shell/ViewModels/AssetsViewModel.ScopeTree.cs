using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class AssetsViewModel
{
    [ObservableProperty] private bool _groupsScopeTreeVisible;
    [ObservableProperty] private bool _lapsScopeTreeVisible;

    public bool CanToggleScopeTree => ShowsGroups || ShowsLaps;
    public bool ShowsScopeTree => ShowsDirectoryTree && (ShowsObjects
        || !CanToggleScopeTree
        || ShowsGroups && GroupsScopeTreeVisible
        || ShowsLaps && LapsScopeTreeVisible);
    public GridLength ScopeTreeWidth => ShowsScopeTree ? new(360) : new(0);
    public double ScopeTreeMinWidth => ShowsScopeTree ? 270 : 0;
    public GridLength ScopeTreeSplitterWidth => ShowsScopeTree ? new(12) : new(0);
    public string ScopeTreeAction => ShowsScopeTree ? "Hide scope tree" : "Show scope tree";
    public string LapsLocation => Selected is null ? "Choose a directory location" : Selected.DistinguishedName;

    [RelayCommand(CanExecute = nameof(CanToggleScopeTree))]
    private void ToggleScopeTree()
    {
        if (ShowsGroups) GroupsScopeTreeVisible = !GroupsScopeTreeVisible;
        else if (ShowsLaps) LapsScopeTreeVisible = !LapsScopeTreeVisible;
    }

    partial void OnGroupsScopeTreeVisibleChanged(bool value) => AnnounceScopeTree();
    partial void OnLapsScopeTreeVisibleChanged(bool value) => AnnounceScopeTree();

    private void AnnounceScopeTree()
    {
        OnPropertyChanged(nameof(CanToggleScopeTree));
        OnPropertyChanged(nameof(ShowsScopeTree));
        OnPropertyChanged(nameof(ScopeTreeWidth));
        OnPropertyChanged(nameof(ScopeTreeMinWidth));
        OnPropertyChanged(nameof(ScopeTreeSplitterWidth));
        OnPropertyChanged(nameof(ScopeTreeAction));
        OnPropertyChanged(nameof(LapsLocation));
        ToggleScopeTreeCommand.NotifyCanExecuteChanged();
    }
}
