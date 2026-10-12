using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class AssetsViewModel
{
    [ObservableProperty] private string _objectSearchText = "";
    [ObservableProperty] private bool _showsCaptureCoverageDetails;
    private string? _objectSearchQuery;
    private ObjectSearchMark? _objectSearchAfter;
    private ObjectSearchMark? _objectSearchNext;
    private readonly Stack<ObjectSearchMark?> _objectSearchBack = new();

    public bool IsObjectSearch => Pane == AssetsPane.Objects && _objectSearchQuery is not null;
    public bool HasEmptyObjectSearch => IsObjectSearch && HasListingResult && Objects.Count == 0;
    public bool CanChangeBrowsingScope => !IsObjectSearch && !(ShowsGroups && GroupsWholeCapture);
    public string ObjectSearchHeading => IsObjectSearch ? ObjectNavigationText.Format("SearchHeading", _objectSearchQuery!) : "";
    public string ObjectSearchEmpty => ObjectNavigationText.Get("SearchEmpty");
    public string NavigationLocation => IsObjectSearch ? ObjectNavigationText.Get("WholeCapture") : Selected?.DistinguishedName ?? "";
    public IReadOnlyList<TreeGapViewModel> CaptureGaps => Gaps.Where(gap => !gap.IsProductExclusion).ToArray();
    public IReadOnlyList<TreeGapViewModel> ScopeNotes => Gaps.Where(gap => gap.IsProductExclusion).ToArray();
    public bool HasCaptureGaps => Gaps.Any(gap => !gap.IsProductExclusion);
    public bool HasScopeNotes => Gaps.Any(gap => gap.IsProductExclusion);
    public bool HasNoTreeGaps => Gaps.Count == 0;
    public string CaptureCoverageAction => ObjectNavigationText.Get(ShowsCaptureCoverageDetails ? "HideDetails" : "ViewDetails");

    private bool CanSearchObjects() => _active && HasTree && ShowsDirectoryTree && !IsLoading &&
        !string.IsNullOrWhiteSpace(ObjectSearchText);
    private bool CanClearObjectSearch() => _objectSearchQuery is not null || !string.IsNullOrEmpty(ObjectSearchText);

    [RelayCommand(CanExecute = nameof(CanSearchObjects))]
    private void SearchObjects()
    {
        CancelRead();
        _objectSearchQuery = ObjectSearchText.Trim();
        _objectSearchAfter = _objectSearchNext = null;
        _objectSearchBack.Clear();
        if (Pane != AssetsPane.Objects) Pane = AssetsPane.Objects;
        else LoadVisible();
        Announce();
    }

    [RelayCommand(CanExecute = nameof(CanClearObjectSearch))]
    private void ClearObjectSearch()
    {
        var wasSearch = _objectSearchQuery is not null;
        if (wasSearch) CancelRead();
        ResetObjectSearch();
        if (wasSearch)
        {
            LoadVisible();
        }
        Announce();
    }

    [RelayCommand]
    private void ToggleCaptureCoverage() => ShowsCaptureCoverageDetails = !ShowsCaptureCoverageDetails;

    partial void OnShowsCaptureCoverageDetailsChanged(bool value) => OnPropertyChanged(nameof(CaptureCoverageAction));
    partial void OnObjectSearchTextChanged(string value)
    {
        SearchObjectsCommand.NotifyCanExecuteChanged();
        ClearObjectSearchCommand.NotifyCanExecuteChanged();
    }

    private void ResetObjectSearch()
    {
        _objectSearchQuery = null;
        _objectSearchAfter = _objectSearchNext = null;
        _objectSearchBack.Clear();
        ObjectSearchText = "";
    }

    private async Task ReadObjectSearchPageAsync(ObjectSearchMark? after, int direction)
    {
        var bundle = BundlePath!;
        var search = _objectSearchQuery!;
        ClearListing(AssetsPane.Objects);
        await ReadViewAsync(bundle, reader => reader.SearchObjects(bundle, search, after), (page, current) =>
        {
            if (direction > 0) _objectSearchBack.Push(_objectSearchAfter);
            else if (direction < 0) _objectSearchBack.Pop();
            _objectSearchAfter = after;
            _objectSearchNext = page.Next;
            foreach (var item in page.Objects) Objects.Add(new(item));
            Shortfall = page.Coverage.IsComplete ? null : page.Coverage.Shortfall;
            RememberPage(Question(), current);
        }, saved: false);
    }

    private void AnnounceObjectNavigation()
    {
        OnPropertyChanged(nameof(IsObjectSearch));
        OnPropertyChanged(nameof(HasEmptyObjectSearch));
        OnPropertyChanged(nameof(CanChangeBrowsingScope));
        OnPropertyChanged(nameof(ObjectSearchHeading));
        OnPropertyChanged(nameof(NavigationLocation));
        OnPropertyChanged(nameof(CaptureGaps));
        OnPropertyChanged(nameof(ScopeNotes));
        OnPropertyChanged(nameof(HasCaptureGaps));
        OnPropertyChanged(nameof(HasScopeNotes));
        OnPropertyChanged(nameof(HasNoTreeGaps));
        OnPropertyChanged(nameof(ParentIsWorthShowing));
        SearchObjectsCommand.NotifyCanExecuteChanged();
        ClearObjectSearchCommand.NotifyCanExecuteChanged();
    }
}
