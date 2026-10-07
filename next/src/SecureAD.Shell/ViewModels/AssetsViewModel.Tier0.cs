using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Judgement;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class AssetsViewModel
{
    public ObservableCollection<Tier0RowViewModel> Tier0Objects { get; } = [];
    [ObservableProperty] private Tier0RowViewModel? _selectedTier0Object;
    [ObservableProperty] private string _tier0OverviewStatus = "";
    [ObservableProperty] private string _tier0OverviewCoverage = "";
    [ObservableProperty] private string _tier0ObjectLimitation = "";
    private Tier0OverviewMark? _tier0After;
    private Tier0OverviewMark? _tier0Next;
    private readonly Stack<Tier0OverviewMark?> _tier0Back = [];
    public bool ShowsTier0 => Pane == AssetsPane.Tier0;
    public bool ShowsTier0Listing => ShowsTier0 && ShowsListing;
    public string Tier0PageDescription => $"Page {_tier0Back.Count + 1} - {Tier0Objects.Count:N0} recorded analysis identities shown";

    private Task LoadTier0Async(ListingQuestion question)
    {
        var selected = SelectedTier0Object?.DistinguishedName;
        return ReadViewAsync(question.Bundle, reader => reader.ReadTier0Overview(question.Bundle, _tier0After),
            (page, current) =>
            {
                if (page is null)
                {
                    Tier0OverviewStatus = "Saved Tier 0 analysis is not available. Judge this sealed capture to produce it.";
                    _tier0Next = null;
                }
                else
                {
                    var summary = page.Summary;
                    Tier0OverviewStatus = $"{summary.ObjectsWithSupportedRoute:N0} with supported distance (including distance zero)   |   "
                        + $"{summary.UnresolvedObjects:N0} unresolved   |   {summary.UnassessedObjects:N0} not assessed\n"
                        + $"{summary.RecordedSubjects:N0} recorded analysis identities; not captured inventory or displayed-page totals.\n"
                        + $"{summary.ClassifiedTier0Objects:N0} classified Tier 0; {summary.OtherObjectsWithSupportedRoute:N0} other objects with supported routes.";
                    Tier0OverviewCoverage = Tier0Presentation.Coverage(summary.Coverage)
                        + $"\n{summary.ObjectsWithRequesterChecks:N0} distinct objects with saved requester checks; not questions or routes.\n"
                        + "Unresolved and unassessed results are not statements of safety. Declared but uncaptured identities remain included.\n"
                        + $"Saved analysis: {summary.Availability}; requester input scan completed: {summary.RequesterInputScanCompleted}.\n"
                        + $"Judgement {summary.GenerationId}; Evidence {summary.EvidenceSeal}; Derivation {summary.DerivationGenerationId?.ToString() ?? "not used"}.";
                    foreach (var row in page.Objects) Tier0Objects.Add(new(row));
                    _tier0Next = page.Next;
                }
                SelectedTier0Object = Tier0Objects.FirstOrDefault(row => row.DistinguishedName == selected) ?? Tier0Objects.FirstOrDefault();
                RememberPage(question, current);
            }, saved: true);
    }

    private bool CanUseTier0() => _active && ShowsTier0Listing && HasTree && !IsLoading;
    private void ResetTier0Paging() { _tier0After = _tier0Next = null; _tier0Back.Clear(); SelectedTier0Object = null; }
    private bool CanOpenTier0() => CanUseTier0() && HasListingResult && SelectedTier0Object is { } row && Tier0Objects.Contains(row);
    private bool CanNextTier0() => CanUseTier0() && HasListingResult && _tier0Next is not null;
    private bool CanPreviousTier0() => CanUseTier0() && _tier0Back.Count != 0;

    [RelayCommand(CanExecute = nameof(CanOpenTier0))]
    private void OpenTier0Path() => Open(SelectedTier0Object!.DistinguishedName, ObjectSectionCatalog.SavedTier0Path);
    [RelayCommand(CanExecute = nameof(CanOpenTier0))]
    private void OpenTier0Findings() => Open(SelectedTier0Object!.DistinguishedName, ObjectSectionCatalog.Findings);
    [RelayCommand(CanExecute = nameof(CanNextTier0))]
    private void NextTier0Page() { _tier0Back.Push(_tier0After); _tier0After = _tier0Next; LoadVisible(); }
    [RelayCommand(CanExecute = nameof(CanPreviousTier0))]
    private void PreviousTier0Page() { _tier0After = _tier0Back.Pop(); LoadVisible(); }
    [RelayCommand] private void ShowTier0Overview() => Pane = AssetsPane.Tier0;
    [RelayCommand] private void ShowFindingsOverview() => Pane = AssetsPane.Findings;
    [RelayCommand] private void ShowObjectPath() => Opened?.Show(ObjectSectionCatalog.SavedTier0Path);
    [RelayCommand] private void ShowObjectFindings() => Opened?.Show(ObjectSectionCatalog.Findings);

    partial void OnSelectedTier0ObjectChanged(Tier0RowViewModel? value)
    {
        Tier0ObjectLimitation = "";
        AnnounceTier0();
    }
    private void AnnounceTier0()
    {
        OnPropertyChanged(nameof(ShowsTier0));
        OnPropertyChanged(nameof(ShowsTier0Listing));
        OnPropertyChanged(nameof(Tier0PageDescription));
        OpenTier0PathCommand.NotifyCanExecuteChanged();
        OpenTier0FindingsCommand.NotifyCanExecuteChanged();
        NextTier0PageCommand.NotifyCanExecuteChanged();
        PreviousTier0PageCommand.NotifyCanExecuteChanged();
    }
}
