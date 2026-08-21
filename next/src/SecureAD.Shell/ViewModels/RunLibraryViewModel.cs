using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence.Run;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
namespace SecureAD.Shell.ViewModels;

/// <summary>
/// The runs this library holds.
/// </summary>
/// <remarks>
/// <para>
/// <b>Three outcomes are kept apart, because collapsing them would mislead.</b> No library chosen
/// is a question the operator has not answered. A library that could not be read is a failure they
/// need to see. A library that was read and holds nothing is an empty library. Showing an empty
/// list for all three would say "you have no runs" in two cases where that is not known to be true.
/// </para>
/// <para>
/// <b>A listing says what became of a run, not what it saw.</b> What became of it is read from the
/// bundle directory without opening anything. How much of the forest it covered is inside the
/// bundle, and is read by opening it - which this product does, through
/// <c>BundleReader.ReadScope</c>. This remark previously said the product could not open a bundle
/// at all; that stopped being true when the Assets section landed, and it is corrected here rather
/// than left to mislead the next reader.
/// </para>
/// </remarks>
internal sealed partial class RunLibraryViewModel : ObservableObject
{
    private readonly IRunCatalog _catalog;
    private readonly RunLibraryLocation _location;
    private readonly IConfirmation _confirmation;

    [ObservableProperty]
    private string? _problem;

    [ObservableProperty]
    private bool _hasLooked;

    [ObservableProperty]
    private RunSummaryViewModel? _selected;

    /// <summary>Creates the run library screen's state.</summary>
    /// <param name="location">Where this installation keeps its runs.</param>
    /// <param name="catalog">How the runs are listed.</param>
    /// <param name="confirmation">How the operator is asked before something cannot be undone.</param>
    public RunLibraryViewModel(
        RunLibraryLocation location, IRunCatalog catalog, IConfirmation confirmation)
    {
        ArgumentNullException.ThrowIfNull(location);
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(confirmation);

        _location = location;
        _catalog = catalog;
        _confirmation = confirmation;

        // Grouped once, here, rather than rebuilt on every refresh: the view watches the collection
        // and a second view built later would leave the screen bound to the first one, showing runs
        // that had already been replaced.
        RunsView = CollectionViewSource.GetDefaultView(Runs);
        RunsView.GroupDescriptions.Add(
            new PropertyGroupDescription(nameof(RunSummaryViewModel.GroupKey)));
    }

    /// <summary>
    /// The runs, gathered into groups of like scope.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Runs are grouped by which domains they covered, per
    /// <c>docs/decisions/0069-a-baseline-is-marked-deliberately.md</c>, because those are the runs
    /// that may be compared with one another and each group carries its own baseline.
    /// </para>
    /// <para>
    /// <b>Grouped on the key and headed with the sentence.</b> The key is the run's own evidence
    /// identity, which already accounts for the forest - two forests whose domains happen to be
    /// named alike are different groups, and grouping on the heading would have merged them.
    /// </para>
    /// </remarks>
    public ICollectionView RunsView { get; }

    /// <summary>The runs found, in the order the library listed them.</summary>
    public ObservableCollection<RunSummaryViewModel> Runs { get; } = [];

    /// <summary>Whether a run is selected, and so whether there is anything to detail.</summary>
    public bool HasSelection => Selected is not null;

    /// <summary>
    /// Whether the library was read and genuinely holds nothing. False while unread or failed, so
    /// that "no runs" is only ever said when it was established.
    /// </summary>
    public bool IsEmpty => HasLooked && Problem is null && Runs.Count == 0;

    /// <summary>Reads the library again.</summary>
    [RelayCommand]
    public void Refresh()
    {
        Runs.Clear();
        HasLooked = false;

        // A selection is a pointer into the list that was just discarded. Keeping it would leave a
        // details card describing a run that this library may no longer hold.
        Selected = null;

        if (!_location.IsChosen)
        {
            Problem = "No run library has been chosen yet.";
            OnPropertyChanged(nameof(IsEmpty));
            return;
        }

        var listed = _catalog.List(_location.Path!);

        if (!listed.IsSuccess)
        {
            Problem = listed.Error.Description;
            OnPropertyChanged(nameof(IsEmpty));
            return;
        }

        Problem = null;

        foreach (var run in listed.Value)
            Runs.Add(new RunSummaryViewModel(run));

        HasLooked = true;
        OnPropertyChanged(nameof(IsEmpty));
    }

    partial void OnSelectedChanged(RunSummaryViewModel? value)
    {
        // The boxes follow the selection rather than being cleared, so an operator who selects a
        // run he has already named sees what he wrote and can correct it rather than retype it.
        TypedName = value?.IsNamed == true ? value.Name : null;
        TypedNotes = value?.Notes;

        OnPropertyChanged(nameof(HasSelection));
    }

    /// <summary>The name the operator is typing for the selected run.</summary>
    [ObservableProperty]
    private string? _typedName;

    /// <summary>The notes the operator is typing for the selected run.</summary>
    [ObservableProperty]
    private string? _typedNotes;

    /// <summary>
    /// Saves what the operator typed against the selected run.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The library is read again afterwards, because a name is what a run is listed under and the
    /// list would otherwise go on showing the old one. The selection is restored by path, since the
    /// refresh discards the object it pointed at.
    /// </para>
    /// <para>
    /// This writes beside the evidence and never into it - see
    /// <see cref="Evidence.Run.RunAnnotations"/>. A failure to save is reported as a problem and
    /// leaves the run untouched.
    /// </para>
    /// </remarks>
    [RelayCommand]
    public void SaveAnnotation()
    {
        if (Selected is not { } selected)
            return;

        var path = selected.Path;
        var saved = _catalog.Annotate(path, new RunAnnotation(TypedName, TypedNotes));

        if (!saved.IsSuccess)
        {
            Problem = saved.Error.Description;
            return;
        }

        Refresh();

        Selected = Runs.FirstOrDefault(
            run => string.Equals(run.Path, path, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Deletes the selected run, after asking once.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One confirmation, naming the run, per
    /// <c>docs/decisions/0078-a-run-can-be-deleted-after-one-confirmation.md</c>. The operator is
    /// choosing between runs that differ by a timestamp, so the prompt states which one he picked
    /// rather than asking whether he is sure.
    /// </para>
    /// <para>
    /// <b>A failure leaves the run listed.</b> Refreshing regardless would drop the row for a run
    /// still on disk, telling the operator he had recovered space he has not.
    /// </para>
    /// </remarks>
    [RelayCommand]
    public void DeleteRun()
    {
        if (Selected is not { } selected)
            return;

        var confirmed = _confirmation.Confirm(
            "Delete this run",
            $"{selected.Name} and all of its evidence will be deleted from "
            + $"{selected.Path}. This cannot be undone.",
            "delete it");

        if (!confirmed)
            return;

        var deleted = _catalog.Delete(selected.Path);

        if (!deleted.IsSuccess)
        {
            Problem = deleted.Error.Description;
            return;
        }

        Refresh();
    }
}
