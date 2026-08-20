using System.Collections.ObjectModel;
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
/// <b>Nothing here reports coverage or findings.</b> A listing says what became of a run, which is
/// read from the bundle directory. What a run saw is inside the bundle, and this product cannot yet
/// open one.
/// </para>
/// </remarks>
internal sealed partial class RunLibraryViewModel : ObservableObject
{
    private readonly IRunCatalog _catalog;
    private readonly RunLibraryLocation _location;

    [ObservableProperty]
    private string? _problem;

    [ObservableProperty]
    private bool _hasLooked;

    [ObservableProperty]
    private RunSummaryViewModel? _selected;

    /// <summary>Creates the run library screen's state.</summary>
    /// <param name="location">Where this installation keeps its runs.</param>
    /// <param name="catalog">How the runs are listed.</param>
    public RunLibraryViewModel(RunLibraryLocation location, IRunCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(location);
        ArgumentNullException.ThrowIfNull(catalog);

        _location = location;
        _catalog = catalog;
    }

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

    partial void OnSelectedChanged(RunSummaryViewModel? value) =>
        OnPropertyChanged(nameof(HasSelection));
}
