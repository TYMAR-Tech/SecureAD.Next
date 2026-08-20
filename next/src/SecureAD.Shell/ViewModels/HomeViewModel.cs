using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// The first screen: where the run library is.
/// </summary>
/// <remarks>
/// <para>
/// <b>An unconfigured installation is asked, not guessed at.</b> There is no default run library
/// path - <c>docs/decisions/0025-the-run-library-is-a-managed-root.md</c> refuses one, because a
/// tool that decides for itself where several gigabytes of evidence go fills the wrong disk. Until
/// the operator answers, this screen says it does not know rather than showing an empty library.
/// </para>
/// <para>
/// <b>A run is no longer started from here.</b> This screen once carried a controller to type and a
/// Run button, which asked for the one thing the product can work out for itself - the forest this
/// machine is in, per <c>docs/decisions/0053-the-tool-finds-its-own-forest.md</c> - and offered
/// nowhere to see what a run would do before it did it. Starting a run is the New Audit window's.
/// </para>
/// </remarks>
internal sealed partial class HomeViewModel : ObservableObject
{
    private readonly IFolderPicker _picker;
    private readonly INewAuditDialog _newAudit;

    /// <summary>Creates the home screen's state.</summary>
    /// <param name="location">Where this installation keeps its runs.</param>
    /// <param name="picker">How the operator is asked for a folder.</param>
    /// <param name="newAudit">How the New Audit window is opened.</param>
    /// <param name="library">The runs this library holds.</param>
    /// <remarks>
    /// <b>Home shows the same library object the Runs section does, not a copy of it.</b> Two
    /// readings of one folder taken at different moments would let Home and Runs disagree about
    /// what a customer has, and an operator would have no way to tell which was current.
    /// </remarks>
    public HomeViewModel(
        RunLibraryLocation location,
        IFolderPicker picker,
        INewAuditDialog newAudit,
        RunLibraryViewModel library)
    {
        ArgumentNullException.ThrowIfNull(location);
        ArgumentNullException.ThrowIfNull(picker);
        ArgumentNullException.ThrowIfNull(newAudit);
        ArgumentNullException.ThrowIfNull(library);

        Location = location;
        _picker = picker;
        _newAudit = newAudit;
        Library = library;
    }

    /// <summary>The runs this library holds, shown here as well as in the Runs section.</summary>
    public RunLibraryViewModel Library { get; }

    /// <summary>
    /// Whether a run can be started at all.
    /// </summary>
    /// <remarks>
    /// A library has to be chosen first. Offering the wizard without one would open a window whose
    /// every action refuses, which teaches an operator that the product's refusals are noise.
    /// </remarks>
    public bool CanStartAnAudit => Location.IsChosen;

    /// <summary>Opens the New Audit window.</summary>
    /// <remarks>
    /// Starting an audit is a modal act, per
    /// <c>docs/decisions/0057-starting-an-audit-is-a-modal-act.md</c>. Home is where it starts and
    /// where the operator lands afterwards.
    /// </remarks>
    [RelayCommand(CanExecute = nameof(CanStartAnAudit))]
    public void NewAudit()
    {
        _newAudit.Show();

        // Show is modal, so this runs once the window has closed - by which time the library may
        // hold a run it did not hold a moment ago. Home would otherwise show a list that omits the
        // run the operator has just watched finish.
        Library.Refresh();
    }

    /// <summary>Where this installation keeps its runs.</summary>
    public RunLibraryLocation Location { get; }

    /// <summary>
    /// What to tell the operator about their library, in a sentence rather than a state name.
    /// </summary>
    public string LibraryDescription => Location.IsChosen
        ? Location.Path!
        : "No run library has been chosen yet. Runs are kept in a folder you choose, "
          + "because this product will not decide for itself where several gigabytes of "
          + "evidence go.";

    /// <summary>Asks the operator for a run library folder and adopts it.</summary>
    [RelayCommand]
    public void ChooseLibrary()
    {
        var chosen = _picker.Pick("Choose the folder your audit runs are kept in", Location.Path);

        if (chosen is null)
            return;

        Location.Choose(chosen);
        OnPropertyChanged(nameof(LibraryDescription));

        // Choosing a library is what makes an audit possible, so the button that starts one has to
        // hear about it.
        OnPropertyChanged(nameof(CanStartAnAudit));
        NewAuditCommand.NotifyCanExecuteChanged();

        // The list on this screen was read from the old library, or from no library at all.
        Library.Refresh();
    }
}
