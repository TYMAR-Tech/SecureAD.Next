using SecureAD.Evidence.Run;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// One run in the library, as a screen shows it.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists to keep a state name off the screen.</b> Binding a view straight to
/// <see cref="RunListing"/> put <see cref="RunState"/> in front of the operator verbatim, so a run
/// that was stopped read "Cancelled" and one still going read "InProgress". Those are the names the
/// code calls them, chosen to be unambiguous to a compiler, and an operator has to work out what
/// they mean.
/// </para>
/// <para>
/// <b>Nothing here is coverage.</b> <see cref="RunListing"/> is explicit that how much of a forest a
/// run saw lives inside the bundle, and this wrapper adds no column that would need opening one.
/// Every value below is a restatement of something already observed.
/// </para>
/// </remarks>
internal sealed class RunSummaryViewModel
{
    private readonly RunListing _listing;

    /// <summary>Creates a screen's view of one listed run.</summary>
    /// <param name="listing">The run as the library listed it.</param>
    public RunSummaryViewModel(RunListing listing)
    {
        ArgumentNullException.ThrowIfNull(listing);

        _listing = listing;
    }

    /// <summary>The run's directory name inside the library.</summary>
    public string Identifier => _listing.Identifier;

    /// <summary>The full path of the run's bundle directory.</summary>
    public string Path => _listing.Path;

    /// <summary>What became of the run, in words rather than in a member name.</summary>
    public string State => _listing.State switch
    {
        RunState.InProgress => "Still running",
        RunState.Sealed => "Finished",
        RunState.Failed => "Failed",
        RunState.Cancelled => "Stopped",
        RunState.Interrupted => "Interrupted",
        RunState.Damaged => "Damaged",
        _ => "Unknown",
    };

    /// <summary>
    /// What the state means for the operator, said once here rather than left to be inferred.
    /// </summary>
    /// <remarks>
    /// A state name says what happened. This says what to do about it, which is the part an
    /// operator looking at a list of runs actually needs. <see cref="RunState.Interrupted"/> and
    /// <see cref="RunState.Damaged"/> read alike and their remedies differ, which is the whole
    /// reason the two are separate members.
    /// </remarks>
    public string Meaning => _listing.State switch
    {
        RunState.InProgress => "Something is still writing to this run.",
        RunState.Sealed => "This run finished and its evidence is sealed.",
        RunState.Failed => "This run ended in an error and recorded what it was.",
        RunState.Cancelled => "Somebody stopped this run.",
        RunState.Interrupted =>
            "This run stopped without recording why. Something outside the product ended it, so "
            + "the reason is on the machine rather than in the bundle.",
        RunState.Damaged =>
            "This run's evidence will not open, or its seal does not match. It cannot be trusted. "
            + "Restore it or discard it - running again will not repair it.",
        _ => "This run's state was not recognised.",
    };

    /// <summary>Why, where the state does not speak for itself. Null for a run that finished.</summary>
    public string? Detail => _listing.Detail;

    /// <summary>Whether there is a detail worth a line of its own.</summary>
    public bool HasDetail => !string.IsNullOrWhiteSpace(_listing.Detail);

    /// <summary>
    /// Whether this run may serve as a comparison baseline.
    /// </summary>
    /// <remarks>
    /// Only a sealed run may, per <see cref="RunState.Sealed"/> - and even then only if every
    /// domain was read, which is inside the bundle and not known here. So this is stated as the
    /// lifecycle half alone and the screen must not present it as the whole answer.
    /// </remarks>
    public bool FinishedCleanly => _listing.State == RunState.Sealed;
}
