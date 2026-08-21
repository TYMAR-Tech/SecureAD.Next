using System.Globalization;
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

    /// <summary>
    /// What to call this run: the operator's own name for it, or its identifier where he has given
    /// none.
    /// </summary>
    /// <remarks>
    /// The identifier is the fallback rather than a generated sentence, because it is the name of
    /// the folder on disk and is what an operator matches a screen against when he goes looking for
    /// the bundle.
    /// </remarks>
    public string Name =>
        string.IsNullOrWhiteSpace(_listing.Annotation.Name)
            ? _listing.Identifier
            : _listing.Annotation.Name;

    /// <summary>Whether the operator has given this run a name of his own.</summary>
    /// <remarks>
    /// Stated so a screen showing <see cref="Name"/> can also show the identifier without printing
    /// it twice for a run nobody has named.
    /// </remarks>
    public bool IsNamed => !string.IsNullOrWhiteSpace(_listing.Annotation.Name);

    /// <summary>What the operator wrote about this run, or null where he wrote nothing.</summary>
    public string? Notes => _listing.Annotation.Notes;

    /// <summary>Whether there are notes worth showing.</summary>
    public bool HasNotes => !string.IsNullOrWhiteSpace(_listing.Annotation.Notes);

    /// <summary>
    /// When the run happened, in the operator's own time zone.
    /// </summary>
    /// <remarks>
    /// Local rather than UTC because an administrator matching a run against a change window, a
    /// ticket or his own memory is working in the time his clock shows.
    /// </remarks>
    public string When => _listing.Moment.Utc.ToLocalTime().ToString("f", CultureInfo.CurrentCulture);

    /// <summary>
    /// Whether <see cref="When"/> is the moment the run recorded for itself.
    /// </summary>
    /// <remarks>
    /// False means the run never recorded one and this is when its folder was created - true on the
    /// machine that made it, and reset by copying the bundle elsewhere. A screen must say so rather
    /// than present it as the run's own statement.
    /// </remarks>
    public bool WhenWasRecorded => _listing.Moment.Recorded;

    /// <summary>
    /// The opposite of <see cref="WhenWasRecorded"/>, stated because the only visibility converter
    /// in the theme turns true into shown, and the caveat is what needs showing.
    /// </summary>
    public bool WhenWasNotRecorded => !_listing.Moment.Recorded;

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

    /// <summary>
    /// Which group of like runs this one belongs to.
    /// </summary>
    /// <remarks>
    /// Runs sharing this covered the same domains and may be compared with one another. A run whose
    /// scope could not be established gets a key of its own rather than being folded in with the
    /// whole-forest runs, because <i>we do not know</i> and <i>everything</i> must not look alike.
    /// </remarks>
    public string GroupKey => _listing.Scope?.Identity ?? UnknownScopeKey;

    /// <summary>
    /// The group's heading: which domains these runs covered, and what was left out.
    /// </summary>
    /// <remarks>
    /// <b>The scope is spelled out rather than counted.</b> <i>2 of 3 domains</i> tells an operator
    /// how many and not which, and which is the one that decides whether a comparison in this group
    /// covers the domain he is worried about. `0069` requires a group that does not cover the whole
    /// forest to say so wherever it appears, and this is where it appears.
    /// </remarks>
    public string GroupHeading
    {
        get
        {
            if (_listing.Scope is not { } scope)
                return "Scope not established - these runs could not be opened";

            var read = scope.Domains
                .Where(d => d.Outcome == DomainReadOutcome.Read)
                .Select(d => d.DomainFqdn)
                .ToArray();

            var left = scope.Domains
                .Where(d => d.Outcome is DomainReadOutcome.ExcludedByChoice
                    or DomainReadOutcome.ExcludedForWantOfCandidates)
                .Select(d => d.DomainFqdn)
                .ToArray();

            var covered = read.Length > 0 ? string.Join(" + ", read) : "no domain";

            return left.Length == 0
                ? covered
                : $"{covered} - {string.Join(", ", left)} left out";
        }
    }

    /// <summary>
    /// The key for a run whose scope is unknown.
    /// </summary>
    /// <remarks>
    /// A constant rather than the run's own path, so every such run gathers into one group instead
    /// of producing a heading each. An operator with four unopenable bundles has one problem.
    /// </remarks>
    private const string UnknownScopeKey = "scope-not-established";
}
