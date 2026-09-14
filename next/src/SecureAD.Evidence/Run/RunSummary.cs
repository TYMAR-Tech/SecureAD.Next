namespace SecureAD.Evidence.Run;

/// <summary>
/// What a caller needs to know about a run in order to decide whether it may be used.
/// </summary>
/// <remarks>
/// <para>
/// The two factories exist so that impossible combinations cannot be built. A run that never
/// finished has no coverage to report, and a finished run always has some - so
/// <c>sealed with no coverage</c> and <c>failed but fully covered</c> are unrepresentable rather
/// than merely rejected. The predecessor's equivalent held every field at once and left each
/// caller to work out which of them applied.
/// </para>
/// </remarks>
public sealed record RunSummary
{
    private RunSummary(
        ProfileId profile,
        RunState state,
        RunCoverage? coverage,
        int majorVersion,
        bool graphFindingsWithheld,
        IReadOnlyList<string>? excludedObjectClasses)
    {
        Profile = profile;
        State = state;
        Coverage = coverage;
        MajorVersion = majorVersion;
        GraphFindingsWithheld = graphFindingsWithheld;
        ExcludedObjectClasses = excludedObjectClasses;
    }

    /// <summary>The forest this run assessed.</summary>
    public ProfileId Profile { get; }

    /// <summary>What became of the run.</summary>
    public RunState State { get; }

    /// <summary>
    /// What the run read, or null when it never finished and so never established any.
    /// </summary>
    public RunCoverage? Coverage { get; }

    /// <summary>
    /// The major version of the product that produced the run. Compared because two major versions
    /// may disagree about what a finding is, which makes a comparison across them worth
    /// qualifying rather than refusing.
    /// </summary>
    public int MajorVersion { get; }

    /// <summary>
    /// Whether any graph analysis was withheld from this run's findings. A comparison against a
    /// run with a hole in its analysis is worth performing and worth saying so about.
    /// </summary>
    public bool GraphFindingsWithheld { get; }

    /// <summary>Recorded class exclusions; absent for a run that never completed.</summary>
    public IReadOnlyList<string>? ExcludedObjectClasses { get; }

    /// <summary>Describes a run that finished and sealed.</summary>
    /// <param name="profile">The forest it assessed.</param>
    /// <param name="coverage">What it read. May be incomplete; that is what makes it refusable.</param>
    /// <param name="majorVersion">The major version that produced it.</param>
    /// <param name="graphFindingsWithheld">Whether graph analysis was withheld.</param>
    /// <param name="excludedObjectClasses">The actual class exclusions from the sealed evidence.</param>
    public static RunSummary OfCompletedRun(
        ProfileId profile,
        RunCoverage coverage,
        int majorVersion,
        bool graphFindingsWithheld,
        IEnumerable<string> excludedObjectClasses)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(coverage);
        ArgumentNullException.ThrowIfNull(excludedObjectClasses);

        return new RunSummary(
            profile, RunState.Sealed, coverage, majorVersion, graphFindingsWithheld,
            Array.AsReadOnly(excludedObjectClasses.Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray()));
    }

    /// <summary>Describes a run that did not finish.</summary>
    /// <param name="profile">The forest it was assessing.</param>
    /// <param name="state">Which of the not-finished states it is in.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="state"/> is <see cref="RunState.Sealed"/>, which would describe a finished
    /// run with no coverage - the combination this factory exists to make unbuildable.
    /// </exception>
    public static RunSummary OfUnfinishedRun(ProfileId profile, RunState state)
    {
        ArgumentNullException.ThrowIfNull(profile);

        if (state == RunState.Sealed)
        {
            throw new ArgumentException(
                "A sealed run finished, so it has coverage to report. Use OfCompletedRun.",
                nameof(state));
        }

        return new RunSummary(profile, state, coverage: null, majorVersion: 0, false, null);
    }
}
