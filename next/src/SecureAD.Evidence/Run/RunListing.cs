namespace SecureAD.Evidence.Run;

/// <summary>
/// One run in the library, as a listing shows it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Everything here was observed, and nothing here was inferred from the directory name.</b> The
/// name a run is created with carries the forest and the moment as a convenience for somebody
/// reading a folder listing, and <see cref="RunLibrary.CreateRun"/> is explicit that nothing reads
/// meaning back out of it. This record keeps that promise: <see cref="State"/> comes from
/// <see cref="RunStateReader.Observe"/> looking at the bundle, not from the name.
/// </para>
/// <para>
/// <b>Coverage is read here, and never guessed at.</b> This record carried no coverage at all until
/// 2026-08-21, on the reasoning that reading it means opening the bundle and that a listing filling
/// a column by inference would be stating something about a customer's directory nobody measured.
/// The second half of that still stands and is why <see cref="Scope"/> is null rather than assumed
/// whenever the bundle could not be opened. What changed is that runs are now grouped by what they
/// covered, which cannot be done without knowing it - so the bundle is opened, one cheap read of
/// the declaration rows per run.
/// </para>
/// </remarks>
/// <param name="Identifier">The run's directory name inside the library.</param>
/// <param name="Path">The full path of the run's bundle directory.</param>
/// <param name="State">What became of the run, as observed.</param>
/// <param name="Detail">
/// Why, where the state does not speak for itself. Null for a sealed run; a sentence an operator
/// can act on for a failed, damaged or interrupted one.
/// </param>
/// <param name="Moment">
/// When the run happened, and whether the run recorded that itself. Never parsed out of
/// <paramref name="Identifier"/>, for the reason stated above.
/// </param>
/// <param name="Annotation">
/// What the operator called this run and wrote about it. Typed by a person, kept outside the seal,
/// and not evidence - see <see cref="RunAnnotations"/>.
/// </param>
/// <param name="Scope">
/// Which domains the run covered, and which group of like runs it therefore belongs to.
/// <b>Null means this was not established</b> - the run never sealed, or its bundle would not open
/// - and a screen must say so rather than showing it among the whole-forest runs.
/// </param>
public sealed record RunListing(
    string Identifier,
    string Path,
    RunState State,
    string? Detail,
    RunMoment Moment,
    RunAnnotation Annotation,
    RunScope? Scope,
    RunProducts Products);
