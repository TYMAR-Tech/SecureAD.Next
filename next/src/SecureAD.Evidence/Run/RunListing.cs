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
/// <b>There is no coverage here, and its absence is deliberate.</b> How much of a forest a run saw
/// is <see cref="RunCoverage"/>, it lives inside the bundle, and reading it means opening the
/// bundle. A listing that guessed at coverage in order to fill a column would be stating something
/// about a customer's directory that nobody measured.
/// </para>
/// </remarks>
/// <param name="Identifier">The run's directory name inside the library.</param>
/// <param name="Path">The full path of the run's bundle directory.</param>
/// <param name="State">What became of the run, as observed.</param>
/// <param name="Detail">
/// Why, where the state does not speak for itself. Null for a sealed run; a sentence an operator
/// can act on for a failed, damaged or interrupted one.
/// </param>
public sealed record RunListing(
    string Identifier,
    string Path,
    RunState State,
    string? Detail);
