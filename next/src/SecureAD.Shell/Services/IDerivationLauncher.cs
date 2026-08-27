using SecureAD.Derivation;
using SecureAD.Kernel;

namespace SecureAD.Shell.Services;

/// <summary>
/// What a derivation produced, in the shell's own words.
/// </summary>
/// <remarks>
/// <para>
/// <b>The state, and how much of the bundle the pass read - nothing else.</b> A
/// <see cref="JudgingOutcome"/> can report what was written because <c>JudgementReader</c> exists to
/// read it back. Nothing reads <c>derivation.db</c> yet, so counting closures here would mean
/// tallying them on the way past, which is the second account of the same run that
/// <c>JudgingLauncher</c> refuses to keep.
/// </para>
/// <para>
/// <b><see cref="ObjectsRead"/> comes from the progress the run reported.</b> It says how far the
/// pass over the evidence got, not how large the answer is. The two are different quantities and
/// only one of them is available without a reader.
/// </para>
/// </remarks>
/// <param name="State">What became of the derivation.</param>
/// <param name="ObjectsRead">How many objects the pass over the bundle read.</param>
internal sealed record DerivingOutcome(DerivationRunState State, long ObjectsRead);

/// <summary>
/// Deriving from a sealed bundle, from a window.
/// </summary>
/// <remarks>
/// <para>
/// <b>A seam for the same reason <see cref="IJudgingLauncher"/> is one.</b> The audit screen can be
/// tested for what it asks to be derived, and for what it does with progress and refusals, without a
/// bundle on disk or a forest's worth of nesting to expand.
/// </para>
/// <para>
/// <b>Deriving follows a capture without being asked for, and precedes the judging.</b> The same
/// shape judging has: the decision to audit was the decision to derive, which is why this has no
/// <c>CanDerive</c> and no confirmation. It runs first because derived facts are what a rule reading
/// more than one object will rest on, and a judging that ran before them would rest on nothing.
/// </para>
/// </remarks>
internal interface IDerivationLauncher
{
    /// <summary>
    /// Derives from the bundle in <paramref name="bundleDirectory"/> and writes the facts beside it.
    /// </summary>
    /// <param name="bundleDirectory">The sealed bundle to derive from.</param>
    /// <param name="progress">
    /// Told which phase is running and how far the pass has read. Required rather than optional, for
    /// the reason <see cref="IJudgingLauncher"/> records: the predecessor's progress reporting went
    /// unused by being something a caller could forget.
    /// </param>
    /// <param name="cancellationToken">
    /// Stops the derivation. Any earlier derivation is left intact, because deriving writes to a
    /// partial file and renames only once every phase has finished.
    /// </param>
    /// <returns>What the derivation produced, or why it could not be done at all.</returns>
    Task<Result<DerivingOutcome>> RunAsync(
        string bundleDirectory,
        IProgress<DerivationProgress> progress,
        CancellationToken cancellationToken);
}
