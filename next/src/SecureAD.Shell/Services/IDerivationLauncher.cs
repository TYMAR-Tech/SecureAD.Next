using SecureAD.Derivation;
using SecureAD.Kernel;

namespace SecureAD.Shell.Services;

/// <summary>
/// What a derivation produced, in the shell's own words.
/// </summary>
/// <remarks>
/// <para>
/// <b>Read back from the store rather than tallied on the way past</b>, which is the rule
/// <see cref="JudgingOutcome"/> already follows. What the completion screen reports is then what an
/// operator will find when he opens the bundle, and cannot drift from it.
/// </para>
/// <para>
/// <b>It reported <c>ObjectsRead</c> until <c>DerivationReader</c> existed</b>, because that was the
/// only number available - the effort of deriving rather than the answer. The two are different
/// quantities and only one of them is worth showing.
/// </para>
/// </remarks>
/// <param name="State">What became of the derivation.</param>
/// <param name="Principals">How many principals it knows about.</param>
/// <param name="NestingEdges">How many direct nesting relationships it holds.</param>
/// <param name="EveryPhaseThatRanSucceeded">
/// Whether anything went wrong in a phase. False makes the counts a floor rather than a total.
/// </param>
internal sealed record DerivingOutcome(
    DerivationRunState State,
    long Principals,
    long NestingEdges,
    bool EveryPhaseThatRanSucceeded);

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
