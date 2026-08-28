using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Shell.Services;

/// <summary>
/// Derives from a bundle by driving <see cref="Stage2aRun"/>, off the interface thread.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is a caller of the one deriving entry point, not a second one.</b> It chooses nothing
/// about what a closure means and expands nothing itself. The budget it passes is
/// <see cref="ExpansionBudget.Bulk"/>, which is the budget for deriving a whole bundle; a launcher
/// that invented its own would be a second opinion about how much of a forest is worth answering
/// for.
/// </para>
/// <para>
/// <b>The work goes to a background thread and the result comes back.</b> Deriving is synchronous
/// all the way down for the reason <c>JudgingLauncher</c> records - SQLite has no asynchronous I/O -
/// so this puts it on a thread rather than pretending it awaits something. Deriving is the most
/// expensive thing this product does, and one that ran on the interface thread would freeze the
/// window for the whole of it.
/// </para>
/// <para>
/// <b>The progress it forwards is the run's own.</b> The count is what the pass over the evidence
/// reported last, so what the screen shows and what the run did cannot drift apart.
/// </para>
/// </remarks>
internal sealed class DerivationLauncher : IDerivationLauncher
{
    /// <inheritdoc/>
    public Task<Result<DerivingOutcome>> RunAsync(
        string bundleDirectory,
        IProgress<DerivationProgress> progress,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(progress);

        return Task.Run(
            () => Derive(bundleDirectory, progress, cancellationToken),
            cancellationToken);
    }

    /// <summary>
    /// Derives, watching the progress go past so the outcome can say how far the pass read.
    /// </summary>
    /// <remarks>
    /// <b>The count is taken from the progress rather than from the store.</b> Judging reads its
    /// counts back, and this would too if there were anything to read <c>derivation.db</c> with.
    /// Until there is, the last thing the run reported is the only honest number available - and it
    /// is one the run itself produced, not one this class assembled from its own traversal.
    /// </remarks>
    private static Result<DerivingOutcome> Derive(
        string bundleDirectory,
        IProgress<DerivationProgress> progress,
        CancellationToken cancellationToken)
    {
        // Progress is forwarded and nothing is remembered from it. It says how far the pass has
        // read, which is what an operator watching wants; what a finished derivation produced is
        // read back from the store below, so the screen cannot report a different answer from the
        // one the bundle holds.
        var watched = new Watching(progress.Report);

        // The capture wrote the first stretch of this file and the judging will write the last. A
        // log that could not be opened does not stop the derivation: the facts are worth more than
        // the account of how they were derived.
        using var file = RunLogFile.Open(bundleDirectory, "deriving", TimeProvider.System)
            is { IsSuccess: true } opened
            ? opened.Value
            : null;

        IRunLog log = file ?? RunLog.Discarded;

        var derived = Stage2aRun.Derive(
            bundleDirectory,
            ExpansionBudget.Bulk,
            DateTimeOffset.UtcNow,
            watched,
            log,
            cancellationToken);

        if (!derived.IsSuccess)
            return Result<DerivingOutcome>.Failure(derived.Error!);

        var reopened = DerivationReader.Open(bundleDirectory);
        if (!reopened.IsSuccess)
            return Result<DerivingOutcome>.Failure(reopened.Error!);

        using var reader = reopened.Value!;
        var stored = reader.Read();

        return Result<DerivingOutcome>.Success(
            new DerivingOutcome(
                derived.Value,
                stored.Size.Principals,
                stored.Size.NestingEdges,
                stored.EveryPhaseThatRanSucceeded));
    }

    /// <summary>
    /// Passes each report on.
    /// </summary>
    private sealed class Watching(Action<DerivationProgress> onReport) : IProgress<DerivationProgress>
    {
        public void Report(DerivationProgress value) => onReport(value);
    }
}
