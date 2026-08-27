using SecureAD.Derivation;
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
        var objectsRead = 0L;

        var watched = new Watching(
            report =>
            {
                objectsRead = report.ObjectsRead;
                progress.Report(report);
            });

        var derived = Stage2aRun.Derive(
            bundleDirectory,
            ExpansionBudget.Bulk,
            DateTimeOffset.UtcNow,
            watched,
            cancellationToken);

        return derived.IsSuccess
            ? Result<DerivingOutcome>.Success(new DerivingOutcome(derived.Value, objectsRead))
            : Result<DerivingOutcome>.Failure(derived.Error!);
    }

    /// <summary>
    /// Passes each report on, and remembers the count from it.
    /// </summary>
    private sealed class Watching(Action<DerivationProgress> onReport) : IProgress<DerivationProgress>
    {
        public void Report(DerivationProgress value) => onReport(value);
    }
}
