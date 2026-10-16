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
    private readonly RunProtectionSessions? _protection;
    internal DerivationLauncher() { }
    internal DerivationLauncher(RunProtectionSessions protection) => _protection =
        protection ?? throw new ArgumentNullException(nameof(protection));

    /// <inheritdoc/>
    public Task<Result<DerivingOutcome>> RunAsync(
        string bundleDirectory,
        IProgress<DerivationProgress> progress,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(progress);

        return Task.Run(
            () =>
            {
                using var standalone = new RunProtectionSessions();
                return (_protection ?? standalone).Produce(bundleDirectory,
                    files => Derive(bundleDirectory, progress, cancellationToken, files));
            },
            cancellationToken);
    }

    /// <summary>
    /// Derives, then reads the saved size and phase outcomes without reconstructing derived products.
    /// </summary>
    private static Result<DerivingOutcome> Derive(
        string bundleDirectory,
        IProgress<DerivationProgress> progress,
        CancellationToken cancellationToken, ProtectedRunFiles files)
    {
        // Only the attempt's generation is retained from progress. Completed counts come from the
        // saved store, and another attempt cannot supply them under this attempt's completion.
        Guid? generationId = null;
        var watched = new Watching(value =>
        {
            generationId = value.DerivationGenerationId ?? generationId;
            progress.Report(value);
        });

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
            cancellationToken, files);

        if (!derived.IsSuccess)
            return Result<DerivingOutcome>.Failure(derived.Error!);

        progress.Report(new DerivationProgress("ReadingDerivedResults", 0));
        var summary = DerivationReader.ReadSummary(files, cancellationToken);
        if (!summary.IsSuccess)
            return Result<DerivingOutcome>.Failure(summary.Error);
        var stored = summary.Value;
        if (stored.Description.GenerationId != generationId)
            return Result<DerivingOutcome>.Failure(AuditError.Create(ErrorCategory.Evidence, "DerivationGenerationChanged",
                ErrorSeverity.Failed, "The selected derivation is not the generation this attempt published.", bundleDirectory));

        return Result<DerivingOutcome>.Success(
            new DerivingOutcome(
                stored.Description.State,
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
