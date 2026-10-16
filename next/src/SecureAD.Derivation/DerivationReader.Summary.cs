using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Derivation;

/// <summary>Saved derivation counts and phase outcomes, without reconstructed protection or membership products.</summary>
public sealed record StoredDerivationSummary(
    DerivationDescription Description,
    IReadOnlyList<StoredDerivationPhase> Phases,
    DerivationSize Size)
{
    /// <summary>No recorded phases is not evidence that an empty forest was fully derived.</summary>
    public bool DidNotRun => Phases.Count == 0;

    /// <summary>A phase with no input is different from one that failed.</summary>
    public bool EveryPhaseThatRanSucceeded =>
        Phases.All(phase => phase.Outcome is DerivationPhaseOutcome.Succeeded or DerivationPhaseOutcome.DidNotRun);
}

public sealed partial class DerivationReader
{
    /// <summary>Verifies and protects the selected derivation, then reads only its saved size and phases.</summary>
    public static Result<StoredDerivationSummary> ReadSummary(string bundleDirectory, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        using var files = new ProtectedRunFiles(bundleDirectory);
        return ReadSummary(files, cancellationToken);
    }

    /// <summary>Reads saved completion figures under the same protected lifetime as the producing stages.</summary>
    public static Result<StoredDerivationSummary> ReadSummary(ProtectedRunFiles files, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(files);
        var bundleDirectory = files.Directory;
        cancellationToken.ThrowIfCancellationRequested();
        var capture = AnalysisStoreLifecycle.ResolveCapture(bundleDirectory);
        if (!capture.IsSuccess) return Result<StoredDerivationSummary>.Failure(capture.Error);
        var selected = AnalysisStoreLifecycle.Resolve(bundleDirectory, AnalysisStoreKind.Derivation);
        if (!selected.IsSuccess) return Result<StoredDerivationSummary>.Failure(selected.Error);
        var protectedFile = files.Analysis(AnalysisStoreKind.Derivation, StoreSegmentRole.Derivation, cancellationToken);
        if (!protectedFile.IsSuccess) return Result<StoredDerivationSummary>.Failure(protectedFile.Error);
        var file = protectedFile.Value;
        var opened = Open(file, cancellationToken);
        if (!opened.IsSuccess) return Result<StoredDerivationSummary>.Failure(opened.Error);
        using var reader = opened.Value;
        try
        {
            if (reader.Description.State is not (DerivationRunState.Completed or DerivationRunState.CompletedDegraded))
                return SummaryFailure("DerivationUnfinished", "The selected derivation did not complete.", bundleDirectory);
            if (reader.Description.EvidenceSeal != capture.Value.EvidenceSeal
                || reader.Description.EvidenceSeal != file.Root.EvidenceSeal
                || file.Root.Segment(StoreSegmentRole.Derivation).SchemaVersion != StorageVersion)
                return SummaryFailure("DerivationIsNotForThisEvidence", "The saved derivation summary contradicts its selected inputs.", bundleDirectory);
            var phases = reader.ReadPhases();
            if (phases.Any(phase => !Enum.IsDefined(phase.Outcome)))
                throw new InvalidDataException("A saved derivation phase has an unsupported outcome.");
            var summary = new StoredDerivationSummary(reader.Description, phases, reader.ReadSize());
            cancellationToken.ThrowIfCancellationRequested();
            var current = AnalysisStoreLifecycle.ResolveRoot(bundleDirectory, AnalysisStoreKind.Derivation);
            var currentCapture = AnalysisStoreLifecycle.ResolveCapture(bundleDirectory);
            if (!current.IsSuccess || current.Value.Hash != file.Root.Hash
                || !currentCapture.IsSuccess || currentCapture.Value.Hash != capture.Value.Hash)
                return SummaryFailure("DerivationGenerationChanged", "The selected inputs changed while reading derivation figures.", bundleDirectory);
            return Result<StoredDerivationSummary>.Success(summary);
        }
        catch (Exception error) when (error is SqliteException or InvalidDataException or FormatException
            or ArgumentException or InvalidOperationException or OverflowException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SummaryFailure("DerivationSummaryUnreadable", $"The saved derivation summary could not be read: {error.Message}", bundleDirectory);
        }
    }

    private static Result<StoredDerivationSummary> SummaryFailure(string code, string detail, string directory) =>
        Result<StoredDerivationSummary>.Failure(AuditError.Create(ErrorCategory.Evidence, code,
            ErrorSeverity.Failed, detail, directory));
}
