using System.IO;
using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;

namespace SecureAD.Shell.Services;

/// <summary>One opened generation's saved path, execution coverage and unchanged source permissions.</summary>
internal sealed record SavedTier0Path(JudgementDescription Description, Tier0PathResult Path,
    PathRequesterCoverage Requesters, IReadOnlyList<ControlEdge> Permissions)
{
    internal bool IsBound => Path.Inputs.JudgementGenerationId == Description.GenerationId
        && Requesters.Inputs.JudgementGenerationId == Description.GenerationId
        && Requesters.EvidenceSeal == Description.EvidenceSeal
        && Requesters.DerivationGenerationId == Description.DerivationGenerationId
        && Permissions.All(value => value.GenerationId == Description.GenerationId
            && value.DerivationGenerationId == Description.DerivationGenerationId);
}

internal sealed partial class BundleAssetSource
{
    /// <inheritdoc/>
    public Task<Result<SavedTier0Path?>> ReadSavedTier0PathAsync(string bundleDirectory, string distinguishedName,
        CancellationToken cancellationToken) =>
        Task.Run(() => ReadSavedTier0Path(bundleDirectory, distinguishedName, cancellationToken), cancellationToken);

    /// <inheritdoc/>
    public Result<SavedTier0Path?> ReadSavedTier0Path(string bundleDirectory, string distinguishedName) =>
        ReadSavedTier0Path(bundleDirectory, distinguishedName, CancellationToken.None);

    private static Result<SavedTier0Path?> ReadSavedTier0Path(string bundleDirectory, string distinguishedName,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            if (HasUnpublishedAnalysis(bundleDirectory)) return PathFailure("Unfinished", bundleDirectory, null);
            var opened = JudgementReader.Open(bundleDirectory);
            if (!opened.IsSuccess)
                return opened.Error.Code == "Evidence.judgementManifestAbsent"
                    ? Result<SavedTier0Path?>.Success(null)
                    : Result<SavedTier0Path?>.Failure(opened.Error);
            using var reader = opened.Value;
            if (reader.Description.State is not (JudgementRunState.Completed or JudgementRunState.CompletedDegraded))
                return PathFailure("Unfinished", bundleDirectory, null);

            var (path, coverage) = reader.ReadTier0PathWithCoverage(distinguishedName, cancellationToken);
            var permissions = new List<ControlEdge>();
            foreach (var step in path.Steps.Where(step => step.PermissionId.HasValue)
                .DistinctBy(step => step.PermissionId))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var id = step.PermissionId.GetValueOrDefault();
                var permission = reader.ReadControlEdge(step.To.DistinguishedName, id);
                permissions.Add(permission);
            }
            var saved = new SavedTier0Path(reader.Description, path, coverage, permissions);
            if (!saved.IsBound) return PathFailure("GenerationChanged", bundleDirectory, null);

            // Publication can change while the saved generation is validated. Never label the
            // earlier generation as the current attempt's result, even though its proof remains valid.
            if (HasUnpublishedAnalysis(bundleDirectory)) return PathFailure("Unfinished", bundleDirectory, null);
            var selected = AnalysisStoreLifecycle.Resolve(bundleDirectory, AnalysisStoreKind.Judgement);
            if (!selected.IsSuccess) return Result<SavedTier0Path?>.Failure(selected.Error);
            if (selected.Value.GenerationId != reader.Description.GenerationId)
                return PathFailure("GenerationChanged", bundleDirectory, null);
            if (reader.Description.DerivationGenerationId is { } derivationId)
            {
                var derived = AnalysisStoreLifecycle.Resolve(bundleDirectory, AnalysisStoreKind.Derivation);
                if (!derived.IsSuccess) return Result<SavedTier0Path?>.Failure(derived.Error);
                if (derived.Value.GenerationId != derivationId) return PathFailure("GenerationChanged", bundleDirectory, null);
            }
            cancellationToken.ThrowIfCancellationRequested();
            return Result<SavedTier0Path?>.Success(saved);
        }
        catch (InvalidDataException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
        catch (IOException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
        catch (UnauthorizedAccessException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
        catch (InvalidOperationException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
        catch (Microsoft.Data.Sqlite.SqliteException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
        catch (JsonException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
        catch (ArgumentException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
    }

    private static bool HasUnpublishedAnalysis(string directory) =>
        File.Exists(AnalysisStoreLifecycle.StagingPath(directory, AnalysisStoreKind.Judgement))
        || File.Exists(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement) + ".partial")
        || File.Exists(AnalysisStoreLifecycle.StagingPath(directory, AnalysisStoreKind.Derivation))
        || File.Exists(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation) + ".partial");

    private static Result<SavedTier0Path?> PathFailure(string reason, string directory, string? detail) =>
        Result<SavedTier0Path?>.Failure(AuditError.Create(ErrorCategory.Shell, "SavedPath" + reason,
            ErrorSeverity.Failed, SavedPathText.Get(reason) + (detail is null ? "" : " " + detail), directory));
}
