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

    private Result<SavedTier0Path?> ReadSavedTier0Path(string bundleDirectory, string distinguishedName,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var read = Flatten(WithRun(bundleDirectory, run => run.ReadJudgement((reader, token) =>
            {
                var (path, coverage) = reader.ReadTier0PathWithCoverage(distinguishedName, token);
                var permissions = new List<ControlEdge>();
                foreach (var step in path.Steps.Where(step => step.PermissionId.HasValue)
                    .DistinctBy(step => (step.To.DistinguishedName, step.PermissionId)))
                {
                    token.ThrowIfCancellationRequested();
                    permissions.Add(reader.ReadControlEdge(step.To.DistinguishedName, step.PermissionId.GetValueOrDefault()));
                }
                var saved = new SavedTier0Path(reader.Description, path, coverage, permissions);
                return saved.IsBound ? Result<SavedTier0Path?>.Success(saved)
                    : PathFailure("GenerationChanged", bundleDirectory, null);
            }, cancellationToken)));
            if (read.IsSuccess) return read;
            return read.Error.Code switch
            {
                "Evidence.judgementManifestAbsent" => Result<SavedTier0Path?>.Success(null),
                "Shell.SavedResultsUnfinished" => PathFailure("Unfinished", bundleDirectory, null),
                "Shell.SavedResultsGenerationChanged" => PathFailure("GenerationChanged", bundleDirectory, null),
                "Shell.SavedResultsInvalidEvidence" => Result<SavedTier0Path?>.Failure(AuditError.Create(ErrorCategory.Shell,
                    "SavedPathInvalidEvidence", ErrorSeverity.Failed, read.Error.Description, bundleDirectory)),
                _ => read,
            };
        }
        catch (InvalidDataException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
        catch (IOException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
        catch (UnauthorizedAccessException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
        catch (InvalidOperationException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
        catch (Microsoft.Data.Sqlite.SqliteException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
        catch (JsonException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
        catch (ArgumentException error) { return PathFailure("InvalidEvidence", bundleDirectory, error.Message); }
    }

    private static Result<SavedTier0Path?> PathFailure(string reason, string directory, string? detail) =>
        Result<SavedTier0Path?>.Failure(AuditError.Create(ErrorCategory.Shell, "SavedPath" + reason,
            ErrorSeverity.Failed, SavedPathText.Get(reason) + (detail is null ? "" : " " + detail), directory));
}
