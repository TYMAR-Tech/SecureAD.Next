using System.IO;
using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;
using SecureAD.Shell.ViewModels;

namespace SecureAD.Shell.Services;

/// <summary>One selected page, its published finding and complete qualification counts from the same opened generation.</summary>
internal sealed record SavedTier0Path(JudgementDescription Description, Tier0FindingSummary? Summary,
    Finding? Finding, PathRiskPage Page, IReadOnlyList<ControlEdge> Permissions)
{
    public SavedPathAccount? Account { get; init; }

    internal bool IsBound => Page.Coverage.GenerationId == Description.GenerationId
        && Page.Coverage.EvidenceSeal == Description.EvidenceSeal
        && Page.Coverage.DerivationGenerationId == Description.DerivationGenerationId
        && (Summary is null || Summary.GenerationId == Description.GenerationId
            && Summary.EvidenceSeal == Description.EvidenceSeal
            && Summary.DerivationGenerationId == Description.DerivationGenerationId
            && Summary.CalculationFingerprint == Page.Coverage.CalculationFingerprint)
        && (Finding is null ? Summary is null || Page.Counts.Unexpected == 0
            : Summary is not null && Finding.RuleId == UnexpectedTier0Route.RuleId && Finding.Evidence is Tier0RouteFindingEvidence proof
                && proof.GenerationId == Description.GenerationId && proof.DerivationGenerationId == Description.DerivationGenerationId
                && proof.EvidenceSeal == Description.EvidenceSeal && proof.CalculationFingerprint == Page.Coverage.CalculationFingerprint
                && proof.RequesterGuid == Finding.ObjectGuid && proof.UnexpectedChecks == Page.Counts.Unexpected
                && string.Equals(proof.RequesterDn, Page.RequesterDn, StringComparison.OrdinalIgnoreCase))
        && Page.Questions.All(value => value.Risk.GenerationId == Description.GenerationId
            && value.Risk.EvidenceSeal == Description.EvidenceSeal
            && value.Risk.DerivationGenerationId == Description.DerivationGenerationId
            && value.Risk.CalculationFingerprint == Page.Coverage.CalculationFingerprint
            && value.Risk.Verdict == Page.Group
            && string.Equals(value.Risk.RequesterDn, Page.RequesterDn, StringComparison.OrdinalIgnoreCase))
        && Permissions.All(value => value.GenerationId == Description.GenerationId
            && value.DerivationGenerationId == Description.DerivationGenerationId)
        && (Account is null || string.Equals(Account.DistinguishedName, Page.RequesterDn, StringComparison.OrdinalIgnoreCase)
            && (Finding is null || Account.ObjectGuid == Finding.ObjectGuid)
            && Page.Questions.All(value =>
                (value.Requester?.Requester ?? value.OwnAccount?.Requester ?? value.Membership?.Membership.Requester
                    ?? value.Risk.CurrentAuthority?.Principal) is not { } requester
                || requester.ObjectGuid == Account.ObjectGuid));
}

internal sealed record SavedPathAccount(Guid? ObjectGuid, string DistinguishedName, string Name,
    string? AccountName, string? GivenName)
{
    internal static SavedPathAccount From(ObjectAttributes value) => new(value.ObjectGuid, value.DistinguishedName,
        CapturedText(value, "displayName") ?? DnHelper.ExtractNameFromDn(value.DistinguishedName),
        CapturedText(value, "sAMAccountName"), CapturedText(value, "givenName"));

    private static string? CapturedText(ObjectAttributes value, string attribute) =>
        value.Find(attribute)?.OnlyValue?.Text is { } text && !string.IsNullOrWhiteSpace(text) ? text : null;
}

internal sealed partial class BundleAssetSource
{
    /// <inheritdoc/>
    public Task<Result<SavedTier0Path?>> ReadSavedTier0PathAsync(string bundleDirectory, string distinguishedName,
        CancellationToken cancellationToken) =>
        ReadAsync(bundleDirectory, (source, _) => source.ReadSavedTier0Path(bundleDirectory, distinguishedName), cancellationToken);

    /// <inheritdoc/>
    public Result<SavedTier0Path?> ReadSavedTier0Path(string bundleDirectory, string distinguishedName) =>
        WithRun(bundleDirectory, reader => reader.ReadSavedTier0Path(bundleDirectory, distinguishedName));

    public Result<SavedTier0Path?> ReadSavedTier0Path(string bundleDirectory, string distinguishedName,
        PathRiskVerdict group, PathRiskPageMark? after) =>
        WithRun(bundleDirectory, reader => reader.ReadSavedTier0Path(bundleDirectory, distinguishedName, group, after));

    public Result<Tier0FindingSummary?> ReadTier0FindingSummary(string bundleDirectory) =>
        WithRun(bundleDirectory, reader => reader.ReadTier0FindingSummary(bundleDirectory));
}

internal sealed partial class AssetReadRequest
{
    /// <inheritdoc/>
    public Result<SavedTier0Path?> ReadSavedTier0Path(string bundleDirectory, string distinguishedName) =>
        ReadSavedTier0Path(bundleDirectory, distinguishedName, PathRiskVerdict.UnexpectedRoute, null);

    public Result<SavedTier0Path?> ReadSavedTier0Path(string bundleDirectory, string distinguishedName,
        PathRiskVerdict group, PathRiskPageMark? after)
    {
        var cancellationToken = _readCancellation;
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var read = Flatten(WithRun(bundleDirectory, run => run.ReadJudgement((reader, token) =>
            {
                var page = reader.ReadPathRiskPage(distinguishedName, group, after, token);
                var summary = reader.ReadTier0FindingSummary(token);
                Finding? finding = null;
                if (summary is not null)
                {
                    var findings = reader.ReadPage(new FindingsQuery(null, UnexpectedTier0Route.RuleId,
                        null, null, distinguishedName, null, 1));
                    if (!findings.IsSuccess) return Result<SavedTier0Path?>.Failure(findings.Error);
                    if (findings.Value.HasMore) throw new InvalidDataException(SavedPathText.Get("InvalidEvidence"));
                    finding = findings.Value.Findings.SingleOrDefault();
                }
                var permissions = new List<ControlEdge>();
                foreach (var step in page.Questions.SelectMany(value => value.Steps).Where(step => step.PermissionId.HasValue)
                    .DistinctBy(step => (step.To.DistinguishedName, step.PermissionId)))
                {
                    token.ThrowIfCancellationRequested();
                    permissions.Add(reader.ReadControlEdge(step.To.DistinguishedName, step.PermissionId.GetValueOrDefault()));
                }
                var saved = new SavedTier0Path(reader.Description, summary, finding, page, permissions);
                if (!saved.IsBound) return PathFailure("GenerationChanged", bundleDirectory, null);
                if (page.Questions.Count > 0)
                {
                    // Names come from this protected run and this account only, not a directory lookup.
                    var account = run.ReadEvidence(evidence => evidence.ReadObjectAttributes(distinguishedName), token);
                    if (!account.IsSuccess) return Result<SavedTier0Path?>.Failure(account.Error);
                    if (account.Value is null && page.Questions.Any(value => value.Risk.Authorization == ControlEvaluationState.Established))
                        return PathFailure("InvalidEvidence", bundleDirectory, null);
                    saved = saved with { Account = account.Value is { } captured ? SavedPathAccount.From(captured) : null };
                }
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

    public Result<Tier0FindingSummary?> ReadTier0FindingSummary(string bundleDirectory) =>
        WithRun(bundleDirectory, run => run.ReadJudgement((reader, token) => reader.ReadTier0FindingSummary(token), _readCancellation));

    private static Result<SavedTier0Path?> PathFailure(string reason, string directory, string? detail) =>
        Result<SavedTier0Path?>.Failure(AuditError.Create(ErrorCategory.Shell, "SavedPath" + reason,
            ErrorSeverity.Failed, SavedPathText.Get(reason) + (detail is null ? "" : " " + detail), directory));
}
