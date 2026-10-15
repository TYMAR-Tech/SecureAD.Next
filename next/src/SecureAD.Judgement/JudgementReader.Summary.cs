using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

/// <summary>Saved completion figures, with the executions that make an empty finding count meaningful.</summary>
public sealed record StoredJudgementSummary(
    JudgementDescription Description,
    long ObjectsJudged,
    IReadOnlyList<StoredRuleExecution> RulesRun,
    IReadOnlyDictionary<Severity, int> FindingsBySeverity)
{
    /// <summary>The saved own-account scan coverage, when requested; null is not an empty scan.</summary>
    public SelfMembershipSummary? Requesters { get; init; }

    /// <summary>The saved selected-question coverage, when requested; it is not whole-forest coverage.</summary>
    public PathRequesterSummary? PathRequesters { get; init; }

    /// <summary>No scheduled rules is not a clean assessment.</summary>
    public bool DidNotRun => RulesRun.Count == 0;

    /// <summary>The number of saved findings, not permissions, members or paths beneath them.</summary>
    public int Findings => FindingsBySeverity.Values.Sum();
}

public sealed partial class JudgementReader
{
    /// <summary>Reads saved counts and execution outcomes without opening original proof or permission classifications.</summary>
    public Result<StoredJudgementSummary> ReadSummary(bool includeRequesters = false, bool includePathRequesters = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        try
        {
            if (Description.State is not (JudgementRunState.Completed or JudgementRunState.CompletedDegraded))
                return SummaryFailure("JudgementUnfinished", "The selected judgement did not complete.");
            var capture = AnalysisStoreLifecycle.ResolveCapture(BundleDirectory);
            if (!capture.IsSuccess) return Result<StoredJudgementSummary>.Failure(capture.Error);
            if (capture.Value.EvidenceSeal != Description.EvidenceSeal || !SummaryGenerationIsCurrent())
                return SummaryFailure("JudgementGenerationChanged", "The saved completion figures no longer belong to the selected inputs.");

            var executions = ReadExecutions();
            var counts = ReadFindingCountsBySeverity();
            if (executions.Any(execution => !Enum.IsDefined(execution.Outcome)
                    || execution.ObjectsJudged < 0 || execution.ObjectsNotApplicable < 0 || execution.ObjectsNotJudged < 0
                    || execution.MissingInputs.Any(input => input.ObjectsAffected < 0))
                || executions.Sum(execution => (long)execution.FindingsProduced) != counts.Values.Sum(count => (long)count))
                throw new InvalidDataException("The saved finding counts and rule executions contradict one another.");

            // A published judging completes the entire captured-object pass or publishes nothing.
            // The source root's saved count therefore counts each offered object once, including
            // objects no rule applies to, rather than adding per-rule evaluations or progress.
            var summary = new StoredJudgementSummary(Description, capture.Value.CapturedObjects!.Value,
                executions, counts)
            {
                Requesters = includeRequesters ? ReadSelfMembershipSummary() : null,
                PathRequesters = includePathRequesters ? ReadPathRequesterSummary(_readCancellation) : null,
            };
            _readCancellation.ThrowIfCancellationRequested();
            var currentCapture = AnalysisStoreLifecycle.ResolveCapture(BundleDirectory);
            if (!currentCapture.IsSuccess) return Result<StoredJudgementSummary>.Failure(currentCapture.Error);
            if (currentCapture.Value.Hash != capture.Value.Hash || !SummaryGenerationIsCurrent())
                return SummaryFailure("JudgementGenerationChanged", "The selected inputs changed while reading completion figures.");
            return Result<StoredJudgementSummary>.Success(summary);
        }
        catch (Exception error) when (error is SqliteException or InvalidDataException or FormatException
            or ArgumentException or InvalidOperationException or OverflowException)
        {
            _readCancellation.ThrowIfCancellationRequested();
            return SummaryFailure("JudgementSummaryUnreadable", $"The saved judgement summary could not be read: {error.Message}");
        }
    }

    private bool SummaryGenerationIsCurrent()
    {
        var selected = AnalysisStoreLifecycle.ResolveRoot(BundleDirectory, AnalysisStoreKind.Judgement);
        if (!selected.IsSuccess || selected.Value.Hash != _publicationRoot?.Hash) return false;
        if (Description.DerivationGenerationId is not { } generation) return true;
        var derivation = AnalysisStoreLifecycle.ResolveRoot(BundleDirectory, AnalysisStoreKind.Derivation);
        return derivation.IsSuccess && derivation.Value.GenerationId == generation
            && derivation.Value.EvidenceSeal == Description.EvidenceSeal
            && derivation.Value.Segment(StoreSegmentRole.Derivation).SchemaVersion == DerivationReader.StorageVersion;
    }

    private Result<StoredJudgementSummary> SummaryFailure(string code, string detail) =>
        Result<StoredJudgementSummary>.Failure(AuditError.Create(ErrorCategory.Evidence, code,
            ErrorSeverity.Failed, detail, BundleDirectory));
}
