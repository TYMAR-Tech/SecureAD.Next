using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.Services;

/// <summary>
/// Judges a bundle by driving <see cref="JudgingRun"/>, off the interface thread.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is a caller of the one judging entry point, not a second one.</b> It constructs nothing a
/// <see cref="JudgingRun"/> would not and decides nothing about what a rule means. The rules it
/// schedules are the product's rules; a launcher that chose a different set would be a second
/// opinion about what an audit is.
/// </para>
/// <para>
/// <b>The work goes to a background thread and the result comes back.</b> Judging is synchronous all
/// the way down - SQLite has no asynchronous I/O, and <c>BundleReader</c> says so in as many words -
/// so this puts it on a thread rather than pretending it awaits something. A judging that ran on the
/// interface thread would freeze the window for as long as it took, which the predecessor measured
/// in hours.
/// </para>
/// </remarks>
internal sealed class JudgingLauncher(SelfMembershipDiscoveryBudget? discoveryBudget) : IJudgingLauncher
{
    /// <inheritdoc/>
    public Task<Result<JudgingOutcome>> RunAsync(
        string bundleDirectory,
        IProgress<JudgingRun.JudgingProgress> progress,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(progress);

        return Task.Run(
            () => Judge(bundleDirectory, progress, cancellationToken),
            cancellationToken);
    }

    /// <summary>
    /// Judges, then reads back what was written.
    /// </summary>
    /// <remarks>
    /// <b>Finding counts are read from the store rather than tallied on the way past.</b> What the
    /// completion screen reports is then what an operator will find when he opens the findings, and
    /// cannot drift from it. A count assembled in flight would be a second account of the same
    /// judging, and the two would disagree on the day one of them had a defect. The unique-object
    /// count comes from the coordinator's stream progress; summing rule counts would count each
    /// object once per applicable rule.
    /// </remarks>
    private Result<JudgingOutcome> Judge(
        string bundleDirectory,
        IProgress<JudgingRun.JudgingProgress> progress,
        CancellationToken cancellationToken)
    {
        using var file = RunLogFile.Open(bundleDirectory, "judging", TimeProvider.System)
            is { IsSuccess: true } log
            ? log.Value
            : null;

        long objectsRead = 0;
        var watched = new Watching(value =>
        {
            objectsRead = Math.Max(objectsRead, value.ObjectsRead);
            progress.Report(value);
        });
        var judged = JudgingRun.Judge(
            bundleDirectory,
            RuleCatalogue.All,
            discoveryBudget,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            watched,
            file ?? RunLog.Discarded,
            cancellationToken);

        if (!judged.IsSuccess)
            return Result<JudgingOutcome>.Failure(judged.Error!);

        progress.Report(new JudgingRun.JudgingProgress(objectsRead) { Phase = JudgingPhase.ReadingResults });
        var opened = JudgementReader.Open(bundleDirectory);
        if (!opened.IsSuccess)
            return Result<JudgingOutcome>.Failure(opened.Error!);

        using var reader = opened.Value!;
        var stored = reader.Read();

        var bySeverity = stored.Findings
            .GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        // Gathered across rules rather than per rule. An operator reading a completion screen is
        // asking what stopped the audit seeing everything, not which rule stopped first, and two
        // rules blocked by the same missing thing are one problem to fix.
        var couldNotDecide = stored.RulesRun
            .SelectMany(r => r.MissingInputs)
            .GroupBy(m => m.Attribute, StringComparer.OrdinalIgnoreCase)
            .Select(g => new UnresolvedCount(
                UnresolvedWording.For(g.Key), g.Sum(m => m.ObjectsAffected)))
            .OrderByDescending(u => u.ObjectsAffected)
            .ThenBy(u => u.Reason, StringComparer.Ordinal)
            .ToList();

        return Result<JudgingOutcome>.Success(
            new JudgingOutcome(
                judged.Value,
                objectsRead,
                bySeverity,
                couldNotDecide)
            {
                Requesters = reader.ReadSelfMembershipSummary(),
            });
    }

    // Observe the stream synchronously before forwarding to the UI's asynchronous progress channel.
    private sealed class Watching(Action<JudgingRun.JudgingProgress> report) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value) => report(value);
    }
}
