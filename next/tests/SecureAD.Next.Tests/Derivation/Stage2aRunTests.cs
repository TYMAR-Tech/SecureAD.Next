using SecureAD.Kernel;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// Running the whole stage over a bundle, and what survives what.
/// </summary>
/// <remarks>
/// <b>Fault isolation only matters when something has gone wrong</b>, so most of these are about a
/// derivation that did not go cleanly. The one thing none of them may allow is a store that stays
/// silent about a phase: a derivation holding no closure because a phase failed and one holding
/// none because the forest has no nesting are opposite facts, and a reader has to be able to tell
/// them apart.
/// </remarks>
public sealed class Stage2aRunTests
{
    private static readonly DateTimeOffset Started = new(2026, 8, 27, 9, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// A bundle with no readable seal is refused before anything is written.
    /// </summary>
    /// <remarks>
    /// Derived facts that cannot name their capture would be consulted silently by every rule
    /// resting on them, which makes naming it the whole of their trustworthiness.
    /// </remarks>
    [Fact]
    public void Stage2a_ABundleWithNoSealIsRefused()
    {
        var directory = NewDirectory();

        var result = Stage2aRun.Derive(
            directory,
            ExpansionBudget.Bulk,
            Started,
            Stage2aRun.Unwatched,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.False(AnalysisStoreLifecycle.Resolve(
            directory, AnalysisStoreKind.Derivation).IsSuccess);
    }

    /// <summary>
    /// A derivation that could not start still says so in the run's log.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the coverage whose absence made a stale binary hard to tell from a defect.</b>
    /// The log was threaded through three coordinators and nothing asserted that any of them wrote
    /// a line, so when a real run produced no <c>run.log</c> the only way to reason about it was
    /// which files were on disk. A test here answers that question directly.
    /// </para>
    /// <para>
    /// The refusal is used rather than a whole derivation because it needs no bundle: what is
    /// being proved is that the coordinator writes to the log it was handed, not what it derives.
    /// </para>
    /// </remarks>
    [Fact]
    public void Stage2a_TheRefusalReachesTheRunsLog()
    {
        var directory = NewDirectory();

        var opened = RunLogFile.Open(directory, "deriving", TimeProvider.System);
        Assert.True(opened.IsSuccess);

        using (var log = opened.Value!)
        {
            Stage2aRun.Derive(
                directory,
                ExpansionBudget.Bulk,
                Started,
                Stage2aRun.Unwatched,
                log,
                CancellationToken.None);
        }

        var written = File.ReadAllText(BundleLayout.RunLogPath(directory));

        Assert.Contains("deriving ====", written, StringComparison.Ordinal);
        Assert.Contains("ERROR", written, StringComparison.Ordinal);
        Assert.Contains("EvidenceSealUnreadable", written, StringComparison.Ordinal);
    }

    /// <summary>
    /// A directory that is not a bundle is refused rather than half-derived.
    /// </summary>
    [Fact]
    public void Stage2a_ADirectoryThatIsNotABundleIsRefused()
    {
        var directory = NewDirectory();
        File.WriteAllText(BundleLayout.SealPath(directory), """{"Algorithm":"SHA256","Hash":"abc"}""");

        var result = Stage2aRun.Derive(
            directory,
            ExpansionBudget.Bulk,
            Started,
            Stage2aRun.Unwatched,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.False(result.IsSuccess);
    }

    /// <summary>
    /// Every phase writes a row, whatever became of it.
    /// </summary>
    /// <remarks>
    /// The check that stops a silent store. Four phases are scheduled and four rows appear, so an
    /// empty closure can always be explained.
    /// </remarks>
    [Fact]
    public void Stage2a_EveryScheduledPhaseIsRecorded()
    {
        var writer = NewStore(out var directory);

        writer.RecordPhase(MembershipNestingPass.PhaseName, DerivationPhaseOutcome.Succeeded, error: null);
        writer.RecordPhase("AuthorizationMembership", DerivationPhaseOutcome.Succeeded, error: null);
        writer.RecordPhase(ProtectedPrincipalDeriver.PhaseName, DerivationPhaseOutcome.DidNotRun, error: null);
        writer.RecordPhase(LatentPrivilegeDeriver.PhaseName, DerivationPhaseOutcome.Succeeded, error: null);
        writer.WriteSids([], []);
        writer.Complete(Started);
        writer.Dispose();

        Assert.Equal(4, CountOf(directory, "SELECT COUNT(*) FROM derivation_phase"));
    }

    /// <summary>
    /// A phase that never ran says so, rather than being absent or blamed.
    /// </summary>
    /// <remarks>
    /// <c>DidNotRun</c> and <c>Failed</c> are different sentences. A phase whose input never
    /// arrived has not misbehaved, and recording it as failed would send whoever reads it looking
    /// in the wrong place.
    /// </remarks>
    [Fact]
    public void Stage2a_APhaseThatNeverRanSaysSoRatherThanFailing()
    {
        var writer = NewStore(out var directory);

        writer.RecordPhase(MembershipNestingPass.PhaseName, DerivationPhaseOutcome.Failed, "The bundle could not be read.");
        writer.RecordPhase(LatentPrivilegeDeriver.PhaseName, DerivationPhaseOutcome.DidNotRun, error: null);
        writer.WriteSids([], []);
        writer.Complete(Started);
        writer.Dispose();

        Assert.Equal(
            DerivationPhaseOutcome.DidNotRun.ToString(),
            ScalarOf(
                directory,
                $"SELECT outcome FROM derivation_phase WHERE phase = '{LatentPrivilegeDeriver.PhaseName}'"));
    }

    /// <summary>
    /// A failed phase leaves its reason behind.
    /// </summary>
    /// <remarks>
    /// A phase failing is the likeliest thing to need diagnosing months later, with the process
    /// gone and the operator unavailable.
    /// </remarks>
    [Fact]
    public void Stage2a_AFailedPhaseLeavesItsReason()
    {
        var writer = NewStore(out var directory);

        writer.RecordPhase(MembershipNestingPass.PhaseName, DerivationPhaseOutcome.Failed, "Out of memory expanding.");
        writer.WriteSids([], []);
        writer.Complete(Started);
        writer.Dispose();

        Assert.Equal(
            "Out of memory expanding.",
            ScalarOf(directory, "SELECT error FROM derivation_phase"));
    }

    /// <summary>
    /// One failed phase leaves the run degraded rather than failed, and the store still readable.
    /// </summary>
    /// <remarks>
    /// Deriving is the most expensive thing this product does. Discarding three good phases over
    /// one bad one would be paid for again on the next attempt, and a store that says what went
    /// wrong is worth more than no store.
    /// </remarks>
    [Fact]
    public void Stage2a_OneFailedPhaseLeavesTheRunDegradedAndTheStoreReadable()
    {
        var writer = NewStore(out var directory);

        writer.RecordPhase(MembershipNestingPass.PhaseName, DerivationPhaseOutcome.Succeeded, error: null);
        writer.RecordPhase(LatentPrivilegeDeriver.PhaseName, DerivationPhaseOutcome.Failed, "Threw.");
        writer.WriteSids([], []);
        writer.Complete(Started);
        writer.Dispose();

        Assert.True(AnalysisStoreLifecycle.Resolve(
            directory, AnalysisStoreKind.Derivation).IsSuccess);
        Assert.Equal(
            DerivationRunState.CompletedDegraded.ToString(),
            ScalarOf(directory, "SELECT state FROM derivation"));
    }

    [Fact]
    public void Stage2a_MissingDeclaredDomainMakesReturnedAndStoredStateDegraded()
    {
        var directory = NewDirectory();
        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.Complete(
                RunCoverage.Of(
                    CoverageId.ForDomainsExcluding(
                        "ad.lab", ["ad.lab", "child.ad.lab"], ["child.ad.lab"]),
                    [
                        DomainCoverage.Read("ad.lab"),
                        DomainCoverage.Excluded(
                            "child.ad.lab",
                            ExclusionKind.ByChoice,
                            "Excluded for this reproduction."),
                    ],
                    [
                        ForestPartitionCoverage.Read(
                            "CN=Configuration,DC=ad,DC=lab", NamingContextKind.Configuration),
                        ForestPartitionCoverage.Read(
                            "CN=Schema,CN=Configuration,DC=ad,DC=lab", NamingContextKind.Schema),
                    ],
                    SysvolCoverage.Of([])),
                Started.AddMinutes(1));
        }

        var result = Stage2aRun.Derive(
            directory,
            ExpansionBudget.Bulk,
            Started.AddMinutes(2),
            Stage2aRun.Unwatched,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal(DerivationRunState.CompletedDegraded, result.Value);

        using var reader = DerivationReader.Open(directory).Value!;
        var stored = reader.Read();
        Assert.Equal(DerivationRunState.CompletedDegraded, stored.Description.State);
        Assert.False(stored.Completeness.IsComplete);
    }

    /// <summary>
    /// Progress nobody is watching is a named choice, and it does not throw.
    /// </summary>
    [Fact]
    public void Stage2a_UnwatchedProgressIsNamedAndHarmless()
    {
        Stage2aRun.Unwatched.Report(new DerivationProgress("Anything", 1));
    }

    private static DerivationWriter NewStore(out string directory)
    {
        directory = NewDirectory();
        return DerivationWriter.Create(directory, "0f9c1d2e3a4b5c6d", Started);
    }

    private static string NewDirectory()
    {
        var directory = TempDirectories.Create("stage2a-tests");

        Directory.CreateDirectory(directory);
        return directory;
    }

    private static string ScalarOf(string directory, string sql) =>
        Read(directory, sql)?.ToString() ?? throw new InvalidOperationException($"'{sql}' read nothing.");

    private static long CountOf(string directory, string sql) =>
        Convert.ToInt64(Read(directory, sql), System.Globalization.CultureInfo.InvariantCulture);

    private static object? Read(string directory, string sql)
    {
        using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = CurrentDataPath(directory),
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());

        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    private static string CurrentDataPath(string directory)
    {
        var generation = AnalysisStoreLifecycle
            .Resolve(directory, AnalysisStoreKind.Derivation)
            .Value!;
        return BundleLayout.AnalysisGenerationDataPath(
            directory, generation.Kind, generation.GenerationId);
    }
}
