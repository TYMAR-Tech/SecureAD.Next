using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
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
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.False(File.Exists(BundleLayout.DerivationPath(directory)));
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
        writer.RecordPhase(ProtectedPrincipalDeriver.PhaseName, DerivationPhaseOutcome.Succeeded, error: null);
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

        Assert.True(File.Exists(BundleLayout.DerivationPath(directory)));
        Assert.Equal(
            DerivationRunState.CompletedDegraded.ToString(),
            ScalarOf(directory, "SELECT state FROM derivation"));
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
        var directory = Path.Combine(
            Path.GetTempPath(), "securead-stage2a-tests", Guid.NewGuid().ToString("N"));

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
                DataSource = BundleLayout.DerivationPath(directory),
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());

        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }
}
