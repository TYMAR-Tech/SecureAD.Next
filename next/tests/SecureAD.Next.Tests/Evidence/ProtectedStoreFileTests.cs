using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

public sealed class ProtectedStoreFileTests
{
    [Fact]
    public void AcquiredConnectionsRemainIndependent()
    {
        var (directory, generation) = CreateStore();
        using var file = ProtectedStoreFile.OpenAnalysis(directory, generation).Value;
        using var first = file.Acquire();
        using var second = file.Acquire();

        first.Dispose();
        using var query = second.Connection.CreateCommand();
        query.CommandText = "SELECT value FROM answer";

        Assert.Equal(42L, query.ExecuteScalar());
    }

    [Fact]
    public void VerifiedDatabaseCannotBeChangedWhileOpen()
    {
        var (directory, generation) = CreateStore();
        using var file = ProtectedStoreFile.OpenAnalysis(directory, generation).Value;

        Assert.Throws<IOException>(() => File.WriteAllText(Data(directory, generation), "changed"));
    }

    [Fact]
    public void VerifiedSealCannotBeChangedWhileOpen()
    {
        var (directory, generation) = CreateStore();
        using var file = ProtectedStoreFile.OpenAnalysis(directory, generation).Value;

        Assert.Throws<IOException>(() => File.WriteAllText(BundleLayout.AnalysisGenerationSealPath(directory,
            generation.Kind, generation.GenerationId), "changed"));
    }

    [Fact]
    public void ActiveLeaseKeepsProtectionAfterStoreClosure()
    {
        var (directory, generation) = CreateStore();
        using var file = ProtectedStoreFile.OpenAnalysis(directory, generation).Value;
        using var lease = file.Acquire();

        file.Dispose();

        Assert.Throws<IOException>(() => File.WriteAllText(Data(directory, generation), "changed"));
    }

    [Fact]
    public void FinalLeaseReleaseAllowsFileReplacement()
    {
        var (directory, generation) = CreateStore();
        using var file = ProtectedStoreFile.OpenAnalysis(directory, generation).Value;
        using var lease = file.Acquire();
        file.Dispose();
        lease.Dispose();

        File.WriteAllText(Data(directory, generation), "replacement");

        Assert.Equal("replacement", File.ReadAllText(Data(directory, generation)));
    }

    [Fact]
    public void ClosedStoreCannotIssueAnotherLease()
    {
        var (directory, generation) = CreateStore();
        using var file = ProtectedStoreFile.OpenAnalysis(directory, generation).Value;
        file.Dispose();

        Assert.Throws<ObjectDisposedException>(() => file.Acquire());
    }

    [Fact]
    public void CorruptedStoreIsNotOpened()
    {
        var (directory, generation) = CreateStore();
        File.AppendAllText(Data(directory, generation), "changed");

        var opened = ProtectedStoreFile.OpenAnalysis(directory, generation);

        Assert.Equal("Evidence.ProtectedStoreMismatch", opened.Error?.Code);
    }

    [Fact]
    public void CancelledOpeningDoesNotAcquireTheFile()
    {
        var (directory, generation) = CreateStore();
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();

        Assert.Throws<OperationCanceledException>(() => ProtectedStoreFile.OpenAnalysis(directory, generation, stopping.Token));
    }

    [Fact]
    public void LeaseDoesNotIncorporateUnsealedWalBytes()
    {
        var directory = TempDirectories.Create("wal-boundary");
        var scratch = Path.Combine(directory, "writer.db");
        using var writer = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = scratch, Pooling = false }.ToString());
        writer.Open();
        using var write = writer.CreateCommand();
        write.CommandText = "PRAGMA journal_mode=WAL; CREATE TABLE answer(value INTEGER); INSERT INTO answer VALUES(42); PRAGMA wal_checkpoint(TRUNCATE);";
        write.ExecuteNonQuery();
        File.Copy(scratch, AnalysisStoreLifecycle.StagingPath(directory, AnalysisStoreKind.Judgement));
        var generation = AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement, Guid.NewGuid());
        write.CommandText = "INSERT INTO answer VALUES(99)";
        write.ExecuteNonQuery();
        File.Copy(scratch + "-wal", Data(directory, generation) + "-wal");
        using var unprotected = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = Data(directory, generation), Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        unprotected.Open();
        using var unverified = unprotected.CreateCommand();
        unverified.CommandText = "SELECT MAX(value) FROM answer";
        var withWal = unverified.ExecuteScalar();
        unprotected.Close();
        using var file = ProtectedStoreFile.OpenAnalysis(directory, generation).Value;
        using var lease = file.Acquire();
        using var query = lease.Connection.CreateCommand();
        query.CommandText = "SELECT MAX(value) FROM answer";

        Assert.Equal((99L, 42L), (withWal, query.ExecuteScalar()));
    }

    [Fact]
    public async Task CancellationInterruptsAnExecutingStatement()
    {
        var (directory, generation) = CreateStore();
        using var stopping = new CancellationTokenSource();
        using var file = ProtectedStoreFile.OpenAnalysis(directory, generation).Value;
        using var lease = file.Acquire(stopping.Token);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        lease.Connection.CreateFunction("started", () => { started.TrySetResult(); return 1; });
        using var query = lease.Connection.CreateCommand();
        query.CommandText = "WITH RECURSIVE work(n) AS (SELECT started() UNION ALL SELECT n+1 FROM work WHERE n<1000000000) SELECT SUM(n) FROM work";
        var reading = Task.Run(() => query.ExecuteScalar());
        try
        {
            await started.Task.WaitAsync(TimeSpan.FromSeconds(15));
            stopping.Cancel();
            var error = await Record.ExceptionAsync(async () => await reading.WaitAsync(TimeSpan.FromSeconds(5)));

            Assert.Equal((typeof(SqliteException), 9), (error?.GetType(), (error as SqliteException)?.SqliteErrorCode));
        }
        finally
        {
            // A deliberate cancellation defect must not leave the synthetic query running.
            SQLitePCL.raw.sqlite3_interrupt(lease.Connection.Handle);
            await reading.ContinueWith(task => _ = task.Exception, TaskScheduler.Default);
        }
    }

    private static (string Directory, AnalysisStoreGeneration Generation) CreateStore()
    {
        var directory = Path.Combine(TempDirectories.Create("protected-store"), "spaces # %");
        Directory.CreateDirectory(directory);
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = AnalysisStoreLifecycle.StagingPath(directory, AnalysisStoreKind.Judgement), Pooling = false }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE answer(value INTEGER NOT NULL); INSERT INTO answer VALUES (42);";
            command.ExecuteNonQuery();
        }
        var generation = AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement, Guid.NewGuid());
        return (directory, generation);
    }

    private static string Data(string directory, AnalysisStoreGeneration generation) =>
        BundleLayout.AnalysisGenerationDataPath(directory, generation.Kind, generation.GenerationId);
}
