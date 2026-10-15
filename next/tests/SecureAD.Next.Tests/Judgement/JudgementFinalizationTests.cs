using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class JudgementFinalizationTests
{
    private static readonly DateTimeOffset When = DateTimeOffset.UnixEpoch;
    private static readonly StoreSegmentRole[] Roles =
        [StoreSegmentRole.Judgement, .. BundleLayout.JudgementParts];
    private static readonly string Evidence = new('a', 64);

    [Fact]
    public void WriterUsesItsUnselectedGenerationPathsFromCreationThroughPublicationWithoutMoves()
    {
        var directory = TempDirectories.Create("generation-finalization");
        using var writer = JudgementWriter.Create(directory, Evidence, null, When, When);
        var generation = new AnalysisStoreGeneration(AnalysisStoreKind.Judgement, writer.GenerationId);
        Assert.Equal(generation, TestSealing.PendingJudgementGeneration(directory));
        Assert.True(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, generation.Kind));
        Assert.False(AnalysisStoreLifecycle.Resolve(directory, generation.Kind).IsSuccess);
        var handles = new List<FileStream>();
        try
        {
            foreach (var role in Roles)
            {
                var path = BundleLayout.AnalysisSegmentDataPath(directory, generation, role);
                Assert.True(File.Exists(path));
                Assert.False(File.Exists(path + ".seal"));
                // Deny renaming from before completion, without holding a SQLite read snapshot.
                handles.Add(new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
            }

            writer.Complete(When);

            var root = AnalysisStoreLifecycle.ResolveRoot(directory, generation.Kind).Value;
            Assert.Equal(generation.GenerationId, root.GenerationId);
            Assert.Equal(Roles, root.Segments.Select(segment => segment.Role));
            Assert.False(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, generation.Kind));
            foreach (var segment in root.Segments)
            {
                var path = BundleLayout.AnalysisSegmentDataPath(directory, generation, segment.Role);
                Assert.Equal(Path.GetFileName(path), segment.FileName);
                Assert.Equal(BundleSealing.HashFile(path), segment.Hash);
                Assert.Equal(segment.Hash, BundleSealing.ReadSeal(path + ".seal")!.Hash);
                Assert.False(File.Exists(path + "-wal"));
            }
        }
        finally { foreach (var handle in handles) handle.Dispose(); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RetryingAnUnpublishedAttemptPreservesEveryEarlierGenerationFile(bool abandon)
    {
        var directory = TempDirectories.Create("generation-retry");
        AnalysisStoreGeneration first;
        using (var writer = JudgementWriter.Create(directory, Evidence, null, When, When))
        {
            first = new(AnalysisStoreKind.Judgement, writer.GenerationId);
            if (abandon) writer.Abandon(When);
        }
        var hashes = Roles.Select(role => BundleSealing.HashFile(
            BundleLayout.AnalysisSegmentDataPath(directory, first, role))).ToArray();
        using var retry = JudgementWriter.Create(directory, Evidence, null, When, When);

        Assert.NotEqual(first.GenerationId, retry.GenerationId);
        Assert.Equal(retry.GenerationId, TestSealing.PendingJudgementGeneration(directory).GenerationId);
        Assert.Equal(hashes, Roles.Select(role => BundleSealing.HashFile(
            BundleLayout.AnalysisSegmentDataPath(directory, first, role))));
        Assert.False(AnalysisStoreLifecycle.Resolve(directory, first.Kind).IsSuccess);
    }

    [Fact]
    public void PublicationProtectsEveryUnmovedProductBeforeSealingOrSelectingTheRoot()
    {
        var directory = TempDirectories.Create("generation-protection");
        var generation = Guid.NewGuid();
        var paths = CreateUnselectedProducts(directory, generation);
        var reached = false;

        Publish(directory, generation, part =>
        {
            if (part != AnalysisPublicationPart.SealData) return;
            reached = true;
            Assert.False(AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).IsSuccess);
            foreach (var path in paths)
            {
                Assert.Equal("complete " + Path.GetFileName(path), File.ReadAllText(path));
                Assert.Throws<IOException>(() => File.AppendAllText(path, "unsealed change"));
                Assert.Throws<IOException>(() => File.Delete(path));
                Assert.False(File.Exists(path + ".seal"));
            }
        });

        Assert.True(reached);
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        Assert.Equal(paths.Select(Path.GetFileName), root.Segments.Select(segment => segment.FileName));
        Assert.All(root.Segments, segment => Assert.Equal(BundleSealing.HashFile(
            Path.Combine(directory, segment.FileName)), segment.Hash));
    }

    [Theory]
    [InlineData(StoreSegmentRole.Judgement)]
    [InlineData(StoreSegmentRole.PermissionProof)]
    [InlineData(StoreSegmentRole.PathProof)]
    [InlineData(StoreSegmentRole.JudgementFacts)]
    public void ANonemptyProductWalCannotReplaceThePreviousCompletedRoot(StoreSegmentRole role)
    {
        var directory = TempDirectories.Create("generation-wal-refusal");
        using (var writer = JudgementWriter.Create(directory, Evidence, null, When, When))
            writer.Complete(When);
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement);
        var previous = File.ReadAllBytes(manifest);
        var generation = Guid.NewGuid();
        CreateUnselectedProducts(directory, generation);
        var path = BundleLayout.AnalysisSegmentDataPath(directory,
            new(AnalysisStoreKind.Judgement, generation), role);
        File.WriteAllText(path + "-wal", "uncheckpointed bytes");

        Assert.Throws<InvalidDataException>(() => Publish(directory, generation));

        Assert.Equal(previous, File.ReadAllBytes(manifest));
        Assert.True(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, AnalysisStoreKind.Judgement));
        Assert.False(File.Exists(path + ".seal"));
    }

    [Fact]
    public void OneCheckpointPersistsAndTruncatesEveryProductWalWhileTheWriterIsStillOpen()
    {
        using var products = new WalProducts();
        foreach (var path in products.Paths)
            Assert.True(new FileInfo(path + "-wal").Length > 0);

        JudgementStoreLayout.Checkpoint(products.Connection);

        foreach (var path in products.Paths)
        {
            Assert.Equal(0, new FileInfo(path + "-wal").Length);
            var snapshot = path + ".checkpointed";
            File.Copy(path, snapshot);
            using var read = Connect(snapshot, SqliteOpenMode.ReadOnly);
            using var query = read.CreateCommand();
            query.CommandText = "SELECT value FROM finalization_value";
            Assert.Equal(42L, query.ExecuteScalar());
        }
        Assert.Equal(System.Data.ConnectionState.Open, products.Connection.State);
    }

    [Theory]
    [InlineData(StoreSegmentRole.Judgement)]
    [InlineData(StoreSegmentRole.PermissionProof)]
    [InlineData(StoreSegmentRole.PathProof)]
    [InlineData(StoreSegmentRole.JudgementFacts)]
    public void ABlockedCheckpointInAnyProductIsExplicitlyRefused(StoreSegmentRole role)
    {
        using var products = new WalProducts();
        JudgementStoreLayout.Checkpoint(products.Connection);
        var path = products.Paths[Array.IndexOf(Roles, role)];
        using var read = Connect(path, SqliteOpenMode.ReadOnly);
        using var query = read.CreateCommand();
        query.CommandText = "SELECT value FROM finalization_value";
        using var rows = query.ExecuteReader();
        Assert.True(rows.Read());
        Assert.Equal(42L, rows.GetInt64(0));
        using var write = products.Connection.CreateCommand();
        write.CommandText = $"INSERT INTO \"{JudgementStoreLayout.Schema(role)}\".finalization_value VALUES(99)";
        write.ExecuteNonQuery();

        Assert.Throws<InvalidOperationException>(() => JudgementStoreLayout.Checkpoint(products.Connection));

        Assert.True(new FileInfo(path + "-wal").Length > 0);
    }

    [Theory]
    [InlineData(StoreSegmentRole.PermissionProof)]
    [InlineData(StoreSegmentRole.PathProof)]
    [InlineData(StoreSegmentRole.JudgementFacts)]
    public void CreatingAProductNeverReplacesAnExistingGenerationFile(StoreSegmentRole role)
    {
        var directory = TempDirectories.Create("generation-collision");
        var generation = Guid.NewGuid();
        var path = BundleLayout.AnalysisSegmentDataPath(directory,
            new(AnalysisStoreKind.Judgement, generation), role);
        File.WriteAllText(path, "previous immutable bytes");
        using var connection = Connect(Path.Combine(directory, "writer.db"));

        Assert.Throws<IOException>(() => JudgementStoreLayout.Create(connection, directory, generation, Evidence, null));

        Assert.Equal("previous immutable bytes", File.ReadAllText(path));
    }

    private static string[] CreateUnselectedProducts(string directory, Guid generation)
    {
        AnalysisStoreLifecycle.BeginAttempt(directory, AnalysisStoreKind.Judgement, generation);
        var paths = Roles.Select(role => BundleLayout.AnalysisSegmentDataPath(directory,
            new(AnalysisStoreKind.Judgement, generation), role)).ToArray();
        foreach (var path in paths) File.WriteAllText(path, "complete " + Path.GetFileName(path));
        return paths;
    }

    private static void Publish(string directory, Guid generation, Action<AnalysisPublicationPart>? beginPart = null) =>
        AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement, generation, CancellationToken.None,
            beginPart, null, JudgementSchema.Version, Evidence, null, BundleLayout.JudgementParts);

    private static SqliteConnection Connect(string path, SqliteOpenMode mode = SqliteOpenMode.ReadWriteCreate)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = path, Mode = mode, Pooling = false, DefaultTimeout = 1 }.ToString());
        connection.Open();
        return connection;
    }

    private sealed class WalProducts : IDisposable
    {
        internal SqliteConnection Connection { get; }
        internal string[] Paths { get; }

        internal WalProducts()
        {
            var directory = TempDirectories.Create("generation-checkpoint");
            var generation = Guid.NewGuid();
            Paths = Roles.Select(role => BundleLayout.AnalysisSegmentDataPath(directory,
                new(AnalysisStoreKind.Judgement, generation), role)).ToArray();
            Connection = Connect(Paths[0]);
            using var pragma = Connection.CreateCommand();
            pragma.CommandText = "PRAGMA journal_mode=WAL";
            pragma.ExecuteNonQuery();
            JudgementStoreLayout.Create(Connection, directory, generation, Evidence, null);
            foreach (var role in Roles)
            {
                pragma.CommandText = $"""
                    CREATE TABLE "{JudgementStoreLayout.Schema(role)}".finalization_value(value INTEGER NOT NULL);
                    INSERT INTO "{JudgementStoreLayout.Schema(role)}".finalization_value VALUES(42);
                    """;
                pragma.ExecuteNonQuery();
            }
        }

        public void Dispose() => Connection.Dispose();
    }
}
