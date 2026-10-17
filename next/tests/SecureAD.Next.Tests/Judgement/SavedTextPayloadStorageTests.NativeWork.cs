using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class SavedTextPayloadStorageTests
{
    [Theory]
    [InlineData(StoreSegmentRole.JudgementFacts)]
    [InlineData(StoreSegmentRole.PermissionProof)]
    public void ColdTextHeadersDoNotReadUnrequestedNativeOverflowBodies(StoreSegmentRole role)
    {
        var store = Store(role);
        var directory = TempDirectories.Create("saved-text-native");
        var path = Path.Combine(directory, "payload.db");
        long id;
        RequestedDetailManifest manifest;
        using (var connection = Open(path))
        {
            Execute(connection, "PRAGMA page_size=4096");
            store.CreateTables(connection);
            id = Write(connection, store, new string('x', 128 * 65536 + 17));
            manifest = Prepare(connection, store);
        }
        using (var warm = ColdReader())
            RequestedDetailIndex.Open(warm, "main", manifest).ReadPage(store.Chunks, id);
        ulong fullReads;
        using (var connection = ColdReader())
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"SELECT data FROM {store.Chunks} WHERE payload_id=$id AND ordinal<50 ORDER BY ordinal";
            command.Parameters.AddWithValue("$id", id);
            var before = PathProofStorageTests.ProcessReadBytes();
            using (var read = command.ExecuteReader())
            {
                long bytes = 0;
                while (read.Read()) bytes += ((byte[])read.GetValue(0)).Length;
                Assert.Equal(50L * 65536, bytes);
            }
            fullReads = checked(PathProofStorageTests.ProcessReadBytes() - before);
        }
        Assert.True(fullReads >= 50UL * (65536 - 4096),
            "The positive control must observe real native payload work.");
        using (var connection = ColdReader())
        {
            var reader = RequestedDetailIndex.Open(connection, "main", manifest);
            var before = PathProofStorageTests.ProcessReadBytes();
            var page = reader.ReadPage(store.Chunks, id);
            Assert.Equal((129L, 50), (page.TotalRows, page.Rows.Count));
            Assert.All(page.Rows, row => Assert.Equal(65536, row.Value("data").ByteLength));
            var headers = checked(PathProofStorageTests.ProcessReadBytes() - before);
            output.WriteLine(JsonSerializer.Serialize(new
            {
                Role = role, HeaderReadBytes = headers, PayloadReadBytes = fullReads,
                JudgementMvid = typeof(JudgingRun).Assembly.ManifestModule.ModuleVersionId,
                TestMvid = typeof(SavedTextPayloadStorageTests).Assembly.ManifestModule.ModuleVersionId,
            }));
            Assert.InRange(headers, 1UL, (2UL * RequestedDetailIndex.MaximumRows + 32) * 4096);
        }

        SqliteConnection ColdReader()
        {
            var connection = Open(path, readOnly: true);
            Execute(connection, "PRAGMA mmap_size=0; PRAGMA cache_size=-8; PRAGMA shrink_memory");
            return connection;
        }
    }

    [Theory]
    [InlineData(StoreSegmentRole.JudgementFacts, true)]
    [InlineData(StoreSegmentRole.PermissionProof, true)]
    [InlineData(StoreSegmentRole.JudgementFacts, false)]
    [InlineData(StoreSegmentRole.PermissionProof, false)]
    public void TextCostControlIncludesWritingValidationPreparationSealAndWholeReadback(StoreSegmentRole role, bool sourceOwned)
    {
        var store = Store(role);
        var value = new string('x', 128 * 65536 + 17) + "\U0001f512\0";
        var path = Path.Combine(TempDirectories.Create("saved-text-cost"), "payload.db");
        var before = GC.GetAllocatedBytesForCurrentThread();
        var clock = Stopwatch.StartNew();
        long id, logicalBytes;
        RequestedDetailManifest manifest;
        TimeSpan written, validated, prepared;
        using (var connection = Open(path))
        {
            Execute(connection, "PRAGMA journal_mode=WAL");
            store.CreateTables(connection);
            id = Write(connection, store, value);
            written = clock.Elapsed;
            store.RequirePublishable(connection, CancellationToken.None);
            validated = clock.Elapsed;
            manifest = RequestedDetailIndex.Prepare(connection, "main", role, JudgementSchema.Version,
                Guid.NewGuid(), new string('a', 64), CancellationToken.None,
                sourceOwned ? store.RequestedPayloads : []);
            prepared = clock.Elapsed;
            using (var checkpoint = connection.CreateCommand())
            {
                checkpoint.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
                using var read = checkpoint.ExecuteReader();
                Assert.True(read.Read());
                Assert.Equal(0, read.GetInt64(0));
            }
            using var size = connection.CreateCommand();
            size.CommandText = "SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size()";
            logicalBytes = (long)size.ExecuteScalar()!;
        }
        BundleSealing.Seal(path, path + ".seal");
        var sealedAt = clock.Elapsed;
        using (var connection = Open(path, readOnly: true))
        {
            var reader = RequestedDetailIndex.Open(connection, "main", manifest);
            var decoder = new UTF8Encoding(false, true).GetDecoder();
            var characters = new char[65537];
            var text = new StringBuilder();
            long pieces = 0;
            foreach (var row in reader.ReadCompleteScope(store.Chunks, id))
            {
                var bytes = row.CompleteBytes("data");
                var count = decoder.GetChars(bytes, characters, flush: bytes.Length < 65536);
                text.Append(characters, 0, count);
                pieces++;
            }
            Assert.Equal(value, text.ToString());
            Assert.Equal(129, pieces);
        }
        var finished = clock.Elapsed;
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal(logicalBytes, new FileInfo(path).Length);
        Assert.Equal(BundleSealing.ReadSeal(path + ".seal")!.Hash, BundleSealing.HashFile(path));
        output.WriteLine(JsonSerializer.Serialize(new
        {
            Role = role, Control = sourceOwned ? "source-owned" : "same-source generic preparation, not original application",
            WriteMs = written.TotalMilliseconds, ValidationMs = (validated - written).TotalMilliseconds,
            PrepareMs = (prepared - validated).TotalMilliseconds, CheckpointCloseSealMs = (sealedAt - prepared).TotalMilliseconds,
            ReadMs = (finished - sealedAt).TotalMilliseconds, TotalMs = finished.TotalMilliseconds,
            AllocatedBytes = allocated,
            LogicalBytes = logicalBytes, PayloadBytes = Encoding.UTF8.GetByteCount(value),
            JudgementMvid = typeof(JudgingRun).Assembly.ManifestModule.ModuleVersionId,
            TestMvid = typeof(SavedTextPayloadStorageTests).Assembly.ManifestModule.ModuleVersionId,
            Limitation = "Native text mechanism control, not complete audit/publication acceptance; cumulative thread allocation, not peak memory.",
        }));
    }

    private static SqliteConnection Open(string path, bool readOnly = false)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path, Pooling = false, Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWriteCreate,
        }.ToString());
        connection.Open();
        return connection;
    }
}
