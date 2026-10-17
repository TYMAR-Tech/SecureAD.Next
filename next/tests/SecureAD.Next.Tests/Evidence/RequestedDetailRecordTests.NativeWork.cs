using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

public sealed partial class RequestedDetailRecordTests
{
    [Fact]
    public void NativeRecordPreparationReadsMetadataInsteadOfTheLargeOriginalBodies()
    {
        using (var warm = Database())
        {
            Write(warm, 1, "warm", [1, 2, 3]);
            Prepare(warm, [Layout]);
        }
        var directory = TempDirectories.Create("record-native-work");
        using var source = Database(Path.Combine(directory, "source.db"));
        var text = new string('x', 4 * 65536 - 1) + "\U0001f512\0\uFEFF";
        var bytes = Enumerable.Range(0, 128 * 65536 + 17).Select(value => (byte)value).ToArray();
        Write(source, 1, text, bytes);
        var metadataBytes = Scalar(source, $"SELECT SUM(byte_length) FROM temp.{RequestedDetailRecordWriter.Records} WHERE ordinal=0");
        using var generic = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(directory, "generic.db"), Pooling = false,
        }.ToString());
        generic.Open();
        source.BackupDatabase(generic);
        foreach (var connection in new[] { source, generic })
            Execute(connection, "PRAGMA mmap_size=0;PRAGMA cache_size=-8;PRAGMA shrink_memory");
        var before = PathProofStorageTests.ProcessReadBytes();
        var baseline = Prepare(generic, []);
        var genericReads = checked(PathProofStorageTests.ProcessReadBytes() - before);
        Assert.True(genericReads >= (ulong)bytes.Length - 4096,
            "The deliberate generic control must observe actual original payload reads.");
        before = PathProofStorageTests.ProcessReadBytes();
        var owned = Prepare(source, [Layout]);
        var ownedReads = checked(PathProofStorageTests.ProcessReadBytes() - before);
        Assert.Equal(baseline, owned);
        Assert.InRange(ownedReads, 1UL, 32UL * 65536);
        var reader = RequestedDetailIndex.Open(source, "main", owned);
        var row = Assert.IsType<RequestedDetailRow>(reader.ReadSingle(Layout.Table, 1L));
        Assert.Equal(text, row.CompleteText("text"));
        Assert.Equal(bytes, row.CompleteBytes("data"));
        output.WriteLine(JsonSerializer.Serialize(new
        {
            NativeProducerMetadataReadBytes = ownedReads, NativeGenericPayloadReadBytes = genericReads,
            ProducerMetadataBytes = metadataBytes, OriginalBinaryBytes = bytes.Length,
            OriginalTextBytes = Encoding.UTF8.GetByteCount(text),
            EvidenceMvid = typeof(RequestedDetailIndex).Assembly.ManifestModule.ModuleVersionId,
            TestMvid = typeof(RequestedDetailRecordTests).Assembly.ManifestModule.ModuleVersionId,
        }));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RecordCostIncludesProducingMetadataPreparationSealAndCompleteReadback(bool sourceOwned)
    {
        const int rows = 256;
        var text = new string('x', 2048) + "\u00e9\0\uFEFF";
        var textBytes = Encoding.UTF8.GetBytes(text);
        var data = Enumerable.Range(0, 256).Select(value => (byte)value).ToArray();
        var binding = SHA256.HashData(data);
        var path = Path.Combine(TempDirectories.Create("record-cost"), "original.db");
        var before = GC.GetAllocatedBytesForCurrentThread();
        var clock = Stopwatch.StartNew();
        RequestedDetailManifest manifest;
        TimeSpan written, prepared;
        long logicalBytes, stagedBytes;
        using (var source = Database(path))
        {
            Execute(source, "PRAGMA journal_mode=WAL");
            using (var writer = new RequestedDetailRecordWriter(source))
            using (var transaction = source.BeginTransaction())
            using (var insert = source.CreateCommand())
            {
                insert.Transaction = transaction;
                insert.CommandText = "INSERT INTO original_record VALUES($id,'Object',7,1,CAST($text AS TEXT),$data,$binding)";
                insert.Parameters.Add("$id", SqliteType.Integer);
                insert.Parameters.AddWithValue("$text", textBytes);
                insert.Parameters.AddWithValue("$data", data);
                insert.Parameters.AddWithValue("$binding", binding);
                for (var id = 1; id <= rows; id++)
                {
                    insert.Parameters["$id"].Value = id;
                    Assert.Equal(1, insert.ExecuteNonQuery());
                    if (sourceOwned)
                        writer.Write(transaction, "main", Layout, id,
                            [id, "Object", 7, true, new RequestedDetailRecordWriter.EncodedText(text, textBytes), data, binding]);
                }
                transaction.Commit();
            }
            written = clock.Elapsed;
            stagedBytes = Scalar(source, $"SELECT COALESCE(SUM(byte_length),0) FROM temp.{RequestedDetailRecordWriter.Records} WHERE ordinal=0");
            manifest = Prepare(source, sourceOwned ? [Layout] : []);
            prepared = clock.Elapsed;
            using (var checkpoint = source.CreateCommand())
            {
                checkpoint.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
                using var read = checkpoint.ExecuteReader();
                Assert.True(read.Read());
                Assert.Equal(0, read.GetInt64(0));
            }
            logicalBytes = Scalar(source, "SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size()");
        }
        BundleSealing.Seal(path, path + ".seal");
        var sealedAt = clock.Elapsed;
        using (var source = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString()))
        {
            source.Open();
            var reader = RequestedDetailIndex.Open(source, "main", manifest);
            Assert.Equal(rows, reader.ReadRowCount(Layout.Table));
            for (var id = 1; id <= rows; id++)
            {
                var row = Assert.IsType<RequestedDetailRow>(reader.ReadSingle(Layout.Table, (long)id));
                Assert.Equal(text, row.CompleteText("text"));
                Assert.Equal(data, row.CompleteBytes("data"));
            }
        }
        var completed = clock.Elapsed;
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal(logicalBytes, new FileInfo(path).Length);
        output.WriteLine(JsonSerializer.Serialize(new
        {
            Control = sourceOwned ? "producer-written record metadata" : "generic field preparation without producer metadata",
            Rows = rows, WriteIncludingMetadataMs = written.TotalMilliseconds,
            PrepareMs = (prepared - written).TotalMilliseconds,
            CheckpointCloseSealMs = (sealedAt - prepared).TotalMilliseconds,
            WholeReadbackMs = (completed - sealedAt).TotalMilliseconds, TotalMs = completed.TotalMilliseconds,
            AllocatedBytes = allocated, LogicalBytes = logicalBytes, TemporaryMetadataBytes = stagedBytes,
            EvidenceMvid = typeof(RequestedDetailIndex).Assembly.ManifestModule.ModuleVersionId,
            TestMvid = typeof(RequestedDetailRecordTests).Assembly.ManifestModule.ModuleVersionId,
            Limitation = "Focused native record control, not the lab forest or production acceptance; cumulative thread allocation, not peak RAM.",
        }));
    }
}
