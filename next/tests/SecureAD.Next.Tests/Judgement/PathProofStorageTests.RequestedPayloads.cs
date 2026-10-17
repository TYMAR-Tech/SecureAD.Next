using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Architecture;
using SQLitePCL;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Judgement;

[Collection(nameof(PathProofNativeIoCollection))]
public sealed partial class PathProofStorageTests
{
    private readonly ITestOutputHelper _output;

    public PathProofStorageTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void FinalPayloadPiecesCarryHashesOfExactlyTheWrittenBytes()
    {
        using var connection = Database();
        var value = new string('x', 2 * PathProofStorage.ChunkSize + 17) + "\u00e9\u6f22\U0001f512\0";
        var saved = Write(connection, value);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT data,byte_length,fingerprint FROM path_proof_chunk ORDER BY ordinal";
        using var read = command.ExecuteReader();
        var chunks = 0;
        var length = 0L;
        while (read.Read())
        {
            var bytes = (byte[])read.GetValue(0);
            Assert.Equal(bytes.LongLength, read.GetInt64(1));
            Assert.Equal(SHA256.HashData(bytes), (byte[])read.GetValue(2));
            chunks++;
            length += bytes.Length;
        }
        Assert.True(chunks > 2);
        Assert.Equal(JsonSerializer.SerializeToUtf8Bytes(value, ProofSerialization.Options).LongLength, length);
        Assert.Equal(SHA256.HashData(Bytes(connection, saved.Id)), saved.Fingerprint);
    }

    [Fact]
    public void SourceOwnedPreparationAndHeadersCannotReadTheFinalPayloadColumn()
    {
        using var connection = Database();
        var saved = Write(connection, new string('x', 3 * PathProofStorage.ChunkSize + 17));
        var denied = 0;
        var metadataReads = 0;
        strdelegate_authorizer guard = (_, action, table, column, _, _) =>
        {
            if (action != raw.SQLITE_READ || table != "path_proof_chunk") return raw.SQLITE_OK;
            if (column != "data")
            {
                metadataReads++;
                return raw.SQLITE_OK;
            }
            denied++;
            return raw.SQLITE_DENY;
        };
        Assert.Equal(raw.SQLITE_OK, raw.sqlite3_set_authorizer(connection.Handle!, guard, null!));
        try
        {
            var blocked = Assert.Throws<SqliteException>(() => Scalar(connection, "SELECT data FROM path_proof_chunk LIMIT 1"));
            Assert.Equal(raw.SQLITE_AUTH, blocked.SqliteErrorCode);
            Assert.True(denied > 0, "The native guard must detect a real payload read before it is trusted.");
            denied = metadataReads = 0;
            var manifest = PreparePayloads(connection);
            var reader = RequestedDetailIndex.Open(connection, "main", manifest);
            var page = reader.ReadPage("path_proof_chunk", saved.Id);
            Assert.Equal((4L, 4), (page.TotalRows, page.Rows.Count));
            Assert.All(page.Rows, row => Assert.InRange(row.Value("data").ByteLength, 1, 65536));
            Assert.Null(page.Next);
            Assert.Equal(0, denied);
            Assert.True(metadataReads > 0, "The request must reach the native source, not an empty or cached result.");
            _output.WriteLine("Resolved test source: " + RebuildTree.Root());
        }
        finally
        {
            raw.sqlite3_set_authorizer(connection.Handle!, (strdelegate_authorizer)null!, null!);
            GC.KeepAlive(guard);
        }
    }

    [Fact]
    public void SourceOwnedPagesKeepFullCountsAndSeekPastAnUnrequestedDamagedPage()
    {
        using var connection = Database();
        var saved = Write(connection, new string('x', 122 * PathProofStorage.ChunkSize + 17));
        var reader = RequestedDetailIndex.Open(connection, "main", PreparePayloads(connection));
        var first = reader.ReadPage("path_proof_chunk", saved.Id);
        var second = reader.ReadPage("path_proof_chunk", saved.Id, first.Next);
        var last = reader.ReadPage("path_proof_chunk", saved.Id, second.Next);
        Assert.Equal(new[] { 50, 50, 23 }, new[] { first.Rows.Count, second.Rows.Count, last.Rows.Count });
        Assert.Equal(new[] { 123L, 123L, 123L }, new[] { first.TotalRows, second.TotalRows, last.TotalRows });
        Assert.Equal(Enumerable.Range(0, 123).Select(ordinal => (long)ordinal),
            first.Rows.Concat(second.Rows).Concat(last.Rows).Select(row => row.Integer("ordinal")));
        Assert.Null(last.Next);
        Execute(connection, "UPDATE path_proof_chunk SET ordinal=5000 WHERE ordinal=0");
        var selected = reader.ReadPageAfter("path_proof_chunk", saved.Id, 99);
        Assert.Equal(123, selected.TotalRows);
        Assert.Equal(Enumerable.Range(100, 23).Select(ordinal => (long)ordinal), selected.Rows.Select(row => row.Integer("ordinal")));
        Assert.Null(selected.Next);
        Assert.Throws<InvalidDataException>(() => reader.ReadPage("path_proof_chunk", saved.Id));
    }

    [Theory]
    [InlineData("rowid")]
    [InlineData("missing")]
    public void SourceOwnedHeadersRefuseMissingOrReplacedNativeLocations(string defect)
    {
        using var connection = Database();
        var saved = Write(connection, new string('x', 2 * PathProofStorage.ChunkSize + 17));
        var reader = RequestedDetailIndex.Open(connection, "main", PreparePayloads(connection));
        Execute(connection, defect == "rowid"
            ? "UPDATE path_proof_chunk SET rowid=rowid+1000 WHERE ordinal=0"
            : "DELETE FROM path_proof_chunk WHERE ordinal=2");
        Assert.Throws<InvalidDataException>(() => reader.ReadPage("path_proof_chunk", saved.Id));
    }

    [Fact]
    public void SourceOwnedSelectedBytesRefuseDamageWithoutReadingUnrequestedChunks()
    {
        using var connection = Database();
        var value = new string('x', 3 * PathProofStorage.ChunkSize + 17);
        var expected = JsonSerializer.SerializeToUtf8Bytes(value, ProofSerialization.Options);
        var saved = Write(connection, value);
        var reader = RequestedDetailIndex.Open(connection, "main", PreparePayloads(connection));
        Execute(connection, "UPDATE path_proof_chunk SET data=zeroblob(length(data)) WHERE ordinal=3");
        var page = reader.ReadPage("path_proof_chunk", saved.Id);
        Assert.Equal(expected.AsSpan(0, PathProofStorage.ChunkSize).ToArray(), page.Rows[0].CompleteBytes("data"));
        var selected = reader.ReadValuePage(page.Rows[1].Value("data"), 29);
        Assert.Equal(PathProofStorage.ChunkSize, selected.TotalBytes);
        Assert.Equal(expected.AsSpan(PathProofStorage.ChunkSize + 29, PathProofStorage.ChunkSize - 29).ToArray(), selected.Bytes);
        Assert.Null(selected.NextOffset);
        Assert.Throws<InvalidDataException>(() => page.Rows[3].CompleteBytes("data"));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("role")]
    [InlineData("evidence")]
    [InlineData("schema")]
    public void SourceOwnedPayloadMetadataCannotMoveToAnotherPublicationContext(string change)
    {
        using var connection = Database();
        var saved = Write(connection, "selected");
        var original = PreparePayloads(connection);
        var changed = change switch
        {
            "generation" => original with { GenerationId = Guid.NewGuid() },
            "role" => original with { Role = StoreSegmentRole.PermissionProof },
            "evidence" => original with { EvidenceSeal = new string('B', 64) },
            "schema" => original with { SchemaVersion = original.SchemaVersion + 1 },
            _ => throw new ArgumentOutOfRangeException(nameof(change)),
        };
        var foreign = RequestedDetailIndex.Open(connection, "main", changed);
        Assert.Throws<InvalidDataException>(() => foreign.ReadPage("path_proof_chunk", saved.Id));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SourceOwnedDeclarationsRefuseMissingOrNonStreamablePayloadTables(bool withoutRowId)
    {
        using var connection = Database();
        Execute(connection, "DROP TABLE path_proof_chunk");
        if (withoutRowId)
            Execute(connection, """
                CREATE TABLE path_proof_chunk(proof_id INTEGER,ordinal INTEGER,data BLOB,
                    byte_length INTEGER,fingerprint BLOB,PRIMARY KEY(proof_id,ordinal)) WITHOUT ROWID
                """);
        Assert.Throws<InvalidDataException>(() => PreparePayloads(connection));
        Assert.Equal(0L, Scalar(connection, "SELECT COUNT(*) FROM sqlite_schema WHERE name='requested_detail_node'"));
    }

    [Fact]
    public void CancellationDuringSourceOwnedPreparationKeepsFinalPayloadsAndRollsBackTheIndex()
    {
        using var connection = Database();
        var saved = Write(connection, new string('x', 3 * PathProofStorage.ChunkSize + 17));
        var original = Bytes(connection, saved.Id);
        using var stopping = new CancellationTokenSource();
        var reached = false;
        strdelegate_trace trace = (_, sql) =>
        {
            if (!sql.Contains("INSERT OR IGNORE", StringComparison.Ordinal)
                || !sql.Contains("requested_detail_node", StringComparison.Ordinal)) return;
            reached = true;
            stopping.Cancel();
        };
        raw.sqlite3_trace(connection.Handle!, trace, null!);
        try
        {
            Assert.Throws<OperationCanceledException>(() => PreparePayloads(connection, stopping.Token));
        }
        finally
        {
            raw.sqlite3_trace(connection.Handle!, (strdelegate_trace)null!, null!);
            GC.KeepAlive(trace);
        }
        Assert.True(reached, "Cancellation must happen inside real index production.");
        Assert.Equal(0L, Scalar(connection, "SELECT COUNT(*) FROM sqlite_schema WHERE name='requested_detail_node'"));
        Assert.Equal(original, Bytes(connection, saved.Id));
        var reader = RequestedDetailIndex.Open(connection, "main", PreparePayloads(connection));
        Assert.Equal(4, reader.ReadPage("path_proof_chunk", saved.Id).TotalRows);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PayloadCostControlCountsFinalWritingPreparationReadbackAndLogicalStorage(bool sourceOwned)
    {
        var value = Enumerable.Repeat(new string('x', 2048), 4096).ToArray();
        using var connection = Database();
        var clock = Stopwatch.StartNew();
        var before = GC.GetAllocatedBytesForCurrentThread();
        var saved = Write(connection, value);
        var written = clock.Elapsed;
        var manifest = sourceOwned ? PreparePayloads(connection)
            : RequestedDetailIndex.Prepare(connection, "main", StoreSegmentRole.PathProof, JudgementSchema.Version,
                Guid.NewGuid(), new string('A', 64), CancellationToken.None);
        var prepared = clock.Elapsed;
        var reader = RequestedDetailIndex.Open(connection, "main", manifest);
        reader.RequireCurrent(() => connection.State == System.Data.ConnectionState.Open);
        using var bytes = new MemoryStream();
        foreach (var row in reader.ReadCompleteScope("path_proof_chunk", saved.Id))
            bytes.Write(row.CompleteBytes("data"));
        var finished = clock.Elapsed;
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal(JsonSerializer.SerializeToUtf8Bytes(value, ProofSerialization.Options), bytes.ToArray());
        var logicalBytes = checked((long)Scalar(connection, "PRAGMA page_count")! * (long)Scalar(connection, "PRAGMA page_size")!);
        _output.WriteLine(JsonSerializer.Serialize(new
        {
            Control = sourceOwned ? "source-owned" : "same-source generic preparation, not original application",
            WriteMs = written.TotalMilliseconds, PrepareMs = (prepared - written).TotalMilliseconds,
            ReadMs = (finished - prepared).TotalMilliseconds, TotalMs = finished.TotalMilliseconds,
            AllocatedBytes = allocated, LogicalBytes = logicalBytes, PayloadBytes = bytes.Length,
            Pieces = reader.ReadRowCount("path_proof_chunk"),
        }));
    }

    [Fact]
    public void ColdNativeHeadersDoNotWalkThroughUnrequestedPayloadOverflowPages()
    {
        var directory = TempDirectories.Create("source-owned-native-pages");
        var path = Path.Combine(directory, "proof.db");
        RequestedDetailManifest manifest;
        long id;
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path, Pooling = false,
        }.ToString()))
        {
            connection.Open();
            Execute(connection, "PRAGMA page_size=4096");
            PathProofStorage.CreateTables(connection);
            id = Write(connection, Enumerable.Repeat(new string('x', 2048), 4096).ToArray()).Id;
            manifest = PreparePayloads(connection);
        }
        using (var warm = ColdReader())
            RequestedDetailIndex.Open(warm, "main", manifest).ReadPage("path_proof_chunk", id);
        ulong payloadReads;
        using (var connection = ColdReader())
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT data FROM path_proof_chunk WHERE proof_id=$id AND ordinal<50 ORDER BY ordinal";
            command.Parameters.AddWithValue("$id", id);
            var before = ProcessReadBytes();
            using (var read = command.ExecuteReader())
            {
                var bytes = 0L;
                while (read.Read()) bytes += ((byte[])read.GetValue(0)).Length;
                Assert.Equal(50L * PathProofStorage.ChunkSize, bytes);
            }
            payloadReads = checked(ProcessReadBytes() - before);
            _output.WriteLine(JsonSerializer.Serialize(new
            {
                PayloadReadBytes = payloadReads,
                PageSize = Scalar(connection, "PRAGMA page_size"),
                PageCount = Scalar(connection, "PRAGMA page_count"),
            }));
        }
        Assert.True(payloadReads >= 50UL * (PathProofStorage.ChunkSize - 4096),
            "The native counter must detect actual overflow-page work before it is trusted.");
        using (var connection = ColdReader())
        {
            var reader = RequestedDetailIndex.Open(connection, "main", manifest);
            var before = ProcessReadBytes();
            var page = reader.ReadPage("path_proof_chunk", id);
            Assert.Equal((129L, 50), (page.TotalRows, page.Rows.Count));
            Assert.All(page.Rows, row => Assert.Equal(PathProofStorage.ChunkSize, row.Value("data").ByteLength));
            var headerReads = checked(ProcessReadBytes() - before);
            _output.WriteLine(JsonSerializer.Serialize(new { HeaderReadBytes = headerReads, PayloadReadBytes = payloadReads }));
            Assert.InRange(headerReads, 1UL, (2UL * RequestedDetailIndex.MaximumRows + 32) * 4096);
        }

        SqliteConnection ColdReader()
        {
            var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false,
            }.ToString());
            connection.Open();
            Execute(connection, "PRAGMA mmap_size=0; PRAGMA cache_size=-8; PRAGMA shrink_memory");
            return connection;
        }
    }

    internal static ulong ProcessReadBytes()
    {
        using var process = Process.GetCurrentProcess();
        if (!GetProcessIoCounters(process.Handle, out var counters))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return counters.ReadBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessIoCounters
    {
        internal ulong ReadOperations;
        internal ulong WriteOperations;
        internal ulong OtherOperations;
        internal ulong ReadBytes;
        internal ulong WriteBytes;
        internal ulong OtherBytes;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessIoCounters(IntPtr process, out ProcessIoCounters counters);

    private static RequestedDetailManifest PreparePayloads(SqliteConnection connection, CancellationToken token = default) =>
        RequestedDetailIndex.Prepare(connection, "main", StoreSegmentRole.PathProof, JudgementSchema.Version,
            Guid.NewGuid(), new string('A', 64), token, PathProofStorage.RequestedPayloads);
}

[CollectionDefinition(nameof(PathProofNativeIoCollection), DisableParallelization = true)]
public sealed class PathProofNativeIoCollection;
