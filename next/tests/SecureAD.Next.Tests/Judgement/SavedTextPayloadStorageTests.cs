using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Architecture;
using SQLitePCL;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Judgement;

[Collection(nameof(PathProofNativeIoCollection))]
public sealed partial class SavedTextPayloadStorageTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData(StoreSegmentRole.JudgementFacts, "empty")]
    [InlineData(StoreSegmentRole.PermissionProof, "empty")]
    [InlineData(StoreSegmentRole.JudgementFacts, "boundary")]
    [InlineData(StoreSegmentRole.PermissionProof, "boundary")]
    [InlineData(StoreSegmentRole.JudgementFacts, "large")]
    [InlineData(StoreSegmentRole.PermissionProof, "large")]
    public void FinalTextPiecesPreserveExactUtf8AndCompleteValues(StoreSegmentRole role, string shape)
    {
        var store = Store(role);
        using var connection = Database(store);
        var value = shape switch
        {
            "empty" => "",
            "boundary" => new string('x', 65535) + "\U0001f512\0\uFEFF\u00e9\u6f22",
            "large" => new string('x', 3 * 65536 + 17) + "\U0001f512\0\uFEFF\u00e9\u6f22",
            _ => throw new ArgumentOutOfRangeException(nameof(shape)),
        };
        var id = Write(connection, store, value);
        var expected = Encoding.UTF8.GetBytes(value);
        using var original = new MemoryStream();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT ordinal,byte_length,fingerprint,data FROM {store.Chunks} WHERE payload_id=$id ORDER BY ordinal";
        command.Parameters.AddWithValue("$id", id);
        using (var read = command.ExecuteReader())
        {
            long ordinal = 0;
            while (read.Read())
            {
                var bytes = (byte[])read.GetValue(3);
                Assert.Equal(ordinal++, read.GetInt64(0));
                Assert.InRange(bytes.Length, 1, 65536);
                Assert.Equal(bytes.LongLength, read.GetInt64(1));
                Assert.Equal(SHA256.HashData(bytes), (byte[])read.GetValue(2));
                original.Write(bytes);
            }
            Assert.Equal(expected.Length == 0 ? 0 : (expected.LongLength - 1) / 65536 + 1, ordinal);
        }
        Assert.Equal(expected, original.ToArray());
        command.CommandText = $"SELECT fingerprint FROM {store.Table} WHERE id=$id";
        Assert.Equal(SHA256.HashData(expected), (byte[])command.ExecuteScalar()!);
        store.RequirePublishable(connection, CancellationToken.None);
        Assert.Equal(value, store.Read(connection, id));
    }

    [Theory]
    [InlineData(StoreSegmentRole.JudgementFacts)]
    [InlineData(StoreSegmentRole.PermissionProof)]
    public void TextPreparationAndRequestedHeadersCannotReadPayloadBodies(StoreSegmentRole role)
    {
        var store = Store(role);
        using var connection = Database(store);
        var id = Write(connection, store, new string('x', 3 * 65536 + 17));
        var denied = 0;
        var metadata = 0;
        strdelegate_authorizer guard = (_, action, table, column, _, _) =>
        {
            if (action != raw.SQLITE_READ || table != store.Chunks) return raw.SQLITE_OK;
            if (column == "data")
            {
                denied++;
                return raw.SQLITE_DENY;
            }
            metadata++;
            return raw.SQLITE_OK;
        };
        Assert.Equal(raw.SQLITE_OK, raw.sqlite3_set_authorizer(connection.Handle!, guard, null!));
        try
        {
            using var positive = connection.CreateCommand();
            positive.CommandText = $"SELECT data FROM {store.Chunks} LIMIT 1";
            Assert.Equal(raw.SQLITE_AUTH, Assert.Throws<SqliteException>(() => positive.ExecuteScalar()).SqliteErrorCode);
            Assert.True(denied > 0);
            denied = metadata = 0;
            var reader = RequestedDetailIndex.Open(connection, "main", Prepare(connection, store));
            var page = reader.ReadPage(store.Chunks, id);
            Assert.Equal((4L, 4), (page.TotalRows, page.Rows.Count));
            Assert.All(page.Rows, row => Assert.InRange(row.Value("data").ByteLength, 1, 65536));
            Assert.True(metadata > 0);
            Assert.Equal(0, denied);
            output.WriteLine("Resolved source: " + RebuildTree.Root());
        }
        finally
        {
            raw.sqlite3_set_authorizer(connection.Handle!, (strdelegate_authorizer)null!, null!);
            GC.KeepAlive(guard);
        }
    }

    [Theory]
    [InlineData(StoreSegmentRole.JudgementFacts)]
    [InlineData(StoreSegmentRole.PermissionProof)]
    public void TextPagesRetainWholeCountsAndDoNotReadAnUnrequestedDamagedPiece(StoreSegmentRole role)
    {
        var store = Store(role);
        using var connection = Database(store);
        var value = new string('x', 122 * 65536 + 17);
        var id = Write(connection, store, value);
        var reader = RequestedDetailIndex.Open(connection, "main", Prepare(connection, store));
        Execute(connection, $"UPDATE {store.Chunks} SET data=zeroblob(byte_length) WHERE payload_id={id} AND ordinal=0");
        var later = reader.ReadPageAfter(store.Chunks, id, 99);
        Assert.Equal((123L, 23), (later.TotalRows, later.Rows.Count));
        Assert.Equal(Enumerable.Range(100, 23).Select(number => (long)number),
            later.Rows.Select(row => row.Integer("ordinal")));
        Assert.Null(later.Next);
        foreach (var row in later.Rows)
        {
            var bytes = row.CompleteBytes("data");
            Assert.Equal(Encoding.UTF8.GetBytes(value.Substring(checked((int)row.Integer("ordinal") * 65536), bytes.Length)), bytes);
        }
        var first = reader.ReadPage(store.Chunks, id);
        Assert.Throws<InvalidDataException>(() => first.Rows[0].CompleteBytes("data"));
    }

    [Theory]
    [InlineData(StoreSegmentRole.JudgementFacts, false)]
    [InlineData(StoreSegmentRole.PermissionProof, false)]
    [InlineData(StoreSegmentRole.JudgementFacts, true)]
    [InlineData(StoreSegmentRole.PermissionProof, true)]
    public void WholeTextReadsRejectDamageRatherThanReturningACompleteLookingValue(StoreSegmentRole role, bool invalidUtf8)
    {
        var store = Store(role);
        using var connection = Database(store);
        var id = Write(connection, store, new string('x', 65536 + 17));
        Assert.Equal(new string('x', 65536 + 17), store.Read(connection, id));
        Execute(connection, $"UPDATE {store.Chunks} SET data="
            + (invalidUtf8 ? "CAST(zeroblob(16)||X'FF' AS BLOB)" : "CAST(replace(CAST(data AS TEXT),'x','y') AS BLOB)")
            + $" WHERE payload_id={id} AND ordinal=1");
        if (role == StoreSegmentRole.JudgementFacts)
            Assert.Throws<InvalidDataException>(() => store.Read(connection, id));
        else
            Assert.Throws<InvalidOperationException>(() => store.Read(connection, id));
    }

    [Theory]
    [InlineData(StoreSegmentRole.JudgementFacts)]
    [InlineData(StoreSegmentRole.PermissionProof)]
    public void CancelledTextWritesRollBackEveryPieceAndReuseOnlyCommittedStorage(StoreSegmentRole role)
    {
        var store = Store(role);
        using var connection = Database(store);
        using var stopping = new CancellationTokenSource();
        connection.CreateFunction("stop_text_write", () => { stopping.Cancel(); return 0; });
        Execute(connection, $"CREATE TRIGGER stop_text AFTER INSERT ON {store.Chunks} BEGIN SELECT stop_text_write(); END");
        using var statements = new PreparedStatements(connection);
        using (var transaction = connection.BeginTransaction())
        {
            Assert.Throws<OperationCanceledException>(() => store.Write(connection, transaction, statements,
                new string('x', 3 * 65536), stopping.Token));
            Assert.Equal(1, Count(connection, store.Chunks));
            Assert.Equal(0, Count(connection, store.Table));
            transaction.Rollback();
        }
        Assert.Equal((0L, 0L), (Count(connection, store.Table), Count(connection, store.Chunks)));
        Execute(connection, "DROP TRIGGER stop_text");
        long id;
        using (var transaction = connection.BeginTransaction())
        {
            id = store.Write(connection, transaction, statements, "complete");
            transaction.Commit();
        }
        Assert.Equal(1, id);
        Assert.Equal("complete", store.Read(connection, id));
    }

    [Theory]
    [InlineData(StoreSegmentRole.JudgementFacts)]
    [InlineData(StoreSegmentRole.PermissionProof)]
    public void TextReadsPreserveTheActiveProducingTransaction(StoreSegmentRole role)
    {
        var store = Store(role);
        using var connection = Database(store);
        using var statements = new PreparedStatements(connection);
        using var transaction = connection.BeginTransaction();
        var value = new string('x', 65536 + 17);
        var id = store.Write(connection, transaction, statements, value);
        Assert.Equal(value, store.Read(connection, id));
        Assert.Equal(value, store.Read(connection, id, transaction));
        Assert.Same(connection, transaction.Connection);
        transaction.Rollback();
        Assert.Equal((0L, 0L), (Count(connection, store.Table), Count(connection, store.Chunks)));
    }

    [Theory]
    [InlineData(StoreSegmentRole.JudgementFacts, "missing")]
    [InlineData(StoreSegmentRole.PermissionProof, "missing")]
    [InlineData(StoreSegmentRole.JudgementFacts, "ordinal")]
    [InlineData(StoreSegmentRole.PermissionProof, "ordinal")]
    [InlineData(StoreSegmentRole.JudgementFacts, "orphan")]
    [InlineData(StoreSegmentRole.PermissionProof, "orphan")]
    public void TextPublicationRejectsMissingMisorderedOrOrphanPieces(StoreSegmentRole role, string defect)
    {
        var store = Store(role);
        using var connection = Database(store);
        var id = Write(connection, store, new string('x', 2 * 65536 + 17));
        store.RequirePublishable(connection, CancellationToken.None);
        Execute(connection, "PRAGMA foreign_keys=OFF");
        Execute(connection, defect switch
        {
            "missing" => $"DELETE FROM {store.Chunks} WHERE payload_id={id} AND ordinal=1",
            "ordinal" => $"UPDATE {store.Chunks} SET ordinal=7 WHERE payload_id={id} AND ordinal=2",
            "orphan" => $"DELETE FROM {store.Table} WHERE id={id}",
            _ => throw new ArgumentOutOfRangeException(nameof(defect)),
        });
        if (role == StoreSegmentRole.JudgementFacts)
            Assert.Throws<InvalidDataException>(() => store.RequirePublishable(connection, CancellationToken.None));
        else
            Assert.Throws<InvalidOperationException>(() => store.RequirePublishable(connection, CancellationToken.None));
    }

    private static SavedTextPayloadStorage Store(StoreSegmentRole role) => role switch
    {
        StoreSegmentRole.JudgementFacts => SavedTextPayloadStorage.Classifications,
        StoreSegmentRole.PermissionProof => SavedTextPayloadStorage.Permissions,
        _ => throw new ArgumentOutOfRangeException(nameof(role)),
    };

    private static SqliteConnection Database(SavedTextPayloadStorage store)
    {
        var connection = new SqliteConnection("Data Source=:memory:;Foreign Keys=True");
        connection.Open();
        store.CreateTables(connection);
        return connection;
    }

    private static long Write(SqliteConnection connection, SavedTextPayloadStorage store, string text)
    {
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        var id = store.Write(connection, transaction, statements, text);
        transaction.Commit();
        return id;
    }

    private static RequestedDetailManifest Prepare(SqliteConnection connection, SavedTextPayloadStorage store) =>
        RequestedDetailIndex.Prepare(connection, "main", store.Role, JudgementSchema.Version, Guid.NewGuid(),
            new string('a', 64), CancellationToken.None, store.RequestedPayloads);

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static long Count(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM " + table;
        return (long)command.ExecuteScalar()!;
    }
}
