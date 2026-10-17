using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Architecture;
using SecureAD.Next.Tests.Judgement;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Evidence;

[Collection(nameof(PathProofNativeIoCollection))]
public sealed partial class RequestedDetailRecordTests(ITestOutputHelper output)
{
    private static readonly Guid Generation = Guid.Parse("82c9c17c-f877-4bdb-9b18-e7d227367708");
    private static readonly RequestedDetailIndex.RecordLayout Layout = new("original_record",
        ["id", "owner", "ordinal", "enabled", "text", "data", "binding"], [0]);

    [Theory]
    [InlineData("empty")]
    [InlineData("small")]
    [InlineData("large")]
    public void ProducerMetadataBuildsExactlyTheGenericPublicationWithoutCopyingOriginalValues(string shape)
    {
        using var source = Database();
        var text = shape switch
        {
            "empty" => "",
            "small" => "Exact \u00e9\u6f22\U0001f512\0\uFEFF",
            "large" => new string('x', 3 * 65536 - 1) + "\U0001f512\0\uFEFF",
            _ => throw new ArgumentOutOfRangeException(nameof(shape)),
        };
        var bytes = shape == "large" ? Enumerable.Range(0, 2 * 65536 + 17).Select(value => (byte)value).ToArray()
            : shape == "empty" ? [] : new byte[] { 0, 127, 255, 0 };
        Write(source, 1, text, bytes);
        Write(source, 4, text, bytes);
        RequestedDetailIndex.Row producedRow;
        using (var transaction = source.BeginTransaction())
        {
            var produced = RequestedDetailRecordWriter.Read(source, transaction, "main", Layout, 1, CancellationToken.None);
            producedRow = produced.Row;
            foreach (var (column, original) in new[] { (4, Encoding.UTF8.GetBytes(text)), (5, bytes) })
            {
                if (original.Length == 0) continue;
                var field = Assert.IsType<RequestedDetailIndex.LargeField>(produced.Row.Cells[column].Large);
                Assert.Equal((original.LongLength, Convert.ToHexString(SHA256.HashData(original))), (field.Length, field.Hash));
                if (original.Length <= 65536) continue;
                var fragments = Assert.Single(produced.Fields.Where(value => value.Column == column)).Fragments;
                for (var ordinal = 0; ordinal < fragments.Length; ordinal++)
                {
                    var count = Math.Min(65536, original.Length - ordinal * 65536);
                    Assert.Equal(new RequestedDetailIndex.Fragment(count,
                        Convert.ToHexString(SHA256.HashData(original.AsSpan(ordinal * 65536, count)))), fragments[ordinal]);
                }
            }
            transaction.Commit();
        }
        using var generic = new SqliteConnection("Data Source=:memory:");
        generic.Open();
        source.BackupDatabase(generic);
        var baseline = Prepare(generic, records: []);
        var genericRow = RequestedDetailIndex.Open(generic, "main", baseline).ReadSingle(Layout.Table, 1L)!.Source;
        Assert.Equal(CellSignatures(genericRow), CellSignatures(producedRow));
        var owned = Prepare(source, [Layout]);
        Assert.Equal(JsonSerializer.Serialize(Page(generic, baseline)), JsonSerializer.Serialize(Page(source, owned)));
        Assert.Equal(baseline, owned);
        Assert.Equal(0, Scalar(source, $"SELECT COUNT(*) FROM temp.{RequestedDetailRecordWriter.Records}"));
        Assert.Equal(0, Scalar(source, "SELECT COUNT(*) FROM sqlite_schema WHERE name LIKE 'requested_detail_record%'"));
        var reader = RequestedDetailIndex.Open(source, "main", owned);
        foreach (var id in new[] { 1L, 4L })
        {
            var row = Assert.IsType<RequestedDetailRow>(reader.ReadSingle(Layout.Table, id));
            Assert.Equal(("Object", 7L, 1L), (row.CompleteText("owner"), row.Integer("ordinal"), row.Integer("enabled")));
            Assert.Equal(text, row.CompleteText("text"));
            Assert.Equal(bytes, row.CompleteBytes("data"));
            Assert.Equal(SHA256.HashData(bytes), row.CompleteBytes("binding"));
        }
        Assert.Null(reader.ReadSingle(Layout.Table, 2L));
        Assert.Equal(2, reader.ReadRowCount(Layout.Table));
        output.WriteLine("Resolved source: " + RebuildTree.Root());
    }

    [Theory]
    [InlineData("missing-header")]
    [InlineData("missing-piece")]
    [InlineData("changed-piece")]
    [InlineData("piece-fingerprint")]
    [InlineData("whole-fingerprint")]
    [InlineData("changed-shape")]
    [InlineData("source-rowid")]
    [InlineData("source-integer")]
    [InlineData("extra-header")]
    [InlineData("orphan-piece")]
    public void MissingForeignOrContradictoryProducerMetadataCannotPublish(string defect)
    {
        using var source = Database();
        Write(source, 1, "preserved", defect == "missing-piece" ? new byte[64 * 1024 * 1024 + 17] : [1, 2, 3]);
        Execute(source, "PRAGMA foreign_keys=OFF");
        Execute(source, defect switch
        {
            "missing-header" => $"DELETE FROM temp.{RequestedDetailRecordWriter.Records} WHERE ordinal=0",
            "missing-piece" => $"DELETE FROM temp.{RequestedDetailRecordWriter.Records} WHERE ordinal>0",
            "changed-piece" => $"UPDATE temp.{RequestedDetailRecordWriter.Records} SET data=zeroblob(piece_length)",
            "piece-fingerprint" => $"UPDATE temp.{RequestedDetailRecordWriter.Records} SET piece_fingerprint=zeroblob(32)",
            "whole-fingerprint" => $"UPDATE temp.{RequestedDetailRecordWriter.Records} SET fingerprint=zeroblob(32)",
            "changed-shape" => $"UPDATE temp.{RequestedDetailRecordWriter.Records} SET source_table='another_table'",
            "source-rowid" => "UPDATE original_record SET id=5",
            "source-integer" => "UPDATE original_record SET ordinal=8",
            "extra-header" => $"""
                INSERT INTO temp.{RequestedDetailRecordWriter.Records}
                SELECT source_schema,source_table,999,ordinal,byte_length,piece_count,fingerprint,piece_length,piece_fingerprint,data
                FROM temp.{RequestedDetailRecordWriter.Records}
                """,
            "orphan-piece" => $"""
                INSERT INTO temp.{RequestedDetailRecordWriter.Records}
                SELECT source_schema,source_table,999,1,byte_length,piece_count,fingerprint,piece_length,piece_fingerprint,data
                FROM temp.{RequestedDetailRecordWriter.Records}
                """,
            _ => throw new ArgumentOutOfRangeException(nameof(defect)),
        });
        Assert.Throws<InvalidDataException>(() => Prepare(source, [Layout]));
        Assert.Equal(0, Scalar(source, "SELECT COUNT(*) FROM sqlite_schema WHERE name='requested_detail_node'"));
    }

    [Fact]
    public void ADeclaredRecordDoesNotSilentlyFallBackToGenericPreparation()
    {
        using var source = Database();
        Execute(source, "INSERT INTO original_record VALUES(1,'Object',7,1,'preserved',X'0102',zeroblob(32))");
        Assert.Throws<InvalidDataException>(() => Prepare(source, [Layout]));
        Assert.Equal(0, Scalar(source, "SELECT COUNT(*) FROM sqlite_schema WHERE name='requested_detail_node'"));
    }

    [Fact]
    public void UndeclaredProducerRecordsAreNotSilentlyLeftOutOfPublication()
    {
        using var source = Database();
        Write(source, 1, "preserved", [1, 2, 3]);
        Assert.Throws<InvalidDataException>(() => Prepare(source, []));
        Assert.Equal(1, Scalar(source, $"SELECT COUNT(*) FROM temp.{RequestedDetailRecordWriter.Records} WHERE ordinal=0"));
    }

    [Theory]
    [InlineData("missing-table")]
    [InlineData("columns")]
    [InlineData("key")]
    [InlineData("duplicate")]
    public void ProducerDeclarationsMustMatchTheNativeTableExactly(string defect)
    {
        using var source = Database();
        RequestedDetailIndex.RecordLayout[] declarations = defect switch
        {
            "missing-table" => [new("missing_record", Layout.Columns, Layout.Keys)],
            "columns" => [new(Layout.Table, ["id", "owner", "ordinal", "enabled", "wrong_text", "data", "binding"], [0])],
            "key" => [new(Layout.Table, Layout.Columns, [1])],
            "duplicate" => [Layout, Layout],
            _ => throw new ArgumentOutOfRangeException(nameof(defect)),
        };
        if (defect == "duplicate")
            Assert.Throws<ArgumentException>(() => Prepare(source, declarations));
        else
            Assert.Throws<InvalidDataException>(() => Prepare(source, declarations));
        Assert.Equal(0, Scalar(source, "SELECT COUNT(*) FROM sqlite_schema WHERE name='requested_detail_node'"));
    }

    [Fact]
    public void CorrectlyHashedMetadataForAnotherRecordShapeIsStillRefused()
    {
        using var source = Database();
        using var writer = new RequestedDetailRecordWriter(source);
        using (var transaction = source.BeginTransaction())
        {
            Execute(source, "INSERT INTO original_record VALUES(1,'Object',7,1,'preserved',X'010203',zeroblob(32))");
            var other = new RequestedDetailIndex.RecordLayout(Layout.Table,
                ["id", "owner", "ordinal", "enabled", "other_text", "data", "binding"], [0]);
            writer.Write(transaction, "main", other, 1, [1, "Object", 7, true, "preserved", new byte[] { 1, 2, 3 }, new byte[32]]);
            transaction.Commit();
        }
        Assert.Throws<InvalidDataException>(() => Prepare(source, [Layout]));
    }

    [Fact]
    public void OversizedFragmentMetadataContinuesInBoundedPiecesWithoutCappingTheOriginalValue()
    {
        using var source = Database();
        var data = new byte[64 * 1024 * 1024 + 17];
        data[^1] = 255;
        Write(source, 1, "large original", data);
        Assert.True(Scalar(source, $"SELECT COUNT(*) FROM temp.{RequestedDetailRecordWriter.Records}") > 1);
        Assert.InRange(Scalar(source, $"SELECT MAX(piece_length) FROM temp.{RequestedDetailRecordWriter.Records}"), 1, 65536);
        var reader = RequestedDetailIndex.Open(source, "main", Prepare(source, [Layout]));
        var row = Assert.IsType<RequestedDetailRow>(reader.ReadSingle(Layout.Table, 1L));
        var value = row.Value("data");
        Assert.Equal(data.LongLength, value.ByteLength);
        var tail = reader.ReadValuePage(value, 64L * 1024 * 1024);
        Assert.Equal(data[^17..], tail.Bytes);
        Assert.Null(tail.NextOffset);
    }

    [Fact]
    public void ProducerMetadataRollsBackWithTheOriginalRowAndCanBeWrittenAgain()
    {
        using var source = Database();
        using var writer = new RequestedDetailRecordWriter(source);
        using (var transaction = source.BeginTransaction())
        {
            Write(source, writer, transaction, 1, "rolled back", [1, 2, 3]);
            Assert.Equal(1, Scalar(source, $"SELECT COUNT(*) FROM temp.{RequestedDetailRecordWriter.Records} WHERE ordinal=0"));
            transaction.Rollback();
        }
        Assert.Equal((0L, 0L), (Scalar(source, "SELECT COUNT(*) FROM original_record"),
            Scalar(source, $"SELECT COUNT(*) FROM temp.{RequestedDetailRecordWriter.Records}")));
        Write(source, 1, "committed", [3, 2, 1]);
        var reader = RequestedDetailIndex.Open(source, "main", Prepare(source, [Layout]));
        Assert.Equal("committed", reader.ReadSingle(Layout.Table, 1L)!.CompleteText("text"));
    }

    [Fact]
    public void CancellationDuringPublicationKeepsProducerMetadataAndOriginalBytesForTheCorrectRetry()
    {
        using var source = Database();
        Write(source, 1, new string('x', 65536 + 17), [1, 2, 3]);
        var before = Scalar(source, $"SELECT COUNT(*) FROM temp.{RequestedDetailRecordWriter.Records}");
        using var stopping = new CancellationTokenSource();
        var reached = false;
        SQLitePCL.strdelegate_trace trace = (_, sql) =>
        {
            if (!sql.Contains("INSERT OR IGNORE", StringComparison.Ordinal)
                || !sql.Contains("requested_detail_node", StringComparison.Ordinal)) return;
            reached = true;
            stopping.Cancel();
        };
        SQLitePCL.raw.sqlite3_trace(source.Handle!, trace, null!);
        try
        {
            Assert.Throws<OperationCanceledException>(() => Prepare(source, [Layout], stopping.Token));
        }
        finally
        {
            SQLitePCL.raw.sqlite3_trace(source.Handle!, (SQLitePCL.strdelegate_trace)null!, null!);
            GC.KeepAlive(trace);
        }
        Assert.True(reached);
        Assert.Equal(before, Scalar(source, $"SELECT COUNT(*) FROM temp.{RequestedDetailRecordWriter.Records}"));
        Assert.Equal(0, Scalar(source, "SELECT COUNT(*) FROM sqlite_schema WHERE name='requested_detail_node'"));
        var reader = RequestedDetailIndex.Open(source, "main", Prepare(source, [Layout]));
        Assert.Equal(new string('x', 65536 + 17), reader.ReadSingle(Layout.Table, 1L)!.CompleteText("text"));
    }

    private static SqliteConnection Database(string? path = null)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path ?? ":memory:", ForeignKeys = true, Pooling = false,
        }.ToString());
        connection.Open();
        Execute(connection, """
            CREATE TABLE original_record(id INTEGER PRIMARY KEY,owner TEXT NOT NULL,ordinal INTEGER NOT NULL,
                enabled INTEGER NOT NULL,text TEXT NOT NULL,data BLOB NOT NULL,binding BLOB NOT NULL);
            """);
        RequestedDetailRecordWriter.Create(connection);
        return connection;
    }

    private static void Write(SqliteConnection source, long id, string text, byte[] bytes)
    {
        using var writer = new RequestedDetailRecordWriter(source);
        using var transaction = source.BeginTransaction();
        Write(source, writer, transaction, id, text, bytes);
        transaction.Commit();
    }

    private static void Write(SqliteConnection source, RequestedDetailRecordWriter writer,
        SqliteTransaction transaction, long id, string text, byte[] bytes)
    {
        var binding = SHA256.HashData(bytes);
        using var command = source.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO original_record VALUES($id,'Object',7,1,CAST($text AS TEXT),$data,$binding)";
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$text", Encoding.UTF8.GetBytes(text));
        command.Parameters.AddWithValue("$data", bytes);
        command.Parameters.AddWithValue("$binding", binding);
        Assert.Equal(1, command.ExecuteNonQuery());
        using (var original = source.CreateCommand())
        {
            original.Transaction = transaction;
            original.CommandText = "SELECT CAST(text AS BLOB) FROM original_record WHERE id=$id";
            original.Parameters.AddWithValue("$id", id);
            Assert.Equal(Encoding.UTF8.GetBytes(text), (byte[])original.ExecuteScalar()!);
        }
        writer.Write(transaction, "main", Layout, id, [id, "Object", 7, true, text, bytes, binding]);
    }

    private static RequestedDetailManifest Prepare(SqliteConnection source,
        IReadOnlyList<RequestedDetailIndex.RecordLayout> records, CancellationToken token = default) =>
        RequestedDetailIndex.Prepare(source, "main", StoreSegmentRole.PermissionProof, JudgementSchema.Version,
            Generation, new string('a', 64), token, [], records);

    private static RequestedDetailIndex.Page Page(SqliteConnection connection, RequestedDetailManifest manifest)
    {
        var map = new RequestedDetailMap(connection, "main", manifest, CancellationToken.None);
        var owner = RequestedDetailMap.Key(new RequestedDetailIndex.KeyValue(1, 1));
        var reference = map.Find(new(manifest.Root, manifest.Items), RequestedDetailIndex.ScopeKey(Layout.Table, owner));
        var scope = map.Read<RequestedDetailIndex.Scope>(reference!);
        return map.Read<RequestedDetailIndex.Page>(map.Find(scope.Index, RequestedDetailIndex.Ordinal(0))!);
    }

    private static string CellSignatures(RequestedDetailIndex.Row row) => JsonSerializer.Serialize(row.Cells.Select(cell => new
    {
        cell.Kind, cell.Integer, cell.Real, cell.Bytes, Length = cell.Large?.Length, Hash = cell.Large?.Hash,
    }));

    private static void Execute(SqliteConnection source, string sql)
    {
        using var command = source.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static long Scalar(SqliteConnection source, string sql)
    {
        using var command = source.CreateCommand();
        command.CommandText = sql;
        return (long)command.ExecuteScalar()!;
    }
}
