using System.Diagnostics.Metrics;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

public sealed class RequestedDetailIndexTests
{
    [Theory]
    [InlineData("attributes")]
    [InlineData("descriptors")]
    [InlineData("classifications")]
    [InlineData("path_proof")]
    public void EveryFamilyReturnsRealOrderedPagesAndIndependentTotals(string table)
    {
        using var input = new Input();
        input.Add(table, 123);
        var reader = input.Publish();
        RequestedDetailMark? mark = null;
        var ordinals = new List<long>();
        var sizes = new List<int>();
        do
        {
            var page = reader.ReadPage(table, 7L, mark);
            Assert.True(page.Exists);
            Assert.Equal(123, page.TotalRows);
            sizes.Add(page.Rows.Count);
            Assert.True(sizes.Count <= 3, "The continuation did not make forward progress.");
            foreach (var row in page.Rows)
            {
                ordinals.Add(row.Integer("ordinal"));
                Assert.Equal("value " + row.Integer("ordinal"), row.CompleteText("value"));
            }
            mark = page.Next;
        } while (mark is not null);
        Assert.Equal([50, 50, 23], sizes);
        Assert.Equal(Enumerable.Range(0, 123).Select(index => (long)index * 2), ordinals);
    }

    [Fact]
    public void EmptyScopeIsProvedAndIsNotTheSameAsAMissingTable()
    {
        using var input = new Input();
        input.Add("attributes", 1);
        var reader = input.Publish();
        var empty = reader.ReadPage("attributes", 99L);
        Assert.False(empty.Exists);
        Assert.Equal(0, empty.TotalRows);
        Assert.Empty(empty.Rows);
        Assert.Null(empty.Next);
        Assert.Throws<InvalidDataException>(() => reader.ReadPage("missing", 99L));
    }

    [Fact]
    public void AnUnloadedDamagedPageDoesNotPreventAnIndependentFirstPage()
    {
        using var input = new Input();
        input.Add("attributes", 123);
        var reader = input.Publish();
        input.Execute("UPDATE attributes SET value='wrong 200' WHERE ordinal=200");
        var first = reader.ReadPage("attributes", 7L);
        Assert.Equal(123, first.TotalRows);
        var second = reader.ReadPage("attributes", 7L, first.Next);
        Assert.Equal(50, second.Rows.Count);
        var third = reader.ReadPage("attributes", 7L, second.Next);
        Assert.Throws<InvalidDataException>(() => third.Rows[0].CompleteText("value"));
    }

    [Fact]
    public void MissingTailIsRefusedInsteadOfReturningAShorterSuccessfulLastPage()
    {
        using var input = new Input();
        input.Add("attributes", 123);
        var reader = input.Publish();
        var first = reader.ReadPage("attributes", 7L);
        var second = reader.ReadPage("attributes", 7L, first.Next);
        input.Execute("DELETE FROM attributes WHERE ordinal=244");
        Assert.Throws<InvalidDataException>(() => reader.ReadPage("attributes", 7L, second.Next));
    }

    [Theory]
    [InlineData("scope")]
    [InlineData("generation")]
    [InlineData("root")]
    public void ContinuationCannotChangeItsQuestionOrGeneration(string change)
    {
        using var input = new Input();
        input.Add("attributes", 123);
        var reader = input.Publish();
        var cursor = Assert.IsType<RequestedDetailMark>(reader.ReadPage("attributes", 7L).Next);
        var changed = change switch
        {
            "scope" => cursor with { Scope = new string('A', 64) },
            "generation" => cursor with { Root = new string('B', 64) },
            _ => cursor with { Page = long.MaxValue },
        };
        Assert.Throws<InvalidDataException>(() => reader.ReadPage("attributes", 7L, changed));
    }

    [Fact]
    public void ChangedValidMetadataCannotAuthorizeItsOwnCount()
    {
        using var input = new Input();
        input.Add("classifications", 123);
        var reader = input.Publish();
        var manifest = input.Manifest!;
        var map = new RequestedDetailMap(input.Connection, "main", manifest, CancellationToken.None);
        var key = RequestedDetailIndex.ScopeKey("classifications",
            RequestedDetailMap.Key(new RequestedDetailIndex.KeyValue(1, 7)));
        var scope = map.Find(new(manifest.Root, manifest.Items), key);
        Assert.NotNull(scope);
        using var command = input.Connection.CreateCommand();
        command.CommandText = "SELECT data FROM requested_detail_node WHERE hash=$hash";
        command.Parameters.AddWithValue("$hash", scope);
        var metadata = JsonNode.Parse((byte[])command.ExecuteScalar()!)!;
        metadata["Rows"] = 122;
        command.CommandText = "UPDATE requested_detail_node SET data=$data WHERE hash=$hash";
        command.Parameters.AddWithValue("$data", Encoding.UTF8.GetBytes(metadata.ToJsonString()));
        command.ExecuteNonQuery();
        Assert.Throws<InvalidDataException>(() => reader.ReadPage("classifications", 7L));
    }

    [Fact]
    public void NumericRecordMetadataCannotChangeUnderTheSameSourceRoot()
    {
        using var input = new Input();
        input.Execute("CREATE TABLE records(id INTEGER PRIMARY KEY,value INTEGER); INSERT INTO records VALUES(1,37)");
        var reader = input.Publish();
        input.Execute("UPDATE records SET value=42 WHERE id=1");
        Assert.Throws<InvalidDataException>(() => reader.ReadPage("records", 1L));
    }

    [Fact]
    public void SourceTypesAndNullEmptyAndBinaryDistinctionsSurvive()
    {
        using var input = new Input();
        input.Execute("""
            CREATE TABLE values_to_read(id INTEGER PRIMARY KEY,n TEXT,e TEXT,b BLOB,i INTEGER,r REAL);
            INSERT INTO values_to_read VALUES(1,NULL,'',X'',-37,1.25);
            """);
        var row = Assert.Single(input.Publish().ReadPage("values_to_read", 1L).Rows);
        Assert.True(row.IsNull("n"));
        Assert.False(row.IsNull("e"));
        Assert.Equal("", row.CompleteText("e"));
        Assert.Empty(row.CompleteBytes("b"));
        Assert.Equal(-37, row.Integer("i"));
        Assert.Equal(1.25, row.Real("r"));
        Assert.Throws<InvalidDataException>(() => row.Integer("e"));
    }

    [Fact]
    public void LargeValueReferencesDoNotReadThePayloadAndFragmentsAreActuallyBounded()
    {
        using var input = new Input();
        var bytes = Enumerable.Range(0, 3 * 65536 + 23).Select(index => (byte)(index * 17)).ToArray();
        input.Execute("CREATE TABLE descriptors(id INTEGER PRIMARY KEY,value BLOB)");
        using (var insert = input.Connection.CreateCommand())
        {
            insert.CommandText = "INSERT INTO descriptors VALUES(1,$value)";
            insert.Parameters.AddWithValue("$value", bytes);
            insert.ExecuteNonQuery();
        }
        var reader = input.Publish();
        long observed = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, owner) =>
        {
            if (instrument.Meter.Name == "SecureAD.Evidence.RequestedDetails" && instrument.Name == "requested_detail.value_bytes")
                owner.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((_, measurement, tags, _) =>
        {
            foreach (var tag in tags)
                if (tag.Key == "index" && Equals(tag.Value, input.Manifest!.Root)) observed += measurement;
        });
        listener.Start();
        var reference = Assert.Single(reader.ReadPage("descriptors", 1L).Rows).Value("value");
        Assert.Equal(0, observed);
        var result = new List<byte>();
        long? offset = 0;
        do
        {
            var before = observed;
            var page = reader.ReadValuePage(reference, offset.Value);
            Assert.Equal(bytes.Length, page.TotalBytes);
            Assert.InRange(page.Bytes.Length, 1, 65536);
            Assert.Equal(page.Bytes.Length, observed - before);
            result.AddRange(page.Bytes);
            offset = page.NextOffset;
        } while (offset is not null);
        Assert.Equal(bytes, result);
    }

    [Fact]
    public void LargeTextPreservesUnicodeAndDoesNotTreatAnUnloadedValueAsEmpty()
    {
        using var input = new Input();
        var value = string.Concat(Enumerable.Repeat("A\u00e9\u4e2d\U0001f512\0", 20000));
        input.Execute("CREATE TABLE text_to_read(id INTEGER PRIMARY KEY,value TEXT)");
        using (var insert = input.Connection.CreateCommand())
        {
            insert.CommandText = "INSERT INTO text_to_read VALUES(1,CAST($value AS TEXT))";
            insert.Parameters.AddWithValue("$value", Encoding.UTF8.GetBytes(value));
            insert.ExecuteNonQuery();
        }
        Assert.Equal((long)Encoding.UTF8.GetByteCount(value),
            input.Scalar("SELECT length(CAST(value AS BLOB)) FROM text_to_read"));
        var row = Assert.Single(input.Publish().ReadPage("text_to_read", 1L).Rows);
        Assert.False(row.IsNull("value"));
        Assert.Equal(Encoding.UTF8.GetByteCount(value), row.Value("value").ByteLength);
        Assert.Equal(value, row.CompleteText("value"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OversizedWithoutRowIdValuesRefuseRatherThanClaimBoundedStreaming(bool text)
    {
        using var input = new Input();
        var original = text
            ? Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("A\u00e9\u4e2d\U0001f512\0", 20000)))
            : Enumerable.Range(0, 3 * 65536 + 23).Select(index => (byte)(index * 17)).ToArray();
        input.Execute("CREATE TABLE selected_values(owner TEXT COLLATE NOCASE,ordinal INTEGER,value "
            + (text ? "TEXT" : "BLOB") + ",PRIMARY KEY(owner,ordinal)) WITHOUT ROWID");
        using (var insert = input.Connection.CreateCommand())
        {
            insert.CommandText = "INSERT INTO selected_values VALUES('Selected',7,"
                + (text ? "CAST($value AS TEXT)" : "$value") + ")";
            insert.Parameters.AddWithValue("$value", original);
            insert.ExecuteNonQuery();
        }
        var error = Assert.Throws<InvalidDataException>(() => input.Publish());
        Assert.Contains("streamable source representation", error.Message, StringComparison.Ordinal);
        Assert.Equal((long)original.Length, input.Scalar("SELECT length(CAST(value AS BLOB)) FROM selected_values"));
        Assert.Equal(0L, input.Scalar("SELECT COUNT(*) FROM sqlite_schema WHERE name='requested_detail_node'"));
    }

    [Fact]
    public void OrdinalSeekReadsOneRequestedSourcePageWithoutWalkingEarlierPages()
    {
        using var input = new Input();
        input.Add("attributes", 123);
        var reader = input.Publish();
        input.Execute("UPDATE attributes SET ordinal=1 WHERE ordinal=0");
        long pages = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, owner) =>
        {
            if (instrument.Name == "requested_detail.source_pages") owner.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            foreach (var tag in tags)
                if (tag.Key == "index" && Equals(tag.Value, input.Manifest!.Root)) pages += value;
        });
        listener.Start();
        var last = reader.ReadPageAfter("attributes", 7L, 199);
        Assert.Equal(1, pages);
        Assert.Equal(123, last.TotalRows);
        Assert.Equal(Enumerable.Range(100, 23).Select(index => (long)index * 2),
            last.Rows.Select(row => row.Integer("ordinal")));
        Assert.Null(last.Next);
        var end = reader.ReadPageAfter("attributes", 7L, 244);
        Assert.Equal(1, pages);
        Assert.Equal(123, end.TotalRows);
        Assert.Empty(end.Rows);
        Assert.Null(end.Next);
        Assert.Throws<InvalidDataException>(() => reader.ReadPage("attributes", 7L));
    }

    [Fact]
    public void SingleRecordReadsCannotReturnTheFirstRowOfAWholeCollection()
    {
        using var input = new Input();
        input.Add("attributes", 123);
        var reader = input.Publish();
        Assert.Throws<InvalidDataException>(() => reader.ReadSingle("attributes", 7L));
        Assert.Null(reader.ReadSingle("attributes", 99L));
    }

    [Fact]
    public void RequestedCorruptLargeFragmentRefusesWhileAnEarlierFragmentRemainsReadable()
    {
        using var input = new Input();
        input.Execute("CREATE TABLE descriptors(id INTEGER PRIMARY KEY,value BLOB); INSERT INTO descriptors VALUES(1,zeroblob(131095))");
        var reader = input.Publish();
        var reference = Assert.Single(reader.ReadPage("descriptors", 1L).Rows).Value("value");
        input.Execute("UPDATE descriptors SET value=CAST(substr(value,1,65536)||X'01'||substr(value,65538) AS BLOB)");
        Assert.Equal(new byte[65536], reader.ReadValuePage(reference, 0).Bytes);
        Assert.Throws<InvalidDataException>(() => reader.ReadValuePage(reference, 65536));
    }

    [Fact]
    public void IndexNodesCannotBeTransplantedToAnotherRoleOrGeneration()
    {
        using var input = new Input();
        input.Add("path_proof", 1);
        input.Publish();
        var original = input.Manifest!;
        foreach (var changed in new[]
        {
            original with { GenerationId = Guid.NewGuid() },
            original with { Role = StoreSegmentRole.PermissionProof },
            original with { EvidenceSeal = new string('C', 64) },
        })
        {
            var foreign = RequestedDetailIndex.Open(input.Connection, "main", changed);
            Assert.Throws<InvalidDataException>(() => foreign.ReadPage("path_proof", 7L));
        }
    }

    [Fact]
    public void CancelledPreparationDoesNotLeaveAPublishablePartialIndex()
    {
        using var input = new Input();
        input.Add("attributes", 123);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => RequestedDetailIndex.Prepare(input.Connection, "main",
            StoreSegmentRole.Evidence, 18, Guid.NewGuid(), "", cancellation.Token));
        Assert.Equal(0L, input.Scalar("SELECT COUNT(*) FROM sqlite_schema WHERE name='requested_detail_node'"));
    }

    [Fact]
    public void CompositeWithoutRowIdSourcesKeepOriginalGapsAndDuplicates()
    {
        using var input = new Input();
        input.Execute("""
            CREATE TABLE entries(descriptor INTEGER NOT NULL,ordinal INTEGER NOT NULL,entry INTEGER NOT NULL,
                PRIMARY KEY(descriptor,ordinal)) WITHOUT ROWID;
            INSERT INTO entries VALUES(9,0,4),(9,2,4),(9,7,6);
            """);
        var page = input.Publish().ReadPage("entries", 9L);
        Assert.Equal(3, page.TotalRows);
        Assert.Equal([0L, 2L, 7L], page.Rows.Select(row => row.Integer("ordinal")));
        Assert.Equal([4L, 4L, 6L], page.Rows.Select(row => row.Integer("entry")));
    }

    private sealed class Input : IDisposable
    {
        internal SqliteConnection Connection { get; } = new("Data Source=:memory:");
        internal RequestedDetailManifest? Manifest { get; private set; }
        internal Input() => Connection.Open();
        internal void Add(string table, int count)
        {
            Execute($"CREATE TABLE {table}(owner INTEGER NOT NULL,ordinal INTEGER NOT NULL,value TEXT NOT NULL,PRIMARY KEY(owner,ordinal))");
            using var transaction = Connection.BeginTransaction();
            using var insert = Connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = $"INSERT INTO {table} VALUES(7,$ordinal,$value)";
            insert.Parameters.Add("$ordinal", SqliteType.Integer);
            insert.Parameters.Add("$value", SqliteType.Text);
            for (var index = 0; index < count; index++)
            {
                insert.Parameters["$ordinal"].Value = index * 2;
                insert.Parameters["$value"].Value = "value " + index * 2;
                insert.ExecuteNonQuery();
            }
            transaction.Commit();
        }
        internal RequestedDetailReader Publish()
        {
            Manifest = RequestedDetailIndex.Prepare(Connection, "main", StoreSegmentRole.Evidence, 18,
                Guid.NewGuid(), "", CancellationToken.None);
            return RequestedDetailIndex.Open(Connection, "main", Manifest);
        }
        internal void Execute(string sql)
        {
            using var command = Connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }
        internal object Scalar(string sql)
        {
            using var command = Connection.CreateCommand();
            command.CommandText = sql;
            return command.ExecuteScalar() ?? throw new InvalidOperationException(sql);
        }
        public void Dispose() => Connection.Dispose();
    }
}
