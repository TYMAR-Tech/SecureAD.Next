using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class PathProofStorageTests
{
    private sealed record Witness(int Ordinal, string? Value, PathUncertaintyCause Cause);
    private sealed record Proof(Guid Generation, string EvidenceSeal, IReadOnlyList<Witness> Witnesses);

    [Theory]
    [InlineData(0)]
    [InlineData(65_535)]
    [InlineData(196_625)]
    public void FragmentedProofsKeepExactBytesOrderDuplicatesAndLargeValues(int valueLength)
    {
        var value = new string('x', valueLength) + "\u00e9\u6f22\ud83d\udd12\\\"\r\n";
        var witness = new Witness(19, value, PathUncertaintyCause.CapturedEvidenceIncomplete);
        var proof = new Proof(Guid.Parse("d6f0fb2a-c7d2-4fc1-8381-55401c2d987e"), new string('a', 64),
            [witness, new(3, null, PathUncertaintyCause.AnalysisUnsupported), witness]);
        var expected = JsonSerializer.SerializeToUtf8Bytes(proof, ProofSerialization.Options);
        using var connection = Database();
        var saved = Write(connection, proof);

        Assert.Equal(expected, Bytes(connection, saved.Id));
        Assert.Equal(SHA256.HashData(expected), saved.Fingerprint);
        var restored = PathProofStorage.Read<Proof>(connection, saved.Id, Convert.ToHexString(saved.Fingerprint), CancellationToken.None);
        Assert.Equal(proof.Generation, restored.Generation);
        Assert.Equal(proof.EvidenceSeal, restored.EvidenceSeal);
        Assert.Equal(proof.Witnesses, restored.Witnesses);
        AssertShape(connection, saved.Id, expected.LongLength);
        PathProofStorage.RequirePublishable(connection, CancellationToken.None);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CollectionWritesAvoidDocumentSizedAllocations(bool scalarNumbers)
    {
        object value = scalarNumbers ? Enumerable.Repeat(1_234_567_890L, 800_000).ToArray()
            : Enumerable.Repeat(new string('x', 2_048), 4_096).ToArray();
        var expected = JsonSerializer.SerializeToUtf8Bytes(value, ProofSerialization.Options);
        using var connection = Database();
        _ = Write<object>(connection, value is long[] ? new long[] { 1 } : new string[] { "warmup" });

        var before = GC.GetAllocatedBytesForCurrentThread();
        var saved = Write(connection, value);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(allocated < 2 * 1024 * 1024,
            $"Writing {expected.Length:N0} JSON bytes allocated {allocated:N0}; whole-value buffers must not return.");
        Assert.Equal(expected, Bytes(connection, saved.Id));
        Assert.Equal(SHA256.HashData(expected), saved.Fingerprint);
        AssertShape(connection, saved.Id, expected.LongLength);
    }

    [Fact]
    public void SelectedReadAllocatesTheResultButNotAnotherWholeJsonDocument()
    {
        var value = Enumerable.Repeat(new string('x', 2_048), 4_096).ToArray();
        using var connection = Database();
        var warmup = Write(connection, new[] { "warmup" });
        _ = PathProofStorage.Read<string[]>(connection, warmup.Id, Convert.ToHexString(warmup.Fingerprint), CancellationToken.None);
        var saved = Write(connection, value);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var restored = PathProofStorage.Read<string[]>(connection, saved.Id, Convert.ToHexString(saved.Fingerprint), CancellationToken.None);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(value, restored);
        Assert.True(allocated < 20 * 1024 * 1024,
            $"Reading an 8 MiB document into its 16 MiB string result allocated {allocated:N0} bytes.");
    }

    [Fact]
    public void SelectedReadDoesNotVisitAnotherProof()
    {
        using var connection = Database();
        var selected = Write(connection, new[] { "selected", "selected" });
        var other = Write(connection, new[] { "not selected" });
        Execute(connection, $"DELETE FROM path_proof_chunk WHERE proof_id={other.Id}");

        string[]? result = null;
        var error = Record.Exception(() => result = PathProofStorage.Read<string[]>(connection,
            selected.Id, Convert.ToHexString(selected.Fingerprint), CancellationToken.None));
        Assert.Null(error);
        Assert.Equal(new[] { "selected", "selected" }, result);
        Assert.Throws<InvalidDataException>(() => PathProofStorage.Read<string[]>(connection,
            other.Id, Convert.ToHexString(other.Fingerprint), CancellationToken.None));
    }

    [Theory]
    [InlineData("length")]
    [InlineData("count")]
    [InlineData("ordinal")]
    [InlineData("missing")]
    [InlineData("reordered")]
    [InlineData("fingerprint")]
    [InlineData("json")]
    [InlineData("missing-manifest")]
    public void ReadRefusesIncompleteOrContradictoryFragments(string defect)
    {
        using var connection = Database();
        var saved = Write(connection, string.Concat("abcd".Select(value => new string(value, PathProofStorage.ChunkSize))));
        var fingerprint = saved.Fingerprint;
        switch (defect)
        {
            case "length": Execute(connection, "UPDATE path_proof SET byte_length=byte_length+1"); break;
            case "count": Execute(connection, "UPDATE path_proof SET chunk_count=chunk_count+1"); break;
            case "ordinal": Execute(connection, "UPDATE path_proof_chunk SET ordinal=ordinal+20"); break;
            case "missing":
                Execute(connection, "DELETE FROM path_proof_chunk WHERE ordinal=2");
                fingerprint = SHA256.HashData(Bytes(connection, saved.Id));
                break;
            case "reordered":
                Execute(connection, "UPDATE path_proof_chunk SET ordinal=10 WHERE ordinal=1; UPDATE path_proof_chunk SET ordinal=1 WHERE ordinal=2; UPDATE path_proof_chunk SET ordinal=2 WHERE ordinal=10");
                break;
            case "fingerprint": fingerprint = new byte[32]; break;
            case "json":
                Execute(connection, "UPDATE path_proof_chunk SET data=zeroblob(length(data)) WHERE ordinal=0");
                fingerprint = SHA256.HashData(Bytes(connection, saved.Id));
                break;
            case "missing-manifest":
                Execute(connection, "PRAGMA foreign_keys=OFF; DELETE FROM path_proof");
                break;
            default: throw new ArgumentOutOfRangeException(nameof(defect));
        }

        Assert.Throws<InvalidDataException>(() => PathProofStorage.Read<string>(connection,
            saved.Id, Convert.ToHexString(fingerprint), CancellationToken.None));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("length")]
    [InlineData("ordinal")]
    [InlineData("orphan")]
    public void PublicationRefusesUnfinishedFragmentStorage(string defect)
    {
        using var connection = Database();
        _ = Write(connection, new string('a', PathProofStorage.ChunkSize * 2));
        PathProofStorage.RequirePublishable(connection, CancellationToken.None);
        Execute(connection, defect switch
        {
            "missing" => "DELETE FROM path_proof_chunk WHERE ordinal=1",
            "length" => "UPDATE path_proof SET byte_length=byte_length+1",
            "ordinal" => "UPDATE path_proof_chunk SET ordinal=ordinal+20",
            "orphan" => "PRAGMA foreign_keys=OFF; DELETE FROM path_proof",
            _ => throw new ArgumentOutOfRangeException(nameof(defect)),
        });

        Assert.Throws<InvalidDataException>(() => PathProofStorage.RequirePublishable(connection, CancellationToken.None));
    }

    [Fact]
    public void CancellationInsideAProofRollsBackEveryFragment()
    {
        using var connection = Database();
        using var stopping = new CancellationTokenSource();
        var inserted = 0;
        connection.CreateFunction("stop_fragments", () => { inserted++; stopping.Cancel(); return 1; });
        Execute(connection, "CREATE TRIGGER stop_fragment AFTER INSERT ON path_proof_chunk BEGIN SELECT stop_fragments(); END");
        using (var transaction = connection.BeginTransaction())
        using (var writer = new PathProofStorage.Writer(connection, transaction, stopping.Token))
            Assert.Throws<OperationCanceledException>(() => writer.Write(new string('a', PathProofStorage.ChunkSize * 3)));

        Assert.Equal(1, inserted);
        Assert.Equal(0L, Scalar(connection, "SELECT (SELECT COUNT(*) FROM path_proof)+(SELECT COUNT(*) FROM path_proof_chunk)"));
    }

    [Fact]
    public void SerializationFailureEscapesUnchangedAndLeavesNoCommittedFragments()
    {
        using var connection = Database();
        var failure = new InvalidOperationException("synthetic source failure");
        using (var transaction = connection.BeginTransaction())
        using (var writer = new PathProofStorage.Writer(connection, transaction, CancellationToken.None))
            Assert.Same(failure, Assert.Throws<InvalidOperationException>(() => writer.Write(Values())));

        Assert.Equal(0L, Scalar(connection, "SELECT (SELECT COUNT(*) FROM path_proof)+(SELECT COUNT(*) FROM path_proof_chunk)"));

        IEnumerable<string> Values()
        {
            yield return new string('a', PathProofStorage.ChunkSize * 2);
            throw failure;
        }
    }

    [Fact]
    public void CancelledReadsDoNotReturnAResult()
    {
        using var connection = Database();
        var saved = Write(connection, "saved");
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();

        Assert.Throws<OperationCanceledException>(() => PathProofStorage.Read<string>(connection,
            saved.Id, Convert.ToHexString(saved.Fingerprint), stopping.Token));
    }

    private static SqliteConnection Database()
    {
        var connection = new SqliteConnection("Data Source=:memory:;Foreign Keys=True");
        connection.Open();
        PathProofStorage.CreateTables(connection);
        return connection;
    }

    private static PathProofStorage.Reference Write<T>(SqliteConnection connection, T value)
    {
        using var transaction = connection.BeginTransaction();
        using var writer = new PathProofStorage.Writer(connection, transaction, CancellationToken.None);
        var saved = writer.Write(value);
        transaction.Commit();
        return saved;
    }

    private static byte[] Bytes(SqliteConnection connection, long id)
    {
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT data FROM path_proof_chunk WHERE proof_id=$id ORDER BY ordinal";
        query.Parameters.AddWithValue("$id", id);
        using var read = query.ExecuteReader();
        using var bytes = new MemoryStream();
        while (read.Read()) bytes.Write((byte[])read.GetValue(0));
        return bytes.ToArray();
    }

    private static void AssertShape(SqliteConnection connection, long id, long length)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT byte_length,chunk_count FROM path_proof WHERE id=$id";
        command.Parameters.AddWithValue("$id", id);
        using (var read = command.ExecuteReader())
        {
            Assert.True(read.Read());
            Assert.Equal(length, read.GetInt64(0));
            Assert.Equal((length - 1) / PathProofStorage.ChunkSize + 1, read.GetInt64(1));
        }
        command.CommandText = "SELECT ordinal,length(data) FROM path_proof_chunk WHERE proof_id=$id ORDER BY ordinal";
        using var rows = command.ExecuteReader();
        var ordinal = 0L;
        var remaining = length;
        while (rows.Read())
        {
            Assert.Equal(ordinal++, rows.GetInt64(0));
            var expected = Math.Min(remaining, PathProofStorage.ChunkSize);
            Assert.Equal(expected, rows.GetInt64(1));
            remaining -= expected;
        }
        Assert.Equal(0, remaining);
    }

    private static object? Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}
