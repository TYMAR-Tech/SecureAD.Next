using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal sealed class SavedTextPayloadStorage(StoreSegmentRole role, string table, Func<Exception> invalid)
{
    internal const int ChunkSize = RequestedDetailMap.MaximumBytes;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    internal static SavedTextPayloadStorage Classifications { get; } = new(
        StoreSegmentRole.JudgementFacts, "classification_payload",
        () => new InvalidDataException(PermissionClassificationStorage.Message("Invalid")));
    internal static SavedTextPayloadStorage Permissions { get; } = new(
        StoreSegmentRole.PermissionProof, "permission_payload", FullControlEvaluator.InvalidProof);

    internal string Table { get; } = table;
    internal string Chunks { get; } = table + "_chunk";
    internal StoreSegmentRole Role { get; } = role;
    internal IReadOnlyList<RequestedDetailIndex.PayloadLayout> RequestedPayloads { get; } =
    [
        new(table + "_chunk", "payload_id", "ordinal", "data", "byte_length", "fingerprint"),
    ];

    private string Schema(SqliteConnection connection) => JudgementStoreLayout.Schema(connection, Role);
    private string Qualified(SqliteConnection connection, string name) =>
        RequestedDetailMap.Quote(Schema(connection)) + "." + RequestedDetailMap.Quote(name);

    internal void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        // Keep headers before data so reading a location does not walk the BLOB's overflow pages.
        command.CommandText = $"""
            CREATE TABLE {Qualified(connection, Table)} (
                id INTEGER PRIMARY KEY CHECK(id>0),
                byte_length INTEGER NOT NULL CHECK(byte_length>=0),
                chunk_count INTEGER NOT NULL CHECK(chunk_count>=0),
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            CREATE TABLE {Qualified(connection, Chunks)} (
                payload_id INTEGER NOT NULL REFERENCES {RequestedDetailMap.Quote(Table)}(id) DEFERRABLE INITIALLY DEFERRED,
                ordinal INTEGER NOT NULL CHECK(ordinal>=0),
                byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 65536 AND byte_length=length(data)),
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
                data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 65536),
                PRIMARY KEY(payload_id,ordinal));
            """;
        command.ExecuteNonQuery();
    }

    internal long Write(SqliteConnection connection, SqliteTransaction transaction, PreparedStatements statements,
        string value, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(value);
        token.ThrowIfCancellationRequested();
        if (transaction.Connection != connection) throw invalid();
        var id = checked((long)statements.Bind(
            $"SELECT COALESCE(MAX(id),0) FROM {Qualified(connection, Table)}", transaction).ExecuteScalar()! + 1);
        var encoded = ArrayPool<byte>.Shared.Rent(ChunkSize);
        var piece = ArrayPool<byte>.Shared.Rent(ChunkSize);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var encoder = Encoding.UTF8.GetEncoder();
        var remaining = value.AsSpan();
        long length = 0, chunks = 0;
        var used = 0;
        try
        {
            var complete = false;
            while (!complete)
            {
                token.ThrowIfCancellationRequested();
                encoder.Convert(remaining, encoded.AsSpan(0, ChunkSize), flush: true,
                    out var chars, out var bytes, out complete);
                if (!complete && chars == 0 && bytes == 0) throw invalid();
                remaining = remaining[chars..];
                var output = encoded.AsSpan(0, bytes);
                hash.AppendData(output);
                length = checked(length + bytes);
                while (!output.IsEmpty)
                {
                    var take = Math.Min(ChunkSize - used, output.Length);
                    output[..take].CopyTo(piece.AsSpan(used));
                    used += take;
                    output = output[take..];
                    if (used == ChunkSize) Flush();
                }
            }
            Flush();
            token.ThrowIfCancellationRequested();
            if (statements.Bind(
                $"INSERT INTO {Qualified(connection, Table)}(id,byte_length,chunk_count,fingerprint) VALUES($id,$length,$chunks,$hash)",
                transaction, ("$id", id), ("$length", length), ("$chunks", chunks),
                ("$hash", hash.GetHashAndReset())).ExecuteNonQuery() != 1) throw invalid();
            return id;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(encoded, clearArray: true);
            ArrayPool<byte>.Shared.Return(piece, clearArray: true);
        }

        void Flush()
        {
            if (used == 0) return;
            token.ThrowIfCancellationRequested();
            var command = statements.Bind(
                $"INSERT INTO {Qualified(connection, Chunks)}(payload_id,ordinal,byte_length,fingerprint,data) VALUES($id,$ordinal,$length,$hash,$data)",
                transaction, ("$id", id), ("$ordinal", chunks), ("$length", used),
                ("$hash", SHA256.HashData(piece.AsSpan(0, used))), ("$data", piece));
            command.Parameters["$data"].Size = used;
            if (command.ExecuteNonQuery() != 1) throw invalid();
            chunks = checked(chunks + 1);
            used = 0;
        }
    }

    internal string Read(SqliteConnection connection, long id, SqliteTransaction? transaction = null,
        CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        var requested = JudgementStoreLayout.Requested(connection, Role);
        JudgementStoreLayout.VerifySelected(connection, Role, Table, id);
        JudgementStoreLayout.Ensure(connection, Role);
        using var command = connection.CreateCommand();
        // CreateCommand already carries the connection's active producing transaction.
        if (transaction is not null) command.Transaction = transaction;
        command.CommandText = $"SELECT byte_length,chunk_count,fingerprint FROM {Qualified(connection, Table)} WHERE id=$id";
        command.Parameters.AddWithValue("$id", id);
        long length, chunks;
        byte[] fingerprint;
        using (var read = command.ExecuteReader())
        {
            if (id <= 0 || !read.Read()) throw invalid();
            length = read.GetInt64(0);
            chunks = read.GetInt64(1);
            fingerprint = (byte[])read.GetValue(2);
            if (length < 0 || chunks != (length == 0 ? 0 : (length - 1) / ChunkSize + 1)
                || fingerprint.Length != 32) throw invalid();
        }
        command.CommandText = $"SELECT ordinal,byte_length,rowid FROM {Qualified(connection, Chunks)} WHERE payload_id=$id ORDER BY ordinal";
        using var rows = command.ExecuteReader();
        using var selected = requested?.ReadCompleteScope(Chunks, id).GetEnumerator();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var bytes = ArrayPool<byte>.Shared.Rent(ChunkSize);
        var characters = ArrayPool<char>.Shared.Rent(Utf8.GetMaxCharCount(ChunkSize));
        var decoder = Utf8.GetDecoder();
        var text = new StringBuilder();
        long ordinal = 0, found = 0;
        try
        {
            while (rows.Read())
            {
                token.ThrowIfCancellationRequested();
                var expected = ordinal == chunks - 1 ? length - ordinal * ChunkSize : ChunkSize;
                if (ordinal >= chunks || rows.GetInt64(0) != ordinal || rows.GetInt64(1) != expected)
                    throw invalid();
                var count = checked((int)expected);
                if (selected is null)
                {
                    using var blob = new SqliteBlob(connection, Schema(connection), Chunks, "data",
                        rows.GetInt64(2), readOnly: true);
                    if (blob.Length != count) throw invalid();
                    blob.ReadExactly(bytes.AsSpan(0, count));
                }
                else
                {
                    if (!selected.MoveNext() || selected.Current.Integer("ordinal") != ordinal
                        || selected.Current.Value("data").ByteLength != count) throw invalid();
                    selected.Current.CompleteBytes("data").CopyTo(bytes, 0);
                }
                hash.AppendData(bytes.AsSpan(0, count));
                var chars = decoder.GetChars(bytes.AsSpan(0, count), characters.AsSpan(),
                    flush: ordinal == chunks - 1);
                text.Append(characters, 0, chars);
                found = checked(found + count);
                ordinal++;
            }
            if (selected?.MoveNext() == true || ordinal != chunks || found != length
                || !hash.GetHashAndReset().AsSpan().SequenceEqual(fingerprint)) throw invalid();
            token.ThrowIfCancellationRequested();
            return text.ToString();
        }
        catch (DecoderFallbackException)
        {
            throw invalid();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(bytes, clearArray: true);
            ArrayPool<char>.Shared.Return(characters, clearArray: true);
        }
    }

    internal void RequirePublishable(SqliteConnection connection, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT p.id FROM {Qualified(connection, Table)} p
            LEFT JOIN {Qualified(connection, Chunks)} c ON c.payload_id=p.id
            GROUP BY p.id HAVING COUNT(c.ordinal)<>p.chunk_count
                OR COALESCE(SUM(c.byte_length),0)<>p.byte_length
                OR p.chunk_count<>CASE WHEN p.byte_length=0 THEN 0 ELSE (p.byte_length-1)/65536+1 END
                OR (p.chunk_count>0 AND (MIN(c.ordinal)<>0 OR MAX(c.ordinal)<>p.chunk_count-1))
                OR SUM(CASE WHEN c.ordinal<p.chunk_count-1 AND c.byte_length<>65536 THEN 1 ELSE 0 END)<>0
            UNION ALL
            SELECT c.payload_id FROM {Qualified(connection, Chunks)} c
            LEFT JOIN {Qualified(connection, Table)} p ON p.id=c.payload_id WHERE p.id IS NULL
            LIMIT 1
            """;
        if (command.ExecuteScalar() is not null) throw invalid();
        token.ThrowIfCancellationRequested();
    }
}
