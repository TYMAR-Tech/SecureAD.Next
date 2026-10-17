using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace SecureAD.Evidence;

internal sealed class RequestedDetailRecordWriter : IDisposable
{
    internal const string Records = "requested_detail_record";
    private readonly SqliteConnection _connection;
    private readonly SqliteCommand _write;
    private readonly UTF8Encoding _utf8 = new(false);

    internal sealed record Field(int Column, RequestedDetailIndex.Fragment[] Fragments);
    internal sealed record Produced(string Shape, RequestedDetailIndex.Row Row, Field[] Fields);
    internal sealed record EncodedText(string Value, byte[] Utf8);

    internal static void Create(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            CREATE TEMP TABLE IF NOT EXISTS {Records}(
                source_schema TEXT NOT NULL,source_table TEXT NOT NULL,source_rowid INTEGER NOT NULL,
                ordinal INTEGER NOT NULL CHECK(ordinal>=0),
                byte_length INTEGER NOT NULL CHECK(byte_length>0),piece_count INTEGER NOT NULL CHECK(piece_count>0),
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
                piece_length INTEGER NOT NULL CHECK(piece_length BETWEEN 1 AND 65536),
                piece_fingerprint BLOB NOT NULL CHECK(length(piece_fingerprint)=32),
                data BLOB NOT NULL CHECK(length(data)=piece_length),
                PRIMARY KEY(source_schema,source_table,source_rowid,ordinal));
            """;
        command.ExecuteNonQuery();
    }

    internal RequestedDetailRecordWriter(SqliteConnection connection)
    {
        _connection = connection;
        _write = connection.CreateCommand();
        _write.CommandText = $"INSERT INTO temp.{Records} VALUES($schema,$table,$row,$ordinal,$length,$pieces,$hash,$pieceLength,$pieceHash,$data)";
        _write.Parameters.Add("$schema", SqliteType.Text);
        _write.Parameters.Add("$table", SqliteType.Text);
        _write.Parameters.Add("$row", SqliteType.Integer);
        _write.Parameters.Add("$ordinal", SqliteType.Integer);
        _write.Parameters.Add("$length", SqliteType.Integer);
        _write.Parameters.Add("$pieces", SqliteType.Integer);
        _write.Parameters.Add("$hash", SqliteType.Blob);
        _write.Parameters.Add("$pieceLength", SqliteType.Integer);
        _write.Parameters.Add("$pieceHash", SqliteType.Blob);
        _write.Parameters.Add("$data", SqliteType.Blob);
    }

    internal void Write(SqliteTransaction transaction, string schema, RequestedDetailIndex.RecordLayout layout,
        long rowId, object?[] values, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        if (transaction.Connection != _connection || rowId <= 0 || values.Length != layout.Columns.Length)
            throw RequestedDetailMap.Invalid();
        var cells = new RequestedDetailIndex.Cell[values.Length];
        var fields = new List<Field>();
        for (var column = 0; column < values.Length; column++)
        {
            token.ThrowIfCancellationRequested();
            var value = Normalize(values[column]);
            cells[column] = value switch
            {
                null => new(0, 0, 0, null, null),
                long integer => new(1, integer, 0, null, null),
                double real => new(2, 0, real, null, null),
                EncodedText text => Binary(column, 3, text.Utf8, fields, token),
                string text => Text(column, text, fields, token),
                byte[] bytes => Binary(column, 4, bytes, fields, token),
                _ => throw RequestedDetailMap.Invalid(),
            };
        }
        var keys = layout.Keys.Select(column => RequestedDetailIndex.KeyValue.From(
            Normalize(values[column]) is EncodedText text ? text.Value : Normalize(values[column]) ?? DBNull.Value)).ToArray();
        var metadata = JsonSerializer.SerializeToUtf8Bytes(new Produced(layout.Shape, new(rowId, keys, cells), [.. fields]));
        var hash = SHA256.HashData(metadata);
        var pieces = (metadata.Length - 1) / RequestedDetailMap.MaximumBytes + 1;
        _write.Transaction = transaction;
        _write.Parameters["$schema"].Value = schema;
        _write.Parameters["$table"].Value = layout.Table;
        _write.Parameters["$row"].Value = rowId;
        _write.Parameters["$length"].Value = metadata.Length;
        _write.Parameters["$pieces"].Value = pieces;
        _write.Parameters["$hash"].Value = hash;
        var ordinal = 0;
        for (var offset = 0; offset < metadata.Length;)
        {
            token.ThrowIfCancellationRequested();
            var length = Math.Min(RequestedDetailMap.MaximumBytes, metadata.Length - offset);
            var bytes = metadata.AsSpan(offset, length);
            _write.Parameters["$ordinal"].Value = ordinal++;
            _write.Parameters["$pieceLength"].Value = length;
            _write.Parameters["$pieceHash"].Value = pieces == 1 ? hash : SHA256.HashData(bytes);
            _write.Parameters["$data"].Value = pieces == 1 ? metadata : bytes.ToArray();
            if (_write.ExecuteNonQuery() != 1) throw RequestedDetailMap.Invalid();
            offset += length;
        }
        token.ThrowIfCancellationRequested();
    }

    private static object? Normalize(object? value) => value switch
    {
        null or DBNull => null,
        bool boolean => boolean ? 1L : 0L,
        byte number => (long)number,
        int number => (long)number,
        long or double or string or byte[] or EncodedText => value,
        _ => throw new InvalidDataException("A producer record contains an undeclared SQLite storage type."),
    };

    private static RequestedDetailIndex.Cell Binary(int column, int kind, byte[] value, List<Field> fields, CancellationToken token)
    {
        if (value.Length == 0) return new(kind, 0, 0, [], null);
        if (value.Length <= RequestedDetailMap.MaximumBytes)
            return Cell(column, kind, value.Length, SHA256.HashData(value), [], fields);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var fragments = new List<RequestedDetailIndex.Fragment>();
        for (var offset = 0; offset < value.Length;)
        {
            token.ThrowIfCancellationRequested();
            var length = Math.Min(RequestedDetailMap.MaximumBytes, value.Length - offset);
            var piece = value.AsSpan(offset, length);
            hash.AppendData(piece);
            fragments.Add(new(length, Convert.ToHexString(SHA256.HashData(piece))));
            offset += length;
        }
        return Cell(column, kind, value.LongLength, hash.GetHashAndReset(), [.. fragments], fields);
    }

    private RequestedDetailIndex.Cell Text(int column, string value, List<Field> fields, CancellationToken token)
    {
        var length = _utf8.GetByteCount(value);
        if (length == 0) return new(3, 0, 0, [], null);
        var encoded = ArrayPool<byte>.Shared.Rent(RequestedDetailMap.MaximumBytes);
        byte[]? piece = null;
        try
        {
            if (length <= RequestedDetailMap.MaximumBytes)
            {
                var count = _utf8.GetBytes(value.AsSpan(), encoded.AsSpan());
                return Cell(column, 3, count, SHA256.HashData(encoded.AsSpan(0, count)), [], fields);
            }
            piece = ArrayPool<byte>.Shared.Rent(RequestedDetailMap.MaximumBytes);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var fragments = new List<RequestedDetailIndex.Fragment>();
            var encoder = _utf8.GetEncoder();
            var remaining = value.AsSpan();
            var used = 0;
            var complete = false;
            while (!complete)
            {
                token.ThrowIfCancellationRequested();
                encoder.Convert(remaining, encoded.AsSpan(0, RequestedDetailMap.MaximumBytes), true,
                    out var chars, out var bytes, out complete);
                if (!complete && chars == 0 && bytes == 0) throw RequestedDetailMap.Invalid();
                remaining = remaining[chars..];
                var output = encoded.AsSpan(0, bytes);
                hash.AppendData(output);
                while (!output.IsEmpty)
                {
                    var take = Math.Min(RequestedDetailMap.MaximumBytes - used, output.Length);
                    output[..take].CopyTo(piece.AsSpan(used));
                    used += take;
                    output = output[take..];
                    if (used == RequestedDetailMap.MaximumBytes) FinishPiece();
                }
            }
            FinishPiece();
            return Cell(column, 3, length, hash.GetHashAndReset(), [.. fragments], fields);

            void FinishPiece()
            {
                if (used == 0) return;
                fragments.Add(new(used, Convert.ToHexString(SHA256.HashData(piece.AsSpan(0, used)))));
                used = 0;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(encoded, clearArray: true);
            if (piece is not null) ArrayPool<byte>.Shared.Return(piece, clearArray: true);
        }
    }

    private static RequestedDetailIndex.Cell Cell(int column, int kind, long length, byte[] hash,
        RequestedDetailIndex.Fragment[] fragments, List<Field> fields)
    {
        if (fragments.Length != 0) fields.Add(new(column, fragments));
        return new(kind, 0, 0, null, new(0, column, kind, length, Convert.ToHexString(hash), null));
    }

    internal static Produced Read(SqliteConnection connection, SqliteTransaction transaction, string schema,
        RequestedDetailIndex.RecordLayout layout, long rowId, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = $"""
            SELECT ordinal,byte_length,piece_count,fingerprint,piece_length,piece_fingerprint,length(data),data
            FROM temp.{Records} WHERE source_schema=$schema AND source_table=$table AND source_rowid=$row ORDER BY ordinal
            """;
        query.Parameters.AddWithValue("$schema", schema);
        query.Parameters.AddWithValue("$table", layout.Table);
        query.Parameters.AddWithValue("$row", rowId);
        byte[] bytes;
        using (var read = query.ExecuteReader())
        {
            if (!read.Read()) throw new InvalidDataException("A declared producer record has no final-write metadata.");
            var length = checked((int)read.GetInt64(1));
            var count = checked((int)read.GetInt64(2));
            var expected = (byte[])read.GetValue(3);
            if (length <= 0 || count != (length - 1) / RequestedDetailMap.MaximumBytes + 1 || expected.Length != 32)
                throw RequestedDetailMap.Invalid();
            bytes = new byte[length];
            var ordinal = 0;
            var offset = 0;
            byte[]? onlyPieceHash = null;
            using var hash = count == 1 ? null : IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            do
            {
                token.ThrowIfCancellationRequested();
                var take = Math.Min(RequestedDetailMap.MaximumBytes, length - offset);
                if (ordinal >= count || read.GetInt64(0) != ordinal || read.GetInt64(1) != length
                    || read.GetInt64(2) != count || !expected.AsSpan().SequenceEqual((byte[])read.GetValue(3))
                    || read.GetInt64(4) != take || read.GetInt64(6) != take)
                    throw RequestedDetailMap.Invalid();
                var piece = (byte[])read.GetValue(7);
                if (piece.Length != take) throw RequestedDetailMap.Invalid();
                var pieceHash = SHA256.HashData(piece);
                if (!pieceHash.AsSpan().SequenceEqual((byte[])read.GetValue(5)))
                    throw RequestedDetailMap.Invalid();
                piece.CopyTo(bytes, offset);
                if (hash is null) onlyPieceHash = pieceHash;
                else hash.AppendData(piece);
                ordinal++;
                offset += take;
            }
            while (read.Read());
            var actual = hash is null ? onlyPieceHash ?? throw RequestedDetailMap.Invalid() : hash.GetHashAndReset();
            if (ordinal != count || offset != length || !actual.AsSpan().SequenceEqual(expected))
                throw RequestedDetailMap.Invalid();
        }
        try
        {
            var value = JsonSerializer.Deserialize<Produced>(bytes) ?? throw RequestedDetailMap.Invalid();
            if (value.Shape != layout.Shape || value.Row?.RowId != rowId || value.Fields is null)
                throw RequestedDetailMap.Invalid();
            return value;
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("A producer record's metadata is invalid.", error);
        }
    }

    internal static void Consume(SqliteConnection connection, SqliteTransaction transaction, string schema,
        RequestedDetailIndex.RecordLayout layout, long rows)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.Parameters.AddWithValue("$schema", schema);
        command.Parameters.AddWithValue("$table", layout.Table);
        command.CommandText = $"SELECT COUNT(*) FROM temp.{Records} WHERE source_schema=$schema AND source_table=$table AND ordinal=0";
        if ((long)command.ExecuteScalar()! != rows)
            throw new InvalidDataException("Producer metadata and source-row counts disagree.");
        command.CommandText = $"""
            SELECT EXISTS(SELECT 1 FROM temp.{Records} p LEFT JOIN temp.{Records} h
                ON p.source_schema=h.source_schema AND p.source_table=h.source_table
                    AND p.source_rowid=h.source_rowid AND h.ordinal=0
                WHERE p.source_schema=$schema AND p.source_table=$table AND h.source_rowid IS NULL)
            """;
        if ((long)command.ExecuteScalar()! != 0)
            throw new InvalidDataException("A producer metadata piece has no complete record.");
        command.CommandText = $"""
            DELETE FROM temp.{Records} WHERE source_schema=$schema AND source_table=$table;
            """;
        command.ExecuteNonQuery();
    }

    internal static void RequireConsumed(SqliteConnection connection, SqliteTransaction transaction, string schema)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT COUNT(*) FROM temp.sqlite_schema WHERE name='{Records}'";
        if ((long)command.ExecuteScalar()! == 0) return;
        command.CommandText = $"""
            SELECT EXISTS(SELECT 1 FROM temp.{Records} WHERE source_schema=$schema)
            """;
        command.Parameters.AddWithValue("$schema", schema);
        if ((long)command.ExecuteScalar()! != 0)
            throw new InvalidDataException("Final-write record metadata was not included in this publication.");
    }

    internal static void RequireAllConsumed(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT EXISTS(SELECT 1 FROM temp.{Records})";
        if ((long)command.ExecuteScalar()! != 0)
            throw new InvalidDataException("A producer record belongs to no completed publication role.");
    }

    public void Dispose()
    {
        _write.Dispose();
    }
}
