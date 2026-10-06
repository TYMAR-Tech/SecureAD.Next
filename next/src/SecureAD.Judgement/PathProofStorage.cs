using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static class PathProofStorage
{
    internal const int ChunkSize = 64 * 1024;

    internal readonly record struct Reference(long Id, byte[] Fingerprint);

    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE path_proof (id INTEGER PRIMARY KEY, byte_length INTEGER NOT NULL CHECK(byte_length>0),
                chunk_count INTEGER NOT NULL CHECK(chunk_count>0));
            CREATE TABLE path_proof_chunk (
                proof_id INTEGER NOT NULL REFERENCES path_proof(id) DEFERRABLE INITIALLY DEFERRED,
                ordinal INTEGER NOT NULL CHECK(ordinal>=0),
                data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 65536),
                PRIMARY KEY(proof_id,ordinal));
            """;
        command.ExecuteNonQuery();
    }

    internal sealed class Writer : IBufferWriter<byte>, IDisposable
    {
        private readonly SqliteCommand _insertProof;
        private readonly SqliteCommand _insertChunk;
        private readonly CancellationToken _cancellationToken;
        private readonly byte[] _chunk = new byte[ChunkSize];
        private byte[] _buffer = [];
        private IncrementalHash? _hash;
        private long _id;
        private long _length;
        private long _chunks;
        private int _used;

        internal Writer(SqliteConnection connection, SqliteTransaction transaction, CancellationToken cancellationToken)
        {
            _cancellationToken = cancellationToken;
            using var query = connection.CreateCommand();
            query.Transaction = transaction;
            query.CommandText = "SELECT COALESCE(MAX(id),0) FROM path_proof";
            _id = (long)query.ExecuteScalar()!;
            _insertProof = connection.CreateCommand();
            _insertProof.Transaction = transaction;
            _insertProof.CommandText = "INSERT INTO path_proof VALUES ($id,$length,$chunks)";
            _insertProof.Parameters.Add("$id", SqliteType.Integer);
            _insertProof.Parameters.Add("$length", SqliteType.Integer);
            _insertProof.Parameters.Add("$chunks", SqliteType.Integer);
            _insertProof.Prepare();
            _insertChunk = connection.CreateCommand();
            _insertChunk.Transaction = transaction;
            _insertChunk.CommandText = "INSERT INTO path_proof_chunk VALUES ($id,$ordinal,$data)";
            _insertChunk.Parameters.Add("$id", SqliteType.Integer);
            _insertChunk.Parameters.Add("$ordinal", SqliteType.Integer);
            _insertChunk.Parameters.Add("$data", SqliteType.Blob).Value = _chunk;
            _insertChunk.Prepare();
        }

        internal Reference Write<T>(T value)
        {
            _cancellationToken.ThrowIfCancellationRequested();
            _id = checked(_id + 1);
            _length = _chunks = _used = 0;
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            _hash = hash;
            try
            {
                // The stream serializer can buffer a scalar collection. Commit UTF-8 segments
                // directly, retaining at most a serializer segment and one database fragment.
                Tier0PathCalculation.WriteJson(this, value);
                FlushChunk();
                _cancellationToken.ThrowIfCancellationRequested();
                _insertProof.Parameters["$id"].Value = _id;
                _insertProof.Parameters["$length"].Value = _length;
                _insertProof.Parameters["$chunks"].Value = _chunks;
                if (_insertProof.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
                return new(_id, hash.GetHashAndReset());
            }
            finally
            {
                _hash = null;
            }
        }

        public void Advance(int count)
        {
            if (count < 0 || count > _buffer.Length) throw new ArgumentOutOfRangeException(nameof(count));
            _cancellationToken.ThrowIfCancellationRequested();
            var bytes = _buffer.AsSpan(0, count);
            (_hash ?? throw new InvalidOperationException("No path proof is being written.")).AppendData(bytes);
            _length = checked(_length + count);
            while (!bytes.IsEmpty)
            {
                var take = Math.Min(ChunkSize - _used, bytes.Length);
                bytes[..take].CopyTo(_chunk.AsSpan(_used));
                _used += take;
                bytes = bytes[take..];
                if (_used == ChunkSize) FlushChunk();
            }
        }

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(sizeHint);
            _cancellationToken.ThrowIfCancellationRequested();
            var minimum = Math.Max(sizeHint, ChunkSize);
            if (_buffer.Length < minimum)
            {
                var replacement = ArrayPool<byte>.Shared.Rent(minimum);
                if (_buffer.Length != 0) ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
                _buffer = replacement;
            }
            return _buffer;
        }

        public Span<byte> GetSpan(int sizeHint = 0) => GetMemory(sizeHint).Span;

        private void FlushChunk()
        {
            if (_used == 0) return;
            _cancellationToken.ThrowIfCancellationRequested();
            _insertChunk.Parameters["$id"].Value = _id;
            _insertChunk.Parameters["$ordinal"].Value = _chunks;
            _insertChunk.Parameters["$data"].Size = _used;
            if (_insertChunk.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
            _chunks = checked(_chunks + 1);
            _used = 0;
        }

        public void Dispose()
        {
            _insertChunk.Dispose();
            _insertProof.Dispose();
            if (_buffer.Length != 0) ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
            _buffer = [];
            Array.Clear(_chunk);
        }
    }

    internal static T Read<T>(SqliteConnection connection, long id, string fingerprint,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT byte_length,chunk_count FROM path_proof WHERE id=$id";
        query.Parameters.AddWithValue("$id", id);
        long length;
        long chunks;
        using (var read = query.ExecuteReader())
        {
            if (id <= 0 || !read.Read()) throw Tier0PathStorage.InvalidProof();
            length = read.GetInt64(0);
            chunks = read.GetInt64(1);
            if (length <= 0 || chunks != (length - 1) / ChunkSize + 1) throw Tier0PathStorage.InvalidProof();
        }
        query.CommandText = "SELECT ordinal,length(data),rowid FROM path_proof_chunk WHERE proof_id=$id ORDER BY ordinal";
        using var rows = query.ExecuteReader();
        using var stream = new ChunkStream(connection, rows, length, chunks, fingerprint, cancellationToken);
        try
        {
            var value = JsonSerializer.Deserialize<T>(stream, ProofSerialization.Options) ?? throw Tier0PathStorage.InvalidProof();
            stream.RequireComplete();
            cancellationToken.ThrowIfCancellationRequested();
            return value;
        }
        catch (JsonException)
        {
            throw Tier0PathStorage.InvalidProof();
        }
    }

    private sealed class ChunkStream(SqliteConnection connection, SqliteDataReader rows, long length, long chunks, string fingerprint,
        CancellationToken cancellationToken) : Stream
    {
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private readonly byte[] _current = new byte[ChunkSize];
        private int _available;
        private int _offset;
        private long _next;
        private long _position;
        private bool _finished;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get => _position; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var copied = 0;
            while (!buffer.IsEmpty)
            {
                if (_offset == _available && !NextChunk()) break;
                var take = Math.Min(buffer.Length, _available - _offset);
                _current.AsSpan(_offset, take).CopyTo(buffer);
                _offset += take;
                copied += take;
                _position += take;
                buffer = buffer[take..];
            }
            return copied;
        }

        private bool NextChunk()
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_finished) return false;
            if (!rows.Read())
            {
                if (_next != chunks || _position != length
                    || Convert.ToHexString(_hash.GetHashAndReset()) != fingerprint) throw Tier0PathStorage.InvalidProof();
                _finished = true;
                return false;
            }
            var expectedLength = _next == chunks - 1 ? length - _next * ChunkSize : ChunkSize;
            if (_next >= chunks || rows.GetInt64(0) != _next || rows.GetInt64(1) != expectedLength)
                throw Tier0PathStorage.InvalidProof();
            _available = checked((int)expectedLength);
            // GetBytes materializes a provider-owned byte array. Incremental BLOB I/O
            // fills our reusable fragment buffer without that extra copy.
            using (var blob = new SqliteBlob(connection, "path_proof_chunk", "data", rows.GetInt64(2), readOnly: true))
                blob.ReadExactly(_current, 0, _available);
            _offset = 0;
            _hash.AppendData(_current.AsSpan(0, _available));
            _next++;
            return true;
        }

        internal void RequireComplete()
        {
            if (ReadByte() != -1 || !_finished) throw Tier0PathStorage.InvalidProof();
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) _hash.Dispose();
            base.Dispose(disposing);
        }
    }

    internal static void RequirePublishable(SqliteConnection connection, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT p.id FROM path_proof p LEFT JOIN path_proof_chunk c ON c.proof_id=p.id
            GROUP BY p.id HAVING COUNT(c.ordinal)<>p.chunk_count OR SUM(length(c.data))<>p.byte_length
                OR MIN(c.ordinal)<>0 OR MAX(c.ordinal)<>p.chunk_count-1
                OR p.chunk_count<>(p.byte_length-1)/65536+1
                OR SUM(CASE WHEN c.ordinal<p.chunk_count-1 AND length(c.data)<>65536 THEN 1 ELSE 0 END)<>0
            UNION ALL
            SELECT c.proof_id FROM path_proof_chunk c LEFT JOIN path_proof p ON p.id=c.proof_id WHERE p.id IS NULL
            LIMIT 1
            """;
        if (query.ExecuteScalar() is not null) throw Tier0PathStorage.InvalidProof();
        cancellationToken.ThrowIfCancellationRequested();
    }
}
