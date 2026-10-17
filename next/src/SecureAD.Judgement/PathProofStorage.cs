using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static class PathProofStorage
{
    internal const int ChunkSize = 64 * 1024;

    internal static IReadOnlyList<RequestedDetailIndex.PayloadLayout> RequestedPayloads { get; } =
    [
        new("path_proof_chunk", "proof_id", "ordinal", "data", "byte_length", "fingerprint"),
    ];

    internal readonly record struct Reference(long Id, byte[] Fingerprint);

    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        // Trailing metadata can make SQLite walk the BLOB's overflow pages just to read a header.
        command.CommandText = $"""
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PathProof)}.path_proof (id INTEGER PRIMARY KEY, byte_length INTEGER NOT NULL CHECK(byte_length>0),
                chunk_count INTEGER NOT NULL CHECK(chunk_count>0));
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PathProof)}.path_proof_chunk (
                proof_id INTEGER NOT NULL REFERENCES path_proof(id) DEFERRABLE INITIALLY DEFERRED,
                ordinal INTEGER NOT NULL CHECK(ordinal>=0),
                byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 65536 AND byte_length=length(data)),
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
                data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 65536),
                PRIMARY KEY(proof_id,ordinal));
            """;
        command.ExecuteNonQuery();
    }

    internal sealed class Writer : IDisposable
    {
        private readonly SqliteCommand _insertProof;
        private readonly SqliteCommand _insertChunk;
        private readonly CancellationToken _cancellationToken;
        private readonly Stack<Document> _available = [];
        private long _id;

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
            _insertChunk.CommandText = "INSERT INTO path_proof_chunk(proof_id,ordinal,data,byte_length,fingerprint) VALUES ($id,$ordinal,$data,$length,$hash)";
            _insertChunk.Parameters.Add("$id", SqliteType.Integer);
            _insertChunk.Parameters.Add("$ordinal", SqliteType.Integer);
            _insertChunk.Parameters.Add("$data", SqliteType.Blob);
            _insertChunk.Parameters.Add("$length", SqliteType.Integer);
            _insertChunk.Parameters.Add("$hash", SqliteType.Blob);
            _insertChunk.Prepare();
        }

        internal Reference Write<T>(T value) => Write(value, ProofSerialization.Options);

        internal Reference Write<T>(T value, JsonSerializerOptions options)
        {
            _cancellationToken.ThrowIfCancellationRequested();
            var id = _id = checked(_id + 1);
            var document = _available.TryPop(out var reusable) ? reusable : new Document(this);
            try
            {
                document.Start(id);
                Tier0PathCalculation.WriteJson(document, value, options);
                var fingerprint = document.Finish();
                _cancellationToken.ThrowIfCancellationRequested();
                _insertProof.Parameters["$id"].Value = id;
                _insertProof.Parameters["$length"].Value = document.Length;
                _insertProof.Parameters["$chunks"].Value = document.Chunks;
                if (_insertProof.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
                return new(id, fingerprint);
            }
            finally
            {
                document.Reset();
                _available.Push(document);
            }
        }

        private sealed class Document(Writer owner) : IBufferWriter<byte>, IDisposable
        {
            private readonly byte[] _chunk = new byte[ChunkSize];
            private byte[] _buffer = [];
            private IncrementalHash? _hash;
            private long _id;
            private int _used;
            internal long Length { get; private set; }
            internal long Chunks { get; private set; }

            internal void Start(long id)
            {
                _id = id;
                Length = Chunks = _used = 0;
                _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            }

            public void Advance(int count)
            {
                if (count < 0 || count > _buffer.Length) throw new ArgumentOutOfRangeException(nameof(count));
                owner._cancellationToken.ThrowIfCancellationRequested();
                var bytes = _buffer.AsSpan(0, count);
                (_hash ?? throw new InvalidOperationException("No path proof is being written.")).AppendData(bytes);
                Length = checked(Length + count);
                while (!bytes.IsEmpty)
                {
                    var take = Math.Min(ChunkSize - _used, bytes.Length);
                    bytes[..take].CopyTo(_chunk.AsSpan(_used));
                    _used += take;
                    bytes = bytes[take..];
                    if (_used == ChunkSize) Flush();
                }
            }

            public Memory<byte> GetMemory(int sizeHint = 0)
            {
                ArgumentOutOfRangeException.ThrowIfNegative(sizeHint);
                owner._cancellationToken.ThrowIfCancellationRequested();
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

            private void Flush()
            {
                if (_used == 0) return;
                owner._cancellationToken.ThrowIfCancellationRequested();
                owner._insertChunk.Parameters["$id"].Value = _id;
                owner._insertChunk.Parameters["$ordinal"].Value = Chunks;
                owner._insertChunk.Parameters["$data"].Value = _chunk;
                owner._insertChunk.Parameters["$data"].Size = _used;
                owner._insertChunk.Parameters["$length"].Value = _used;
                owner._insertChunk.Parameters["$hash"].Value = SHA256.HashData(_chunk.AsSpan(0, _used));
                if (owner._insertChunk.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
                Chunks = checked(Chunks + 1);
                _used = 0;
            }

            internal byte[] Finish()
            {
                Flush();
                return (_hash ?? throw Tier0PathStorage.InvalidProof()).GetHashAndReset();
            }

            internal void Reset()
            {
                _hash?.Dispose();
                _hash = null;
            }

            public void Dispose()
            {
                Reset();
                if (_buffer.Length != 0) ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
                _buffer = [];
                Array.Clear(_chunk);
            }
        }

        public void Dispose()
        {
            _insertChunk.Dispose();
            _insertProof.Dispose();
            foreach (var document in _available) document.Dispose();
            _available.Clear();
        }
    }

    internal static T Read<T>(SqliteConnection connection, long id, string fingerprint,
        CancellationToken cancellationToken) => Read<T>(connection, id, fingerprint, cancellationToken, ProofSerialization.Options);

    internal static T Read<T>(SqliteConnection connection, long id, string fingerprint,
        CancellationToken cancellationToken, JsonSerializerOptions options)
    {
        using var stream = Open(connection, id, fingerprint, cancellationToken);
        try
        {
            var value = JsonSerializer.Deserialize<T>(stream, options) ?? throw Tier0PathStorage.InvalidProof();
            stream.RequireComplete();
            cancellationToken.ThrowIfCancellationRequested();
            return value;
        }
        catch (JsonException)
        {
            throw Tier0PathStorage.InvalidProof();
        }
    }

    internal static bool Matches<T>(SqliteConnection connection, Reference reference, T value,
        JsonSerializerOptions options, CancellationToken cancellationToken)
    {
        using var stream = Open(connection, reference.Id, Convert.ToHexString(reference.Fingerprint), cancellationToken);
        using var comparison = new ComparisonBuffer(stream);
        Tier0PathCalculation.WriteJson(comparison, value, options);
        return comparison.Finish();
    }

    private static ChunkStream Open(SqliteConnection connection, long id, string fingerprint, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var requested = JudgementStoreLayout.Requested(connection, StoreSegmentRole.PathProof);
        JudgementStoreLayout.VerifySelected(connection, StoreSegmentRole.PathProof, "path_proof", id);
        JudgementStoreLayout.Ensure(connection, StoreSegmentRole.PathProof);
        var query = connection.CreateCommand();
        try
        {
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
            return new(connection, query, query.ExecuteReader(), length, chunks, fingerprint, cancellationToken,
                requested?.ReadCompleteScope("path_proof_chunk", id).GetEnumerator());
        }
        catch
        {
            query.Dispose();
            throw;
        }
    }

    private sealed class ChunkStream(SqliteConnection connection, SqliteCommand command, SqliteDataReader rows, long length, long chunks, string fingerprint,
        CancellationToken cancellationToken, IEnumerator<RequestedDetailRow>? requestedRows = null) : Stream
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
                if (requestedRows?.MoveNext() == true || _next != chunks || _position != length
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
            if (requestedRows is null)
            {
                using var blob = new SqliteBlob(connection, JudgementStoreLayout.Schema(connection, StoreSegmentRole.PathProof),
                    "path_proof_chunk", "data", rows.GetInt64(2), readOnly: true);
                blob.ReadExactly(_current, 0, _available);
            }
            else
            {
                if (!requestedRows.MoveNext() || requestedRows.Current.Integer("ordinal") != _next
                    || requestedRows.Current.Value("data").ByteLength != expectedLength) throw Tier0PathStorage.InvalidProof();
                requestedRows.Current.CompleteBytes("data").CopyTo(_current, 0);
            }
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
            if (disposing) requestedRows?.Dispose();
            if (disposing)
            {
                _hash.Dispose();
                rows.Dispose();
                command.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    private sealed class ComparisonBuffer(ChunkStream source) : IBufferWriter<byte>, IDisposable
    {
        private byte[] _buffer = [];
        private readonly byte[] _read = new byte[ChunkSize];
        private bool _equal = true;

        public void Advance(int count)
        {
            var remaining = _buffer.AsSpan(0, count);
            while (!remaining.IsEmpty)
            {
                var wanted = Math.Min(remaining.Length, _read.Length);
                var read = source.Read(_read.AsSpan(0, wanted));
                if (read != wanted || !remaining[..wanted].SequenceEqual(_read.AsSpan(0, wanted))) _equal = false;
                remaining = remaining[wanted..];
            }
        }

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            if (_buffer.Length < Math.Max(sizeHint, ChunkSize))
            {
                if (_buffer.Length != 0) ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
                _buffer = ArrayPool<byte>.Shared.Rent(Math.Max(sizeHint, ChunkSize));
            }
            return _buffer;
        }

        public Span<byte> GetSpan(int sizeHint = 0) => GetMemory(sizeHint).Span;

        internal bool Finish()
        {
            while (source.Read(_read) != 0) _equal = false;
            source.RequireComplete();
            return _equal;
        }

        public void Dispose()
        {
            if (_buffer.Length != 0) ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
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
