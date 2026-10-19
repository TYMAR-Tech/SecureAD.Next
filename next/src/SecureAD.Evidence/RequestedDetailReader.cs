using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace SecureAD.Evidence;

/// <summary>A continuation belongs to one exact native index, table and source scope.</summary>
public sealed record RequestedDetailMark(string Root, string Scope, long Page);

/// <summary>Source records and saved totals; references to large values are not loaded values.</summary>
public sealed record RequestedDetailPage(bool Exists, long TotalRows, IReadOnlyList<RequestedDetailRow> Rows,
    RequestedDetailMark? Next);

/// <summary>One bounded range of the original SQLite text or binary bytes.</summary>
public sealed record RequestedDetailBytes(long Offset, long TotalBytes, byte[] Bytes, long? NextOffset);

/// <summary>An unforgeable locator produced by a verified native metadata page.</summary>
public sealed class RequestedDetailValue
{
    internal RequestedDetailValue(string root, string table, RequestedDetailIndex.KeyValue owner,
        long page, int row, int column, int kind, long length)
        => (Root, Table, Owner, Page, Row, Column, Kind, ByteLength) =
            (root, table, owner, page, row, column, kind, length);

    internal string Root { get; }
    internal string Table { get; }
    internal RequestedDetailIndex.KeyValue Owner { get; }
    internal long Page { get; }
    internal int Row { get; }
    internal int Column { get; }
    internal int Kind { get; }
    /// <summary>The complete stored byte count, independent of the loaded fragment.</summary>
    public long ByteLength { get; }
    /// <summary>Text fragments contain the original stored UTF-8, not a reworded value.</summary>
    public bool IsText => Kind == 3;
}

/// <summary>A source-bound record header; text/binary references are checked when their values are read.</summary>
public sealed class RequestedDetailRow
{
    private readonly RequestedDetailReader _reader;
    internal readonly RequestedDetailIndex.Table Table;
    internal readonly RequestedDetailIndex.Row Source;
    internal readonly RequestedDetailIndex.KeyValue Owner;
    internal readonly long Page;
    internal readonly int Position;

    internal RequestedDetailRow(RequestedDetailReader reader, RequestedDetailIndex.Table table,
        RequestedDetailIndex.Row source, RequestedDetailIndex.KeyValue owner, long page, int position)
        => (_reader, Table, Source, Owner, Page, Position) = (reader, table, source, owner, page, position);

    private int Column(string name)
    {
        var index = Array.IndexOf(Table.Columns, name);
        return index >= 0 ? index : throw new InvalidDataException("The requested native column is absent.");
    }

    /// <summary>Whether this exact source column was null.</summary>
    public bool IsNull(string name) => Source.Cells[Column(name)].Kind == 0;
    /// <summary>Reads one stored integer without a conversion or default.</summary>
    public long Integer(string name) => Source.Cells[Column(name)] is { Kind: 1 } cell
        ? cell.Integer : throw RequestedDetailMap.Invalid();
    /// <summary>Reads one stored real without a conversion or default.</summary>
    public double Real(string name) => Source.Cells[Column(name)] is { Kind: 2 } cell
        ? cell.Real : throw RequestedDetailMap.Invalid();

    /// <summary>Returns a source-bound text/binary locator without loading a large value.</summary>
    public RequestedDetailValue Value(string name)
    {
        var column = Column(name);
        var cell = Source.Cells[column];
        if (cell.Kind is not (3 or 4)) throw RequestedDetailMap.Invalid();
        return new(_reader.Manifest.Root, Table.Name, Owner, Page, Position, column, cell.Kind,
            cell.Large?.Length ?? cell.Bytes!.LongLength);
    }

    /// <summary>Reads a complete text value; this is not a page operation.</summary>
    public string CompleteText(string name)
    {
        var reference = Value(name);
        if (!reference.IsText) throw RequestedDetailMap.Invalid();
        using var stream = _reader.OpenValue(reference);
        using var text = new StreamReader(stream, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: false,
            bufferSize: 4096, leaveOpen: false);
        return text.ReadToEnd();
    }

    /// <summary>Reads a complete binary value; this is not a page operation.</summary>
    public byte[] CompleteBytes(string name)
    {
        var reference = Value(name);
        if (reference.IsText || reference.ByteLength > Array.MaxLength) throw RequestedDetailMap.Invalid();
        using var stream = _reader.OpenValue(reference);
        var bytes = new byte[checked((int)reference.ByteLength)];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw RequestedDetailMap.Invalid();
        return bytes;
    }

    /// <summary>Checks every value in this selected record without assembling its large values.</summary>
    public void VerifyValues()
    {
        foreach (var column in Table.Columns)
        {
            if (IsNull(column) || Source.Cells[Column(column)].Kind is not (3 or 4)) continue;
            var value = Value(column);
            long? offset = 0;
            do { offset = _reader.ReadValuePage(value, offset.Value).NextOffset; }
            while (offset is not null);
        }
    }
}

/// <summary>Reads only authenticated native metadata pages and the source ranges actually requested.</summary>
public sealed class RequestedDetailReader
{
    private static readonly Meter Meter = new("SecureAD.Evidence.RequestedDetails");
    private static readonly Counter<long> SourceBytes = Meter.CreateCounter<long>("requested_detail.value_bytes");
    private static readonly Counter<long> SourcePages = Meter.CreateCounter<long>("requested_detail.source_pages");
    private readonly SqliteConnection _connection;
    private readonly string _schema;
    private readonly RequestedDetailMap _map;
    private readonly CancellationToken _token;
    private Func<bool>? _current;
    private (string Table, string Owner, long Page, RequestedDetailPage Result)? _verifiedPage;
    internal RequestedDetailManifest Manifest { get; }

    internal void RequireCurrent(Func<bool> current) => _current = current ?? throw new ArgumentNullException(nameof(current));

    private void CheckCurrent()
    {
        _token.ThrowIfCancellationRequested();
        if (_current is not null && !_current())
            throw new InvalidOperationException("The selected requested-detail generation changed or its reader was closed.");
    }

    internal RequestedDetailReader(SqliteConnection connection, string schema, RequestedDetailManifest manifest,
        CancellationToken token)
    {
        if (manifest.Version != RequestedDetailIndex.Version || manifest.GenerationId == Guid.Empty
            || manifest.SchemaVersion <= 0 || manifest.Items < 0 || !RequestedDetailMap.ValidHash(manifest.Root))
            throw new InvalidDataException("The requested-detail index version or binding is unsupported.");
        (_connection, _schema, Manifest, _token) = (connection, schema, manifest, token);
        _map = new(connection, schema, manifest, token);
    }

    private string? Find(string key) => _map.Find(new(Manifest.Root, Manifest.Items), key);

    private RequestedDetailIndex.Table Table(string name)
    {
        var value = Find(RequestedDetailIndex.TableKey(name)) ?? throw new InvalidDataException("The requested native table is not declared.");
        var table = _map.Read<RequestedDetailIndex.Table>(value);
        if (table.Name != name || table.Rows < 0 || table.Columns is not { Length: > 0 }
            || table.Columns.Distinct(StringComparer.Ordinal).Count() != table.Columns.Length
            || table.Owner < 0 || table.Owner >= table.Columns.Length || table.Keys is null
            || table.Collations is null || table.Keys.Length != table.Collations.Length
            || table.Keys.Any(key => key < 0 || key >= table.Columns.Length)
            || table.Collations.Any(collation => collation is not ("BINARY" or "NOCASE")))
            throw RequestedDetailMap.Invalid();
        return table;
    }

    internal RequestedDetailIndex.KeyValue? ResolveObject(string distinguishedName) =>
        ResolveAlias("captured_object", "distinguished_name", distinguishedName);

    private RequestedDetailIndex.KeyValue? ResolveAlias(string table, string column, string value)
    {
        CheckCurrent();
        var reference = Find(RequestedDetailIndex.AliasKey(table, column, value));
        var owner = reference is null ? null : _map.Read<RequestedDetailIndex.KeyValue>(reference);
        CheckCurrent();
        return owner;
    }

    internal RequestedDetailRow? ReadAlias(string table, string column, string value) =>
        ResolveAlias(table, column, value) is { } owner ? ReadSingle(table, owner) : null;

    /// <summary>Reads one source record, refusing a scope that contains more than one.</summary>
    public RequestedDetailRow? ReadSingle(string table, object owner) =>
        ReadSingle(table, RequestedDetailIndex.KeyValue.From(owner));

    private RequestedDetailRow? ReadSingle(string table, RequestedDetailIndex.KeyValue owner)
    {
        var page = ReadPage(table, owner);
        if (page.TotalRows > 1 || page.Rows.Count != page.TotalRows || page.Next is not null)
            throw RequestedDetailMap.Invalid();
        return page.Rows.SingleOrDefault();
    }

    /// <summary>Reads a real backend page; no whole-scope materialization precedes it.</summary>
    public RequestedDetailPage ReadPage(string table, object owner, RequestedDetailMark? after = null)
        => ReadPage(table, RequestedDetailIndex.KeyValue.From(owner), after);

    /// <summary>Seeks to the bounded native page containing the first integer key after a saved ordinal.</summary>
    public RequestedDetailPage ReadPageAfter(string name, object owner, long ordinal)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(ordinal);
        CheckCurrent();
        var table = Table(name);
        if (table.Keys.Length != 2) throw new ArgumentException("An ordinal seek needs a two-column native key.", nameof(name));
        var key = RequestedDetailIndex.KeyValue.From(owner);
        var ownerHash = RequestedDetailMap.Key(key.Normalize(table.Collations[0]));
        var scopeKey = RequestedDetailIndex.ScopeKey(name, ownerHash);
        var reference = Find(scopeKey);
        if (reference is null) return ReadPage(name, key);
        var scope = _map.Read<RequestedDetailIndex.Scope>(reference);
        if (scope.Table != name || scope.Owner != ownerHash || scope.Rows <= 0 || scope.Rows > table.Rows
            || scope.Pages <= 0 || scope.Index.Count != scope.Pages) throw RequestedDetailMap.Invalid();
        long first = 0, end = scope.Pages;
        while (first < end)
        {
            CheckCurrent();
            var middle = first + (end - first) / 2;
            var page = _map.Read<RequestedDetailIndex.Page>(_map.Find(scope.Index,
                RequestedDetailIndex.Ordinal(middle)) ?? throw RequestedDetailMap.Invalid());
            if (page.Last is not { Length: 2 } || page.Last[1].Kind != 1) throw RequestedDetailMap.Invalid();
            if (page.Last[1].Integer <= ordinal) first = middle + 1;
            else end = middle;
        }
        CheckCurrent();
        return first == scope.Pages ? new(true, scope.Rows, [], null)
            : ReadPage(name, key, new(Manifest.Root, scopeKey, first));
    }

    /// <summary>The publication's complete source-table count, independent of loaded pages.</summary>
    public long ReadRowCount(string table)
    {
        CheckCurrent();
        var count = Table(table).Rows;
        CheckCurrent();
        return count;
    }

    internal RequestedDetailPage ReadPage(string name, RequestedDetailIndex.KeyValue owner, RequestedDetailMark? after = null)
    {
        CheckCurrent();
        var table = Table(name);
        var normalized = owner.Normalize(table.Keys.Length == 0 ? "BINARY" : table.Collations[0]);
        var ownerHash = RequestedDetailMap.Key(normalized);
        var scopeKey = RequestedDetailIndex.ScopeKey(name, ownerHash);
        var pageNumber = after?.Page ?? 0;
        if (after is not null && (after.Root != Manifest.Root || after.Scope != scopeKey || pageNumber < 0))
            throw new InvalidDataException("The requested-detail continuation belongs to another source, scope or generation.");
        // Only an actual protected lease can retain this verification, and only one page is retained.
        if (_current is not null && _verifiedPage is { } cached
            && cached.Table == name && cached.Owner == ownerHash && cached.Page == pageNumber)
        {
            CheckCurrent();
            return cached.Result;
        }
        var reference = Find(scopeKey);
        if (reference is null)
        {
            if (after is not null) throw RequestedDetailMap.Invalid();
            CheckCurrent();
            return new(false, 0, [], null);
        }
        var scope = _map.Read<RequestedDetailIndex.Scope>(reference);
        if (scope.Table != name || scope.Owner != ownerHash || scope.Rows <= 0 || scope.Rows > table.Rows
            || scope.Pages <= 0 || scope.Index.Count != scope.Pages || pageNumber >= scope.Pages)
            throw RequestedDetailMap.Invalid();
        var pageHash = _map.Find(scope.Index, RequestedDetailIndex.Ordinal(pageNumber)) ?? throw RequestedDetailMap.Invalid();
        var page = _map.Read<RequestedDetailIndex.Page>(pageHash);
        if (page.Rows is < 1 or > RequestedDetailIndex.MaximumRows || page.Rows > scope.Rows || page.Large is null
            || page.First is null || page.Last is null || page.First.Length != page.Last.Length
            || page.First.Length != (table.Keys.Length == 0 ? 1 : table.Keys.Length)
            || !RequestedDetailMap.ValidHash(page.Hash))
            throw RequestedDetailMap.Invalid();
        var fields = new Dictionary<(int Row, int Column), RequestedDetailIndex.LargeField>();
        foreach (var field in page.Large)
        {
            if (field.Row < 0 || field.Row >= page.Rows || field.Column < 0 || field.Column >= table.Columns.Length
                || field.Kind is not (3 or 4) || field.Length <= RequestedDetailIndex.InlineBytes
                || !RequestedDetailMap.ValidHash(field.Hash)
                || field.Length > RequestedDetailMap.MaximumBytes
                    && (field.Fragments is null || field.Fragments.Count != (field.Length - 1) / RequestedDetailMap.MaximumBytes + 1)
                || field.Length <= RequestedDetailMap.MaximumBytes && field.Fragments is not null
                || !fields.TryAdd((field.Row, field.Column), field)) throw RequestedDetailMap.Invalid();
        }
        using var query = RequestedDetailIndex.SourceCommand(_connection, _schema, table, null, owner, page);
        using var read = query.ExecuteReader();
        var rows = new List<RequestedDetailIndex.Row>();
        var footprint = 0;
        while (read.Read())
        {
            CheckCurrent();
            if (rows.Count == page.Rows) throw RequestedDetailMap.Invalid();
            var row = ReadRow(table, read, rows.Count, fields);
            footprint = checked(footprint + RequestedDetailIndex.Footprint(row));
            if (footprint > RequestedDetailMap.MaximumBytes) throw RequestedDetailMap.Invalid();
            rows.Add(row);
        }
        if (rows.Count != page.Rows || RequestedDetailIndex.Fingerprint(rows, _token) != page.Hash)
            throw RequestedDetailMap.Invalid();
        CheckCurrent();
        SourcePages.Add(1, new KeyValuePair<string, object?>("role", Manifest.Role.ToString()),
            new KeyValuePair<string, object?>("index", Manifest.Root));
        var result = new RequestedDetailPage(true, scope.Rows,
            rows.Select((row, position) => new RequestedDetailRow(this, table, row, owner, pageNumber, position)).ToArray(),
            pageNumber + 1 == scope.Pages ? null : new(Manifest.Root, scopeKey, pageNumber + 1));
        if (_current is not null) _verifiedPage = (name, ownerHash, pageNumber, result);
        return result;
    }

    private RequestedDetailIndex.Row ReadRow(RequestedDetailIndex.Table table, SqliteDataReader read, int position,
        Dictionary<(int Row, int Column), RequestedDetailIndex.LargeField> fields)
    {
        var rowId = table.HasRowId ? read.GetInt64(0) : (long?)null;
        var keyOffset = table.HasRowId ? 1 : 0;
        var keyCount = table.Keys.Length == 0 ? 1 : table.Keys.Length;
        var keys = Enumerable.Range(0, keyCount)
            .Select(key => RequestedDetailIndex.KeyValue.From(read.GetValue(keyOffset + key))).ToArray();
        if (table.Keys.Length == 0) keys = [RequestedDetailIndex.KeyValue.From(rowId ?? throw RequestedDetailMap.Invalid())];
        var offset = keyOffset + keyCount;
        var cells = new RequestedDetailIndex.Cell[table.Columns.Length];
        for (var column = 0; column < cells.Length; column++)
        {
            _token.ThrowIfCancellationRequested();
            var kind = RequestedDetailIndex.Kind(read.GetString(offset + column * 2));
            var hasLarge = fields.TryGetValue((position, column), out var large);
            if (kind == 0 && !hasLarge) cells[column] = new(0, 0, 0, null, null);
            else if (kind == 1 && !hasLarge) cells[column] = new(1, read.GetInt64(offset + column * 2 + 1), 0, null, null);
            else if (kind == 2 && !hasLarge) cells[column] = new(2, 0, read.GetDouble(offset + column * 2 + 1), null, null);
            else if (kind is 3 or 4)
            {
                using var source = RequestedDetailIndex.OpenValue(_connection, _schema, table, rowId, keys, column, null, _token);
                if (hasLarge)
                {
                    if (large!.Kind != kind || source.Length != large.Length) throw RequestedDetailMap.Invalid();
                    cells[column] = new(kind, 0, 0, null, large);
                }
                else
                {
                    if (source.Length > RequestedDetailIndex.InlineBytes) throw RequestedDetailMap.Invalid();
                    var bytes = new byte[checked((int)source.Length)];
                    source.ReadExactly(bytes);
                    Observe(bytes.Length);
                    cells[column] = new(kind, 0, 0, bytes, null);
                }
            }
            else throw RequestedDetailMap.Invalid();
        }
        return new(rowId, keys, cells);
    }

    /// <summary>Streams a complete selected scope; callers must not describe this as a page read.</summary>
    public IEnumerable<RequestedDetailRow> ReadCompleteScope(string table, object owner)
    {
        RequestedDetailMark? mark = null;
        long count = 0, total = -1;
        do
        {
            var page = ReadPage(table, owner, mark);
            if (total < 0) total = page.TotalRows;
            if (page.TotalRows != total) throw RequestedDetailMap.Invalid();
            foreach (var row in page.Rows)
            {
                count++;
                yield return row;
            }
            mark = page.Next;
        } while (mark is not null);
        if (count != total) throw RequestedDetailMap.Invalid();
    }

    /// <summary>Reads at most one 64-KiB source fragment, including for an oversized value.</summary>
    public RequestedDetailBytes ReadValuePage(RequestedDetailValue reference, long offset)
    {
        ArgumentNullException.ThrowIfNull(reference);
        CheckCurrent();
        if (reference.Root != Manifest.Root || offset < 0 || offset > reference.ByteLength)
            throw new InvalidDataException("The requested value belongs to another source or has an invalid offset.");
        var table = Table(reference.Table);
        var ownerHash = RequestedDetailMap.Key(reference.Owner.Normalize(
            table.Keys.Length == 0 ? "BINARY" : table.Collations[0]));
        var page = ReadPage(reference.Table, reference.Owner,
            new(Manifest.Root, RequestedDetailIndex.ScopeKey(reference.Table, ownerHash), reference.Page));
        if (reference.Row < 0 || reference.Row >= page.Rows.Count || reference.Column < 0
            || reference.Column >= table.Columns.Length) throw RequestedDetailMap.Invalid();
        var row = page.Rows[reference.Row];
        var cell = row.Source.Cells[reference.Column];
        var length = cell.Large?.Length ?? cell.Bytes?.LongLength ?? -1;
        if (cell.Kind != reference.Kind || length != reference.ByteLength) throw RequestedDetailMap.Invalid();
        if (offset == length)
        {
            CheckCurrent();
            return new(offset, length, [], null);
        }
        var beginning = offset / RequestedDetailMap.MaximumBytes * RequestedDetailMap.MaximumBytes;
        var fragmentLength = checked((int)Math.Min(RequestedDetailMap.MaximumBytes, length - beginning));
        byte[] bytes;
        if (cell.Large is { } large)
        {
            var expected = large.Fragments is null ? new RequestedDetailIndex.Fragment(fragmentLength, large.Hash)
                : _map.Read<RequestedDetailIndex.Fragment>(_map.Find(large.Fragments,
                    RequestedDetailIndex.Ordinal(beginning / RequestedDetailMap.MaximumBytes)) ?? throw RequestedDetailMap.Invalid());
            if (expected.Length != fragmentLength || !RequestedDetailMap.ValidHash(expected.Hash))
                throw RequestedDetailMap.Invalid();
            bytes = new byte[fragmentLength];
            using var source = RequestedDetailIndex.OpenValue(_connection, _schema, table, row.Source.RowId,
                row.Source.Keys, reference.Column, null, _token);
            if (source.Length != length) throw RequestedDetailMap.Invalid();
            source.Position = beginning;
            source.ReadExactly(bytes);
            Observe(bytes.Length);
            if (Convert.ToHexString(SHA256.HashData(bytes)) != expected.Hash) throw RequestedDetailMap.Invalid();
        }
        else bytes = cell.Bytes ?? throw RequestedDetailMap.Invalid();
        var start = checked((int)(offset - beginning));
        var returned = start == 0 ? bytes : bytes.AsSpan(start).ToArray();
        var next = checked(offset + returned.Length);
        CheckCurrent();
        return new(offset, length, returned, next == length ? null : next);
    }

    internal Stream OpenValue(RequestedDetailValue value) => new ValueStream(this, value);

    private void Observe(int count) => SourceBytes.Add(count,
        new KeyValuePair<string, object?>("role", Manifest.Role.ToString()),
        new KeyValuePair<string, object?>("index", Manifest.Root));

    private sealed class ValueStream(RequestedDetailReader owner, RequestedDetailValue reference) : Stream
    {
        private byte[] _buffer = [];
        private int _index;
        private long _position;
        private bool _closed;
        public override bool CanRead => !_closed;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => reference.ByteLength;
        public override long Position { get => _position; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            owner.CheckCurrent();
            var copied = 0;
            while (!buffer.IsEmpty && _position < Length)
            {
                if (_index == _buffer.Length)
                {
                    _buffer = owner.ReadValuePage(reference, _position).Bytes;
                    _index = 0;
                    if (_buffer.Length == 0) throw RequestedDetailMap.Invalid();
                }
                var take = Math.Min(buffer.Length, _buffer.Length - _index);
                _buffer.AsSpan(_index, take).CopyTo(buffer);
                buffer = buffer[take..];
                _index += take;
                copied += take;
                _position += take;
            }
            return copied;
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _closed = true;
                Array.Clear(_buffer);
                _buffer = [];
            }
            base.Dispose(disposing);
        }
    }
}

public static partial class RequestedDetailIndex
{
    /// <summary>Creates a requested-page reader from the exact declaration selected by the publication root.</summary>
    public static RequestedDetailReader Open(SqliteConnection connection, string schema,
        RequestedDetailManifest manifest, CancellationToken cancellationToken = default) =>
        new(connection, schema, manifest, cancellationToken);
}
