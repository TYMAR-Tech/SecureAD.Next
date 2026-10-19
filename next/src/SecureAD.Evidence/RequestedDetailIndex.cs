using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace SecureAD.Evidence;

/// <summary>Produces source-bound logical pages without copying the source payloads.</summary>
public static partial class RequestedDetailIndex
{
    internal const int Version = 1;
    // A record page proves field references; it must not read other attribute families' values.
    internal const int InlineBytes = 0;
    internal const int MaximumRows = 50;
    internal const string BuildTable = "requested_detail_build";
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal sealed record KeyValue(int Kind, long Integer = 0, double Real = 0, string? Text = null)
    {
        internal static KeyValue From(object value) => value switch
        {
            DBNull => new(0),
            long integer => new(1, integer),
            int integer => new(1, integer),
            double real => new(2, Real: real),
            string text => new(3, Text: text),
            _ => throw new InvalidDataException("The native requested-detail key has an unsupported storage class."),
        };

        internal object Parameter => Kind switch
        {
            0 => DBNull.Value,
            1 => Integer,
            2 => Real,
            3 when Text is not null => Text,
            _ => throw RequestedDetailMap.Invalid(),
        };

        internal KeyValue Normalize(string collation) =>
            Kind == 3 && collation == "NOCASE" ? this with { Text = AsciiFold(Text!) } : this;
    }

    internal sealed record Table(string Name, string[] Columns, int[] Keys, string[] Collations,
        int Owner, bool HasRowId, long Rows);
    internal sealed record Scope(string Table, string Owner, long Rows, long Pages, RequestedDetailMap.Root Index);
    internal sealed record LargeField(int Row, int Column, int Kind, long Length, string Hash,
        RequestedDetailMap.Root? Fragments);
    internal sealed record Fragment(int Length, string Hash);
    internal sealed record Page(KeyValue[] First, KeyValue[] Last, int Rows, string Hash, LargeField[] Large);
    internal sealed record Cell(int Kind, long Integer, double Real, byte[]? Bytes, LargeField? Large);
    internal sealed record Row(long? RowId, KeyValue[] Keys, Cell[] Cells);

    /// <summary>Builds the native commitment inside the producing stage's reported work.</summary>
    public static RequestedDetailManifest Prepare(SqliteConnection connection, string schema, StoreSegmentRole role,
        int schemaVersion, Guid generationId, string evidenceSeal, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (generationId == Guid.Empty || schemaVersion <= 0) throw new ArgumentException("A detail index needs its producing generation.");
        cancellationToken.ThrowIfCancellationRequested();
        using var transaction = connection.BeginTransaction();
        var manifest = new RequestedDetailManifest(Version, role, schemaVersion, generationId, evidenceSeal, "", 0);
        var map = new RequestedDetailMap(connection, schema, manifest, cancellationToken, transaction);
        map.Create();
        using var staging = connection.CreateCommand();
        staging.Transaction = transaction;
        staging.CommandText = $"CREATE TEMP TABLE {BuildTable}(key TEXT PRIMARY KEY COLLATE BINARY, hash TEXT NOT NULL) WITHOUT ROWID";
        staging.ExecuteNonQuery();
        var tables = Tables(connection, schema, transaction);
        foreach (var table in tables)
        {
            cancellationToken.ThrowIfCancellationRequested();
            BuildTableIndex(connection, schema, table, map, transaction, cancellationToken);
        }
        if (tables.Any(table => table.Name == "captured_object"))
            BuildObjectAliases(connection, schema, map, transaction, cancellationToken,
                tables.Any(table => table.Name == "trustee"));
        var builder = map.Build();
        staging.CommandText = $"SELECT key,hash FROM temp.{BuildTable} ORDER BY key COLLATE BINARY";
        using (var read = staging.ExecuteReader())
            while (read.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                builder.Add(read.GetString(0), read.GetString(1));
            }
        var root = builder.Finish();
        staging.CommandText = $"DROP TABLE temp.{BuildTable}";
        staging.ExecuteNonQuery();
        cancellationToken.ThrowIfCancellationRequested();
        transaction.Commit();
        return manifest with { Root = root.Hash, Items = root.Count };
    }

    private static List<Table> Tables(SqliteConnection connection, string schema, SqliteTransaction transaction)
    {
        var definitions = new List<(string Name, string Sql)>();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT name,sql FROM {Q(schema)}.sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'requested_detail_%' ORDER BY name";
        using (var read = command.ExecuteReader())
            while (read.Read()) definitions.Add((read.GetString(0), read.GetString(1)));
        var result = new List<Table>();
        foreach (var definition in definitions)
        {
            var columns = new List<string>();
            var keys = new List<(int Position, int Column)>();
            command.CommandText = $"PRAGMA {Q(schema)}.table_info({Q(definition.Name)})";
            using (var read = command.ExecuteReader())
                while (read.Read())
                {
                    columns.Add(read.GetString(1));
                    if (read.GetInt32(5) != 0) keys.Add((read.GetInt32(5), read.GetInt32(0)));
                }
            if (columns.Count == 0) throw RequestedDetailMap.Invalid();
            var primary = keys.OrderBy(key => key.Position).Select(key => key.Column).ToArray();
            var collations = primary.Select(_ => "BINARY").ToArray();
            var indexes = new List<string>();
            command.CommandText = $"PRAGMA {Q(schema)}.index_list({Q(definition.Name)})";
            using (var read = command.ExecuteReader())
                while (read.Read())
                    if (read.GetString(3) == "pk") indexes.Add(read.GetString(1));
            foreach (var index in indexes)
            {
                command.CommandText = $"PRAGMA {Q(schema)}.index_xinfo({Q(index)})";
                using var read = command.ExecuteReader();
                while (read.Read())
                {
                    if (read.GetInt32(5) != 1) continue;
                    var position = Array.IndexOf(primary, read.GetInt32(1));
                    if (position >= 0) collations[position] = read.GetString(4);
                }
            }
            if (collations.Any(collation => collation is not ("BINARY" or "NOCASE")))
                throw new InvalidDataException("The native requested-detail key uses an unsupported collation.");
            result.Add(new(definition.Name, [.. columns], primary, collations,
                primary.Length == 0 ? 0 : primary[0],
                !definition.Sql.Contains("WITHOUT ROWID", StringComparison.OrdinalIgnoreCase), 0));
        }
        return result;
    }

    private static void BuildTableIndex(SqliteConnection connection, string schema, Table table,
        RequestedDetailMap map, SqliteTransaction transaction, CancellationToken token)
    {
        using var command = SourceCommand(connection, schema, table, transaction, null, null);
        using var read = command.ExecuteReader();
        string? ownerKey = null;
        RequestedDetailMap.Builder? pages = null;
        var rows = new List<Row>();
        long total = 0, scopeRows = 0, indexedRows = 0, pageCount = 0;
        var bytes = 0;

        void FinishPage()
        {
            if (rows.Count == 0) return;
            var large = rows.SelectMany((row, position) => row.Cells.Select((cell, column) =>
                cell.Large is null ? null : cell.Large with { Row = position, Column = column }))
                .Where(field => field is not null).Select(field => field!).ToArray();
            var page = new Page(rows[0].Keys, rows[^1].Keys, rows.Count, Fingerprint(rows, token), large);
            pages!.Add(Ordinal(pageCount), map.Put(page));
            indexedRows = checked(indexedRows + rows.Count);
            pageCount++;
            rows.Clear();
            bytes = 0;
        }

        void FinishScope()
        {
            if (pages is null || ownerKey is null) return;
            FinishPage();
            if (indexedRows != scopeRows) throw RequestedDetailMap.Invalid();
            Stage(connection, transaction, ScopeKey(table.Name, ownerKey),
                map.Put(new Scope(table.Name, ownerKey, scopeRows, pageCount, pages.Finish())));
        }

        while (read.Read())
        {
            token.ThrowIfCancellationRequested();
            var nextOwner = ReadOwner(read, table);
            var normalized = nextOwner.Normalize(table.Keys.Length == 0 ? "BINARY" : table.Collations[0]);
            var nextKey = RequestedDetailMap.Key(normalized);
            if (nextKey != ownerKey)
            {
                FinishScope();
                ownerKey = nextKey;
                pages = map.Build();
                scopeRows = indexedRows = pageCount = 0;
            }
            var row = ReadSourceRow(connection, schema, table, read, map, transaction, token);
            var size = Footprint(row);
            if (rows.Count != 0 && (rows.Count == MaximumRows || bytes + size > RequestedDetailMap.MaximumBytes))
                FinishPage();
            if (size > RequestedDetailMap.MaximumBytes)
                throw new InvalidDataException("A native row's structural metadata exceeds the requested-detail page size.");
            rows.Add(row);
            bytes += size;
            scopeRows++;
            total++;
        }
        FinishScope();
        using var count = connection.CreateCommand();
        count.Transaction = transaction;
        count.CommandText = $"SELECT COUNT(*) FROM {Q(schema)}.{Q(table.Name)}";
        if ((long)count.ExecuteScalar()! != total)
            throw new InvalidDataException("The requested-detail index omitted source records and cannot be published.");
        Stage(connection, transaction, TableKey(table.Name), map.Put(table with { Rows = total }));
    }

    private static Row ReadSourceRow(SqliteConnection connection, string schema, Table table, SqliteDataReader read,
        RequestedDetailMap map, SqliteTransaction transaction, CancellationToken token)
    {
        var rowId = table.HasRowId ? read.GetInt64(0) : (long?)null;
        var keyOffset = table.HasRowId ? 1 : 0;
        var keyCount = table.Keys.Length == 0 ? 1 : table.Keys.Length;
        var keys = Enumerable.Range(0, keyCount).Select(position => KeyValue.From(read.GetValue(keyOffset + position))).ToArray();
        if (table.Keys.Length == 0) keys = [KeyValue.From(rowId ?? throw RequestedDetailMap.Invalid())];
        var offset = keyOffset + keyCount;
        var cells = new Cell[table.Columns.Length];
        for (var column = 0; column < cells.Length; column++)
        {
            token.ThrowIfCancellationRequested();
            var kind = Kind(read.GetString(offset + column * 2));
            if (kind == 0) cells[column] = new(0, 0, 0, null, null);
            else if (kind == 1) cells[column] = new(1, read.GetInt64(offset + column * 2 + 1), 0, null, null);
            else if (kind == 2) cells[column] = new(2, 0, read.GetDouble(offset + column * 2 + 1), null, null);
            else
            {
                using var source = OpenValue(connection, schema, table, rowId, keys, column, transaction, token);
                if (source.Length <= InlineBytes)
                {
                    var data = new byte[checked((int)source.Length)];
                    source.ReadExactly(data);
                    cells[column] = new(kind, 0, 0, data, null);
                }
                else
                {
                    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    var fragments = source.Length > RequestedDetailMap.MaximumBytes ? map.Build() : null;
                    var buffer = new byte[RequestedDetailMap.MaximumBytes];
                    long position = 0;
                    while (position < source.Length)
                    {
                        token.ThrowIfCancellationRequested();
                        var count = checked((int)Math.Min(buffer.Length, source.Length - position));
                        source.ReadExactly(buffer.AsSpan(0, count));
                        hash.AppendData(buffer.AsSpan(0, count));
                        if (fragments is not null)
                            fragments.Add(Ordinal(position / buffer.Length), map.Put(new Fragment(count,
                                Convert.ToHexString(SHA256.HashData(buffer.AsSpan(0, count))))));
                        position += count;
                    }
                    cells[column] = new(kind, 0, 0, null, new(0, column, kind, source.Length,
                        Convert.ToHexString(hash.GetHashAndReset()), fragments?.Finish()));
                }
            }
        }
        return new(rowId, keys, cells);
    }

    internal static SqliteCommand SourceCommand(SqliteConnection connection, string schema, Table table,
        SqliteTransaction? transaction, KeyValue? owner, Page? page)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        var keyColumns = table.Keys.Length == 0 ? [table.Owner] : table.Keys;
        string[] rowId = table.HasRowId ? ["rowid"] : [];
        var selections = rowId
            .Concat(keyColumns.Select(column => Q(table.Columns[column])))
            .Concat(table.Columns.SelectMany(column => new[]
            {
                $"typeof({Q(column)})",
                $"CASE WHEN typeof({Q(column)}) IN ('integer','real') THEN {Q(column)} ELSE NULL END",
            }));
        var order = keyColumns.Select((column, index) => Q(table.Columns[column])
            + " COLLATE " + (table.Keys.Length == 0 ? "BINARY" : table.Collations[index])).ToList();
        if (table.Keys.Length == 0) order.Add("rowid");
        command.CommandText = $"SELECT {string.Join(",", selections)} FROM {Q(schema)}.{Q(table.Name)}";
        if (owner is not null)
        {
            var ownerColumn = Q(table.Columns[table.Owner]);
            var collation = table.Keys.Length == 0 ? "BINARY" : table.Collations[0];
            command.CommandText += $" WHERE {ownerColumn} COLLATE {collation} IS $owner";
            command.Parameters.AddWithValue("$owner", owner.Parameter);
            if (page is not null)
            {
                var sort = table.Keys.Length == 0 ? "rowid" : "(" + string.Join(",", keyColumns.Select(column => Q(table.Columns[column]))) + ")";
                var first = new List<string>();
                var last = new List<string>();
                for (var index = 0; index < page.First.Length; index++)
                {
                    first.Add("$first" + index);
                    last.Add("$last" + index);
                    command.Parameters.AddWithValue(first[^1], page.First[index].Parameter);
                    command.Parameters.AddWithValue(last[^1], page.Last[index].Parameter);
                }
                var begin = first.Count == 1 ? first[0] : "(" + string.Join(",", first) + ")";
                var end = last.Count == 1 ? last[0] : "(" + string.Join(",", last) + ")";
                command.CommandText += $" AND {sort}>={begin} AND {sort}<={end}";
            }
        }
        command.CommandText += " ORDER BY " + string.Join(",", order);
        if (page is not null) command.CommandText += " LIMIT 51";
        return command;
    }

    internal static Stream OpenValue(SqliteConnection connection, string schema, Table table, long? rowId,
        KeyValue[] keys, int column, SqliteTransaction? transaction, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (rowId is { } id)
            return new SqliteBlob(connection, schema, table.Name, table.Columns[column], id, readOnly: true);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT {Q(table.Columns[column])} FROM {Q(schema)}.{Q(table.Name)} WHERE "
            + string.Join(" AND ", table.Keys.Select((key, index) => $"{Q(table.Columns[key])} IS $key{index}"));
        for (var index = 0; index < keys.Length; index++)
            command.Parameters.AddWithValue("$key" + index, keys[index].Parameter);
        var value = command.ExecuteScalar();
        var bytes = value switch
        {
            string text => Utf8.GetBytes(text),
            byte[] binary => binary,
            _ => throw RequestedDetailMap.Invalid(),
        };
        token.ThrowIfCancellationRequested();
        if (bytes.Length > RequestedDetailMap.MaximumBytes)
            throw new InvalidDataException("A WITHOUT ROWID native key/value needs a streamable source representation.");
        return new MemoryStream(bytes, writable: false);
    }

    internal static int Kind(string kind) => kind switch
    {
        "null" => 0, "integer" => 1, "real" => 2, "text" => 3, "blob" => 4,
        _ => throw RequestedDetailMap.Invalid(),
    };

    internal static KeyValue ReadOwner(SqliteDataReader read, Table table) =>
        KeyValue.From(read.GetValue(table.HasRowId ? 1 : 0));
    internal static string TableKey(string table) => RequestedDetailMap.Key(new[] { "table", table });
    internal static string ScopeKey(string table, string owner) => RequestedDetailMap.Key(new[] { "scope", table, owner });
    internal static string AliasKey(string table, string column, string value) =>
        RequestedDetailMap.Key(new[] { "alias", table, column, AsciiFold(value) });
    internal static string Ordinal(long value) => value.ToString("D20", CultureInfo.InvariantCulture);
    private static string Q(string identifier) => RequestedDetailMap.Quote(identifier);

    private static string AsciiFold(string value) => string.Create(value.Length, value, (result, source) =>
    {
        for (var index = 0; index < source.Length; index++)
            result[index] = source[index] is >= 'A' and <= 'Z' ? (char)(source[index] + ('a' - 'A')) : source[index];
    });

    private static void Stage(SqliteConnection connection, SqliteTransaction transaction, string key, string hash)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"INSERT INTO temp.{BuildTable} VALUES ($key,$hash)";
        command.Parameters.AddWithValue("$key", key);
        command.Parameters.AddWithValue("$hash", hash);
        if (command.ExecuteNonQuery() != 1) throw RequestedDetailMap.Invalid();
    }

    private static void BuildObjectAliases(SqliteConnection connection, string schema, RequestedDetailMap map,
        SqliteTransaction transaction, CancellationToken token, bool hasTrustees)
    {
        using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = $"SELECT distinguished_name,MIN(object_id) FROM {Q(schema)}.captured_object GROUP BY distinguished_name COLLATE NOCASE";
        using var read = query.ExecuteReader();
        while (read.Read())
        {
            token.ThrowIfCancellationRequested();
            Stage(connection, transaction, AliasKey("captured_object", "distinguished_name", read.GetString(0)),
                map.Put(new KeyValue(1, read.GetInt64(1))));
        }
        read.Close();
        Add("captured_object", "objectsid",
            $"SELECT hex(objectsid),MIN(object_id) FROM {Q(schema)}.captured_object WHERE objectsid IS NOT NULL GROUP BY objectsid");
        if (hasTrustees) Add("trustee", "sid", $"SELECT sid,trustee_id FROM {Q(schema)}.trustee");

        void Add(string table, string column, string sql)
        {
            query.CommandText = sql;
            using var aliases = query.ExecuteReader();
            while (aliases.Read())
            {
                token.ThrowIfCancellationRequested();
                Stage(connection, transaction, AliasKey(table, column, aliases.GetString(0)),
                    map.Put(new KeyValue(1, aliases.GetInt64(1))));
            }
        }
    }

    internal static int Footprint(Row row) => checked(32 + row.Cells.Sum(cell =>
        cell.Large is null ? 24 + (cell.Bytes?.Length ?? 0) : 256));

    internal static string Fingerprint(IEnumerable<Row> rows, CancellationToken token)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> number = stackalloc byte[8];
        void Number(long value)
        {
            Span<byte> data = stackalloc byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(data, value);
            hash.AppendData(data);
        }
        long count = 0;
        foreach (var row in rows)
        {
            token.ThrowIfCancellationRequested();
            Number(row.RowId ?? -1);
            Number(row.Cells.Length);
            foreach (var cell in row.Cells)
            {
                Number(cell.Kind);
                Number(cell.Large is null ? 0 : 1);
                if (cell.Kind == 1) Number(cell.Integer);
                else if (cell.Kind == 2) Number(BitConverter.DoubleToInt64Bits(cell.Real));
                else if (cell.Large is { } large)
                {
                    Number(large.Length);
                    hash.AppendData(Convert.FromHexString(large.Hash));
                }
                else if (cell.Bytes is { } bytes)
                {
                    Number(bytes.Length);
                    hash.AppendData(bytes);
                }
            }
            count++;
        }
        BinaryPrimitives.WriteInt64LittleEndian(number, count);
        hash.AppendData(number);
        return Convert.ToHexString(hash.GetHashAndReset());
    }
}
