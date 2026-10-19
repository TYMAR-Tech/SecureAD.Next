using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace SecureAD.Evidence;

/// <summary>The requested-data commitment, separate from the seal over every database byte.</summary>
public sealed record RequestedDetailManifest(int Version, StoreSegmentRole Role, int SchemaVersion,
    Guid GenerationId, string EvidenceSeal, string Root, long Items);

internal sealed class RequestedDetailMap
{
    internal const int MaximumBytes = 64 * 1024;
    private const int Fanout = 32;
    private readonly SqliteConnection _connection;
    private readonly string _schema;
    private readonly byte[] _context;
    private readonly CancellationToken _token;
    private readonly SqliteTransaction? _transaction;

    internal sealed record Root(string Hash, long Count);
    private sealed record Item(string Key, string Value);
    private sealed record Branch(string First, string Last, string Hash, long Count);
    private sealed record Node(int Level, long Count, string First, string Last,
        Item[] Items, Branch[] Children);

    internal RequestedDetailMap(SqliteConnection connection, string schema, RequestedDetailManifest manifest,
        CancellationToken token, SqliteTransaction? transaction = null)
    {
        _connection = connection;
        _schema = Quote(schema);
        _token = token;
        _transaction = transaction;
        _context = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
        {
            manifest.Version, manifest.Role, manifest.SchemaVersion, manifest.GenerationId, manifest.EvidenceSeal,
        }));
    }

    internal static string Quote(string identifier) => "\"" + identifier.Replace("\"", "\"\"") + "\"";
    internal static string Key<T>(T value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value)));

    internal void Create()
    {
        using var command = _connection.CreateCommand();
        command.Transaction = _transaction;
        command.CommandText = $"""
            CREATE TABLE {_schema}.requested_detail_node (
                hash TEXT PRIMARY KEY COLLATE BINARY,
                kind INTEGER NOT NULL CHECK(kind IN (1,2)),
                data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 65536)
            ) WITHOUT ROWID;
            """;
        command.ExecuteNonQuery();
    }

    internal Builder Build() => new(this);

    internal string Put<T>(T value) => PutBytes(JsonSerializer.SerializeToUtf8Bytes(value), 1);

    private string PutBytes(byte[] bytes, int kind)
    {
        _token.ThrowIfCancellationRequested();
        if (bytes.Length is < 1 or > MaximumBytes)
            throw new InvalidDataException("Requested-detail metadata exceeds its native page size.");
        var hash = Hash(bytes, kind);
        using var command = _connection.CreateCommand();
        command.Transaction = _transaction;
        command.CommandText = $"INSERT OR IGNORE INTO {_schema}.requested_detail_node VALUES ($hash,$kind,$data)";
        command.Parameters.AddWithValue("$hash", hash);
        command.Parameters.AddWithValue("$kind", kind);
        command.Parameters.AddWithValue("$data", bytes);
        command.ExecuteNonQuery();
        return hash;
    }

    private string Hash(ReadOnlySpan<byte> data, int kind)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(_context);
        hash.AppendData([(byte)kind]);
        while (!data.IsEmpty)
        {
            _token.ThrowIfCancellationRequested();
            var take = Math.Min(8192, data.Length);
            hash.AppendData(data[..take]);
            data = data[take..];
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    internal T Read<T>(string hash) => JsonSerializer.Deserialize<T>(ReadBytes(hash, 1))
        ?? throw Invalid();

    private byte[] ReadBytes(string hash, int kind)
    {
        _token.ThrowIfCancellationRequested();
        if (!ValidHash(hash)) throw Invalid();
        using var command = _connection.CreateCommand();
        command.Transaction = _transaction;
        command.CommandText = $"SELECT kind,length(data),data FROM {_schema}.requested_detail_node WHERE hash=$hash";
        command.Parameters.AddWithValue("$hash", hash);
        using var read = command.ExecuteReader();
        if (!read.Read() || read.GetInt32(0) != kind || read.GetInt64(1) is < 1 or > MaximumBytes)
            throw Invalid();
        var bytes = (byte[])read.GetValue(2);
        if (Hash(bytes, kind) != hash || read.Read()) throw Invalid();
        return bytes;
    }

    internal string? Find(Root root, string key)
    {
        if (root.Count < 0 || key.Length == 0) throw Invalid();
        var hash = root.Hash;
        var count = root.Count;
        int? level = null;
        string? first = null, last = null;
        for (var depth = 0; depth < 64; depth++)
        {
            var node = JsonSerializer.Deserialize<Node>(ReadBytes(hash, 2)) ?? throw Invalid();
            Validate(node);
            if (node.Count != count || level is not null && node.Level != level
                || first is not null && (node.First != first || node.Last != last))
                throw Invalid();
            if (node.Count == 0 || Compare(key, node.First) < 0 || Compare(key, node.Last) > 0) return null;
            if (node.Level == 0)
                return node.Items.FirstOrDefault(item => item.Key == key)?.Value;
            var child = node.Children.FirstOrDefault(child => Compare(key, child.First) >= 0 && Compare(key, child.Last) <= 0);
            if (child is null) return null;
            (hash, count, level, first, last) = (child.Hash, child.Count, node.Level - 1, child.First, child.Last);
        }
        throw Invalid();
    }

    private static void Validate(Node node)
    {
        if (node.Level is < 0 or > 63 || node.Count < 0 || node.Items is null || node.Children is null)
            throw Invalid();
        if (node.Level == 0)
        {
            if (node.Children.Length != 0 || node.Items.Length > Fanout || node.Count != node.Items.Length)
                throw Invalid();
            if (node.Count == 0)
            {
                if (node.First != "" || node.Last != "") throw Invalid();
                return;
            }
            if (node.First != node.Items[0].Key || node.Last != node.Items[^1].Key) throw Invalid();
            string? previous = null;
            foreach (var item in node.Items)
            {
                if (string.IsNullOrEmpty(item.Key) || !ValidHash(item.Value)
                    || previous is not null && Compare(previous, item.Key) >= 0) throw Invalid();
                previous = item.Key;
            }
            return;
        }
        if (node.Items.Length != 0 || node.Children.Length is < 1 or > Fanout
            || node.First != node.Children[0].First || node.Last != node.Children[^1].Last) throw Invalid();
        long count = 0;
        string? end = null;
        foreach (var child in node.Children)
        {
            if (child.Count <= 0 || !ValidHash(child.Hash) || string.IsNullOrEmpty(child.First)
                || Compare(child.First, child.Last) > 0 || end is not null && Compare(end, child.First) >= 0)
                throw Invalid();
            count = checked(count + child.Count);
            end = child.Last;
        }
        if (node.Count != count) throw Invalid();
    }

    private static int Compare(string left, string right) => string.CompareOrdinal(left, right);
    internal static bool ValidHash(string value) =>
        value is { Length: 64 } && value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
    internal static InvalidDataException Invalid() => new("Requested-detail data or its source-bound index is invalid.");

    internal sealed class Builder(RequestedDetailMap store)
    {
        private readonly List<Item> _items = [];
        private readonly List<List<Branch>> _levels = [];
        private string? _previous;
        private bool _finished;
        private long _count;

        internal void Add(string key, string value)
        {
            store._token.ThrowIfCancellationRequested();
            if (_finished || string.IsNullOrEmpty(key) || !ValidHash(value)
                || _previous is not null && Compare(_previous, key) >= 0) throw Invalid();
            _previous = key;
            _items.Add(new(key, value));
            _count = checked(_count + 1);
            if (_items.Count == Fanout) FlushItems();
        }

        private void FlushItems()
        {
            if (_items.Count == 0) return;
            var node = new Node(0, _items.Count, _items[0].Key, _items[^1].Key, [.. _items], []);
            var hash = store.PutBytes(JsonSerializer.SerializeToUtf8Bytes(node), 2);
            _items.Clear();
            AddBranch(0, new(node.First, node.Last, hash, node.Count));
        }

        private void AddBranch(int level, Branch branch)
        {
            while (_levels.Count <= level) _levels.Add([]);
            var items = _levels[level];
            items.Add(branch);
            if (items.Count != Fanout) return;
            FlushBranches(level);
        }

        private void FlushBranches(int level)
        {
            var items = _levels[level];
            if (items.Count == 0) return;
            var node = new Node(level + 1, items.Sum(item => item.Count), items[0].First, items[^1].Last, [], [.. items]);
            var hash = store.PutBytes(JsonSerializer.SerializeToUtf8Bytes(node), 2);
            items.Clear();
            AddBranch(level + 1, new(node.First, node.Last, hash, node.Count));
        }

        internal Root Finish()
        {
            if (_finished) throw new InvalidOperationException("The requested-detail index is already complete.");
            _finished = true;
            FlushItems();
            if (_count == 0)
                return new(store.PutBytes(JsonSerializer.SerializeToUtf8Bytes(new Node(0, 0, "", "", [], [])), 2), 0);
            for (var level = 0; level < _levels.Count; level++)
            {
                var items = _levels[level];
                if (items.Count == 0) continue;
                if (items.Count == 1 && _levels.Skip(level + 1).All(above => above.Count == 0))
                    return new(items[0].Hash, _count);
                FlushBranches(level);
            }
            throw Invalid();
        }
    }
}
