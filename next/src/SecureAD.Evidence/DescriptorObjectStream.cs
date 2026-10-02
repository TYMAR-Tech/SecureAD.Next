using System.Collections;
using Microsoft.Data.Sqlite;

namespace SecureAD.Evidence;

/// <summary>Streams descriptor groups without retaining their objects or the decoded forest.</summary>
internal sealed class DescriptorObjectStream : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly Action<long, string> _rememberIdentity;
    private readonly CancellationToken _token;
    private readonly string _order = "descriptor_order_" + Guid.NewGuid().ToString("N");
    private ObjectStreamReader.StreamedObject? _current;
    private Descriptor? _descriptor;
    private bool _enumerated;
    private bool _disposed;

    internal DescriptorObjectStream(SqliteConnection connection, Action<long, string> rememberIdentity,
        bool unambiguousNames, CancellationToken token)
    {
        _connection = connection;
        _rememberIdentity = rememberIdentity;
        _token = token;
        token.ThrowIfCancellationRequested();
        try
        {
            Execute($"CREATE TEMP TABLE {_order} (position INTEGER PRIMARY KEY, object_id INTEGER NOT NULL UNIQUE, permission_object_id INTEGER NOT NULL, descriptor_id INTEGER)");
            // Only the narrow identity map is sorted. Wide objects and every multivalued table
            // subsequently follow this same position, rather than keeping an entire group in RAM.
            // Ambiguous names use the original SQLite NOCASE/LIMIT 1 selection, not a new tie-breaker.
            var identities = unambiguousNames
                ? "SELECT object_id, object_id AS permission_object_id FROM captured_object"
                : "SELECT o.object_id, (SELECT chosen.object_id FROM captured_object chosen "
                    + "WHERE chosen.distinguished_name=o.distinguished_name COLLATE NOCASE LIMIT 1) AS permission_object_id FROM captured_object o";
            Execute($"""
                WITH identities AS MATERIALIZED ({identities})
                INSERT INTO {_order}(object_id,permission_object_id,descriptor_id)
                SELECT i.object_id,i.permission_object_id,s.descriptor_id
                FROM identities i LEFT JOIN object_security_descriptor s ON s.object_id=i.permission_object_id
                ORDER BY s.descriptor_id,i.object_id
                """);
            using var pages = connection.CreateCommand();
            pages.CommandText = "PRAGMA temp.page_count";
            var count = Convert.ToInt64(pages.ExecuteScalar());
            pages.CommandText = "PRAGMA temp.page_size";
            OrderingTemporaryBytes = checked(count * Convert.ToInt64(pages.ExecuteScalar()));
        }
        catch
        {
            try { Dispose(); }
            catch (SqliteException) { /* Cleanup must not replace the preparation failure. */ }
            token.ThrowIfCancellationRequested();
            throw;
        }
    }

    internal long OrderingTemporaryBytes { get; }
    internal long PreparedDescriptors { get; private set; }
    internal long PreparedEntries { get; private set; }

    internal IEnumerable<ObjectAttributes> Objects
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_enumerated) throw new InvalidOperationException("A descriptor stream is consumed only once.");
            _enumerated = true;
            using var rows = ObjectStreamReader.StreamRows(_connection, _rememberIdentity, _order, _token).GetEnumerator();
            try
            {
                while (MoveNext(rows))
                {
                    _current = rows.Current;
                    yield return _current.Attributes;
                }
            }
            finally { _current = null; }
        }
    }

    internal Reading ReadPermissions(ObjectAttributes subject)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ObjectDisposedException.ThrowIf(_connection.State != System.Data.ConnectionState.Open, this);
        _token.ThrowIfCancellationRequested();
        if (_current is not { } current || !ReferenceEquals(current.Attributes, subject))
            throw new InvalidOperationException("Permissions must be bound to the current evidence object.");
        try
        {
            if (current.DescriptorId is not { } id)
            {
                _descriptor = null;
                return new(this, current, null,
                    ObjectPermissionsReader.ReadAt(_connection, current.PermissionObjectId, current.PermissionDn));
            }
            if (_descriptor?.Id != id)
            {
                var permissions = ObjectPermissionsReader.ReadAt(_connection, current.PermissionObjectId, current.PermissionDn);
                if (permissions.DescriptorId != id) throw new InvalidDataException("The descriptor does not match the evidence object.");
                _descriptor = new Descriptor(permissions);
                PreparedDescriptors++;
                PreparedEntries += permissions.Entries.Count;
            }
            return new(this, current, _descriptor, _descriptor.ForObject(current.PermissionDn));
        }
        catch (SqliteException) when (_token.IsCancellationRequested)
        {
            _token.ThrowIfCancellationRequested();
            throw;
        }
    }

    private bool MoveNext(IEnumerator<ObjectStreamReader.StreamedObject> rows)
    {
        _token.ThrowIfCancellationRequested();
        try { return rows.MoveNext(); }
        catch (SqliteException) when (_token.IsCancellationRequested)
        {
            _token.ThrowIfCancellationRequested();
            throw;
        }
    }

    private void Execute(string sql)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
        _token.ThrowIfCancellationRequested();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _current = null;
        _descriptor = null;
        if (_connection.State != System.Data.ConnectionState.Open) return;
        try
        {
            using var command = _connection.CreateCommand();
            command.CommandText = $"DROP TABLE IF EXISTS temp.{_order}";
            command.ExecuteNonQuery();
        }
        catch (SqliteException) when (_token.IsCancellationRequested)
        {
            // A cancelled protected connection can refuse even DROP. Its disposal releases TEMP.
        }
    }

    /// <summary>An unforgeable-by-public-callers binding to the current row of this evidence stream.</summary>
    internal sealed class Reading
    {
        private readonly DescriptorObjectStream _stream;
        private readonly ObjectStreamReader.StreamedObject _row;
        internal Reading(DescriptorObjectStream stream, ObjectStreamReader.StreamedObject row,
            Descriptor? descriptor, ObjectPermissions permissions)
        {
            _stream = stream;
            _row = row;
            Descriptor = descriptor;
            Permissions = permissions;
        }

        internal Descriptor? Descriptor { get; }
        internal ObjectPermissions Permissions { get; }
        internal DescriptorObjectStream Source => _stream;

        internal void RequireCurrent()
        {
            ObjectDisposedException.ThrowIf(_stream._disposed, _stream);
            ObjectDisposedException.ThrowIf(_stream._connection.State != System.Data.ConnectionState.Open, _stream);
            _stream._token.ThrowIfCancellationRequested();
            if (!ReferenceEquals(_stream._current, _row) || !ReferenceEquals(_stream._descriptor, Descriptor)
                || Permissions.DescriptorId != _row.DescriptorId
                || Permissions.DistinguishedName != _row.PermissionDn)
                throw new InvalidOperationException("The prepared permissions belong to a different evidence object or stream.");
        }
    }

    /// <summary>Owned descriptor data; no caller receives its mutable application-data buffers.</summary>
    internal sealed class Descriptor
    {
        private readonly ObjectPermissions _snapshot;

        internal Descriptor(ObjectPermissions permissions)
        {
            _snapshot = permissions with
            {
                Owner = permissions.Owner?.Shared(),
                Entries = Array.AsReadOnly(permissions.Entries.Select(entry => entry with
                {
                    Trustee = entry.Trustee.Shared(), ApplicationData = entry.ApplicationData.ToArray(),
                }).ToArray()),
                Errors = Array.AsReadOnly(permissions.Errors.ToArray()),
            };
        }

        internal long? Id => _snapshot.DescriptorId;
        internal ObjectPermissions ClassificationInput
        {
            get
            {
                var result = ForObject(_snapshot.DistinguishedName);
                return result with { Entries = Array.AsReadOnly(result.Entries.ToArray()) };
            }
        }

        internal ObjectPermissions ForObject(string distinguishedName) => _snapshot with
        {
            DistinguishedName = distinguishedName,
            Owner = _snapshot.Owner?.DisplayedAgainst(distinguishedName),
            Entries = new EntryView(_snapshot.Entries, distinguishedName),
        };

        private sealed class EntryView(IReadOnlyList<PermissionEntry> entries, string distinguishedName)
            : IReadOnlyList<PermissionEntry>
        {
            public int Count => entries.Count;
            public PermissionEntry this[int index]
            {
                get
                {
                    var entry = entries[index];
                    if (entry.Trustee.IsPrincipalSelf) entry = entry.DisplayedAgainst(distinguishedName);
                    return entry.ApplicationData.Length == 0 ? entry
                        : entry with { ApplicationData = entry.ApplicationData.ToArray() };
                }
            }
            public IEnumerator<PermissionEntry> GetEnumerator()
            {
                for (var i = 0; i < Count; i++) yield return this[i];
            }
            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }
    }
}
