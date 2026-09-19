using System.Globalization;
using System.Resources;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class PermissionClassificationStorage
{
    private static readonly ResourceManager Messages = new("SecureAD.Judgement.Resources.PermissionClassification", typeof(PermissionClassificationStorage).Assembly);
    internal static string Message(string key) => Messages.GetString(key, CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException(key);
    private static InvalidDataException Invalid() => new(Message("Invalid"));
    private sealed record Reading(string Summary, bool RightsAreComplete, PermissionScope Scope,
        IReadOnlyList<ClassifiedPermissionRight> Rights);

    internal static void CreateTables(SqliteConnection connection) => Execute(connection, null, """
        CREATE TABLE permission_classification_product (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), generation TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('Writing','Complete')),
            producer_version INTEGER NOT NULL, schema_version INTEGER NOT NULL,
            has_captured_schema INTEGER NOT NULL CHECK(has_captured_schema IN (0,1)),
            object_count INTEGER NULL CHECK(object_count>=0));
        CREATE TABLE permission_classification_schema (guid TEXT PRIMARY KEY COLLATE BINARY, payload TEXT NOT NULL);
        CREATE TABLE permission_classification_object (
            target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES control_object(target),
            descriptor TEXT NOT NULL, entry_count INTEGER NOT NULL CHECK(entry_count>=0));
        CREATE TABLE permission_classification_entry (
            target TEXT NOT NULL REFERENCES permission_classification_object(target),
            position INTEGER NOT NULL CHECK(position>=0), ordinal INTEGER NOT NULL CHECK(ordinal>=0),
            entry_id INTEGER NOT NULL REFERENCES permission_entry(id), fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
            right_count INTEGER NOT NULL CHECK(right_count>=0), reading TEXT NOT NULL,
            object_schema TEXT NULL REFERENCES permission_classification_schema(guid),
            inherited_schema TEXT NULL REFERENCES permission_classification_schema(guid),
            PRIMARY KEY(target,position), UNIQUE(target,ordinal));
        """);

    internal static void Start(SqliteConnection connection, Guid generation, bool hasCapturedSchema) =>
        Execute(connection, null, "INSERT INTO permission_classification_product VALUES (1,$generation,'Writing',$producer,$schema,$captured,NULL)",
            ("$generation", generation.ToString("D")), ("$producer", PermissionClassificationProducer.Version),
            ("$schema", SchemaGuidCatalog.Version), ("$captured", hasCapturedSchema));

    internal static void Write(SqliteConnection connection, Guid generation, PermissionClassification result, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        Validate(result, token);
        using var transaction = connection.BeginTransaction();
        var target = result.Permissions.DistinguishedName;
        var shared = new SharedPermissionStorage(connection, transaction);
        shared.Load(target, generation);
        Execute(connection, transaction, "INSERT INTO permission_classification_object VALUES ($target,$descriptor,$count)",
            ("$target", target), ("$descriptor", JsonSerializer.Serialize(result.Permissions with { Entries = [] })),
            ("$count", result.Entries.Count));
        for (var position = 0; position < result.Entries.Count; position++)
        {
            token.ThrowIfCancellationRequested();
            var entry = result.Entries[position];
            var reference = shared.Write(target, generation, entry.Entry);
            WriteSupport(entry.ObjectType);
            WriteSupport(entry.InheritedObjectType);
            Execute(connection, transaction, """
                INSERT INTO permission_classification_entry VALUES
                ($target,$position,$ordinal,$entry,$hash,$count,$reading,$object,$inherited)
                """, ("$target", target), ("$position", position), ("$ordinal", entry.Entry.Ordinal),
                ("$entry", reference.Id), ("$hash", reference.Fingerprint), ("$count", entry.Rights.Count),
                ("$reading", JsonSerializer.Serialize(new Reading(entry.Summary, entry.RightsAreComplete, entry.Scope, entry.Rights))),
                ("$object", entry.ObjectType?.Guid), ("$inherited", entry.InheritedObjectType?.Guid));
        }
        transaction.Commit();

        void WriteSupport(PermissionSchemaSupport? support)
        {
            if (support is null) return;
            var payload = JsonSerializer.Serialize(support);
            Execute(connection, transaction, "INSERT OR IGNORE INTO permission_classification_schema VALUES ($guid,$payload)",
                ("$guid", support.Guid), ("$payload", payload));
            using var check = connection.CreateCommand();
            check.Transaction = transaction;
            check.CommandText = "SELECT payload FROM permission_classification_schema WHERE guid=$guid COLLATE BINARY";
            check.Parameters.AddWithValue("$guid", support.Guid);
            if (check.ExecuteScalar() as string != payload) throw Invalid();
        }
    }

    internal static void Complete(SqliteConnection connection, long objectCount)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE permission_classification_product SET state='Complete',object_count=$count
            WHERE singleton=1 AND state='Writing'
                AND (SELECT COUNT(*) FROM permission_classification_object)=$count
                AND NOT EXISTS (SELECT 1 FROM permission_classification_object o WHERE o.entry_count <>
                    (SELECT COUNT(*) FROM permission_classification_entry e WHERE e.target=o.target))
            """;
        command.Parameters.AddWithValue("$count", objectCount);
        if (command.ExecuteNonQuery() != 1) throw Invalid();
    }

    internal static void RequirePublishable(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT state,object_count,(SELECT COUNT(*) FROM permission_classification_object)
            FROM permission_classification_product
            """;
        using var read = command.ExecuteReader();
        // A findings-only writer has not produced this product. Readback refuses that absence.
        if (read.Read() && (read.GetString(0) != "Complete" || read.IsDBNull(1) || read.GetInt64(1) != read.GetInt64(2)))
            throw Invalid();
    }

    internal static SavedPermissionClassification Read(SqliteConnection connection, JudgementDescription description,
        string distinguishedName, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        token.ThrowIfCancellationRequested();
        bool captured;
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT generation,state,producer_version,schema_version,has_captured_schema,object_count FROM permission_classification_product WHERE singleton=1";
            using var read = command.ExecuteReader();
            if (!read.Read()) throw new InvalidOperationException(Message("Unavailable"));
            if (read.GetString(0) != description.GenerationId.ToString("D") || read.GetString(1) != "Complete"
                || read.GetInt32(2) != PermissionClassificationProducer.Version || read.GetInt32(3) != SchemaGuidCatalog.Version
                || read.GetInt32(4) is not (0 or 1) || read.IsDBNull(5) || read.GetInt64(5) < 0) throw Invalid();
            captured = read.GetBoolean(4);
        }
        ObjectPermissions permissions;
        int expected;
        string target;
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT target,descriptor,entry_count FROM permission_classification_object WHERE target=$target COLLATE NOCASE";
            command.Parameters.AddWithValue("$target", distinguishedName);
            using var read = command.ExecuteReader();
            if (!read.Read()) throw Invalid();
            target = read.GetString(0);
            permissions = JsonSerializer.Deserialize<ObjectPermissions>(read.GetString(1)) ?? throw Invalid();
            expected = read.GetInt32(2);
            if (permissions.DistinguishedName != target || permissions.Entries is null || permissions.Entries.Count != 0 || expected < 0)
                throw Invalid();
        }
        var entries = new List<ClassifiedPermissionEntry>();
        var supports = new Dictionary<string, PermissionSchemaSupport>(StringComparer.Ordinal);
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT " + SharedPermissionStorage.Projection + ",e.ordinal,e.fingerprint,e.position,e.right_count,e.reading,e.object_schema,e.inherited_schema"
                + " FROM permission_classification_entry e LEFT JOIN permission_entry p ON p.id=e.entry_id"
                + SharedPermissionStorage.MeaningJoin + " WHERE e.target=$target COLLATE BINARY ORDER BY e.position";
            command.Parameters.AddWithValue("$target", target);
            using var read = command.ExecuteReader();
            while (read.Read())
            {
                token.ThrowIfCancellationRequested();
                PermissionEntry entry;
                try { entry = SharedPermissionStorage.Read(read, target, description.GenerationId); }
                catch (InvalidOperationException error) { throw new InvalidDataException(Message("Invalid"), error); }
                const int offset = SharedPermissionStorage.ProjectionColumns + 2;
                if (read.GetInt32(offset) != entries.Count) throw Invalid();
                var reading = JsonSerializer.Deserialize<Reading>(read.GetString(offset + 2)) ?? throw Invalid();
                if (reading.Rights is null || reading.Rights.Count != read.GetInt32(offset + 1)) throw Invalid();
                entries.Add(new(entry, reading.Summary, reading.RightsAreComplete, reading.Scope, reading.Rights,
                    ReadSupport(read.IsDBNull(offset + 3) ? null : read.GetString(offset + 3)),
                    ReadSupport(read.IsDBNull(offset + 4) ? null : read.GetString(offset + 4))));
            }
        }
        if (entries.Count != expected) throw Invalid();
        var result = new PermissionClassification(permissions with { Entries = [.. entries.Select(value => value.Entry)] },
            entries, PermissionClassificationProducer.Version, SchemaGuidCatalog.Version, captured);
        Validate(result, token);
        token.ThrowIfCancellationRequested();
        return new(description, result);

        PermissionSchemaSupport? ReadSupport(string? guid)
        {
            if (guid is null) return null;
            if (supports.TryGetValue(guid, out var found)) return found;
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT payload FROM permission_classification_schema WHERE guid=$guid COLLATE BINARY";
            command.Parameters.AddWithValue("$guid", guid);
            if (command.ExecuteScalar() is not string json) throw Invalid();
            var support = JsonSerializer.Deserialize<PermissionSchemaSupport>(json) ?? throw Invalid();
            if (support.Guid != guid) throw Invalid();
            supports.Add(guid, support);
            return support;
        }
    }

    // These are structural checks of requested stored records, not a replay of risk or schema interpretation.
    private static void Validate(PermissionClassification result, CancellationToken token)
    {
        var permissions = result.Permissions;
        if (permissions is null || string.IsNullOrWhiteSpace(permissions.DistinguishedName) || permissions.Errors is null
            || permissions.Entries is null || result.Entries is null || permissions.Entries.Count != result.Entries.Count
            || !Enum.IsDefined(permissions.Availability) || !Enum.IsDefined(permissions.DaclState)
            || !Enum.IsDefined(permissions.DaclCompleteness) || result.ProducerVersion != PermissionClassificationProducer.Version
            || result.SchemaVersion != SchemaGuidCatalog.Version) throw Invalid();
        var previous = -1;
        for (var index = 0; index < result.Entries.Count; index++)
        {
            token.ThrowIfCancellationRequested();
            var value = result.Entries[index];
            if (value is null || value.Entry is null || value.Entry.Ordinal <= previous || value.Rights is null
                || value.Scope is null || string.IsNullOrWhiteSpace(value.Summary)
                || string.IsNullOrWhiteSpace(value.Scope.AppliesTo) || string.IsNullOrWhiteSpace(value.Scope.Inheritance)
                || SharedPermissionStorage.ValueKey(value.Entry) != SharedPermissionStorage.ValueKey(permissions.Entries[index])) throw Invalid();
            previous = value.Entry.Ordinal;
            var mask = 0;
            foreach (var right in value.Rights)
            {
                if (right?.Right is null || right.Assessment is null || right.Right.Bits == 0
                    || (mask & right.Right.Bits) != 0 || string.IsNullOrWhiteSpace(right.Right.Name)
                    || !Enum.IsDefined(right.Assessment.Verdict) || string.IsNullOrWhiteSpace(right.Assessment.Reason)
                    || (!right.Right.IsNamed && right.Assessment.Verdict != PermissionVerdict.CannotClassify)) throw Invalid();
                mask |= right.Right.Bits;
            }
            if (mask != value.Entry.AccessMask || value.RightsAreComplete != value.Rights.All(right => right.Right.IsNamed)) throw Invalid();
            ValidateSupport(value.ObjectType, value.Entry.ObjectTypeGuid);
            ValidateSupport(value.InheritedObjectType, value.Entry.InheritedObjectTypeGuid);
        }
    }

    private static void ValidateSupport(PermissionSchemaSupport? support, string? guid)
    {
        if (guid is null) { if (support is not null) throw Invalid(); return; }
        if (support is null || support.Guid != guid || support.Definitions is null || support.AmbiguousNames is null
            || support.Definitions.Any(value => value is null || !Enum.IsDefined(value.Kind) || !Enum.IsDefined(value.Source)
                || !string.Equals(value.Guid, guid, StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(value.LdapName))
            || support.PropertySetMembers?.Any(string.IsNullOrWhiteSpace) == true
            || support.AmbiguousNames.Any(string.IsNullOrWhiteSpace)) throw Invalid();
    }

    private static void Execute(SqliteConnection connection, SqliteTransaction? transaction, string sql,
        params (string Name, object? Value)[] parameters)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        command.ExecuteNonQuery();
    }
}
