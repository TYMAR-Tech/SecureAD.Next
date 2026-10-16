using Microsoft.Data.Sqlite;

namespace SecureAD.Evidence;

/// <summary>Captured permission browsing without unrelated attributes or object-expanded ACE copies.</summary>
internal static class CapturedDelegationStorage
{
    internal const int Version = 1;
    internal const string CandidateSql = """
        SELECT DISTINCT descriptor_id FROM delegation_candidate
        WHERE sid=$sid AND descriptor_id >= $after
          AND ($mask=0 OR (access_mask & $mask)<>0)
          AND ($inherited=1 OR is_inherited=0)
        ORDER BY descriptor_id
        """;

    internal static void Write(SqliteConnection connection, string directory, Guid generation, long objects,
        CancellationToken token)
    {
        var path = BundleLayout.DelegationsPartialPath(directory);
        if (File.Exists(path)) throw new IOException("An unfinished captured-permission product already exists.");
        using var command = connection.CreateCommand();
        command.CommandText = "ATTACH DATABASE $path AS delegations";
        command.Parameters.AddWithValue("$path", path);
        command.ExecuteNonQuery();
        command.Parameters.Clear();
        command.CommandText = "PRAGMA delegations.journal_mode=WAL; PRAGMA delegations.synchronous=NORMAL; PRAGMA delegations.cache_size=-2048";
        command.ExecuteNonQuery();
        using var transaction = connection.BeginTransaction();
        command.Transaction = transaction;
        foreach (var table in NavigationStorage.Metadata)
        {
            token.ThrowIfCancellationRequested();
            command.CommandText = $"CREATE TABLE delegations.{table} AS SELECT * FROM main.{table}";
            command.ExecuteNonQuery();
        }
        command.CommandText = """
            CREATE TABLE delegations.captured_object (
                object_id INTEGER PRIMARY KEY, object_guid TEXT NULL, distinguished_name TEXT NOT NULL,
                domain_fqdn TEXT NOT NULL, samaccountname TEXT NULL, objectsid BLOB NULL,
                delegation_is_user INTEGER NOT NULL, delegation_is_group INTEGER NOT NULL,
                delegation_class_was_read INTEGER NOT NULL);
            INSERT INTO delegations.captured_object
                SELECT o.object_id,o.object_guid,o.distinguished_name,o.domain_fqdn,o.samaccountname,o.objectsid,
                    o.delegation_is_user,o.delegation_is_group,o.delegation_class_was_read
                FROM navigation.captured_object o;
            CREATE INDEX delegations.ix_delegation_sid ON captured_object(objectsid);
            CREATE TABLE delegations.security_descriptor (
                descriptor_id INTEGER PRIMARY KEY, raw_bytes BLOB NOT NULL, dacl_completeness TEXT NOT NULL);
            INSERT INTO delegations.security_descriptor
                SELECT descriptor_id,raw_bytes,dacl_completeness FROM main.security_descriptor d
                WHERE EXISTS(SELECT 1 FROM main.object_security_descriptor o WHERE o.descriptor_id=d.descriptor_id);
            CREATE TABLE delegations.object_security_descriptor (object_id INTEGER PRIMARY KEY,descriptor_id INTEGER NOT NULL);
            INSERT INTO delegations.object_security_descriptor SELECT object_id,descriptor_id FROM main.object_security_descriptor;
            CREATE INDEX delegations.ix_object_security_descriptor ON object_security_descriptor(descriptor_id,object_id);
            CREATE TABLE delegations.delegation_candidate (
                sid TEXT NOT NULL, descriptor_id INTEGER NOT NULL, is_inherited INTEGER NOT NULL, access_mask INTEGER NOT NULL,
                PRIMARY KEY(sid,descriptor_id,is_inherited,access_mask)) WITHOUT ROWID;
            INSERT INTO delegations.delegation_candidate
                SELECT DISTINCT t.sid,d.descriptor_id,a.is_inherited,(a.access_mask & 289)
                FROM main.trustee t
                JOIN main.access_entry a ON a.trustee_id=t.trustee_id
                JOIN main.descriptor_entry d ON d.entry_id=a.entry_id
                WHERE t.sid IS NOT NULL AND EXISTS
                    (SELECT 1 FROM main.object_security_descriptor o WHERE o.descriptor_id=d.descriptor_id);
            CREATE TABLE delegations.delegation_coverage AS
                SELECT (SELECT count(*) FROM main.unreadable_security_descriptor) AS unreadable,
                    (SELECT count(*) FROM main.captured_object)-(SELECT count(*) FROM main.object_security_descriptor)
                        -(SELECT count(*) FROM main.unreadable_security_descriptor) AS unattempted,
                    (SELECT count(*) FROM main.security_descriptor d WHERE d.dacl_completeness<>'Complete'
                        AND EXISTS(SELECT 1 FROM main.object_security_descriptor o WHERE o.descriptor_id=d.descriptor_id)) AS incomplete,
                    (SELECT count(*) FROM main.security_descriptor_error e
                        WHERE EXISTS(SELECT 1 FROM main.object_security_descriptor o WHERE o.descriptor_id=e.descriptor_id)) AS errors;
            CREATE TABLE delegations.delegation_product (
                id INTEGER PRIMARY KEY CHECK(id=1),schema_version INTEGER NOT NULL,generation TEXT NOT NULL,objects INTEGER NOT NULL);
            INSERT INTO delegations.delegation_product VALUES(1,$version,$generation,$objects);
            """;
        command.Parameters.AddWithValue("$version", Version);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.Parameters.AddWithValue("$objects", objects);
        command.ExecuteNonQuery();
        command.Parameters.Clear();
        token.ThrowIfCancellationRequested();
        WriteSchema(connection, "delegations", transaction);
        token.ThrowIfCancellationRequested();
        transaction.Commit();
    }

    internal static void WriteSchema(SqliteConnection connection, string schema, SqliteTransaction transaction)
    {
        if (schema is not ("navigation" or "delegations")) throw new ArgumentException(nameof(schema));
        var fields = string.Join(",", new[] { "lDAPDisplayName", "cn", "schemaIDGUID", "rightsGuid",
            "validAccesses", "isSingleValued", "attributeSecurityGUID" }.Select(BundleSchema.ColumnNameFor));
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"""
            CREATE TABLE {schema}.delegation_schema AS SELECT {fields} FROM main.captured_object
            WHERE {BundleSchema.ColumnNameFor("schemaIDGUID")} IS NOT NULL OR {BundleSchema.ColumnNameFor("rightsGuid")} IS NOT NULL;
            """;
        command.ExecuteNonQuery();
    }

    internal static void RequireBinding(SqliteConnection connection, StoreRootManifest root)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT schema_version,generation,objects FROM delegation_product WHERE id=1";
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetInt32(0) != Version
            || root.Segment(StoreSegmentRole.Delegations).SchemaVersion != Version
            || row.GetString(1) != root.GenerationId.ToString("D") || row.GetInt64(2) != root.CapturedObjects || row.Read())
            throw new InvalidDataException("The captured-permission product contradicts its root.");
    }

    internal static DelegationCoverage ReadCoverage(SqliteConnection connection, BundleDescription description)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT unreadable,unattempted,incomplete,errors FROM delegation_coverage";
        using var row = command.ExecuteReader();
        if (!row.Read()) throw new InvalidDataException("Captured permission coverage is absent.");
        var coverage = new DelegationCoverage(description.EveryDeclaredUnitRecordedAsRead, description.ExcludedObjectClasses,
            row.GetInt64(0), row.GetInt64(1), row.GetInt64(2), row.GetInt64(3));
        if (coverage.UnreadableDescriptors < 0 || coverage.UnattemptedDescriptors < 0
            || coverage.IncompleteDescriptors < 0 || coverage.DescriptorErrors < 0 || row.Read())
            throw new InvalidDataException("Captured permission coverage is contradictory.");
        return coverage;
    }
}
