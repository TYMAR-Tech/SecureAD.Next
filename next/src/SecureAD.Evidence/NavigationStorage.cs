using Microsoft.Data.Sqlite;
using SecureAD.Kernel.Naming;

namespace SecureAD.Evidence;

internal static class NavigationStorage
{
    internal const int Version = 2;
    private static readonly string[] Metadata =
    [
        "bundle", "capture_object_class_exclusion", "partition_coverage", "domain_coverage",
        "forest_partition_coverage", "unread_partition", "excluded_domain", "sysvol_gpo_coverage",
        "continuation_reconciliation_item", "domain_capture_failure",
    ];

    internal static long Write(SqliteConnection connection, string directory, Guid generation, CancellationToken token)
    {
        var path = BundleLayout.NavigationPartialPath(directory);
        if (File.Exists(path)) throw new IOException("An unfinished navigation product already exists.");
        using var command = connection.CreateCommand();
        command.CommandText = "ATTACH DATABASE $path AS navigation";
        command.Parameters.AddWithValue("$path", path);
        command.ExecuteNonQuery();
        command.Parameters.Clear();
        command.CommandText = "PRAGMA navigation.journal_mode=WAL; PRAGMA navigation.synchronous=NORMAL; PRAGMA navigation.cache_size=-2048";
        command.ExecuteNonQuery();
        using var transaction = connection.BeginTransaction();
        command.Transaction = transaction;
        foreach (var table in Metadata)
        {
            token.ThrowIfCancellationRequested();
            command.CommandText = $"CREATE TABLE navigation.{table} AS SELECT * FROM main.{table}";
            command.ExecuteNonQuery();
        }
        command.CommandText = """
            CREATE TABLE navigation.captured_object (
                object_id INTEGER PRIMARY KEY, coverage_id INTEGER NOT NULL, object_guid TEXT NULL,
                distinguished_name TEXT NOT NULL, dn_reversed TEXT NOT NULL, parent_dn TEXT NULL,
                parent_guid TEXT NULL, domain_fqdn TEXT NOT NULL, most_specific_class TEXT NULL,
                samaccountname TEXT NULL, objectsid BLOB NULL, name_sort TEXT NOT NULL,
                is_container INTEGER NOT NULL CHECK(is_container IN (0,1)));
            """;
        command.ExecuteNonQuery();
        var classes = string.Join(",", DirectoryTreeReader.ContainerClasses.Select(value => "'" + value + "'"));
        command.CommandText = $"""
            INSERT INTO navigation.captured_object
            SELECT o.object_id,o.coverage_id,o.object_guid,o.distinguished_name,o.dn_reversed,o.parent_dn,
                o.parent_guid,o.domain_fqdn,
                (SELECT v.value FROM main.objectclass_value v WHERE v.object_id=o.object_id ORDER BY v.ordinal DESC LIMIT 1),
                o.samaccountname,o.objectsid,SUBSTR(o.distinguished_name,INSTR(o.distinguished_name,'=')+1),
                EXISTS(SELECT 1 FROM main.objectclass_value v WHERE v.object_id=o.object_id AND v.value COLLATE NOCASE IN ({classes}))
            FROM main.captured_object o;
            """;
        var objects = command.ExecuteNonQuery();
        token.ThrowIfCancellationRequested();
        command.CommandText = """
            CREATE INDEX navigation.ix_navigation_dn ON captured_object(distinguished_name);
            CREATE INDEX navigation.ix_navigation_dn_nocase ON captured_object(distinguished_name COLLATE NOCASE);
            CREATE INDEX navigation.ix_navigation_parent ON captured_object(parent_dn);
            CREATE INDEX navigation.ix_navigation_parent_nocase ON captured_object(parent_dn COLLATE NOCASE);
            CREATE INDEX navigation.ix_navigation_reversed ON captured_object(dn_reversed);
            CREATE INDEX navigation.ix_navigation_reversed_nocase ON captured_object(dn_reversed COLLATE NOCASE);
            CREATE INDEX navigation.ix_navigation_name_order ON captured_object(name_sort COLLATE NOCASE,object_id);
            CREATE INDEX navigation.ix_navigation_parent_order ON captured_object(parent_dn COLLATE NOCASE,name_sort COLLATE NOCASE,object_id);
            CREATE TABLE navigation.observed_parent (ordinal INTEGER PRIMARY KEY,parent_dn TEXT UNIQUE);
            INSERT INTO navigation.observed_parent(parent_dn)
                SELECT DISTINCT parent_dn FROM main.captured_object WHERE parent_dn IS NOT NULL;
            CREATE TABLE navigation.captured_container AS
                SELECT distinguished_name,object_guid,most_specific_class,is_container
                FROM navigation.captured_object
                WHERE is_container=1 OR distinguished_name IN (SELECT parent_dn FROM navigation.observed_parent);
            CREATE TABLE navigation.navigation_product (
                id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL,
                generation TEXT NOT NULL, objects INTEGER NOT NULL CHECK(objects>=0));
            INSERT INTO navigation.navigation_product VALUES(1,$version,$generation,$objects);
            """;
        command.Parameters.AddWithValue("$version", Version);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.Parameters.AddWithValue("$objects", objects);
        command.ExecuteNonQuery();
        command.Parameters.Clear();
        command.CommandText = """
            CREATE TEMP TABLE navigation_name (distinguished_name TEXT PRIMARY KEY);
            SELECT parent_dn FROM navigation.observed_parent
            UNION SELECT distinguished_name FROM navigation.captured_container
            UNION SELECT naming_context_dn FROM navigation.partition_coverage;
            """;
        var names = new HashSet<string>(StringComparer.Ordinal);
        using (var rows = command.ExecuteReader())
            while (rows.Read())
            {
                token.ThrowIfCancellationRequested();
                for (var current = rows.GetString(0); current is not null && names.Add(current);
                    current = DnHelper.GetParentDn(current)) { }
            }
        command.CommandText = "INSERT INTO temp.navigation_name VALUES($dn)";
        var dn = command.Parameters.Add("$dn", SqliteType.Text);
        command.Prepare();
        foreach (var name in names)
        {
            token.ThrowIfCancellationRequested();
            dn.Value = name;
            command.ExecuteNonQuery();
        }
        command.Parameters.Clear();
        command.CommandText = """
            DELETE FROM navigation.captured_container;
            INSERT INTO navigation.captured_container
                SELECT distinguished_name,object_guid,most_specific_class,is_container
                FROM navigation.captured_object WHERE distinguished_name IN
                    (SELECT distinguished_name FROM temp.navigation_name);
            DROP TABLE temp.navigation_name;
            """;
        command.ExecuteNonQuery();
        token.ThrowIfCancellationRequested();
        transaction.Commit();
        return objects;
    }

    internal static void RequireBinding(SqliteConnection connection, StoreRootManifest root)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT schema_version,generation,objects FROM navigation_product WHERE id=1";
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetInt32(0) != Version
            || root.Segment(StoreSegmentRole.Navigation).SchemaVersion != Version
            || row.GetString(1) != root.GenerationId.ToString("D") || row.GetInt64(2) != root.CapturedObjects || row.Read())
            throw new InvalidDataException("The captured navigation product contradicts its root.");
    }
}
