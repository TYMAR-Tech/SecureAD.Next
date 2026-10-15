using System.Runtime.CompilerServices;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static class JudgementStoreLayout
{
    private sealed record Access(Action<StoreSegmentRole> Open);
    private sealed record Reference(string Child, StoreSegmentRole ChildRole, string Column,
        string Parent, StoreSegmentRole ParentRole, string ParentColumn, bool DeferredCalculation = false);
    private static readonly ConditionalWeakTable<SqliteConnection, Access> Readers = new();
    private static readonly ConditionalWeakTable<SqliteConnection, object> Writers = new();
    private static readonly string[] FindingProofTables =
    [
        "finding_attribute_write", "finding_circular_membership", "finding_delegation_configuration",
        "finding_duplicate_spn", "finding_broad_group_membership", "finding_membership_review",
        "finding_unconstrained_delegation", "finding_admincount_without_protection", "finding_user_account_control",
        "finding_privileged_sid_history", "finding_privileged_sid_history_value", "finding_kerberoastable_account",
        "finding_kerberoastable_account_spn", "finding_laps_deployment", "finding_laps_password_reader",
        "finding_laps_password_reader_path", "finding_object_takeover", "finding_object_takeover_path",
        "finding_object_ownership", "finding_laps_decryptor", "finding_replication_permission",
        "finding_service_account", "finding_tier0_route",
    ];
    private static readonly Reference[] ProductReferences =
    [
        new("tier0_best_route", StoreSegmentRole.PathProof, "target", "ownership_target", StoreSegmentRole.PermissionProof, "target"),
        new("path_calculation_record", StoreSegmentRole.PathProof, "calculation", "tier0_path_calculation", StoreSegmentRole.Judgement, "id", true),
        new("path_anchor", StoreSegmentRole.PathProof, "target", "ownership_seed", StoreSegmentRole.PermissionProof, "target"),
        new("path_requester_work", StoreSegmentRole.PathProof, "calculation", "tier0_path_calculation", StoreSegmentRole.Judgement, "id", true),
        new("permission_classification_object", StoreSegmentRole.JudgementFacts, "target", "control_object", StoreSegmentRole.PermissionProof, "target"),
        new("permission_classification_value", StoreSegmentRole.JudgementFacts, "entry_id", "permission_entry", StoreSegmentRole.PermissionProof, "id"),
        new("permission_classification_entry", StoreSegmentRole.JudgementFacts, "entry_id", "permission_entry", StoreSegmentRole.PermissionProof, "id"),
        new("tier0_distance", StoreSegmentRole.PathProof, "target", "ownership_target", StoreSegmentRole.PermissionProof, "target"),
        new("tier0_path_calculation", StoreSegmentRole.Judgement, "proof", "path_proof", StoreSegmentRole.PathProof, "id"),
        new("tier0_path_node", StoreSegmentRole.PathProof, "target", "ownership_target", StoreSegmentRole.PermissionProof, "target"),
    ];

    internal static void RegisterReader(SqliteConnection connection, Action<StoreSegmentRole> open) =>
        Readers.Add(connection, new(open));

    internal static void Ensure(SqliteConnection connection, StoreSegmentRole role)
    {
        if (Readers.TryGetValue(connection, out var access)) access.Open(role);
    }

    internal static void Create(SqliteConnection connection, string directory, Guid generation,
        string evidenceSeal, Guid? derivation)
    {
        Execute(connection, "PRAGMA temp_store=FILE");
        // Split the original 2 MiB writer cache, rather than opening four large caches.
        Execute(connection, "PRAGMA main.cache_size=-512");
        var selected = new AnalysisStoreGeneration(AnalysisStoreKind.Judgement, generation);
        foreach (var role in BundleLayout.JudgementParts)
        {
            var path = BundleLayout.AnalysisSegmentDataPath(directory, selected, role);
            using (File.Open(path, FileMode.CreateNew, FileAccess.Write)) { }
            using var attach = connection.CreateCommand();
            attach.CommandText = $"ATTACH DATABASE $path AS {Quote(Schema(role))}";
            attach.Parameters.AddWithValue("$path", path);
            attach.ExecuteNonQuery();
            Execute(connection, $"PRAGMA {Quote(Schema(role))}.journal_mode=WAL");
            Execute(connection, $"PRAGMA {Quote(Schema(role))}.synchronous=NORMAL");
            Execute(connection, $"PRAGMA {Quote(Schema(role))}.cache_size=-512");
        }

        foreach (var role in BundleLayout.JudgementParts)
        {
            Execute(connection, $"""
                CREATE TABLE {Quote(Schema(role))}.judgement_part (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL,
                    role TEXT NOT NULL, generation TEXT NOT NULL, evidence_seal TEXT NOT NULL, derivation_generation TEXT NULL);
                """);
            using var header = connection.CreateCommand();
            header.CommandText = $"INSERT INTO {Quote(Schema(role))}.judgement_part VALUES(1,$schema,$role,$generation,$evidence,$derived)";
            header.Parameters.AddWithValue("$schema", JudgementSchema.Version);
            header.Parameters.AddWithValue("$role", role.ToString());
            header.Parameters.AddWithValue("$generation", generation.ToString("D"));
            header.Parameters.AddWithValue("$evidence", evidenceSeal);
            header.Parameters.AddWithValue("$derived", (object?)derivation?.ToString("D") ?? DBNull.Value);
            header.ExecuteNonQuery();
        }
        Writers.Add(connection, new());
    }

    internal static void CreateReferences(SqliteConnection connection)
    {
        foreach (var table in FindingProofTables)
            CreateReference(connection, new(table, StoreSegmentRole.PermissionProof, "finding_id",
                "finding", StoreSegmentRole.Judgement, "finding_id"));
        foreach (var reference in ProductReferences)
            if (reference.DeferredCalculation) CreateCalculationReference(connection, reference);
            else CreateReference(connection, reference);
    }

    internal static void RequirePublishable(SqliteConnection connection)
    {
        // Both deferred cross-product references name calculation 1. Their CHECKs cover the key;
        // this constant-size probe supplies parent existence without another pass over saved proofs.
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT (EXISTS(SELECT 1 FROM path_calculation_record) OR EXISTS(SELECT 1 FROM path_requester_work))
                AND NOT EXISTS(SELECT 1 FROM tier0_path_calculation WHERE id=1)
            """;
        if ((long)query.ExecuteScalar()! != 0) throw Tier0PathStorage.InvalidProof();
    }

    internal static void Checkpoint(SqliteConnection connection)
    {
        // Omitting the schema checkpoints every attached WAL database, not just main.
        using var checkpoint = connection.CreateCommand();
        checkpoint.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
        if ((long)checkpoint.ExecuteScalar()! != 0)
            throw new InvalidOperationException("The judgement products could not be fully checkpointed and were not published.");
    }

    internal static string Schema(StoreSegmentRole role) => role == StoreSegmentRole.Judgement ? "main" : role.ToString();

    internal static string Schema(SqliteConnection connection, StoreSegmentRole role) =>
        Readers.TryGetValue(connection, out _) || Writers.TryGetValue(connection, out _) ? Schema(role) : "main";

    internal static (long Changes, long MainVersion, long ProofVersion) Revision(SqliteConnection connection)
    {
        Ensure(connection, StoreSegmentRole.PermissionProof);
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT total_changes()";
        var changes = (long)query.ExecuteScalar()!;
        query.CommandText = "PRAGMA main.data_version";
        var main = (long)query.ExecuteScalar()!;
        var schema = Schema(connection, StoreSegmentRole.PermissionProof);
        if (schema == "main") return (changes, main, main);
        query.CommandText = $"PRAGMA {schema}.data_version";
        return (changes, main, (long)query.ExecuteScalar()!);
    }

    private static void CreateReference(SqliteConnection connection, Reference reference)
    {
        var child = $"{Quote(Schema(connection, reference.ChildRole))}.{Quote(reference.Child)}";
        var parent = $"{Quote(Schema(connection, reference.ParentRole))}.{Quote(reference.Parent)}";
        var column = Quote(reference.Column);
        var parentColumn = Quote(reference.ParentColumn);
        var name = reference.Child + "_" + reference.Column;
        foreach (var operation in new[] { "INSERT", $"UPDATE OF {column}" })
            Execute(connection, $"""
                CREATE TEMP TRIGGER {Quote(name + (operation == "INSERT" ? "_insert" : "_update"))}
                BEFORE {operation} ON {child}
                WHEN NEW.{column} IS NOT NULL AND NOT EXISTS(SELECT 1 FROM {parent} WHERE {parentColumn}=NEW.{column})
                BEGIN SELECT RAISE(ABORT,'FOREIGN KEY constraint failed'); END;
                """);
        Execute(connection, $"""
            CREATE TEMP TRIGGER {Quote(name + "_delete")} BEFORE DELETE ON {parent}
            WHEN EXISTS(SELECT 1 FROM {child} WHERE {column}=OLD.{parentColumn})
            BEGIN SELECT RAISE(ABORT,'FOREIGN KEY constraint failed'); END;
            CREATE TEMP TRIGGER {Quote(name + "_parent_update")} BEFORE UPDATE OF {parentColumn} ON {parent}
            WHEN NEW.{parentColumn} IS NOT OLD.{parentColumn}
                AND EXISTS(SELECT 1 FROM {child} WHERE {column}=OLD.{parentColumn})
            BEGIN SELECT RAISE(ABORT,'FOREIGN KEY constraint failed'); END;
            """);
    }

    private static void CreateCalculationReference(SqliteConnection connection, Reference reference)
    {
        Execute(connection, $"""
            CREATE TEMP TRIGGER {Quote(reference.Child + "_calculation_delete")} AFTER DELETE ON main.tier0_path_calculation
            BEGIN DELETE FROM {Quote(reference.Child)} WHERE calculation=OLD.id; END;
            CREATE TEMP TRIGGER {Quote(reference.Child + "_calculation_update")} BEFORE UPDATE OF id ON main.tier0_path_calculation
            WHEN NEW.id IS NOT OLD.id AND EXISTS(SELECT 1 FROM {Quote(Schema(connection, reference.ChildRole))}.{Quote(reference.Child)} WHERE calculation=OLD.id)
            BEGIN SELECT RAISE(ABORT,'FOREIGN KEY constraint failed'); END;
            """);
    }

    private static string Quote(string name) => "\"" + name + "\"";

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}
