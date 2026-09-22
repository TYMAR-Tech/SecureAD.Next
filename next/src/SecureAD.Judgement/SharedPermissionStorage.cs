using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

// One instance per object transaction: failed writes cannot leave reusable identities behind.
internal sealed class SharedPermissionStorage(SqliteConnection connection, SqliteTransaction transaction,
    PreparedStatements statements)
{
    private readonly Dictionary<string, (long Id, byte[] Fingerprint)> entries = new(StringComparer.Ordinal);
    internal SharedProofStorage Proofs { get; } = new(connection, transaction, statements);

    internal const int ProjectionColumns = 30;
    internal const string Projection = """
        p.id,p.target,p.generation,p.ordinal,p.ace_type,p.sid,p.name,p.dn,p.domain,p.unresolved_reason,p.role,v.payload AS meaning,
        p.mask,p.object_type,p.inherited_object_type,p.inherited,p.inheritance_flags,p.propagation_flags,p.has_object_type,
        p.has_inherited_object_type,p.application_data,p.meaning AS meaning_id,p.meaning_binding,
        v.id AS resolved_meaning_id,v.kind,v.format_version,v.generation AS meaning_generation,
        v.derivation_generation AS meaning_derivation,v.catalogue_version,v.fingerprint AS meaning_fingerprint
        """;
    internal const string MeaningJoin = " LEFT JOIN shared_proof_value v ON v.id=p.meaning ";

    internal static void CreateTables(SqliteConnection connection)
    {
        SharedProofStorage.CreateTables(connection);
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE permission_entry (id INTEGER PRIMARY KEY,
                target TEXT NOT NULL REFERENCES control_object(target), generation TEXT NOT NULL,
                ordinal INTEGER NOT NULL, ace_type TEXT NOT NULL, sid TEXT NOT NULL,
                name TEXT NULL, dn TEXT NULL, domain TEXT NULL, unresolved_reason TEXT NULL, role TEXT NULL,
                meaning INTEGER NULL REFERENCES shared_proof_value(id),
                mask INTEGER NOT NULL, object_type TEXT NULL, inherited_object_type TEXT NULL,
                inherited INTEGER NOT NULL CHECK(inherited IN (0,1)),
                inheritance_flags INTEGER NOT NULL CHECK(inheritance_flags BETWEEN 0 AND 255),
                propagation_flags INTEGER NOT NULL CHECK(propagation_flags BETWEEN 0 AND 255),
                has_object_type INTEGER NOT NULL CHECK(has_object_type IN (0,1)),
                has_inherited_object_type INTEGER NOT NULL CHECK(has_inherited_object_type IN (0,1)), application_data BLOB NOT NULL,
                meaning_binding BLOB NOT NULL CHECK(length(meaning_binding)=32));
            CREATE INDEX ix_permission_entry_target_generation ON permission_entry(target COLLATE BINARY,generation,id);
            """;
        command.ExecuteNonQuery();
    }

    internal (long Id, byte[] Fingerprint) Write(string target, Guid generation, PermissionEntry entry)
    {
        // JSON is only an exact, transient comparison key, never the stored proof representation.
        // Dictionary equality checks the complete key even when hash codes collide.
        var key = Key(target, generation, entry);
        if (entries.TryGetValue(key, out var existing)) return existing;
        var meaning = Proofs.WriteMeaning(target, generation, entry.Ordinal, entry.Trustee.Meaning);
        const string insert = """
            INSERT INTO permission_entry(target,generation,ordinal,ace_type,sid,name,dn,domain,unresolved_reason,role,meaning,
                mask,object_type,inherited_object_type,inherited,inheritance_flags,propagation_flags,has_object_type,has_inherited_object_type,application_data,meaning_binding)
            VALUES ($target,$generation,$ordinal,$type,$sid,$name,$dn,$domain,$unresolved,$role,$meaning,
                $mask,$object,$inheritedobject,$inherited,$inheritance,$propagation,$hasobject,$hasinheritedobject,$data,$meaningbinding);
            SELECT last_insert_rowid();
            """;
        (string Name, object? Value)[] values =
        [
            ("$target", target), ("$generation", generation.ToString("D")), ("$ordinal", entry.Ordinal), ("$type", entry.AceType),
            ("$sid", entry.Trustee.Sid), ("$name", entry.Trustee.Name), ("$dn", entry.Trustee.DistinguishedName),
            ("$domain", entry.Trustee.DomainFqdn), ("$unresolved", entry.Trustee.UnresolvedReason?.ToString()),
            ("$role", entry.Trustee.WellKnownRole?.ToString()), ("$meaning", meaning.Id), ("$mask", entry.AccessMask),
            ("$object", entry.ObjectTypeGuid), ("$inheritedobject", entry.InheritedObjectTypeGuid), ("$inherited", entry.IsInherited),
            ("$inheritance", (int)entry.InheritanceFlags), ("$propagation", (int)entry.PropagationFlags),
            ("$hasobject", entry.HasObjectType), ("$hasinheritedobject", entry.HasInheritedObjectType), ("$data", entry.ApplicationData),
            ("$meaningbinding", meaning.Fingerprint),
        ];
        var id = Convert.ToInt64(statements.Bind(insert, transaction, values).ExecuteScalar());
        var reference = (id, SHA256.HashData(Encoding.UTF8.GetBytes(key)));
        entries.Add(key, reference);
        return reference;
    }

    // Queries append the association's original ordinal and fingerprint after the checked projection.
    internal static PermissionEntry Read(SqliteDataReader read, string target, Guid generation)
    {
        if (read.IsDBNull(0) || read.GetString(1) != target || read.GetString(2) != generation.ToString("D")
            || read.GetInt32(3) != read.GetInt32(ProjectionColumns)) throw FullControlEvaluator.InvalidProof();
        var entry = ReadValue(read);
        var fingerprint = SHA256.HashData(Encoding.UTF8.GetBytes(Key(target, generation, entry)));
        if (!fingerprint.AsSpan().SequenceEqual((byte[])read.GetValue(ProjectionColumns + 1))) throw FullControlEvaluator.InvalidProof();
        return entry;
    }

    // A later selected-target transaction must reuse the original values without replacing their IDs.
    internal void Load(string target, Guid generation)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT " + Projection + " FROM permission_entry p" + MeaningJoin
            + "WHERE p.target=$target COLLATE BINARY AND p.generation=$generation ORDER BY p.id";
        command.Parameters.AddWithValue("$target", target);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        using var read = command.ExecuteReader();
        while (read.Read())
        {
            var entry = ReadValue(read);
            var key = Key(target, generation, entry);
            entries.TryAdd(key, (read.GetInt64(0), SHA256.HashData(Encoding.UTF8.GetBytes(key))));
        }
    }

    private static PermissionEntry ReadValue(SqliteDataReader read)
    {
        var generation = Guid.Parse(read.GetString(2));
        var meaning = Text(read, 11);
        if (read.IsDBNull(21))
        {
            if (meaning is not null || !read.IsDBNull(23)) throw FullControlEvaluator.InvalidProof();
        }
        else if (read.IsDBNull(23) || read.GetInt64(21) != read.GetInt64(23) || meaning is null
            || read.GetString(24) != "Meaning" || read.GetInt32(25) != SharedProofStorage.FormatVersion
            || read.GetString(26) != generation.ToString("D") || !read.IsDBNull(27) || read.GetInt32(28) != 0
            || !SharedProofStorage.ValueFingerprint("Meaning", generation, null, 0, meaning).AsSpan().SequenceEqual((byte[])read.GetValue(29)))
            throw FullControlEvaluator.InvalidProof();
        if (!SharedProofStorage.MeaningBinding(read.GetString(1), generation, read.GetInt32(3), meaning).AsSpan().SequenceEqual((byte[])read.GetValue(22)))
            throw FullControlEvaluator.InvalidProof();
        return new(read.GetInt32(3), read.GetString(4),
            new(read.GetString(5), Text(read, 6), Text(read, 7), Text(read, 8),
                Text(read, 9) is { } reason ? Enum.Parse<UnresolvedReferenceReason>(reason) : null,
                Text(read, 10) is { } role ? Enum.Parse<WellKnownSidRole>(role) : null, meaning),
            read.GetInt32(12), Text(read, 13), Text(read, 14), read.GetBoolean(15), checked((byte)read.GetInt32(16)),
            checked((byte)read.GetInt32(17)), read.GetBoolean(18), read.GetBoolean(19), (byte[])read.GetValue(20));
    }

    internal static string ValueKey(PermissionEntry entry) => JsonSerializer.Serialize(entry);

    private static string Key(string target, Guid generation, PermissionEntry entry) =>
        JsonSerializer.Serialize(new { Target = target, Generation = generation, Entry = entry });

    private static string? Text(SqliteDataReader read, int ordinal) => read.IsDBNull(ordinal) ? null : read.GetString(ordinal);
}
