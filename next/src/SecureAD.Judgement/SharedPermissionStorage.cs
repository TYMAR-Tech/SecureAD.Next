using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

// One instance per object transaction, but the identities it hands out belong to the run and outlive
// it: PermissionWriteSession is what decides when a written row may be trusted by a later object.
internal sealed class SharedPermissionStorage(SqliteConnection connection, SqliteTransaction transaction,
    PreparedStatements statements, PermissionWriteSession session)
{
    internal SharedProofStorage Proofs { get; } = new(connection, transaction, statements);

    internal const int ProjectionColumns = 29;
    internal const string Projection = """
        p.id,p.generation,p.entry_hash,p.ace_type,p.sid,p.name,p.dn,p.domain,p.unresolved_reason,p.role,v.payload AS meaning,
        p.mask,p.object_type,p.inherited_object_type,p.inherited,p.inheritance_flags,p.propagation_flags,p.has_object_type,
        p.has_inherited_object_type,p.application_data,p.meaning AS meaning_id,p.meaning_binding,
        v.id AS resolved_meaning_id,v.kind,v.format_version,v.generation AS meaning_generation,
        v.derivation_generation AS meaning_derivation,v.catalogue_version,v.fingerprint AS meaning_fingerprint
        """;
    internal const string MeaningJoin = " LEFT JOIN shared_proof_value v ON v.id=p.meaning ";

    // ONE ROW PER DISTINCT ENTRY IN THE RUN, NOT ONE PER OBJECT (P-279).
    //
    // Until this changed, the row named the object it was found on and deduplicated only within that
    // object, so an entry inherited by a thousand objects was written a thousand times with a
    // thousand copies of a distinguished name as text. Reproduced at the production forest's shape:
    // 24,098 distinct entries stored 17,164,866 times - 712 copies each - for a judgement of 13.3 GB
    // describing 592 MB of evidence, with storing the permissions taking 64% of the object pass
    // against 0.7% for reaching the verdicts being stored. next/artifacts/p279-before holds the
    // measurement. This is the same defect P-272 removed from the evidence side, and the same fix.
    //
    // THE ORDINAL IS ON THE LINK AND NOT HERE, exactly as P-272 put it on descriptor_entry, and it is
    // load-bearing rather than tidy. The same entry sits at different positions in different lists - a
    // deny that comes first on one object is fourth on another - and Windows evaluates a DACL by
    // accumulating granted and denied masks in stored order, adding a deny only for rights not already
    // granted ([MS-ADTS] 5.1.3.3.2). An order stored on the shared entry would be one object's order
    // imposed on every other object carrying it. control_ace, full_control_source_entry and
    // permission_classification_entry each already record the ordinal of the position they are about.
    //
    // NOR IS THE TARGET, and nothing is lost with the column. Every link row carries a fingerprint
    // over the complete (target, generation, entry) triple including that ordinal, written when the
    // link is written and recomputed on every read, so each occurrence still proves which object
    // carried which entry at which position. That fingerprint is the binding; this row is only the
    // value it points at. The foreign key to control_object goes too, and each link table keeps its
    // own to its owning object or edge, so no occurrence becomes unattributable.
    //
    // entry_hash is the identity, and the only way a second object finds the first object's row. It is
    // a SHA-256 over the generation and the complete entry with the ordinal normalised away. A
    // collision here would not corrupt a row - it would quietly give one trustee another trustee's
    // rights - which is why it is cryptographic, the same reasoning access_entry.ace_hash carries.
    internal static void CreateTables(SqliteConnection connection)
    {
        SharedProofStorage.CreateTables(connection);
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE permission_entry (id INTEGER PRIMARY KEY,
                generation TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE,
                ace_type TEXT NOT NULL, sid TEXT NOT NULL,
                name TEXT NULL, dn TEXT NULL, domain TEXT NULL, unresolved_reason TEXT NULL, role TEXT NULL,
                meaning INTEGER NULL REFERENCES shared_proof_value(id),
                mask INTEGER NOT NULL, object_type TEXT NULL, inherited_object_type TEXT NULL,
                inherited INTEGER NOT NULL CHECK(inherited IN (0,1)),
                inheritance_flags INTEGER NOT NULL CHECK(inheritance_flags BETWEEN 0 AND 255),
                propagation_flags INTEGER NOT NULL CHECK(propagation_flags BETWEEN 0 AND 255),
                has_object_type INTEGER NOT NULL CHECK(has_object_type IN (0,1)),
                has_inherited_object_type INTEGER NOT NULL CHECK(has_inherited_object_type IN (0,1)), application_data BLOB NOT NULL,
                meaning_binding BLOB NOT NULL CHECK(length(meaning_binding)=32));
            """;
        command.ExecuteNonQuery();
    }

    /// <summary>Records one occurrence of an entry, storing the entry itself only once per run.</summary>
    /// <param name="target">The object this occurrence was found on.</param>
    /// <param name="generation">The generation being judged.</param>
    /// <param name="entry">The entry, at the ordinal the directory stored it at.</param>
    /// <returns>The shared row to link to, and the fingerprint binding this occurrence to it.</returns>
    internal (long Id, byte[] Fingerprint) Write(string target, Guid generation, PermissionEntry entry)
    {
        // JSON is only an exact, transient comparison key, never the stored proof representation.
        var fingerprint = SHA256.HashData(Encoding.UTF8.GetBytes(Key(target, generation, entry)));
        return (EntryId(generation, entry), fingerprint);
    }

    // Two lookups, and both are needed. The session answers for the whole run but only for rows that
    // are committed or in flight in this very transaction. The table answers for a transaction the
    // session never saw, which is how ControlEdgeStorage.Assess and AppendOwnership - each opening
    // their own transaction outside the judging batch - reuse what the object pass already stored.
    private long EntryId(Guid generation, PermissionEntry entry)
    {
        var content = ContentKey(generation, entry);
        var hash = Identity(content);
        if (session.TryGetEntry(hash, out var known)) return known;
        if (statements.Bind("SELECT id FROM permission_entry WHERE entry_hash=$hash", transaction,
            ("$hash", hash)).ExecuteScalar() is long found)
        {
            session.AddEntry(hash, found);
            return found;
        }
        var meaning = Proofs.WriteMeaning(generation, content, entry.Trustee.Meaning);
        const string insert = """
            INSERT INTO permission_entry(generation,entry_hash,ace_type,sid,name,dn,domain,unresolved_reason,role,meaning,
                mask,object_type,inherited_object_type,inherited,inheritance_flags,propagation_flags,has_object_type,has_inherited_object_type,application_data,meaning_binding)
            VALUES ($generation,$hash,$type,$sid,$name,$dn,$domain,$unresolved,$role,$meaning,
                $mask,$object,$inheritedobject,$inherited,$inheritance,$propagation,$hasobject,$hasinheritedobject,$data,$meaningbinding);
            SELECT last_insert_rowid();
            """;
        (string Name, object? Value)[] values =
        [
            ("$generation", generation.ToString("D")), ("$hash", hash), ("$type", entry.AceType),
            ("$sid", entry.Trustee.Sid), ("$name", entry.Trustee.Name), ("$dn", entry.Trustee.DistinguishedName),
            ("$domain", entry.Trustee.DomainFqdn), ("$unresolved", entry.Trustee.UnresolvedReason?.ToString()),
            ("$role", entry.Trustee.WellKnownRole?.ToString()), ("$meaning", meaning.Id), ("$mask", entry.AccessMask),
            ("$object", entry.ObjectTypeGuid), ("$inheritedobject", entry.InheritedObjectTypeGuid), ("$inherited", entry.IsInherited),
            ("$inheritance", (int)entry.InheritanceFlags), ("$propagation", (int)entry.PropagationFlags),
            ("$hasobject", entry.HasObjectType), ("$hasinheritedobject", entry.HasInheritedObjectType), ("$data", entry.ApplicationData),
            ("$meaningbinding", meaning.Fingerprint),
        ];
        var id = Convert.ToInt64(statements.Bind(insert, transaction, values).ExecuteScalar());
        session.AddEntry(hash, id);
        return id;
    }

    // Queries append the occurrence's own ordinal and fingerprint after the checked projection. The
    // ordinal is now the only place the position is recorded, and the fingerprint is what proves it:
    // it covers the target, the generation and the complete entry including that ordinal, so an entry
    // moved to another position, another object or another generation fails here rather than reading
    // back as something the directory never held.
    internal static PermissionEntry Read(SqliteDataReader read, string target, Guid generation)
    {
        if (read.IsDBNull(0) || read.GetString(1) != generation.ToString("D")) throw FullControlEvaluator.InvalidProof();
        var entry = ReadValue(read, generation, read.GetInt32(ProjectionColumns));
        var fingerprint = SHA256.HashData(Encoding.UTF8.GetBytes(Key(target, generation, entry)));
        if (!fingerprint.AsSpan().SequenceEqual((byte[])read.GetValue(ProjectionColumns + 1))) throw FullControlEvaluator.InvalidProof();
        return entry;
    }

    private static PermissionEntry ReadValue(SqliteDataReader read, Guid generation, int ordinal)
    {
        var meaning = Text(read, 10);
        if (read.IsDBNull(20))
        {
            if (meaning is not null || !read.IsDBNull(22)) throw FullControlEvaluator.InvalidProof();
        }
        else if (read.IsDBNull(22) || read.GetInt64(20) != read.GetInt64(22) || meaning is null
            || read.GetString(23) != "Meaning" || read.GetInt32(24) != SharedProofStorage.FormatVersion
            || read.GetString(25) != generation.ToString("D") || !read.IsDBNull(26) || read.GetInt32(27) != 0
            || !SharedProofStorage.ValueFingerprint("Meaning", generation, null, 0, meaning).AsSpan().SequenceEqual((byte[])read.GetValue(28)))
            throw FullControlEvaluator.InvalidProof();
        var entry = new PermissionEntry(ordinal, read.GetString(3),
            new(read.GetString(4), Text(read, 5), Text(read, 6), Text(read, 7),
                Text(read, 8) is { } reason ? Enum.Parse<UnresolvedReferenceReason>(reason) : null,
                Text(read, 9) is { } role ? Enum.Parse<WellKnownSidRole>(role) : null, meaning),
            read.GetInt32(11), Text(read, 12), Text(read, 13), read.GetBoolean(14), checked((byte)read.GetInt32(15)),
            checked((byte)read.GetInt32(16)), read.GetBoolean(17), read.GetBoolean(18), (byte[])read.GetValue(19));
        // Both recomputed from the row that was just read, and they now overlap: the meaning text is
        // inside the content key, so either one alone would catch a tampered column. That overlap is
        // new - the binding named (target, ordinal) before P-279 and did independent work - and both
        // are kept deliberately. The identity is checked because it is what decided which objects
        // share this row, which is the one way two different entries could collapse into one. The
        // binding is kept because it is the store's standard proof that a consumer may point at a
        // shared value, the same shape ControlBinding and FullControlBinding carry.
        var content = ContentKey(generation, entry);
        if (!string.Equals(read.GetString(2), Identity(content), StringComparison.Ordinal)
            || !SharedProofStorage.MeaningBinding(generation, content, meaning).AsSpan()
                .SequenceEqual((byte[])read.GetValue(21))) throw FullControlEvaluator.InvalidProof();
        return entry;
    }

    internal static string ValueKey(PermissionEntry entry) => JsonSerializer.Serialize(entry);

    // The occurrence: what this object carried at this position. Link rows are fingerprinted with it.
    private static string Key(string target, Guid generation, PermissionEntry entry) =>
        JsonSerializer.Serialize(new { Target = target, Generation = generation, Entry = entry });

    // The value: the same entry wherever it was found. The target never enters it and the ordinal is
    // normalised away, so two objects share a row exactly when this agrees. Normalising rather than
    // omitting keeps the key derived from the whole record, so a field added to PermissionEntry
    // cannot silently fall out of the identity.
    private static string ContentKey(Guid generation, PermissionEntry entry) =>
        JsonSerializer.Serialize(new { Generation = generation, Entry = entry with { Ordinal = 0 } });

    private static string Identity(string content) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content)));

    private static string? Text(SqliteDataReader read, int index) => read.IsDBNull(index) ? null : read.GetString(index);
}
