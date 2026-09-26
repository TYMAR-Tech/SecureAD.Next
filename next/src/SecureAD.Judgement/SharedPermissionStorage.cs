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
    // "The complete entry" includes the resolved trustee name, so the object being read reaches the
    // identity after all; see ContentKey, which is the only place that is decided.
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
    /// <param name="boundTo">
    /// Anything else this occurrence must be inseparable from, or empty when there is nothing.
    /// See <see cref="Key"/>: <c>P-283</c> is what it exists for.
    /// </param>
    /// <returns>The shared row to link to, and the fingerprint binding this occurrence to it.</returns>
    internal (long Id, byte[] Fingerprint) Write(
        string target, Guid generation, PermissionEntry entry, ReadOnlySpan<byte> boundTo = default)
    {
        // WHAT IS STORED AND HASHED IS THE SHARED FORM (P-285). PermissionTrustee.Shared strips the
        // one thing in an entry that depends on the object it was found on: S-1-5-10 arrives here
        // rendered as "This object (Alice)" and is put back to the catalogue's own name. Read
        // resolves it forward again from the target it has just verified.
        //
        // The fingerprint therefore covers the target, the generation and the RAW entry rather than
        // the raw entry and a rendering of the target. That is the same binding it always was -
        // (target, generation, ordinal, entry) - with presentation taken out of it, and an entry
        // moved to another position, another object or another generation still fails on read.
        var shared = Shared(entry);

        // JSON is only an exact, transient comparison key, never the stored proof representation.
        var fingerprint = SHA256.HashData(Encoding.UTF8.GetBytes(Key(target, generation, shared, boundTo)));
        return (EntryId(generation, shared), fingerprint);
    }

    /// <summary>The entry as it is shared between objects, with nothing object-dependent in it.</summary>
    private static PermissionEntry Shared(PermissionEntry entry) =>
        entry with { Trustee = entry.Trustee.Shared() };

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
    //
    // THE DISPLAYED NAME IS RESOLVED LAST, AND THAT ORDER IS LOAD-BEARING (P-285). The row holds the
    // shared entry, so S-1-5-10 comes out of it as the catalogue's own name and is rendered against
    // this target on the way out. Doing it here rather than in the row is what lets Alice and Bob
    // share one row without either being shown the other's name - but it has to happen AFTER the
    // fingerprint has established that this target really carried this entry. Resolved before, the
    // name would be taken from a target nothing had yet proved.
    internal static PermissionEntry Read(
        SqliteDataReader read, string target, Guid generation, ReadOnlySpan<byte> boundTo = default)
    {
        if (read.IsDBNull(0) || read.GetString(1) != generation.ToString("D")) throw FullControlEvaluator.InvalidProof();
        var entry = ReadValue(read, generation, read.GetInt32(ProjectionColumns));
        var fingerprint = SHA256.HashData(Encoding.UTF8.GetBytes(Key(target, generation, entry, boundTo)));
        if (!fingerprint.AsSpan().SequenceEqual((byte[])read.GetValue(ProjectionColumns + 1))) throw FullControlEvaluator.InvalidProof();
        return entry with { Trustee = entry.Trustee.DisplayedAgainst(target) };
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

    /// <summary>Reads a shared entry that no single target owns, verifying the row against itself.</summary>
    /// <param name="read">A reader positioned on a row carrying <see cref="Projection"/> then the ordinal.</param>
    /// <param name="generation">The generation being judged.</param>
    /// <returns>The entry in its shared form, with no trustee name resolved against any object.</returns>
    /// <remarks>
    /// <para>
    /// <b>For a row shared between objects, where <see cref="Read"/> cannot apply</b> (<c>P-280</c>).
    /// That overload proves <i>this target carried this entry</i> from a fingerprint over the
    /// target's name; a per-descriptor occurrence has no name on it, because 4,568 objects may
    /// carry the same descriptor. The equivalent proof is
    /// <see cref="DescriptorFingerprint"/>, taken over the whole list once, and the caller checks
    /// it after reading every row.
    /// </para>
    /// <para>
    /// What is still checked here is everything the row can prove about itself: the entry's own
    /// identity hash, and the binding to its resolved meaning. <b>The trustee is left in its shared
    /// form</b> — <c>S-1-5-10</c> comes out as the catalogue's own name — because rendering it
    /// against an object is the caller's to do, and only after the list fingerprint has established
    /// that the object's descriptor really holds these entries.
    /// </para>
    /// </remarks>
    internal static PermissionEntry ReadShared(SqliteDataReader read, Guid generation)
    {
        ArgumentNullException.ThrowIfNull(read);
        if (read.IsDBNull(0) || read.GetString(1) != generation.ToString("D")) throw FullControlEvaluator.InvalidProof();
        return ReadValue(read, generation, read.GetInt32(ProjectionColumns));
    }

    internal static string ValueKey(PermissionEntry entry) => JsonSerializer.Serialize(entry);

    /// <summary>
    /// Binds a descriptor to the complete ordered list of entries it carries.
    /// </summary>
    /// <param name="generation">The generation being judged.</param>
    /// <param name="entries">Every entry the descriptor carries, at the ordinals it carries them.</param>
    /// <returns>The fingerprint the descriptor's own row must hold.</returns>
    /// <remarks>
    /// <para>
    /// <b>The second of <c>P-280</c>'s three bindings</b> — <i>descriptor at ordinal carries entry</i>
    /// — and the replacement for the per-occurrence fingerprint a target-keyed row used to hold.
    /// Once a row is shared between every object carrying that descriptor it has no single name on
    /// it, so the old <c>(target, generation, entry)</c> triple cannot be computed from the row.
    /// </para>
    /// <para>
    /// <b>Taken over the whole list at once, not per row, and the reason is the size of the thing
    /// being fixed.</b> A fingerprint on every occurrence would be 32 bytes across the production
    /// capture's 141,693,937 of them — 4.5 GB, in a change whose entire worth is 6.9 GB. Over the
    /// list it is 267,550 × 32 = 8.5 MB, and it is <i>stronger</i>: it binds the ordinals to each
    /// other, so removing an entry, reordering two or truncating the tail all fail, where a
    /// per-row fingerprint would still verify every row that remained.
    /// </para>
    /// <para>
    /// The ordinal is inside the key because the same entry sits at different positions in
    /// different lists and Windows evaluates a DACL in stored order, adding a deny only for rights
    /// not already granted ([MS-ADTS] 5.1.3.3.2). The entries reach this in their shared form, as
    /// everywhere else in this type.
    /// </para>
    /// </remarks>
    internal static byte[] DescriptorFingerprint(
        Guid generation, IReadOnlyList<PermissionEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        return SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            Generation = generation,
            Entries = entries.Select(Shared),
        })));
    }

    /// <summary>
    /// Binds one distinct entry to the interpretation saved for it.
    /// </summary>
    /// <param name="generation">The generation being judged.</param>
    /// <param name="entry">The entry that was interpreted.</param>
    /// <param name="readingFingerprint">The digest of the reading that explains it.</param>
    /// <param name="rightCount">How many rights the reading names.</param>
    /// <param name="objectSchema">The schema GUID supporting the entry's object type, if any.</param>
    /// <param name="inheritedSchema">The schema GUID supporting its inherited object type, if any.</param>
    /// <returns>The fingerprint the entry's classification row must hold.</returns>
    /// <remarks>
    /// <b>The third of <c>P-280</c>'s three bindings</b>, and the one that was missing outright
    /// until <c>P-283</c>: <c>reading_id</c> could be repointed at another valid reading with every
    /// check still passing, so an allow <c>WRITE_DAC</c> could be made to read as <i>"a deny entry
    /// grants no access"</i> — dangerous reported as harmless, and structural validation accepts it
    /// because the verdict is defined, the reason is non-empty and the rights still sum to the
    /// entry's own mask. <c>P-283</c> folded it into the occurrence fingerprint. Normalisation
    /// moves it here, onto the one row per distinct entry, because that is now where a single wrong
    /// association would reach every occurrence of that entry at once. The ordinal is normalised
    /// away for the same reason it is in <see cref="ContentKey"/>: the interpretation is a fact
    /// about the entry, not about where it sat.
    /// </remarks>
    internal static byte[] ValueFingerprint(Guid generation, PermissionEntry entry,
        ReadOnlySpan<byte> readingFingerprint, int rightCount, string? objectSchema, string? inheritedSchema) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            Content = ContentKey(generation, Shared(entry)),
            Reading = Convert.ToHexString(readingFingerprint),
            RightCount = rightCount,
            ObjectSchema = objectSchema,
            InheritedSchema = inheritedSchema,
        })));

    // The occurrence: what this object carried at this position. Link rows are fingerprinted with it.
    //
    // AND WHATEVER ELSE THE OCCURRENCE MUST BE INSEPARABLE FROM (P-283). A classification link also
    // names the reading that explains the entry, and until this that pointer was bound by nothing:
    // repointing reading_id at another valid reading left every fingerprint matching, so an allow
    // WRITE_DAC could be made to read as "A deny entry grants no access" and classify NotDangerous.
    // Structural validation accepts it, because the verdict is defined, the reason is non-empty, the
    // wording is complete and the rights still sum to the entry's own mask - a deny reading of the
    // same rights satisfies all four. The whole-judgement seal catches an edit made after
    // publication; it does not catch a wrong association written before sealing.
    //
    // Folded into the existing fingerprint rather than given a column of its own, which would have
    // cost 32 bytes on every occurrence - 10.6 GB across the production capture's 330,856,576, in a
    // store P-280 exists to shrink. The 32 bytes already there now do the job they should have done.
    //
    // Empty for control_ace and full_control_source_entry, which name no interpretation.
    private static string Key(
        string target, Guid generation, PermissionEntry entry, ReadOnlySpan<byte> boundTo) =>
        JsonSerializer.Serialize(new
        {
            Target = target,
            Generation = generation,
            Entry = entry,
            BoundTo = boundTo.IsEmpty ? null : Convert.ToHexString(boundTo),
        });

    // The value: the same entry wherever it was found, at whatever position. The ordinal is
    // normalised away, and normalising rather than omitting keeps the key derived from the whole
    // record, so a field added to PermissionEntry cannot silently fall out of the identity.
    //
    // WHAT REACHES THIS IS ALREADY THE SHARED FORM. Write and Read both pass an entry whose trustee
    // has been through PermissionTrustee.Shared, so the one object-dependent thing an entry carries
    // - S-1-5-10 rendered as "This object (Alice)" - is not in the key and two objects carrying the
    // same raw SELF entry now share one row.
    //
    // UNTIL P-285 THEY DID NOT, and the comment here said the target never entered the key at all.
    // It did, through Trustee.Name, and that mistake had two costs. The smaller one was measured:
    // on a real forest 34,593 of 36,484 rows in this table were S-1-5-10 written once per object,
    // so the deduplication P-279 built barely deduplicated. The larger one was that a P-280 design
    // built on the stated contract rather than on the code reached review, and it would have shown
    // one object's name against another object's permission. Nothing shipped ever did, because the
    // name being in the key is precisely what stopped the sharing.
    private static string ContentKey(Guid generation, PermissionEntry entry) =>
        JsonSerializer.Serialize(new { Generation = generation, Entry = entry with { Ordinal = 0 } });

    private static string Identity(string content) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content)));

    private static string? Text(SqliteDataReader read, int index) => read.IsDBNull(index) ? null : read.GetString(index);
}
