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


    // KEYED PER DESCRIPTOR, NOT PER OBJECT (P-280). The classification of an entry is a function of
    // the entry and the run's catalogue, and of nothing about the object carrying it - the review of
    // 2026-09-24 followed the tempting contextual cases (computer creation on the Domain Controllers
    // OU, WRITE_OWNER against OWNER RIGHTS, replication combinations, callback and inherit-only
    // entries, property sets) and found no path from a target property to a verdict. So the
    // occurrence says THIS DESCRIPTOR, AT THIS ORDINAL, CARRIES THAT ENTRY, and objects reach their
    // own rows through the descriptor they carry. On the production capture that is 330,856,576
    // occurrences against 141,693,937 - the whole of the 2.34-to-1 reduction - because 940,067
    // objects share 267,550 descriptors.
    //
    // THREE BINDINGS, AND NONE IS INFERRED FROM THE OTHERS. This is the review's central demand and
    // the reason the table is shaped this way rather than simply narrowed:
    //
    //   1. object -> descriptor comes from ObjectPermissions.DescriptorId, read under the EVIDENCE
    //      seal. descriptor_id is recorded here as well, and Read refuses when the two disagree -
    //      recorded so Complete can still count occurrences per object, never trusted so a judgement
    //      claiming "X uses D2" where evidence says "X uses D1" is a detected contradiction rather
    //      than D2's permissions silently attributed to X. Recording and trusting is the defect the
    //      review named; recording and comparing is a second witness.
    //   2. descriptor -> ordered entries is permission_classification_descriptor.fingerprint, taken
    //      over the whole list at once. Per descriptor rather than per occurrence deliberately: 32
    //      bytes on each of 141,693,937 rows is 4.5 GB, in a change that exists to save 6.9.
    //   3. entry -> interpretation is permission_classification_value.fingerprint. Before P-283 this
    //      was missing entirely and reading_id could be repointed at another valid reading with
    //      every check still passing, so an allow WRITE_DAC could be made to read as "a deny entry
    //      grants no access". P-283 folded it into the occurrence fingerprint; normalisation moves
    //      it here, where one wrong association would otherwise affect every occurrence at once.
    //
    // position IS GONE, and it was never information. Validation requires strictly increasing
    // non-negative ordinals and the writer assigned position from the list index, so it was exactly
    // zero-based rank by ordinal and is recovered by ordering at read. Ordinals may have gaps -
    // ParseAcl advances its counter past an ACE that fails to parse - which is precisely when
    // DaclCompleteness is Incomplete, and rank-at-read is correct either way. Dropping it removes a
    // column and an entire index. Completeness is never inferred from contiguity: a truncated tail
    // leaves a contiguous prefix.
    //
    // WITHOUT ROWID on (descriptor_id, ordinal), so the primary-key b-tree is the table: one stored
    // copy of the key and no separate index, against three copies and two indexes before.
    internal static void CreateTables(SqliteConnection connection) => Execute(connection, null, """
        CREATE TABLE permission_classification_product (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), generation TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('Writing','Complete')),
            producer_version INTEGER NOT NULL, schema_version INTEGER NOT NULL,
            has_captured_schema INTEGER NOT NULL CHECK(has_captured_schema IN (0,1)),
            object_count INTEGER NULL CHECK(object_count>=0));
        CREATE TABLE permission_classification_schema (guid TEXT PRIMARY KEY COLLATE BINARY, payload TEXT NOT NULL);
        CREATE TABLE permission_classification_descriptor (
            descriptor_id INTEGER PRIMARY KEY,
            descriptor TEXT NOT NULL, entry_count INTEGER NOT NULL CHECK(entry_count>=0),
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        CREATE TABLE permission_classification_object (
            target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES control_object(target),
            descriptor_id INTEGER NULL REFERENCES permission_classification_descriptor(descriptor_id),
            availability TEXT NOT NULL, unreadable_reason TEXT NULL);
        CREATE TABLE permission_classification_reading (
            id INTEGER PRIMARY KEY,
            fingerprint BLOB NOT NULL UNIQUE CHECK(length(fingerprint)=32),
            payload TEXT NOT NULL);
        CREATE TABLE permission_classification_value (
            entry_id INTEGER PRIMARY KEY REFERENCES permission_entry(id),
            right_count INTEGER NOT NULL CHECK(right_count>=0),
            reading_id INTEGER NOT NULL REFERENCES permission_classification_reading(id),
            object_schema TEXT NULL REFERENCES permission_classification_schema(guid),
            inherited_schema TEXT NULL REFERENCES permission_classification_schema(guid),
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        CREATE TABLE permission_classification_entry (
            descriptor_id INTEGER NOT NULL REFERENCES permission_classification_descriptor(descriptor_id),
            ordinal INTEGER NOT NULL CHECK(ordinal>=0),
            entry_id INTEGER NOT NULL REFERENCES permission_entry(id),
            PRIMARY KEY(descriptor_id,ordinal)) WITHOUT ROWID;
        """);

    internal static void Start(SqliteConnection connection, Guid generation, bool hasCapturedSchema) =>
        Execute(connection, null, "INSERT INTO permission_classification_product VALUES (1,$generation,'Writing',$producer,$schema,$captured,NULL)",
            ("$generation", generation.ToString("D")), ("$producer", PermissionClassificationProducer.Version),
            ("$schema", SchemaGuidCatalog.Version), ("$captured", hasCapturedSchema));

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, Guid generation,
        PermissionClassification result, PermissionWriteWork work, PreparedStatements statements,
        PermissionWriteSession session, CancellationToken token)
    {
        work.Total.Start();
        token.ThrowIfCancellationRequested();
        work.Validate.Start();
        Validate(result, token);
        work.Validate.Stop();
        var target = result.Permissions.DistinguishedName;
        var descriptorId = result.Permissions.DescriptorId;
        var shared = new SharedPermissionStorage(connection, transaction, statements, session);

        // THE DESCRIPTOR IS WRITTEN BEFORE THE OBJECT THAT POINTS AT IT, because the object row now
        // references it. An object whose descriptor was never stored is not a small inconsistency
        // to be tidied later: it is an object whose permissions cannot be reached at all, and the
        // foreign key is what makes that unwritable rather than merely unlikely.
        if (descriptorId is { } descriptor)
        {
            // THE SECOND AND EVERY LATER OBJECT CARRYING THIS DESCRIPTOR WRITES NO PERMISSIONS. That
            // is the whole of P-280: on the production capture 940,067 objects carry 267,550
            // descriptors, so 71.5% of this work stops at the check below. The fingerprint is
            // recomputed rather than trusted, so a descriptor already stored still has to agree
            // with what this object read.
            var fingerprint = SharedPermissionStorage.DescriptorFingerprint(generation, result.Permissions.Entries);
            if (!Stored(descriptor, fingerprint))
            {
                work.DescriptorRow.Start();
                statements.Bind("INSERT INTO permission_classification_descriptor VALUES ($id,$descriptor,$count,$hash)", transaction,
                    ("$id", descriptor),
                    ("$descriptor", JsonSerializer.Serialize(result.Permissions with
                    {
                        Entries = [], DescriptorId = null, DistinguishedName = null!,
                        Availability = default, UnreadableReason = null,
                    })),
                    ("$count", result.Entries.Count), ("$hash", fingerprint)).ExecuteNonQuery();
                work.DescriptorRow.Stop();

                foreach (var entry in result.Entries)
                {
                    token.ThrowIfCancellationRequested();
                    work.SharedEntry.Start();
                    var entryId = shared.WriteValue(generation, entry.Entry);
                    work.SharedEntry.Stop();

                    work.EntryRow.Start();
                    statements.Bind("INSERT INTO permission_classification_entry VALUES ($descriptor,$ordinal,$entry)",
                        transaction, ("$descriptor", descriptor), ("$ordinal", entry.Entry.Ordinal),
                        ("$entry", entryId)).ExecuteNonQuery();
                    work.EntryRow.Stop();

                    // THE SCHEMA SUPPORT IS VERIFIED FOR EVERY ENTRY, NOT ONLY FOR EACH ENTRY WHOSE
                    // INTERPRETATION IS NEW. Two entries can name one schema GUID and disagree about
                    // what it means, and that disagreement is a fault in the run's catalogue rather
                    // than in either entry - so it has to be caught wherever it appears, not only
                    // the first time a GUID is seen. Cheap: the session answers without a query.
                    work.SchemaSupport.Start();
                    WriteSupport(entry.ObjectType);
                    WriteSupport(entry.InheritedObjectType);
                    work.SchemaSupport.Stop();

                    // THE INTERPRETATION IS WRITTEN ONCE PER DISTINCT ENTRY, NOT ONCE PER OCCURRENCE.
                    // Every column there is a function of the entry and the run's catalogue alone -
                    // right_count, reading_id and both schema GUIDs - which the 2026-09-24 review
                    // confirmed after following the contextual cases that might have made it
                    // otherwise. The two GUIDs are text and cost 14.9 GB on the occurrence.
                    work.ValueRow.Start();
                    WriteValue(entryId, entry);
                    work.ValueRow.Stop();
                    work.Entries++;
                }
                work.Descriptors++;
                session.AddDescriptor(descriptor, fingerprint);
            }
        }
        else if (result.Entries.Count != 0)
        {
            // NO STORED DESCRIPTOR AND YET ENTRIES TO STORE is a contradiction, not a shortfall:
            // the entries came from a descriptor, so there was one.
            throw Invalid();
        }

        work.ObjectRow.Start();

        // THE OBJECT ROW IS NOW SMALL, AND WHAT LEFT IT WENT TO THE DESCRIPTOR (P-280). It held the
        // whole ObjectPermissions record as JSON - owner, DACL state, completeness, canonical order,
        // protected flag and parse errors - every one a property of the DESCRIPTOR, repeated across
        // 940,067 objects where 267,550 would do. Availability and the unreadable reason stay,
        // because those are facts about the READ of this object and not about the descriptor: two
        // objects sharing a descriptor can still differ over whether it was reachable. An object
        // with no descriptor at all still gets this row - 280,871 of the production capture's
        // 940,067 are in that state, and "nobody could read it" must not read back as "it grants
        // nothing", which is the distinction this half of the schema exists to keep.
        statements.Bind("INSERT INTO permission_classification_object VALUES ($target,$descriptor,$availability,$reason)", transaction,
            ("$target", target), ("$descriptor", descriptorId),
            ("$availability", result.Permissions.Availability.ToString()),
            ("$reason", result.Permissions.UnreadableReason)).ExecuteNonQuery();
        work.ObjectRow.Stop();
        work.Objects++;
        work.Total.Stop();

        void WriteValue(long entryId, ClassifiedPermissionEntry entry)
        {
            if (session.HasValue(entryId)) return;
            var reading = ReadingId(entry);
            statements.Bind("INSERT OR IGNORE INTO permission_classification_value VALUES ($entry,$count,$reading,$object,$inherited,$hash)",
                transaction, ("$entry", entryId), ("$count", entry.Rights.Count), ("$reading", reading.Id),
                ("$object", entry.ObjectType?.Guid), ("$inherited", entry.InheritedObjectType?.Guid),
                ("$hash", SharedPermissionStorage.ValueFingerprint(generation, entry.Entry, reading.Fingerprint,
                    entry.Rights.Count, entry.ObjectType?.Guid, entry.InheritedObjectType?.Guid))).ExecuteNonQuery();
            session.AddValue(entryId);
        }

        /// <summary>Whether this descriptor's classification is already stored, and still agrees.</summary>
        /// <remarks>
        /// <b>Two lookups, and both are needed</b>, for the same reason
        /// <see cref="SharedPermissionStorage"/> needs two: the session answers for the whole run
        /// but only for rows committed or in flight in this transaction, and the table answers for
        /// a transaction the session never saw - which is how an on-demand assessment, opening its
        /// own transaction outside the judging batch, meets what the object pass already stored.
        /// Either way the stored fingerprint is <i>compared</i>, never assumed: a descriptor
        /// identity seen before is not on its own a promise that the entries behind it are the same.
        /// Mutation-tested 2026-09-25, and the first attempt found this check measuring nothing —
        /// disabling it left all sixty classification tests passing, because no case had two
        /// objects claim one descriptor while carrying different entries.
        /// <c>P280ADescriptorCannotBeClaimedTwiceWithDifferentEntries</c> was written for it and
        /// fails when it is disabled.
        /// </remarks>
        bool Stored(long descriptor, byte[] fingerprint)
        {
            if (session.TryGetDescriptor(descriptor, out var known))
                return fingerprint.AsSpan().SequenceEqual(known) ? true : throw Invalid();

            if (statements.Bind("SELECT fingerprint FROM permission_classification_descriptor WHERE descriptor_id=$id",
                transaction, ("$id", descriptor)).ExecuteScalar() is not byte[] found) return false;

            if (!fingerprint.AsSpan().SequenceEqual(found)) throw Invalid();
            session.AddDescriptor(descriptor, found);
            return true;
        }

        // ONE ROW PER DISTINCT READING, NOT ONE PER ENTRY. The P-251 comparison found 240 distinct
        // readings behind 209,032 entries; writing each one 871 times was half the result file, and
        // on the laboratory's standard SSD those bytes are what the commits are moving.
        (long Id, byte[] Fingerprint) ReadingId(ClassifiedPermissionEntry entry)
        {
            var payload = JsonSerializer.Serialize(
                new Reading(entry.Summary, entry.RightsAreComplete, entry.Scope, entry.Rights));
            var (fingerprint, key) = PermissionWriteSession.Fingerprint(payload);
            if (session.TryGetReading(key, out var known)) return (known, fingerprint);

            statements.Bind("INSERT OR IGNORE INTO permission_classification_reading(fingerprint,payload) VALUES ($fingerprint,$payload)",
                transaction, ("$fingerprint", fingerprint), ("$payload", payload)).ExecuteNonQuery();
            var found = statements.Bind("SELECT id,payload FROM permission_classification_reading WHERE fingerprint=$fingerprint",
                transaction, ("$fingerprint", fingerprint));
            using var read = found.ExecuteReader();
            // THE STORED PAYLOAD IS COMPARED, NOT ASSUMED. Sharing by digest means a collision would
            // quietly give two different readings one row, and every entry pointing at it would then
            // report a verdict nothing produced.
            // THE STORED PAYLOAD IS COMPARED, NOT ASSUMED. Sharing by digest means a collision would
            // quietly give two different readings one row, and every entry pointing at it would then
            // report a verdict nothing produced. Mutation-tested 2026-09-22: dropping the comparison
            // let the second object adopt another reading's words and
            // P249SharedReadingIsNotAdoptedWhenTheStoredWordsDiffer failed with no exception thrown.
            if (!read.Read() || read.GetString(1) != payload) throw Invalid();
            var id = read.GetInt64(0);
            session.AddReading(key, id);
            return (id, fingerprint);
        }

        void WriteSupport(PermissionSchemaSupport? support)
        {
            if (support is null) return;
            var payload = session.SerializeSchema(support);
            // ONE VERIFICATION PER DISTINCT PAYLOAD PER RUN, NOT TWO PER ENTRY. The check exists to
            // catch a second, conflicting definition arriving under a GUID already stored, and it
            // still does: an identical payload is the case already proved, and anything else falls
            // through to the original write and read-back.
            if (session.TryGetSchema(support.Guid, out var known)
                && string.Equals(known, payload, StringComparison.Ordinal))
                return;

            statements.Bind("INSERT OR IGNORE INTO permission_classification_schema VALUES ($guid,$payload)", transaction,
                ("$guid", support.Guid), ("$payload", payload)).ExecuteNonQuery();
            var check = statements.Bind("SELECT payload FROM permission_classification_schema WHERE guid=$guid COLLATE BINARY",
                transaction, ("$guid", support.Guid));
            if (check.ExecuteScalar() as string != payload) throw Invalid();
            session.AddSchema(support.Guid, payload);
        }
    }

    internal static void Complete(SqliteConnection connection, long objectCount)
    {
        using var command = connection.CreateCommand();
        // Count the indexed occurrences once per descriptor, not again for every object using it.
        // Link integrity is checked separately: an absent joined row must not compare as zero and
        // silently make an object with a dangling descriptor look complete.
        command.CommandText = """
            WITH counts AS MATERIALIZED (
                SELECT descriptor_id, COUNT(*) AS entry_count
                FROM permission_classification_entry GROUP BY descriptor_id
            )
            UPDATE permission_classification_product SET state='Complete',object_count=$count
            WHERE singleton=1 AND state='Writing'
                AND (SELECT COUNT(*) FROM permission_classification_object)=$count
                AND NOT EXISTS (SELECT 1 FROM permission_classification_descriptor d
                    LEFT JOIN counts c ON c.descriptor_id=d.descriptor_id
                    WHERE d.entry_count <> COALESCE(c.entry_count,0))
                AND NOT EXISTS (SELECT 1 FROM permission_classification_object o
                    LEFT JOIN permission_classification_descriptor d ON d.descriptor_id=o.descriptor_id
                    WHERE o.descriptor_id IS NOT NULL AND d.descriptor_id IS NULL)
                AND NOT EXISTS (SELECT 1 FROM counts c
                    LEFT JOIN permission_classification_descriptor d ON d.descriptor_id=c.descriptor_id
                    WHERE d.descriptor_id IS NULL)
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

    /// <summary>Reads one object's saved interpretations, against the descriptor evidence says it carries.</summary>
    /// <param name="connection">The judgement store.</param>
    /// <param name="description">The judgement being read.</param>
    /// <param name="distinguishedName">The object to read.</param>
    /// <param name="carried">
    /// The descriptor the object carries, taken from the sealed evidence, or <c>null</c> when the
    /// evidence kept none for it.
    /// </param>
    /// <param name="token">Cancels the read.</param>
    /// <remarks>
    /// <b>The evidence is a parameter because the judgement is not entitled to answer this</b>
    /// (<c>P-280</c>). Keyed per descriptor, an object reaches its permissions through a descriptor
    /// identity; a judgement claiming <i>X uses D2</i> where the evidence says <i>X uses D1</i>
    /// would validate every fingerprint it holds and attribute D2's permissions to X, because
    /// whoever edited it recomputes them. So the caller brings the answer from the other store and
    /// this refuses any disagreement.
    /// </remarks>
    internal static SavedPermissionClassification Read(SqliteConnection connection, JudgementDescription description,
        string distinguishedName, long? carried, CancellationToken token)
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
        long descriptorId;
        byte[] listFingerprint;
        using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT o.target,o.descriptor_id,o.availability,o.unreadable_reason,d.descriptor,d.entry_count,d.fingerprint
                FROM permission_classification_object o
                LEFT JOIN permission_classification_descriptor d ON d.descriptor_id=o.descriptor_id
                WHERE o.target=$target COLLATE NOCASE
                """;
            command.Parameters.AddWithValue("$target", distinguishedName);
            using var read = command.ExecuteReader();
            if (!read.Read()) throw Invalid();
            target = read.GetString(0);

            // BINDING 1, CHECKED RATHER THAN TAKEN. Recorded here so Complete can count occurrences
            // per object, and compared against the evidence so recording it cannot become trusting
            // it. Disagreement is a refusal, never a silent preference for one store over the other.
            var stored = read.IsDBNull(1) ? (long?)null : read.GetInt64(1);
            if (stored != carried) throw Invalid();

            if (stored is null)
            {
                // NO DESCRIPTOR IS NOT NO PERMISSIONS, and the two must not read back alike.
                // 280,871 of the production capture's 940,067 objects are in this state.
                var absent = new ObjectPermissions(target, Availability(read.GetString(2)),
                    read.IsDBNull(3) ? null : read.GetString(3), Owner: null, DaclState.Unreadable,
                    DaclCompleteness.Unknown, DaclWasCanonical: false, IsDaclProtected: false, [], []);
                var empty = new PermissionClassification(absent, [],
                    PermissionClassificationProducer.Version, SchemaGuidCatalog.Version, captured);
                Validate(empty, token);
                return new(description, empty);
            }

            descriptorId = stored.Value;
            if (read.IsDBNull(4)) throw Invalid();
            permissions = JsonSerializer.Deserialize<ObjectPermissions>(read.GetString(4)) ?? throw Invalid();
            expected = read.GetInt32(5);
            listFingerprint = (byte[])read.GetValue(6);

            // THE DESCRIPTOR ROW IS SHARED, SO IT CARRIES NO NAME AND NO IDENTITY OF ITS OWN. Both
            // are put on from the object being read: the name from the row just matched, the
            // identity from the evidence just verified. A stored name would be one object's name
            // shown against every object sharing the descriptor, which is F-S44 in miniature.
            if (permissions.DistinguishedName is not null || permissions.DescriptorId is not null
                || permissions.Entries is null || permissions.Entries.Count != 0 || expected < 0) throw Invalid();
            permissions = permissions with
            {
                DistinguishedName = target,
                DescriptorId = descriptorId,
                Availability = Availability(read.GetString(2)),
                UnreadableReason = read.IsDBNull(3) ? null : read.GetString(3),
            };
        }
        var entries = new List<ClassifiedPermissionEntry>();
        var supports = new Dictionary<string, PermissionSchemaSupport>(StringComparer.Ordinal);
        var raw = new List<PermissionEntry>();
        using (var command = connection.CreateCommand())
        {
            // ORDERED BY ORDINAL, WHICH IS WHAT position USED TO RECORD. Validation requires
            // strictly increasing ordinals and the writer assigned position from the list index, so
            // rank by ordinal is exactly what it held. Gaps are kept: they are the directory's own
            // ordinals and DaclCompleteness, not contiguity, is what says whether any are missing.
            //
            // The value table is aliased c rather than v: MeaningJoin already binds v, and SQLite
            // reports a duplicate alias only when a column name happens to exist on both sides.
            command.CommandText = "SELECT " + SharedPermissionStorage.Projection + ",e.ordinal,c.right_count,r.payload,c.object_schema,c.inherited_schema,r.fingerprint,c.fingerprint"
                + " FROM permission_classification_entry e LEFT JOIN permission_entry p ON p.id=e.entry_id"
                + " LEFT JOIN permission_classification_value c ON c.entry_id=e.entry_id"
                + " LEFT JOIN permission_classification_reading r ON r.id=c.reading_id"
                + SharedPermissionStorage.MeaningJoin + " WHERE e.descriptor_id=$descriptor ORDER BY e.ordinal";
            command.Parameters.AddWithValue("$descriptor", descriptorId);
            using var read = command.ExecuteReader();
            while (read.Read())
            {
                token.ThrowIfCancellationRequested();
                const int offset = SharedPermissionStorage.ProjectionColumns + 1;
                if (read.IsDBNull(offset) || read.IsDBNull(offset + 1)) throw Invalid();
                var payload = read.GetString(offset + 1);

                // THE READING IS VERIFIED BEFORE IT IS USED TO VERIFY ANYTHING ELSE. Its own digest
                // is checked here, and only then does it enter the value fingerprint below - a
                // value that has not been proved cannot be evidence that something else is sound.
                //
                // A SHARED ROW IS READ BY EVERY ENTRY POINTING AT IT, so a single damaged payload
                // would misreport hundreds of entries rather than one. Mutation-tested 2026-09-22:
                // disabling this check let a tampered summary through and
                // P249SharedReadingRefusesATamperedPayload failed with no exception thrown.
                var readingFingerprint = (byte[])read.GetValue(offset + 4);
                if (!PermissionWriteSession.Fingerprint(payload).Bytes.AsSpan()
                        .SequenceEqual(readingFingerprint)) throw Invalid();

                PermissionEntry entry;
                try { entry = SharedPermissionStorage.ReadShared(read, description.GenerationId); }
                catch (InvalidOperationException error) { throw new InvalidDataException(Message("Invalid"), error); }
                raw.Add(entry);

                var rightCount = read.GetInt32(offset);
                var objectSchema = read.IsDBNull(offset + 2) ? null : read.GetString(offset + 2);
                var inheritedSchema = read.IsDBNull(offset + 3) ? null : read.GetString(offset + 3);

                // BINDING 3. Without it reading_id can be repointed at another valid reading and
                // every other check still passes, so an allow WRITE_DAC reads as "a deny entry
                // grants no access" - dangerous reported as harmless, and structural validation
                // accepts it because the verdict is defined, the reason is non-empty and the rights
                // still sum to the mask. Mutation-tested 2026-09-25: disabled, the repointed
                // reading was read back with no exception thrown.
                if (!SharedPermissionStorage.ValueFingerprint(description.GenerationId, entry, readingFingerprint,
                        rightCount, objectSchema, inheritedSchema).AsSpan()
                    .SequenceEqual((byte[])read.GetValue(offset + 5))) throw Invalid();

                var reading = JsonSerializer.Deserialize<Reading>(payload) ?? throw Invalid();
                if (reading.Rights is null || reading.Rights.Count != rightCount) throw Invalid();
                entries.Add(new(entry.DisplayedAgainst(target), reading.Summary, reading.RightsAreComplete,
                    reading.Scope, reading.Rights, ReadSupport(objectSchema), ReadSupport(inheritedSchema)));
            }
        }
        if (entries.Count != expected) throw Invalid();

        // BINDING 2, OVER THE WHOLE LIST AT ONCE. Per-row fingerprints would verify each surviving
        // row after an entry was removed or two were reordered; this does not, because the list is
        // hashed as a list. Computed from the shared form, as it was written.
        //
        // Mutation-tested 2026-09-25 with the entry count check disabled beside it, so the count
        // could not stand in for it: removing an entry and reordering two both read back as valid
        // shorter or rearranged DACLs with no exception thrown.
        if (!SharedPermissionStorage.DescriptorFingerprint(description.GenerationId, raw).AsSpan()
                .SequenceEqual(listFingerprint)) throw Invalid();

        var result = new PermissionClassification(permissions with { Entries = [.. entries.Select(value => value.Entry)] },
            entries, PermissionClassificationProducer.Version, SchemaGuidCatalog.Version, captured);
        Validate(result, token);
        token.ThrowIfCancellationRequested();
        return new(description, result);

        static DescriptorAvailability Availability(string value) =>
            Enum.TryParse<DescriptorAvailability>(value, out var parsed) ? parsed : throw Invalid();

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
                || !ReferenceEquals(value.Entry, permissions.Entries[index])
                    && SharedPermissionStorage.ValueKey(value.Entry) != SharedPermissionStorage.ValueKey(permissions.Entries[index])) throw Invalid();
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
