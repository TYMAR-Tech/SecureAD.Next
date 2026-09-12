using Microsoft.Data.Sqlite;

namespace SecureAD.Evidence;

/// <summary>
/// What one shard contributed to the bundle it was merged into.
/// </summary>
/// <param name="Trustees">Trustees this shard added that the bundle had not seen.</param>
/// <param name="TrusteesAlreadyPresent">
/// Trustees this shard named that the bundle already held under the same SID, and whose access
/// control entries were therefore pointed at the existing row rather than at a second one.
/// </param>
/// <param name="Descriptors">Security descriptors this shard added.</param>
/// <param name="DescriptorsAlreadyPresent">
/// Descriptors this shard read that were byte-for-byte ones the bundle already held.
/// </param>
/// <param name="AccessControlEntries">Entries copied in, which is entries of new descriptors only.</param>
public sealed record BundleMergeResult(
    int Trustees,
    int TrusteesAlreadyPresent,
    int Descriptors,
    int DescriptorsAlreadyPresent,
    int AccessControlEntries);

/// <summary>
/// Folds a domain's own evidence database into the bundle, without letting two domains' numbering
/// collide.
/// </summary>
/// <remarks>
/// <para>
/// <b>This could not be copied from the predecessor, and the reason is a real difference between
/// the two schemas.</b> The old <c>MergeShardDatabases</c> is four lines of
/// <c>INSERT OR IGNORE INTO ... SELECT * FROM shard....</c>, and it is correct there because that
/// schema keyed on natural values - <c>object_guid</c>, trustee SID strings - so a duplicate row
/// genuinely was a duplicate. <see cref="BundleSchema"/> keys on surrogate integers, so two shards
/// each hand out the same number to different things. Copying the rows would let
/// <c>UNIQUE(sid)</c> drop the second shard's trustee and leave that shard's entries pointing at
/// the first shard's principal: <b>a permission reported against the wrong account</b>, in a bundle
/// that looks perfectly healthy.
/// </para>
/// <para>
/// <b>Only two things are genuinely shared between domains, and both already carry a natural
/// key.</b> A trustee appears in several domains under one SID, and an identical security
/// descriptor hashes to one <c>sha256</c> wherever it is found. Those two are remapped. Everything
/// else - objects, coverage, entries, the per-attribute value tables - is private to its shard and
/// only has to not collide, which <see cref="BundleShard"/> arranges by giving each shard its own
/// range. That matters because the value tables are generated from the captured schema and are not
/// a list anything could hand-maintain.
/// </para>
/// <para>
/// <b>A descriptor the bundle already holds brings no entries with it, and that is not an
/// optimisation.</b> <c>ace</c> is constrained <c>UNIQUE(descriptor_id, ordinal)</c> and
/// <c>security_descriptor_error</c> is keyed the same way, so copying a shared descriptor's entries
/// would fail outright - and a merge that worked around that by ignoring the conflict would be
/// choosing arbitrarily between two rows. It is safe to drop them because the descriptor is
/// identified by the SHA-256 of its own bytes: equal hashes mean equal bytes mean the same entries
/// in the same order. The entries already in the bundle are the same entries.
/// </para>
/// <para>
/// <b>Run-level rows are refused rather than merged.</b> What a shard database ought to contain -
/// whether each parallel reader writes its own <c>bundle</c> row, its own coverage, its own
/// attested exclusions - is decided by how the plan is split into a serial prologue and a parallel
/// domain set, which is not built yet. Guessing here would either duplicate a run's identity or
/// silently drop a domain's coverage, so a shard carrying those rows stops the merge and says so.
/// </para>
/// </remarks>
public static class BundleMerge
{
    /// <summary>
    /// Tables holding facts about the run as a whole rather than about one domain.
    /// </summary>
    /// <remarks>
    /// Refused rather than merged, per the remarks on <see cref="BundleMerge"/>. They are named
    /// here rather than discovered, because the point is to fail on a table nobody has thought
    /// about yet - and a rule derived from the schema would quietly accept whatever was added next.
    /// </remarks>
    private static readonly string[] RunLevelTables =
    [
        "bundle",
        "domain_coverage",
        "excluded_domain",
        "forest_partition_coverage",
        "continuation_reconciliation_item",
        "unread_partition",
    ];

    /// <summary>
    /// Tables whose rows carry only this shard's own identifiers, copied as they stand.
    /// </summary>
    /// <remarks>
    /// In foreign-key order: a partition before the objects read against it, an object before its
    /// attribute values and before anything recording what could not be read about it.
    /// </remarks>
    private static readonly string[] CopiedVerbatim =
    [
        "partition_coverage",
        "continuation_reference",
        "captured_object",
        "unreadable_security_descriptor",
        "unresolved_reference",
        "sysvol_gpo_coverage",
        "gpo_registry_setting",
        "gpo_security_setting",
        "gpo_restricted_group",
        "gpo_stored_credential",
        "gpo_file_error",
        "unreadable_sysvol_descriptor",
    ];

    /// <summary>
    /// Copies everything <paramref name="shardPath"/> read into <paramref name="destination"/>.
    /// </summary>
    /// <param name="destination">An open read-write connection to the bundle being assembled.</param>
    /// <param name="shardPath">The shard database one domain was read into.</param>
    /// <param name="shard">
    /// Which shard this is, so the merge can check the rows carry the identifiers they should.
    /// </param>
    /// <returns>What the shard contributed.</returns>
    public static BundleMergeResult Absorb(
        SqliteConnection destination, string shardPath, BundleShard shard)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentException.ThrowIfNullOrWhiteSpace(shardPath);

        if (!File.Exists(shardPath))
        {
            throw new FileNotFoundException(
                $"The shard database '{shardPath}' is not there, so the domain it read cannot be "
                + "merged. A bundle missing a domain nobody accounted for is refused by "
                + "docs/decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md.",
                shardPath);
        }

        Execute(destination, "ATTACH DATABASE $path AS shard", ("$path", shardPath));

        try
        {
            RefuseRunLevelRows(destination, shardPath);
            RefuseForeignIdentifiers(destination, shardPath, shard);

            BuildMap(
                destination,
                map: "trustee_map",
                table: "trustee",
                key: "trustee_id",
                naturalKey: "sid");

            BuildMap(
                destination,
                map: "descriptor_map",
                table: "security_descriptor",
                key: "descriptor_id",
                naturalKey: "sha256");

            var trustees = CopyNewRows(destination, "trustee", "trustee_id", "trustee_map");
            var descriptors =
                CopyNewRows(destination, "security_descriptor", "descriptor_id", "descriptor_map");

            foreach (var table in CopiedVerbatim)
            {
                CopyVerbatim(destination, table);
            }

            var entries = CopyAccessControlEntries(destination);

            CopyDescriptorErrors(destination);
            CopyDescriptorReferences(
                destination, "object_security_descriptor", "object_id");
            CopyDescriptorReferences(
                destination, "sysvol_path_security_descriptor", "gpo_guid", "relative_path");

            foreach (var table in ValueTables(destination, shardPath))
            {
                CopyVerbatim(destination, table);
            }

            return new BundleMergeResult(
                trustees,
                Count(destination, "SELECT COUNT(*) FROM trustee_map WHERE is_new = 0"),
                descriptors,
                Count(destination, "SELECT COUNT(*) FROM descriptor_map WHERE is_new = 0"),
                entries);
        }
        finally
        {
            Execute(destination, "DROP TABLE IF EXISTS temp.trustee_map");
            Execute(destination, "DROP TABLE IF EXISTS temp.descriptor_map");
            Execute(destination, "DETACH DATABASE shard");
        }
    }

    /// <summary>
    /// Refuses a shard carrying rows about the run rather than about its own domain.
    /// </summary>
    private static void RefuseRunLevelRows(SqliteConnection destination, string shardPath)
    {
        foreach (var table in RunLevelTables)
        {
            if (Count(destination, $"SELECT COUNT(*) FROM shard.{table}") == 0)
                continue;

            throw new InvalidOperationException(
                $"The shard '{shardPath}' carries rows in '{table}', which records a fact about "
                + "the whole run rather than about the one domain this shard read. Merging them "
                + "would either duplicate the run's identity or overwrite another domain's "
                + "account of itself. What a shard database should contain is settled by how the "
                + "capture plan is split into a serial prologue and a parallel domain set, under "
                + "docs/decisions/0041-capture-reads-domains-in-parallel.md, and until that is "
                + "built this merge refuses to guess.");
        }
    }

    /// <summary>
    /// Refuses a shard whose rows carry another shard's identifiers.
    /// </summary>
    /// <remarks>
    /// <b>The last moment this is a crash rather than a wrong answer.</b> A shard numbering outside
    /// its own range has already gone wrong somewhere upstream, and every collision this type
    /// exists to prevent becomes possible again. Checking the two extremes of each keyed table is
    /// enough, because the counters only ever move forwards.
    /// </remarks>
    private static void RefuseForeignIdentifiers(
        SqliteConnection destination, string shardPath, BundleShard shard)
    {
        foreach (var (table, key) in new[]
        {
            ("partition_coverage", "coverage_id"),
            ("captured_object", "object_id"),
            ("security_descriptor", "descriptor_id"),
            ("trustee", "trustee_id"),
            ("ace", "ace_id"),
        })
        {
            using var command = destination.CreateCommand();
            command.CommandText = $"SELECT MIN({key}), MAX({key}) FROM shard.{table}";

            using var reader = command.ExecuteReader();

            if (!reader.Read() || reader.IsDBNull(0))
                continue;

            var lowest = reader.GetInt64(0);
            var highest = reader.GetInt64(1);

            if (shard.Owns(lowest) && shard.Owns(highest))
                continue;

            throw new InvalidOperationException(
                $"The shard '{shardPath}' says it is shard {shard.Index}, which owns identifiers "
                + $"{shard.FirstId} to {shard.LastId}, but '{table}.{key}' runs from {lowest} to "
                + $"{highest}. Merging it would give two domains' rows the same number, and the "
                + "entries of one would end up against the principals of the other.");
        }
    }

    /// <summary>
    /// Works out, for every row of <paramref name="table"/>, which identifier it will have once
    /// merged: its own where the bundle has not seen it, and the bundle's where it has.
    /// </summary>
    /// <remarks>
    /// <b><c>is_new</c> is stored rather than inferred from whether the two identifiers differ.</b>
    /// They are in fact equal exactly when the row is new, because the shard ranges are disjoint -
    /// but resting the decision on that would mean the correctness of every access control entry
    /// depended on a coincidence between two mechanisms, discoverable only by reasoning about both
    /// at once.
    /// </remarks>
    private static void BuildMap(
        SqliteConnection destination, string map, string table, string key, string naturalKey)
    {
        Execute(
            destination,
            $"""
             CREATE TEMP TABLE {map} (
                 old_id INTEGER PRIMARY KEY,
                 new_id INTEGER NOT NULL,
                 is_new INTEGER NOT NULL
             )
             """);

        Execute(
            destination,
            $"""
             INSERT INTO {map} (old_id, new_id, is_new)
             SELECT s.{key},
                    COALESCE(d.{key}, s.{key}),
                    CASE WHEN d.{key} IS NULL THEN 1 ELSE 0 END
             FROM shard.{table} s
             LEFT JOIN main.{table} d ON d.{naturalKey} = s.{naturalKey}
             """);
    }

    /// <summary>Copies the rows of a mapped table the bundle had not already seen.</summary>
    private static int CopyNewRows(
        SqliteConnection destination, string table, string key, string map)
    {
        var columns = string.Join(", ", Columns(destination, table));

        return Execute(
            destination,
            $"""
             INSERT INTO main.{table} ({columns})
             SELECT {string.Join(", ", Columns(destination, table).Select(c => "s." + c))}
             FROM shard.{table} s
             JOIN {map} m ON m.old_id = s.{key} AND m.is_new = 1
             """);
    }

    /// <summary>
    /// Copies the entries of descriptors this shard contributed, pointing each at whichever trustee
    /// row the merged bundle holds for its SID.
    /// </summary>
    /// <remarks>
    /// Entries of a descriptor the bundle already had are deliberately absent; see the remarks on
    /// <see cref="BundleMerge"/> for why they are the same entries.
    /// </remarks>
    private static int CopyAccessControlEntries(SqliteConnection destination) =>
        Execute(
            destination,
            """
            INSERT INTO main.ace (
                ace_id, descriptor_id, ordinal, ace_type, trustee_id, access_mask,
                object_type_guid, inherited_object_type_guid, is_inherited,
                inheritance_flags, propagation_flags, ace_hash)
            SELECT a.ace_id, a.descriptor_id, a.ordinal, a.ace_type, t.new_id, a.access_mask,
                   a.object_type_guid, a.inherited_object_type_guid, a.is_inherited,
                   a.inheritance_flags, a.propagation_flags, a.ace_hash
            FROM shard.ace a
            JOIN descriptor_map d ON d.old_id = a.descriptor_id AND d.is_new = 1
            JOIN trustee_map t ON t.old_id = a.trustee_id
            """);

    /// <summary>Copies parse failures of descriptors this shard contributed.</summary>
    private static void CopyDescriptorErrors(SqliteConnection destination) =>
        Execute(
            destination,
            """
            INSERT INTO main.security_descriptor_error (descriptor_id, ordinal, message)
            SELECT e.descriptor_id, e.ordinal, e.message
            FROM shard.security_descriptor_error e
            JOIN descriptor_map d ON d.old_id = e.descriptor_id AND d.is_new = 1
            """);

    /// <summary>
    /// Copies a table that points at a descriptor, redirecting it to whichever row the merged
    /// bundle holds for those bytes.
    /// </summary>
    private static void CopyDescriptorReferences(
        SqliteConnection destination, string table, params string[] ownColumns)
    {
        var columns = string.Join(", ", [.. ownColumns, "descriptor_id"]);
        var selected = string.Join(", ", [.. ownColumns.Select(c => "s." + c), "d.new_id"]);

        Execute(
            destination,
            $"""
             INSERT INTO main.{table} ({columns})
             SELECT {selected}
             FROM shard.{table} s
             JOIN descriptor_map d ON d.old_id = s.descriptor_id
             """);
    }

    /// <summary>Copies a table whose identifiers are this shard's alone.</summary>
    private static void CopyVerbatim(SqliteConnection destination, string table)
    {
        var columns = string.Join(", ", Columns(destination, table));

        Execute(
            destination,
            $"INSERT INTO main.{table} ({columns}) SELECT {columns} FROM shard.{table}");
    }

    /// <summary>
    /// The tables this merge handles by remapping rather than by copying.
    /// </summary>
    private static readonly string[] Remapped =
    [
        "trustee",
        "security_descriptor",
        "ace",
        "security_descriptor_error",
        "object_security_descriptor",
        "sysvol_path_security_descriptor",
    ];

    /// <summary>
    /// The per-attribute value tables, worked out by elimination rather than by matching a name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Every table in the shard is accounted for, and an unrecognised one stops the merge.</b>
    /// The first draft of this matched <c>LIKE 'value_%'</c> against tables that are in fact named
    /// <c>&lt;attribute&gt;_value</c>, so it matched nothing at all - and because a merge that
    /// copies no attribute values still succeeds and still seals, every multi-valued attribute in
    /// every domain would have been dropped in silence. Group membership is a multi-valued
    /// attribute.
    /// </para>
    /// <para>
    /// Eliminating what is handled and refusing the remainder cannot fail that way. A table added
    /// to <see cref="BundleSchema"/> and forgotten here fails the merge loudly instead of
    /// disappearing from the evidence.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<string> ValueTables(SqliteConnection destination, string shardPath)
    {
        var handled = new HashSet<string>(
            [.. RunLevelTables, .. CopiedVerbatim, .. Remapped],
            StringComparer.OrdinalIgnoreCase);

        var values = new List<string>();
        var unrecognised = new List<string>();

        using var command = destination.CreateCommand();
        command.CommandText =
            """
            SELECT name FROM shard.sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """;

        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                var name = reader.GetString(0);

                if (handled.Contains(name))
                    continue;

                if (name.EndsWith("_value", StringComparison.Ordinal))
                    values.Add(name);
                else
                    unrecognised.Add(name);
            }
        }

        if (unrecognised.Count > 0)
        {
            throw new InvalidOperationException(
                $"The shard '{shardPath}' holds table(s) this merge does not know what to do "
                + $"with: {string.Join(", ", unrecognised)}. Copying them blindly could duplicate "
                + "a run-level fact and skipping them would drop evidence out of the bundle "
                + "without anything saying so, so the merge stops instead. Add them to "
                + "BundleMerge, deliberately.");
        }

        return values;
    }

    /// <summary>The columns of a table, in the order the schema declares them.</summary>
    private static IReadOnlyList<string> Columns(SqliteConnection destination, string table)
    {
        var columns = new List<string>();

        using var command = destination.CreateCommand();
        command.CommandText = $"SELECT name FROM pragma_table_info('{table}')";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            columns.Add(reader.GetString(0));
        }

        return columns;
    }

    private static int Count(SqliteConnection destination, string sql)
    {
        using var command = destination.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt32(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static int Execute(
        SqliteConnection destination, string sql, params (string Name, object Value)[] parameters)
    {
        using var command = destination.CreateCommand();
        command.CommandText = sql;

        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        return command.ExecuteNonQuery();
    }
}
