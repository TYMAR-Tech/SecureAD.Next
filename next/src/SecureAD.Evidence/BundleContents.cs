using System.Globalization;
using Microsoft.Data.Sqlite;
using SecureAD.Kernel;

namespace SecureAD.Evidence;

/// <summary>
/// One table's weight inside a bundle.
/// </summary>
/// <param name="Table">The table measured.</param>
/// <param name="Rows">How many rows it holds.</param>
/// <param name="ContentBytes">
/// The summed length of its rows' values. This is content only: it excludes index pages and
/// per-page overhead, so it under-reports the file and is meant for ranking tables against one
/// another rather than for reconciling to the byte.
/// </param>
public sealed record BundleTableWeight(string Table, long Rows, long ContentBytes);

/// <summary>
/// Why one Group Policy object could not be read in full.
/// </summary>
/// <param name="DisplayName">The policy's name, as the directory gave it.</param>
/// <param name="Outcome">Whether nothing was read, or only part of it.</param>
/// <param name="Reason">
/// What the file system said. Free text, because there is no closed set of reasons a share can
/// refuse a folder, and never invented: a failure arriving without a usable reason says so.
/// </param>
public sealed record UnreadPolicy(string DisplayName, string Outcome, string Reason);

/// <summary>
/// What a sealed bundle actually holds.
/// </summary>
/// <remarks>
/// <para>
/// <b>Written because nothing could answer it.</b> Every size and budget argument about this
/// product had been made against the predecessor's figures - a different application that gathered
/// less - because no sealed run had ever reported its own shape. The first production capture then
/// produced a bundle several times the expected size, and there was no way to ask what was in it
/// short of attaching a database tool to a customer's only copy.
/// </para>
/// <para>
/// <b>It lives here rather than in the command line</b> because the window will want the same
/// numbers, and because the table names it reads are defined in this project: renaming one breaks
/// this build rather than failing at run time against a bundle somebody spent hours capturing.
/// </para>
/// <para>
/// <b>Nothing here writes.</b> The connection is opened immutable, which is what makes it safe to
/// run against a bundle held on a machine with no room for a second copy of it.
/// </para>
/// </remarks>
public sealed record BundleContents
{
    private BundleContents() { }

    /// <summary>Objects captured from the directory.</summary>
    public long Objects { get; private init; }

    /// <summary>
    /// Access control entries across every descriptor, counting each position in each descriptor's
    /// list rather than each row stored.
    /// </summary>
    /// <remarks>
    /// This and <see cref="DistinctEntries"/> were the same number until <c>P-272</c>, because an
    /// entry was stored once per position. They are now a link count and a row count, and the
    /// distance between them is what the storage redesign bought.
    /// </remarks>
    public long AccessControlEntries { get; private init; }

    /// <summary>Group Policy objects the directory declared.</summary>
    public long PoliciesDeclared { get; private init; }

    /// <summary>Group Policy objects whose files were read in full.</summary>
    public long PoliciesRead { get; private init; }

    /// <summary>Distinct trustees named by any entry.</summary>
    public long Trustees { get; private init; }

    /// <summary>Domains the run covered.</summary>
    public long Domains { get; private init; }

    /// <summary>Distinct security descriptors stored.</summary>
    public long DescriptorsStored { get; private init; }

    /// <summary>Objects that reference a stored descriptor.</summary>
    public long DescriptorUses { get; private init; }

    /// <summary>
    /// How many stored entries are distinct from one another.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The question the first production capture raised, and the reason the schema changed.</b>
    /// That bundle held 141,706,338 entries across 271,845 descriptors - 521 apiece, where a typical
    /// directory object carries twenty to fifty - and permissions were 96% of a 51 GB file. Two
    /// explanations fit, and they called for opposite responses: either the forest genuinely carried
    /// access control lists that large, or an inherited entry was being stored once per descendant
    /// rather than once. It was the second, 294 times over, and <c>P-272</c> is the fix.
    /// </para>
    /// <para>
    /// <b>It is now a row count, because a distinct entry is now a row.</b> <c>access_entry</c> is
    /// unique on <c>ace_hash</c>, so the storage and the answer are the same fact and cannot
    /// disagree - which is the point of the change rather than a shortcut in this reader.
    /// <see cref="AccessControlEntries"/> beside it comes from a different table entirely, so the
    /// two can still be compared: two numbers read off one table could never have disagreed, and a
    /// check that cannot fail is the worst kind there is.
    /// </para>
    /// <para>
    /// <b>It was once written as <c>COUNT(DISTINCT ace_hash)</c> over every stored row, and that
    /// measured nothing.</b> Until version 4 the hash mixed in the object's own GUID, so the same
    /// inherited entry on two objects hashed differently and the count returned roughly the row
    /// count however the evidence was stored - a figure that looked like a measurement and was not.
    /// Recorded because the shape of that mistake outlives the line that made it.
    /// </para>
    /// </remarks>
    public long DistinctEntries { get; private init; }

    /// <summary>
    /// How many entries are held for each distinct one, or null when none were stored.
    /// </summary>
    /// <remarks>
    /// The deduplication answer for entries, as <see cref="ReuseFactor"/> is for descriptors. A
    /// figure near 1.0 means each entry really is its own fact; the production capture of
    /// 2026-09-23 measured 294, which is what this storage was redesigned for.
    /// </remarks>
    public double? EntryRepetition => DistinctEntries > 0
        ? (double)AccessControlEntries / DistinctEntries
        : null;

    /// <summary>Descriptors that could not be parsed.</summary>
    public long DescriptorsUnparsed { get; private init; }

    /// <summary>Objects whose permissions could not be read at all.</summary>
    public long PermissionsUnreadable { get; private init; }

    /// <summary>SYSVOL paths whose permissions could not be read.</summary>
    public long SysvolPathsUnreadable { get; private init; }

    /// <summary>Individual policy files that errored.</summary>
    public long PolicyFileErrors { get; private init; }

    /// <summary>Domains that failed outright.</summary>
    public long DomainsFailed { get; private init; }

    /// <summary>The evidence file's size on disk.</summary>
    public long FileBytes { get; private init; }

    /// <summary>
    /// Why each policy went unread, kept raw so a permissions refusal and a vanished folder are
    /// never conflated.
    /// </summary>
    /// <remarks>
    /// <b>Internal, per gate 4.</b> An empty list here cannot say on its own whether every policy
    /// was read or whether nothing ever looked, and a public member handing back an answer that
    /// cannot distinguish those is the one failure an audit tool must not have. The vouched
    /// question is <see cref="PoliciesNotReadInFull"/>, a count against a declared denominator.
    /// </remarks>
    internal IReadOnlyList<UnreadPolicy> UnreadPolicies { get; private init; } = [];

    /// <summary>Per-table weight, empty unless it was asked for.</summary>
    /// <remarks>Internal for the same reason: empty means "not measured", not "nothing there".</remarks>
    internal IReadOnlyList<BundleTableWeight> Weights { get; private init; } = [];

    /// <summary>
    /// How many declared policies were not read in full.
    /// </summary>
    /// <remarks>
    /// The denominator is the point. A run that read 3,275 policies has said nothing until it also
    /// says how many were declared: 3,275 of 3,275 and 3,275 of 3,453 lead an operator to opposite
    /// conclusions about whether his audit is complete.
    /// </remarks>
    public long PoliciesNotReadInFull => PoliciesDeclared - PoliciesRead;

    /// <summary>
    /// Why policies went unread, each reason with how many policies met it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Grouped rather than listed. A hundred and seventy-eight policies refused for one reason is
    /// a single fact about an account's access; the same number printed as separate lines buries
    /// it. The reason is what the file system said and is never invented, so an operator can tell
    /// a refusal he can fix by running as somebody else from a folder that is simply gone.
    /// </para>
    /// <para>
    /// <b>Internal, per gate 4.</b> A bare collection on a public surface cannot say whether it is
    /// empty because every policy was read or because nothing ever looked. The public statement of
    /// that fact is <see cref="PoliciesNotReadInFull"/>, a scalar against a declared denominator,
    /// which cannot be read apart from the count it describes.
    /// </para>
    /// </remarks>
    internal IReadOnlyList<(string Reason, long Policies)> WhyPoliciesWentUnread =>
    [
        .. UnreadPolicies
            .GroupBy(p => string.IsNullOrWhiteSpace(p.Reason) ? "no reason was recorded" : p.Reason,
                StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .Select(g => (g.Key, (long)g.Count())),
    ];

    /// <summary>
    /// Where the bytes went, heaviest first, or null when no measurement was asked for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Null rather than empty, and that is the whole vouching mechanism here.</b> "Nobody
    /// measured" and "there is nothing here" are different answers, and a caller must be able to
    /// tell them apart; a nullable reference says so in the type, which no separate flag can be
    /// out of step with.
    /// </para>
    /// <para>
    /// <b>Internal, per gate 4</b>, for the same reason the reasons above are: a collection on the
    /// public surface would need a companion saying whether it was filled, and gate 4b proved no
    /// such flag on this record can vary, because <see cref="Read"/> is its only constructor.
    /// </para>
    /// </remarks>
    internal IReadOnlyList<BundleTableWeight>? SpaceByTable => Measured ? Weights : null;

    private bool Measured { get; init; }

    /// <summary>
    /// How many objects share each stored descriptor, or null when nothing was stored.
    /// </summary>
    /// <remarks>
    /// The deduplication answer in one number. A descriptor is stored once and referenced, so a
    /// healthy bundle reuses each one many times over; a figure near 1.0 means deduplication is
    /// not happening, which on a forest of any size is most of the file.
    /// </remarks>
    public double? ReuseFactor => DescriptorsStored > 0
        ? (double)DescriptorUses / DescriptorsStored
        : null;

    /// <summary>
    /// Reads a sealed bundle and reports what is in it, without writing to it.
    /// </summary>
    /// <param name="bundleDirectory">The run folder holding the evidence file.</param>
    /// <param name="includeWeights">
    /// Whether to measure per-table weight. This reads every row of every table, so it is a full
    /// pass over the file and is slow on a large bundle; the counts above do not need it.
    /// </param>
    /// <param name="cancellationToken">Cancellation, checked between tables.</param>
    public static Result<BundleContents> Read(
        string bundleDirectory, bool includeWeights, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var evidencePath = BundleLayout.EvidencePath(bundleDirectory);
        if (!File.Exists(evidencePath))
        {
            // A partial file means the capture never finished sealing, and its contents are not
            // evidence. Saying so is not the same as saying the folder is empty: one is a run that
            // stopped, the other is the wrong folder, and an operator acts differently on each.
            return AuditError.Create(
                ErrorCategory.Evidence,
                File.Exists(evidencePath + ".partial") ? "BundleUnsealed" : "BundleAbsent",
                ErrorSeverity.Failed,
                File.Exists(evidencePath + ".partial")
                    ? "This run never finished sealing, so what it holds is not evidence and is not "
                        + "described. A capture that was stopped or that failed leaves the file it "
                        + "was writing behind under a different name."
                    : "There is no evidence file here. Name the run's own folder rather than the "
                        + "library that holds several of them.",
                bundleDirectory);
        }

        using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = BundleReader.ImmutableDataSource(evidencePath),
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());
        connection.Open();

        var description = new BundleContents
        {
            Objects = Count(connection, "captured_object"),

            // Positions, not stored rows. One per entry of every descriptor, which is what a reader
            // of the evidence sees and what the production figure of 141,706,338 counted.
            AccessControlEntries = Count(connection, "descriptor_entry"),
            PoliciesDeclared = Count(connection, "sysvol_gpo_coverage"),
            PoliciesRead = Scalar(connection,
                "SELECT COUNT(*) FROM sysvol_gpo_coverage WHERE outcome = 'Read'"),
            Trustees = Count(connection, "trustee"),
            Domains = Count(connection, "domain_coverage"),
            DescriptorsStored = Count(connection, "security_descriptor"),
            DescriptorUses = Count(connection, "object_security_descriptor"),

            // And the rows actually stored to say all of that. A different table from the line
            // above, which is what makes comparing the two a measurement rather than a tautology.
            DistinctEntries = Count(connection, "access_entry"),
            DescriptorsUnparsed = Count(connection, "security_descriptor_error"),
            PermissionsUnreadable = Count(connection, "unreadable_security_descriptor"),
            SysvolPathsUnreadable = Count(connection, "unreadable_sysvol_descriptor"),
            PolicyFileErrors = Count(connection, "gpo_file_error"),
            DomainsFailed = Count(connection, "domain_capture_failure"),
            FileBytes = new FileInfo(evidencePath).Length,
            UnreadPolicies = ReadUnreadPolicies(connection, cancellationToken),
        };

        return includeWeights
            ? description with { Weights = Weigh(connection, cancellationToken), Measured = true }
            : description;
    }

    private static long Count(SqliteConnection connection, string table) =>
        Scalar(connection, "SELECT COUNT(*) FROM \"" + table + "\"");

    private static long Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    /// <summary>Every policy that was not read in full, with what the file system said.</summary>
    private static List<UnreadPolicy> ReadUnreadPolicies(
        SqliteConnection connection, CancellationToken cancellationToken)
    {
        var unread = new List<UnreadPolicy>();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT display_name, outcome, reason
            FROM sysvol_gpo_coverage
            WHERE outcome <> 'Read'
            ORDER BY outcome, display_name
            """;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            unread.Add(new UnreadPolicy(
                reader.GetString(0),
                reader.GetString(1),
                reader.IsDBNull(2) ? string.Empty : reader.GetString(2)));
        }

        return unread;
    }

    /// <summary>
    /// Sums the content of every table, heaviest first.
    /// </summary>
    /// <remarks>
    /// <b>Not <c>dbstat</c>, and deliberately.</b> The obvious tool for this is the dbstat virtual
    /// table, which attributes every page to its table or index; it is an optional SQLite module
    /// and is absent from the build shipped with Microsoft.Data.Sqlite, so a report built on it
    /// fails outright. Summing value lengths works everywhere. It counts no index pages, so the
    /// gap between this total and the file's size on disk is itself the index and overhead cost.
    /// </remarks>
    private static IReadOnlyList<BundleTableWeight> Weigh(
        SqliteConnection connection, CancellationToken cancellationToken)
    {
        var weights = new List<BundleTableWeight>();
        foreach (var table in Tables(connection))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var columns = Columns(connection, table);
            if (columns.Count == 0)
                continue;

            var sum = string.Join(" + ", columns.Select(c => $"COALESCE(LENGTH(\"{c}\"), 0)"));
            using var command = connection.CreateCommand();
            command.CommandText = $"SELECT COUNT(*), COALESCE(SUM({sum}), 0) FROM \"{table}\"";
            using var reader = command.ExecuteReader();
            if (reader.Read())
                weights.Add(new BundleTableWeight(table, reader.GetInt64(0), reader.GetInt64(1)));
        }

        return [.. weights.OrderByDescending(w => w.ContentBytes)];
    }

    private static List<string> Tables(SqliteConnection connection)
    {
        var tables = new List<string>();
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name";
        using var reader = command.ExecuteReader();
        while (reader.Read())
            tables.Add(reader.GetString(0));
        return tables;
    }

    private static List<string> Columns(SqliteConnection connection, string table)
    {
        var columns = new List<string>();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT name FROM pragma_table_info($table)";
        command.Parameters.AddWithValue("$table", table);
        using var reader = command.ExecuteReader();
        while (reader.Read())
            columns.Add(reader.GetString(0));
        return columns;
    }
}
