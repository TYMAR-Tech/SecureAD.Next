using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Inventory;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Evidence;

/// <summary>
/// The one way a bundle gets written.
/// </summary>
/// <remarks>
/// <para>
/// <b>It is handed a directory and writes there.</b> Where that directory comes from is not its
/// business and not the caller's choice: per <c>docs/decisions/0025</c> the tool owns a configured
/// root and creates each run inside it. Re-analysis derives into a new bundle from a sealed one per
/// <c>docs/decisions/0021</c>. These remarks previously re-argued both points from a session note
/// that <c>0025</c> had already overruled, which is how the stale claim reached the code.
/// </para>
/// <para>
/// <b>One connection, held for the run, never shared.</b> That is not a simplification, it is what
/// SQLite is: only one transaction may have changes pending at a time, and the .NET objects are
/// not thread-safe, so a second writer buys contention and nothing else.
/// </para>
/// <para>
/// <b>Every method here is synchronous, deliberately.</b> SQLite has no asynchronous I/O and the
/// async ADO.NET methods run synchronously, so an <c>async</c> surface would await nothing and
/// mislead every caller about what it costs.
/// </para>
/// <para>
/// <b>It is fail-fast.</b> There is no partial bundle, so a value that cannot be written down ends
/// the run rather than being logged and skipped. That is not the same as refusing bad news from
/// the forest: a security descriptor the forest holds and this product could not parse is a fact
/// about the customer's directory and is stored, errors and all. A value <i>this product</i>
/// cannot represent is a defect in this product. Conflating the two is how a real finding about a
/// real domain gets thrown away as a bug in the reader.
/// </para>
/// </remarks>
public sealed class BundleWriter : IDisposable
{
    /// <summary>
    /// The single-valued attributes, by name, so an object's attributes can be matched to columns
    /// without searching the catalogue once per attribute per object.
    /// </summary>
    /// <remarks>
    /// Keyed without regard to case, because an LDAP display name is.
    /// </remarks>
    private const int ObjectAttributeParameterOffset = 8;
    private static readonly Dictionary<string, (CapturedAttribute Attribute, int ParameterIndex)> SingleValuedColumns =
        BundleSchema.SingleValuedColumns
            .Select((attribute, index) => (Attribute: attribute, ParameterIndex: index + ObjectAttributeParameterOffset))
            .ToDictionary(a => a.Attribute.LdapDisplayName, StringComparer.OrdinalIgnoreCase);

    // One shape for every object, including omitted attributes. Rebuilding sparse INSERTs per
    // object would retain an unbounded set of statements as attribute combinations change.
    private static readonly string ObjectInsertSql =
        "INSERT INTO captured_object "
        + "(object_id, coverage_id, object_guid, distinguished_name, dn_reversed, "
        + "parent_dn, parent_guid, domain_fqdn, captured_utc, ace_count"
        + string.Concat(BundleSchema.SingleValuedColumns.Select(a => ", " + BundleSchema.ColumnNameFor(a.LdapDisplayName)))
        + ") VALUES ($id, $coverage, $guid, $dn, $dnReversed, $parentDn, NULL, $domain, $captured, NULL"
        + string.Concat(SingleValuedColumns.Values.Select(a => $", $a{a.ParameterIndex}")) + ")";

    private static readonly string[] ObjectInsertParameters =
    [
        "$id", "$coverage", "$guid", "$dn", "$dnReversed", "$parentDn", "$domain", "$captured",
        .. SingleValuedColumns.Values.Select(a => $"$a{a.ParameterIndex}"),
    ];

    private static readonly Dictionary<string, CapturedAttribute> MultiValuedTables =
        BundleSchema.MultiValuedTables.ToDictionary(
            a => a.LdapDisplayName, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The attributes already written as identity columns, which arrive on an object like any
    /// other and are not written twice.
    /// </summary>
    private static readonly HashSet<string> StructurallyStored =
        new(BundleSchema.StructurallyStoredAttributes, StringComparer.OrdinalIgnoreCase);

    private readonly string _bundleDirectory;
    private readonly string _partialPath;
    private readonly SqliteConnection _connection;
    private readonly Dictionary<string, long> _trustees = new(StringComparer.Ordinal);
    private readonly Dictionary<(string NamingContextDn, string Controller), long> _coverageIds = [];

    private readonly List<SqliteCommand> _insertCommands = [];
    private readonly Dictionary<string, SqliteCommand> _attributeInserts = new(StringComparer.OrdinalIgnoreCase);
    private SqliteCommand? _objectInsert;
    private SqliteCommand? _descriptorInsert;
    private SqliteCommand? _descriptorLinkInsert;
    private SqliteCommand? _entryInsert;
    private SqliteCommand? _entryLinkInsert;
    private SqliteCommand? _trusteeInsert;

    /// <summary>
    /// Distinct descriptors already stored, by the hexadecimal SHA-256 of their bytes. This is what
    /// makes the deduplication O(1) per object rather than a query per object.
    /// </summary>
    private readonly Dictionary<string, long> _descriptors = new(StringComparer.Ordinal);

    /// <summary>
    /// Distinct access control entries already stored, by <c>ace_hash</c>.
    /// </summary>
    /// <remarks>
    /// <b>The largest thing this writer keeps in memory, and much the smallest of the two it could
    /// have kept.</b> The production capture of 2026-09-23 held 481,967 distinct entries against
    /// 141,706,338 stored rows, so this dictionary is the size of the former and saves the latter.
    /// It grows with what a forest actually says rather than with how many objects say it.
    /// </remarks>
    private readonly Dictionary<string, long> _entries = new(StringComparer.Ordinal);

    /// <summary>The partition each object was written against, so an unreadable descriptor can be counted against it.</summary>
    private readonly Dictionary<long, long> _objectCoverage = [];

    /// <summary>Objects per partition whose descriptor could not be read, written out in <see cref="Complete"/>.</summary>
    private readonly Dictionary<long, int> _unreadableDescriptors = [];
    private readonly Dictionary<long, Guid> _objectGuids = [];
    private readonly DateTimeOffset _startedUtc;
    private readonly Guid _captureGeneration = Guid.NewGuid();

    private SqliteTransaction? _transaction;
    private long _nextObjectId;
    private long _nextCoverageId;
    private long _nextDescriptorId;
    private long _nextTrusteeId;
    private long _nextEntryId;
    private bool _completed;
    private bool _disposed;
    private AttemptCheckpoint? _attempt;

    private sealed record AttemptCheckpoint(
        long ObjectId,
        long CoverageId,
        long DescriptorId,
        long TrusteeId,
        long EntryId);

    private BundleWriter(
        string bundleDirectory,
        string partialPath,
        SqliteConnection connection,
        DateTimeOffset startedUtc,
        BundleShard shard)
    {
        _bundleDirectory = bundleDirectory;
        _partialPath = partialPath;
        _connection = connection;
        _startedUtc = startedUtc;
        Shard = shard;

        // EVERY SURROGATE KEY STARTS AT THIS SHARD'S FLOOR, which for an unsharded run is 1 and so
        // is exactly what the product wrote before shards existed. The five counters move together
        // because all five are keys the merge would otherwise have to reconcile, and a counter left
        // at 1 while its neighbours were seeded would collide in precisely one table - the hardest
        // possible version of this defect to find.
        //
        // WHICH IS WHAT HAPPENED. ace_id was missing from this list until 2026-09-13, and the
        // sentence above was already warning about it: entries were the one table left numbering
        // from 1 in every shard. It was never spotted by reading, because ace_id is the only one of
        // the five the writer did not name in its INSERT - SQLite assigned it - so it was invisible
        // at the point the other four are obviously being set. The first run of the merge tests
        // caught it immediately, which is the argument for those tests existing at all. The table
        // is access_entry now and the counter is named for it, but the trap is the same one.
        _nextObjectId = shard.FirstId;
        _nextCoverageId = shard.FirstId;
        _nextDescriptorId = shard.FirstId;
        _nextTrusteeId = shard.FirstId;
        _nextEntryId = shard.FirstId;
    }

    /// <summary>Which of a run's parallel readers wrote this, and therefore which identifiers it owns.</summary>
    public BundleShard Shard { get; }

    /// <summary>
    /// Creates a bundle in <paramref name="bundleDirectory"/> and opens it for writing.
    /// </summary>
    /// <remarks>
    /// Writing goes to <c>evidence.db.partial</c>. It is given the name a reader asks for only by
    /// <see cref="Complete"/>, after the write-ahead log has been folded back in and the seal
    /// written - so an interrupted run leaves nothing a reader can open.
    /// </remarks>
    /// <param name="bundleDirectory">The directory the operator named. Created if absent.</param>
    /// <param name="startedUtc">When the run started.</param>
    /// <param name="shard">
    /// Which of a run's parallel readers this is. Omitted means <see cref="BundleShard.Whole"/> -
    /// one writer for the whole bundle, numbering from 1 as the product always has.
    /// </param>
    public static BundleWriter Create(
        string bundleDirectory, DateTimeOffset startedUtc, BundleShard shard = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        Directory.CreateDirectory(bundleDirectory);

        var evidencePath = BundleLayout.EvidencePath(bundleDirectory);
        if (File.Exists(evidencePath))
        {
            throw new InvalidOperationException(
                $"'{evidencePath}' already exists. A bundle is sealed evidence of one forest at "
                + "one moment and is never written over; capture to a new directory.");
        }

        // A shard writes its own file; only the whole bundle writes the partial one. Sharing the
        // partial path would be the defect the shard ranges exist to prevent, arriving one layer
        // earlier and more bluntly: nine writers appending to one SQLite file, each holding the
        // single write lock the others are waiting for.
        var partialPath = shard.Index == BundleShard.Whole.Index
            ? BundleLayout.PartialPath(bundleDirectory)
            : BundleLayout.ShardPath(bundleDirectory, shard);

        if (File.Exists(partialPath))
            File.Delete(partialPath);

        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = partialPath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Pooling = false,
                ForeignKeys = true,
            }.ToString());

        connection.Open();

        // page_size comes first and cannot be moved. SQLite fixes it when the first table is
        // created, and after that only a full VACUUM can change it - which a sealed bundle will
        // never get. Setting it after CreateTables would therefore be a line that reads as
        // configuration and does nothing.
        //
        // It is also before journal_mode, because the page size cannot be changed once the
        // database is in write-ahead logging mode.
        //
        // 8192 rather than the 4096 default. Descriptors on a production domain averaged 31,742
        // bytes (F-S20-17), which no supported page size holds inline, so the question is only how
        // long the overflow chain is: doubling the page halves it. It is not raised further because
        // the bundle is not mostly descriptors - `ace`, `trustee` and `captured_object` are small
        // rows and there are millions of them, and a 32 KB page would make every one of those reads
        // fetch far more than it needs to serve the minority that are large.
        Pragma(connection, "page_size = 8192");

        // Write-ahead logging rather than async, which is what the guidance for this provider says
        // to reach for: SQLite has no asynchronous I/O. It costs the checkpoint in Complete().
        Pragma(connection, "journal_mode = WAL");
        Pragma(connection, "synchronous = NORMAL");

        BundleSchema.CreateTables(connection);

        var writer = new BundleWriter(bundleDirectory, partialPath, connection, startedUtc, shard);
        writer._transaction = connection.BeginTransaction();
        return writer;
    }

    /// <summary>
    /// Reserves the handle every object read from one naming context is written against, before
    /// the pass that reads it has finished.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why a partition is opened before it is described.</b> An object may not be written until
    /// the partition it came from has a row - coverage is what an absence is interpreted against,
    /// so an object filed under the wrong one silently changes what its neighbours' absence means.
    /// But a capture pass hands objects on one at a time as it reads them, and only knows what it
    /// read once it has read all of it. The two cannot both be satisfied by writing coverage first
    /// unless a partition's objects are held in memory until the pass ends, and a forest partition
    /// is millions of objects.
    /// </para>
    /// <para>
    /// So the row is created from what is known before the first request - which partition, which
    /// controller, how well protected the connection turned out to be - and its counts are filled
    /// in by <see cref="CompletePartition"/>. Until then it reads
    /// <c>continuation_references_are_complete = 0</c> and zero
    /// of everything, which is the truth about a pass that has not finished.
    /// </para>
    /// <para>
    /// <b>What stops a reserved row being read as a finished one.</b> Nothing in this file, and it
    /// does not need to be: a run that does not finish never calls <see cref="Complete"/>, so the
    /// database is never given the name a reader opens and there is no bundle to misread. The
    /// guarantee is the same one that stops a half-written bundle being analysed, and it is
    /// enforced by <see cref="BundleLayout"/> rather than by anybody remembering to check.
    /// </para>
    /// </remarks>
    /// <param name="namingContextDn">The partition root, as the controller reported it.</param>
    /// <param name="kind">Which kind of partition it is.</param>
    /// <param name="controller">The host it is being read from.</param>
    /// <param name="connectionSecurity">The rung the connection to that host reached.</param>
    public long BeginPartition(
        string namingContextDn,
        NamingContextKind kind,
        string controller,
        ConnectionSecurityLevel connectionSecurity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(namingContextDn);
        ArgumentException.ThrowIfNullOrWhiteSpace(controller);
        ThrowIfFinished();

        if (_attempt is not null)
            throw new InvalidOperationException("A partition attempt is already open.");

        var key = (namingContextDn, controller);
        if (_coverageIds.ContainsKey(key))
        {
            throw new InvalidOperationException(
                $"'{namingContextDn}' on '{controller}' has already been opened. One pass reads "
                + "one partition on one controller, and a second row for the same pair would be a "
                + "second account of what was read.");
        }

        var checkpoint = new AttemptCheckpoint(
            _nextObjectId, _nextCoverageId, _nextDescriptorId, _nextTrusteeId, _nextEntryId);
        Execute("SAVEPOINT partition_attempt");
        _attempt = checkpoint;

        var coverageId = _nextCoverageId++;

        Execute(
            """
            INSERT INTO partition_coverage (
                coverage_id, naming_context_dn, naming_context_kind, controller,
                connection_security, pages_read, objects_read, attribute_blocks_fetched,
                referrals_suppressed, continuation_references_are_complete)
            VALUES ($id, $dn, $kind, $dc, $security, 0, 0, 0, 0, 0)
            """,
            command =>
            {
                command.Parameters.AddWithValue("$id", coverageId);
                command.Parameters.AddWithValue("$dn", namingContextDn);
                command.Parameters.AddWithValue("$kind", kind.ToString());
                command.Parameters.AddWithValue("$dc", controller);
                command.Parameters.AddWithValue("$security", connectionSecurity.ToString());
            });

        _coverageIds[key] = coverageId;

        return coverageId;
    }

    /// <summary>
    /// Records what a pass actually read, against the row <see cref="BeginPartition"/> reserved.
    /// </summary>
    /// <remarks>
    /// The claim is still made by <see cref="PartitionCoverage"/>, which only the capture loop can
    /// construct and only at the moment it is true. What changed is when the row gets its identity,
    /// not who is entitled to say the partition was read.
    /// </remarks>
    /// <param name="coverage">What the pass read.</param>
    public void CompletePartition(PartitionCoverage coverage)
    {
        ArgumentNullException.ThrowIfNull(coverage);
        ThrowIfFinished();

        var coverageId = CoverageIdFor(coverage);

        Execute(
            """
            UPDATE partition_coverage
            SET pages_read = $pages,
                objects_read = $objects,
                attribute_blocks_fetched = $blocks,
                referrals_suppressed = $suppressed,
                continuation_references_are_complete = $complete
            WHERE coverage_id = $id
            """,
            command =>
            {
                command.Parameters.AddWithValue("$id", coverageId);
                command.Parameters.AddWithValue("$pages", coverage.PagesRead);
                command.Parameters.AddWithValue("$objects", coverage.ObjectsRead);
                command.Parameters.AddWithValue("$blocks", coverage.AttributeBlocksFetched);
                command.Parameters.AddWithValue("$suppressed", coverage.ReferralsSuppressed ? 1 : 0);
                command.Parameters.AddWithValue(
                    "$complete", coverage.ContinuationReferencesAreComplete ? 1 : 0);
            });

        for (var ordinal = 0; ordinal < coverage.ContinuationReferences.Count; ordinal++)
        {
            var referral = coverage.ContinuationReferences[ordinal];
            Execute(
                "INSERT INTO continuation_reference (coverage_id, ordinal, referral) "
                + "VALUES ($id, $ordinal, $referral)",
                command =>
                {
                    command.Parameters.AddWithValue("$id", coverageId);
                    command.Parameters.AddWithValue("$ordinal", ordinal);
                    command.Parameters.AddWithValue("$referral", referral);
                });
        }

        Execute("RELEASE SAVEPOINT partition_attempt");
        _attempt = null;
    }

    /// <summary>Rolls back every durable and cached value allocated by the open partition attempt.</summary>
    public void AbortPartition()
    {
        ThrowIfFinished();

        if (_attempt is not { } checkpoint)
            throw new InvalidOperationException("There is no partition attempt to abort.");

        try
        {
            Execute("ROLLBACK TO SAVEPOINT partition_attempt");
            Execute("RELEASE SAVEPOINT partition_attempt");
        }
        finally
        {
            RemoveValuesAllocatedAtOrAfter(_coverageIds, checkpoint.CoverageId);
            RemoveValuesAllocatedAtOrAfter(_descriptors, checkpoint.DescriptorId);
            RemoveValuesAllocatedAtOrAfter(_entries, checkpoint.EntryId);
            RemoveValuesAllocatedAtOrAfter(_trustees, checkpoint.TrusteeId);
            RemoveKeysAllocatedAtOrAfter(_objectCoverage, checkpoint.ObjectId);
            RemoveKeysAllocatedAtOrAfter(_objectGuids, checkpoint.ObjectId);
            RemoveKeysAllocatedAtOrAfter(_unreadableDescriptors, checkpoint.CoverageId);

            _nextObjectId = checkpoint.ObjectId;
            _nextCoverageId = checkpoint.CoverageId;
            _nextDescriptorId = checkpoint.DescriptorId;
            _nextTrusteeId = checkpoint.TrusteeId;

            // Rolled back with the rest, and it has to be. SQLite assigned the entry identifier
            // until 2026-09-13, and its implicit counter is max(rowid) + 1 - so a restart reused the
            // numbers the abandoned attempt had taken. An explicit counter that kept climbing would
            // leave gaps where there were none, changing the bytes of an unsharded bundle that the
            // frozen golden hashes cover. Editing one of those is a finding, not a fix.
            //
            // THE CACHE HAS TO GO BACK WITH IT, which is new and is why it is named above. An entry
            // remembered here but rolled back out of the table would be handed out again as the
            // identifier of a row that no longer exists, and every descriptor linking to it would
            // point at nothing - or worse, at whatever later took the number.
            _nextEntryId = checkpoint.EntryId;
            _attempt = null;
        }
    }

    /// <summary>
    /// Records a partition the forest declares that this run does not read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The application directory partitions - in practice the DNS zone partitions every forest has.
    /// The DNS scope decision of 2026-08-11 puts DNS zones and records out of scope, and this is the
    /// evidence saying so. Until <c>F-S31-5</c> the fact reached the operator's console and nothing
    /// else, so a reader opening the bundle afterwards could not tell a forest whose DNS partitions
    /// were skipped from a forest that has none.
    /// </para>
    /// <para>
    /// Separate from <see cref="PartitionCoverage"/> deliberately. That records what a capture unit
    /// read, and nothing here was read: there is no controller, no page count and no connection
    /// rung to record, and a row claiming otherwise would be a second kind of thing hidden in a
    /// table that means one.
    /// </para>
    /// </remarks>
    /// <param name="namingContextDn">The partition root, as the forest's cross-reference gave it.</param>
    /// <exception cref="ArgumentException">The naming context is absent.</exception>
    public void RecordUnreadPartition(string namingContextDn)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(namingContextDn);
        ThrowIfFinished();

        Execute(
            "INSERT INTO unread_partition (naming_context_dn) VALUES ($dn)",
            command => command.Parameters.AddWithValue("$dn", namingContextDn));
    }

    /// <summary>Records 0040's controller failure history outside discarded attempt evidence.</summary>
    /// <param name="failure">The failed controller attempt, in domain-local attempt order.</param>
    public void RecordDomainCaptureFailure(DomainCaptureFailure failure)
    {
        ArgumentNullException.ThrowIfNull(failure);
        ArgumentNullException.ThrowIfNull(failure.Error);
        ThrowIfFinished();

        Execute(
            """
            INSERT INTO domain_capture_failure (
                naming_context_dn, controller, attempt, started_utc, failed_utc,
                error_category, error_code, error_severity, error_description, error_context)
            VALUES ($dn, $controller, $attempt, $started, $failed,
                    $category, $code, $severity, $description, $context)
            """,
            command =>
            {
                command.Parameters.AddWithValue("$dn", failure.NamingContextDn);
                command.Parameters.AddWithValue("$controller", failure.Controller);
                command.Parameters.AddWithValue("$attempt", failure.Attempt);
                command.Parameters.AddWithValue("$started", failure.StartedUtc.ToString("O", CultureInfo.InvariantCulture));
                command.Parameters.AddWithValue("$failed", failure.FailedUtc.ToString("O", CultureInfo.InvariantCulture));
                command.Parameters.AddWithValue("$category", failure.Error.Category.ToString());
                command.Parameters.AddWithValue("$code", failure.Error.Code);
                command.Parameters.AddWithValue("$severity", failure.Error.Severity.ToString());
                command.Parameters.AddWithValue("$description", failure.Error.Description);
                command.Parameters.AddWithValue("$context", (object?)failure.Error.Context ?? DBNull.Value);
            });
    }

    private static void RemoveValuesAllocatedAtOrAfter<TKey>(
        Dictionary<TKey, long> values, long firstAllocated)
        where TKey : notnull
    {
        foreach (var key in values.Where(pair => pair.Value >= firstAllocated).Select(pair => pair.Key).ToArray())
            values.Remove(key);
    }

    private static void RemoveKeysAllocatedAtOrAfter<TValue>(
        Dictionary<long, TValue> values, long firstAllocated)
    {
        foreach (var key in values.Keys.Where(key => key >= firstAllocated).ToArray())
            values.Remove(key);
    }

    /// <summary>
    /// Records what an operator stated when a domain was left out of this run.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The whole attestation, per
    /// <c>docs/decisions/0062-what-an-exclusion-attestation-asks-for.md</c>: the reason, the free
    /// text, both names and the time. An exclusion that governed a run but was not stored with it
    /// is a fact about the audit that the audit does not carry.
    /// </para>
    /// <para>
    /// Separate from <see cref="RecordUnreadPartition"/> and from domain coverage, and for the same
    /// reason those two are separate from each other: a domain nobody could read, a partition this
    /// product does not read, and a domain somebody decided not to read are three different events,
    /// and one table meaning all three would be a table meaning nothing.
    /// </para>
    /// </remarks>
    /// <param name="exclusion">What was stated, and for which domain.</param>
    /// <exception cref="ArgumentNullException">The exclusion is absent.</exception>
    public void RecordExcludedDomain(AttestedExclusion exclusion)
    {
        ArgumentNullException.ThrowIfNull(exclusion);
        ThrowIfFinished();

        Execute(
            """
            INSERT INTO excluded_domain (
                naming_context_dn, kind, reason, note, run_by, authorised_by, attested_utc)
            VALUES ($dn, $kind, $reason, $note, $runBy, $authorisedBy, $attestedUtc)
            """,
            command =>
            {
                command.Parameters.AddWithValue("$dn", exclusion.NamingContext);
                command.Parameters.AddWithValue("$kind", exclusion.Kind.ToString());
                command.Parameters.AddWithValue("$reason", exclusion.Reason);
                command.Parameters.AddWithValue(
                    "$note", (object?)exclusion.Note ?? DBNull.Value);
                command.Parameters.AddWithValue("$runBy", exclusion.RunBy);
                command.Parameters.AddWithValue("$authorisedBy", exclusion.AuthorisedBy);
                command.Parameters.AddWithValue(
                    "$attestedUtc", exclusion.AttestedUtc.UtcDateTime.ToString("O"));
            });
    }

    /// <summary>
    /// Records that one naming context was read, and returns the handle every object read from it
    /// is written against.
    /// </summary>
    /// <remarks>
    /// Opening and completing in one call, for a caller that already has the finished coverage.
    /// There is one write path underneath, because two ways to record what a partition contained
    /// is two accounts that can disagree.
    /// </remarks>
    /// <param name="coverage">What the pass read.</param>
    public long WriteCoverage(PartitionCoverage coverage)
    {
        ArgumentNullException.ThrowIfNull(coverage);

        var coverageId = BeginPartition(
            coverage.NamingContextDn,
            coverage.Kind,
            coverage.Controller,
            coverage.ConnectionSecurity);

        CompletePartition(coverage);

        return coverageId;
    }

    /// <summary>
    /// The handle for a partition that has already been written, refusing one that has not.
    /// </summary>
    /// <remarks>
    /// Keyed on the naming context and the controller, which is what <c>partition_coverage</c> is
    /// unique on - one pass over one partition on one controller. Keying on the record itself would
    /// be keying on a value equality that its continuation-reference list does not really have.
    /// <para>
    /// An object whose partition was never written ends the run rather than being attributed to
    /// some other partition or to none. Coverage is what an absence is interpreted against, so an
    /// object filed under the wrong one silently changes what its neighbours' absence means.
    /// </para>
    /// </remarks>
    private long CoverageIdFor(PartitionCoverage coverage)
    {
        var key = (coverage.NamingContextDn, coverage.Controller);
        if (_coverageIds.TryGetValue(key, out var coverageId))
            return coverageId;

        throw new InvalidOperationException(
            $"An object read from '{coverage.NamingContextDn}' on '{coverage.Controller}' is being "
            + "written before that partition's coverage. Coverage is what the absence of an object "
            + "is interpreted against, so it has to exist before anything is attributed to it.");
    }

    /// <summary>
    /// Writes one object and its attributes. Inventory row B9.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An attribute that did not come back is written as a null column, or as no rows in its value
    /// table, and nothing records that it was asked for. Per <c>docs/decisions/0022</c> that is not
    /// a loss: the directory omits an absent attribute without saying whether the caller was
    /// refused it, so a record of the difference would be a record of a guess.
    /// </para>
    /// <para>
    /// <b>An attribute the catalogue does not name ends the run.</b> There is no column for it and
    /// no table, so the alternatives are to refuse it or to drop it silently - and a capture that
    /// read something this schema cannot hold is a defect in this product, not a fact about the
    /// forest.
    /// </para>
    /// </remarks>
    /// <param name="evidenceObject">The object, carrying the partition it was read from.</param>
    public long WriteObject(EvidenceObject evidenceObject)
    {
        ArgumentNullException.ThrowIfNull(evidenceObject);
        ThrowIfFinished();

        var coverageId = CoverageIdFor(evidenceObject.Coverage);
        var objectId = _nextObjectId++;
        var dn = evidenceObject.DistinguishedName;

        var command = RetainInsert(ref _objectInsert, ObjectInsertSql, ObjectInsertParameters);
        // Also clears bindings left by a row that failed validation before it was executed.
        for (var i = ObjectAttributeParameterOffset; i < command.Parameters.Count; i++)
            command.Parameters[i].Value = DBNull.Value;
        var valueTableWrites = new List<EvidenceAttribute>();

        foreach (var attribute in evidenceObject.Attributes)
        {
            if (SingleValuedColumns.TryGetValue(attribute.LdapDisplayName, out var single))
            {
                if (attribute.Completeness == StoredAttributeCompleteness.NotReturned)
                {
                    RefuseValuesWithoutAnAnswer(dn, attribute);
                    continue;
                }

                if (attribute.Values.Count == 0)
                    continue;

                if (attribute.Values.Count > 1)
                {
                    throw new InvalidOperationException(
                        $"'{dn}' offers {attribute.Values.Count} values for "
                        + $"'{attribute.LdapDisplayName}', which the catalogue declares single-valued. "
                        + "One column cannot hold them and choosing one would discard evidence.");
                }

                var value = StorageMatched(dn, single.Attribute, attribute.Values[0]);
                var parameter = command.Parameters[single.ParameterIndex];
                // SQLite used the first value when a sparse INSERT named a column twice.
                if (parameter.Value is DBNull)
                    parameter.Value = value;
                continue;
            }

            if (MultiValuedTables.ContainsKey(attribute.LdapDisplayName))
            {
                if (attribute.Completeness == StoredAttributeCompleteness.NotReturned)
                {
                    RefuseValuesWithoutAnAnswer(dn, attribute);
                    continue;
                }

                valueTableWrites.Add(attribute);
                continue;
            }

            if (StructurallyStored.Contains(attribute.LdapDisplayName))
                continue;

            throw new InvalidOperationException(
                $"'{dn}' carries '{attribute.LdapDisplayName}', which "
                + $"{nameof(CapturedAttributeCatalog)} does not name. The schema is derived from the "
                + "catalogue, so there is nowhere to put it; storing the object without it would "
                + "lose evidence that was read.");
        }

        command.Parameters[0].Value = objectId;
        command.Parameters[1].Value = coverageId;
        command.Parameters[2].Value = (object?)evidenceObject.ObjectGuid?.ToString("D") ?? DBNull.Value;
        command.Parameters[3].Value = dn;
        command.Parameters[4].Value = DnHelper.ReverseDn(dn);
        command.Parameters[5].Value = (object?)DnHelper.GetParentDn(dn) ?? DBNull.Value;
        command.Parameters[6].Value = DnHelper.DnToFqdn(dn);
        command.Parameters[7].Value = evidenceObject.CapturedUtc.UtcDateTime.ToString("O");
        command.ExecuteNonQuery();

        _objectCoverage[objectId] = coverageId;

        if (evidenceObject.ObjectGuid is { } guid)
            _objectGuids[objectId] = guid;

        foreach (var attribute in valueTableWrites)
            WriteAttributeValues(objectId, dn, attribute);

        return objectId;
    }

    /// <summary>
    /// Writes one object's security descriptor, storing it once however many objects carry it.
    /// Inventory row B10.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Nothing is recomputed here: the entries arrive already canonicalised, each carrying its own
    /// hash and the version of the pipeline that produced it.
    /// </para>
    /// <para>
    /// <b>The descriptor is identified by the SHA-256 of its bytes, and stored once.</b> A forest
    /// does not hold one descriptor per object; it holds a few thousand distinct ones repeated
    /// across millions, mostly by inheritance. Two objects sharing a descriptor therefore share one
    /// stored descriptor and one stored list, and the second object costs a hash and one row
    /// in <c>object_security_descriptor</c> rather than a parse and an insert per entry.
    /// </para>
    /// <para>
    /// <b>Sharing goes one level deeper than that, and it has to.</b> Two descriptors that are not
    /// byte-identical still hold most of the same entries, because each container down a tree adds
    /// entries that everything beneath it inherits. Deduplicating only whole descriptors therefore
    /// saved almost nothing on a real forest: the production capture of 2026-09-23 stored
    /// 141,706,338 entries saying 481,967 distinct things. Each distinct entry is now stored once in
    /// <c>access_entry</c> and pointed at from <c>descriptor_entry</c>, per <c>P-272</c>.
    /// </para>
    /// <para>
    /// <b>The hash is cryptographic and that is load-bearing.</b> A collision here does not corrupt
    /// a row - it silently gives one object another object's permissions, which is the one failure
    /// an audit tool cannot have. The byte length is stored beside it so a collision would have to
    /// agree on two things.
    /// </para>
    /// <para>
    /// Four things are stored that a smaller design would not. The raw bytes, so a defect in the
    /// parser is repaired by re-analysis rather than by asking a customer to re-read his forest.
    /// The DACL state, because a null DACL and an empty DACL mean opposite things and both produce
    /// no entries. The parse errors, because a descriptor that could not be read produces no
    /// entries in exactly the way an object granting nothing does. And inherited entries, because
    /// skipping them forces a reader to reconstruct inheritance - recomputing what the directory
    /// already told us, and being wrong wherever the reconstruction disagrees.
    /// </para>
    /// </remarks>
    /// <param name="objectId">The object the descriptor belongs to.</param>
    /// <param name="descriptorBytes">The descriptor exactly as the controller sent it.</param>
    /// <param name="normalization">The canonicalised descriptor.</param>
    public void WriteSecurityDescriptor(
        long objectId, byte[] descriptorBytes, AceNormalizationResult normalization)
    {
        ArgumentNullException.ThrowIfNull(descriptorBytes);
        ArgumentNullException.ThrowIfNull(normalization);
        ThrowIfFinished();

        // The descriptor carries its own view of which object it belongs to. If that disagrees
        // with the object it is being written against, one of them is wrong and there is no way to
        // tell which - so the run ends rather than attributing a set of permissions to an object
        // that may not have them. A permission reported against the wrong object is the failure an
        // audit tool cannot have.
        if (_objectGuids.TryGetValue(objectId, out var storedGuid)
            && normalization.ObjectGuid != Guid.Empty
            && normalization.ObjectGuid != storedGuid)
        {
            throw new InvalidOperationException(
                $"A security descriptor for {normalization.ObjectGuid} is being written against "
                + $"object {objectId}, which is {storedGuid}. Storing it would attribute one "
                + "object's permissions to another.");
        }

        var sha256 = Convert.ToHexString(SHA256.HashData(descriptorBytes));

        var descriptorId = EnsureDescriptor(sha256, descriptorBytes, normalization);

        var command = RetainInsert(ref _descriptorLinkInsert,
            "INSERT INTO object_security_descriptor (object_id, descriptor_id) "
            + "VALUES ($object, $descriptor)",
            ["$object", "$descriptor"]);
        command.Parameters[0].Value = objectId;
        command.Parameters[1].Value = descriptorId;
        command.ExecuteNonQuery();
    }

    /// <summary>
    /// Stores a descriptor if the bundle has not seen these exact bytes before, and returns the
    /// identifier either way.
    /// </summary>
    /// <remarks>
    /// Shared by directory objects and SYSVOL paths on purpose. A folder DACL and an object DACL
    /// are the same kind of evidence and are judged by the same classifier, so storing them through
    /// two paths would let the two disagree about what an access mask means - which is what the
    /// predecessor's separate <c>fact_sysvol_ace</c> writer allowed.
    /// </remarks>
    private long EnsureDescriptor(
        string sha256, byte[] descriptorBytes, AceNormalizationResult normalization)
    {
        if (!_descriptors.TryGetValue(sha256, out var descriptorId))
        {
            descriptorId = _nextDescriptorId++;
            WriteDistinctDescriptor(descriptorId, sha256, descriptorBytes, normalization);
            _descriptors[sha256] = descriptorId;
        }

        return descriptorId;
    }

    /// <summary>
    /// Writes a descriptor the bundle has not seen before, with its errors and its entry set.
    /// </summary>
    private void WriteDistinctDescriptor(
        long descriptorId, string sha256, byte[] descriptorBytes, AceNormalizationResult normalization)
    {
        var command = RetainInsert(ref _descriptorInsert,
            """
            INSERT INTO security_descriptor (
                descriptor_id, sha256, byte_length, raw_bytes, owner_sid, group_sid,
                dacl_state, dacl_completeness, dacl_was_canonical,
                is_dacl_protected, ace_set_hash, canonicalization_version)
            VALUES ($id, $sha, $length, $raw, $owner, $group,
                    $dacl, $completeness, $canonical,
                    $protected, $setHash, $version)
            """,
            ["$id", "$sha", "$length", "$raw", "$owner", "$group", "$dacl", "$completeness",
                "$canonical", "$protected", "$setHash", "$version"]);
        command.Parameters[0].Value = descriptorId;
        command.Parameters[1].Value = sha256;
        command.Parameters[2].Value = descriptorBytes.Length;
        command.Parameters[3].Value = descriptorBytes;
        command.Parameters[4].Value = (object?)normalization.OwnerSid ?? DBNull.Value;
        command.Parameters[5].Value = (object?)normalization.GroupSid ?? DBNull.Value;
        command.Parameters[6].Value = normalization.DaclState.ToString();
        command.Parameters[7].Value = normalization.DaclCompleteness.ToString();
        command.Parameters[8].Value = normalization.DaclWasCanonical ? 1 : 0;
        command.Parameters[9].Value = normalization.IsDaclProtected ? 1 : 0;
        command.Parameters[10].Value = AceSetHash.Compute(normalization.Aces);
        command.Parameters[11].Value = CanonicalizationVersionOf(normalization);
        command.ExecuteNonQuery();

        for (var ordinal = 0; ordinal < normalization.Errors.Count; ordinal++)
        {
            var message = normalization.Errors[ordinal];
            Execute(
                "INSERT INTO security_descriptor_error (descriptor_id, ordinal, message) "
                + "VALUES ($id, $ordinal, $message)",
                command =>
                {
                    command.Parameters.AddWithValue("$id", descriptorId);
                    command.Parameters.AddWithValue("$ordinal", ordinal);
                    command.Parameters.AddWithValue("$message", message);
                });
        }

        for (var ordinal = 0; ordinal < normalization.Aces.Count; ordinal++)
            LinkEntry(descriptorId, ordinal, normalization.Aces[ordinal]);
    }

    /// <summary>
    /// The canonicalization version to record against a descriptor, taken from the entries
    /// themselves rather than from this build.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The column exists so a later build can refuse hashes it cannot reproduce</b>, and
    /// <see cref="BundleReader"/> reads this column and nothing else to decide. Binding it to
    /// <see cref="AceCanonicalization.Version"/> made it a restatement of the reader's own constant
    /// rather than a fact about the stored bytes - a self-certifying loop, closed only by the call
    /// graph happening to contain one producer of an <see cref="AceNormalizationResult"/>. That is a
    /// property of today's callers and not something this writer asserts, and
    /// <c>docs/decisions/0021-re-analysis-produces-a-new-bundle.md</c> puts a second producer on the
    /// roadmap: re-analysis derives a new bundle from a sealed one, which is exactly the path that
    /// would hand this writer entries it did not normalise.
    /// </para>
    /// <para>
    /// <b>A set carrying more than one version is refused rather than reduced.</b> A descriptor
    /// whose entries were canonicalised by two recipes is not a descriptor this product can hash:
    /// <c>ace_set_hash</c> covers the set as a whole, so there is no single version that describes
    /// it and picking one would certify a value no build can reproduce. This is a refusal for the
    /// same reason the reader's is - the alternative is a bundle that opens and compares equal to
    /// nothing.
    /// </para>
    /// <para>
    /// <b>An empty set keeps this build's constant</b>, and that is correct rather than a fallback.
    /// There is no entry to ask, and the set hash over nothing was produced by this build.
    /// </para>
    /// </remarks>
    /// <param name="normalization">The normalized descriptor being written.</param>
    /// <exception cref="InvalidOperationException">
    /// The entries carry more than one canonicalization version.
    /// </exception>
    private static int CanonicalizationVersionOf(AceNormalizationResult normalization)
    {
        if (normalization.Aces.Count == 0)
            return AceCanonicalization.Version;

        var version = normalization.Aces[0].CanonicalizationVersion;

        foreach (var ace in normalization.Aces)
        {
            if (ace.CanonicalizationVersion != version)
            {
                var found = normalization.Aces
                    .Select(a => a.CanonicalizationVersion)
                    .Distinct()
                    .Order();

                throw new InvalidOperationException(
                    $"A descriptor's entries carry canonicalization versions "
                    + $"{string.Join(", ", found)}. One descriptor is hashed as one set, so a set "
                    + "produced by two recipes has no version that describes it, and recording "
                    + "either would certify a hash no build can reproduce.");
            }
        }

        return version;
    }

    /// <summary>
    /// Records that an object's security descriptor could not be read at all.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A positive row, because the alternative is silence that reads as good news.</b> An object
    /// with no descriptor row, no error row and no entries is indistinguishable from an object that
    /// grants nobody anything - and on a production domain that was 19,927 objects in 100,000
    /// (<c>F-S20-16</c>). The predecessor returned early on exactly this case and incremented its
    /// only counter below the return, so a fifth of a domain was unknown and nothing anywhere said
    /// so.
    /// </para>
    /// <para>
    /// The count is also kept against the partition, so a reader can get from <i>this many were
    /// unreadable</i> to the controller they were unreadable on. The run total is the sum of those
    /// rows rather than a number stored beside them, because a stored total is a second fact that
    /// can disagree with the first.
    /// </para>
    /// </remarks>
    /// <param name="objectId">The object whose descriptor could not be read.</param>
    /// <param name="reason">What went wrong, as the controller or the client reported it.</param>
    public void WriteUnreadableSecurityDescriptor(long objectId, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        ThrowIfFinished();

        Execute(
            "INSERT INTO unreadable_security_descriptor (object_id, reason) VALUES ($id, $reason)",
            command =>
            {
                command.Parameters.AddWithValue("$id", objectId);
                command.Parameters.AddWithValue("$reason", reason);
            });

        if (_objectCoverage.TryGetValue(objectId, out var coverageId))
        {
            _unreadableDescriptors[coverageId] =
                _unreadableDescriptors.GetValueOrDefault(coverageId) + 1;
        }
    }

    /// <summary>
    /// Records something this object pointed at that nothing in the run ever saw.
    /// </summary>
    /// <remarks>
    /// The reason is a closed set with no free text beside it, per <c>docs/decisions/0022</c>. The
    /// predecessor's equivalent carried both, and the prose was not the problem - reading behaviour
    /// off its wording was, which made the message text a load-bearing contract. What the closed
    /// set cannot carry is <i>which</i> thing was pointed at, so that is stored as data in
    /// <paramref name="reference"/> rather than described in a sentence.
    /// </remarks>
    /// <param name="objectId">The object that pointed at something.</param>
    /// <param name="ordinal">Which of this object's unresolved references this is.</param>
    /// <param name="kind">What the object was pointing at it as.</param>
    /// <param name="reference">The distinguished name or identifier that was pointed at.</param>
    /// <param name="reason">Why it was never seen.</param>
    public void WriteUnresolvedReference(
        long objectId,
        int ordinal,
        UnresolvedReferenceKind kind,
        string reference,
        UnresolvedReferenceReason reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reference);
        ThrowIfFinished();

        Execute(
            "INSERT INTO unresolved_reference (object_id, ordinal, kind, reference, reason) "
            + "VALUES ($id, $ordinal, $kind, $reference, $reason)",
            command =>
            {
                command.Parameters.AddWithValue("$id", objectId);
                command.Parameters.AddWithValue("$ordinal", ordinal);
                command.Parameters.AddWithValue("$kind", kind.ToString());
                command.Parameters.AddWithValue("$reference", reference);
                command.Parameters.AddWithValue("$reason", reason.ToString());
            });
    }

    /// <summary>
    /// Records the permissions on one path inside a policy's folder on SYSVOL.
    /// </summary>
    /// <remarks>
    /// Goes through the same descriptor store as a directory object's permissions, so a trustee
    /// found on a folder and one found on an object are the same evidence and are compared the same
    /// way. Which paths appear is set by <c>docs/decisions/0043</c>.
    /// </remarks>
    /// <param name="gpoGuid">The policy whose folder this path is inside.</param>
    /// <param name="relativePath">
    /// The path beneath the policy's folder, or empty for the folder itself.
    /// </param>
    /// <param name="descriptorBytes">The descriptor exactly as the file system returned it.</param>
    /// <param name="normalization">The canonicalised descriptor.</param>
    public void WriteSysvolSecurityDescriptor(
        Guid gpoGuid,
        string relativePath,
        byte[] descriptorBytes,
        AceNormalizationResult normalization)
    {
        ArgumentNullException.ThrowIfNull(relativePath);
        ArgumentNullException.ThrowIfNull(descriptorBytes);
        ArgumentNullException.ThrowIfNull(normalization);
        ThrowIfFinished();

        var sha256 = Convert.ToHexString(SHA256.HashData(descriptorBytes));
        var descriptorId = EnsureDescriptor(sha256, descriptorBytes, normalization);

        Execute(
            "INSERT INTO sysvol_path_security_descriptor (gpo_guid, relative_path, descriptor_id) "
            + "VALUES ($gpo, $path, $descriptor)",
            command =>
            {
                command.Parameters.AddWithValue("$gpo", Text(gpoGuid));
                command.Parameters.AddWithValue("$path", relativePath);
                command.Parameters.AddWithValue("$descriptor", descriptorId);
            });
    }

    /// <summary>
    /// Records a path inside a policy's folder whose permissions could not be read at all.
    /// </summary>
    /// <remarks>
    /// The file-share counterpart of <see cref="WriteUnreadableSecurityDescriptor"/>, and it exists
    /// for the same reason: without it, a folder nobody was allowed to inspect looks exactly like a
    /// folder that grants nobody anything.
    /// </remarks>
    /// <param name="gpoGuid">The policy whose folder this path is inside.</param>
    /// <param name="relativePath">The path beneath the policy's folder.</param>
    /// <param name="reason">What the file system said.</param>
    public void WriteUnreadableSysvolDescriptor(Guid gpoGuid, string relativePath, string reason)
    {
        ArgumentNullException.ThrowIfNull(relativePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        ThrowIfFinished();

        Execute(
            "INSERT INTO unreadable_sysvol_descriptor (gpo_guid, relative_path, reason) "
            + "VALUES ($gpo, $path, $reason)",
            command =>
            {
                command.Parameters.AddWithValue("$gpo", Text(gpoGuid));
                command.Parameters.AddWithValue("$path", relativePath);
                command.Parameters.AddWithValue("$reason", reason);
            });
    }

    /// <summary>
    /// Records one registry-backed setting a policy applies.
    /// </summary>
    /// <param name="gpoGuid">The policy the setting came from.</param>
    /// <param name="ordinal">Which of this policy's registry settings this is.</param>
    /// <param name="scope">Whether the setting applies to the machine or to the user.</param>
    /// <param name="keyPath">The registry key the policy writes to.</param>
    /// <param name="valueName">The value it writes.</param>
    /// <param name="registryType">
    /// The raw registry type, kept as the file stated it rather than as an interpretation of it.
    /// </param>
    /// <param name="valueData">The value's bytes, undecoded.</param>
    public void WriteGpoRegistrySetting(
        Guid gpoGuid,
        int ordinal,
        GpoSettingScope scope,
        string keyPath,
        string valueName,
        uint registryType,
        byte[] valueData)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);
        ArgumentNullException.ThrowIfNull(valueName);
        ArgumentNullException.ThrowIfNull(valueData);
        ThrowIfFinished();

        Execute(
            """
            INSERT INTO gpo_registry_setting (
                gpo_guid, ordinal, scope, key_path, value_name, registry_type, value_data)
            VALUES ($gpo, $ordinal, $scope, $key, $value, $type, $data)
            """,
            command =>
            {
                command.Parameters.AddWithValue("$gpo", Text(gpoGuid));
                command.Parameters.AddWithValue("$ordinal", ordinal);
                command.Parameters.AddWithValue("$scope", scope.ToString());
                command.Parameters.AddWithValue("$key", keyPath);
                command.Parameters.AddWithValue("$value", valueName);
                command.Parameters.AddWithValue("$type", registryType);
                command.Parameters.AddWithValue("$data", valueData);
            });
    }

    /// <summary>
    /// Records one setting out of a policy's security template.
    /// </summary>
    /// <param name="gpoGuid">The policy the setting came from.</param>
    /// <param name="ordinal">Which of this policy's template settings this is.</param>
    /// <param name="section">The section of the file it was in.</param>
    /// <param name="name">The setting's name.</param>
    /// <param name="value">Its value, as the file stated it.</param>
    public void WriteGpoSecuritySetting(
        Guid gpoGuid, int ordinal, string section, string name, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(section);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(value);
        ThrowIfFinished();

        Execute(
            "INSERT INTO gpo_security_setting (gpo_guid, ordinal, section, name, value) "
            + "VALUES ($gpo, $ordinal, $section, $name, $value)",
            command =>
            {
                command.Parameters.AddWithValue("$gpo", Text(gpoGuid));
                command.Parameters.AddWithValue("$ordinal", ordinal);
                command.Parameters.AddWithValue("$section", section);
                command.Parameters.AddWithValue("$name", name);
                command.Parameters.AddWithValue("$value", value);
            });
    }

    /// <summary>
    /// Records one principal a policy places into, or takes into, a privileged local group.
    /// </summary>
    /// <param name="gpoGuid">The policy the entry came from.</param>
    /// <param name="ordinal">Which of this policy's Restricted Groups entries this is.</param>
    /// <param name="groupName">The group the file names.</param>
    /// <param name="relationship">Which way round the membership goes.</param>
    /// <param name="principal">The principal on the other end of it.</param>
    public void WriteGpoRestrictedGroup(
        Guid gpoGuid,
        int ordinal,
        string groupName,
        RestrictedGroupRelationship relationship,
        string principal)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(groupName);
        ArgumentException.ThrowIfNullOrWhiteSpace(principal);
        ThrowIfFinished();

        Execute(
            """
            INSERT INTO gpo_restricted_group (
                gpo_guid, ordinal, group_name, relationship, principal)
            VALUES ($gpo, $ordinal, $group, $relationship, $principal)
            """,
            command =>
            {
                command.Parameters.AddWithValue("$gpo", Text(gpoGuid));
                command.Parameters.AddWithValue("$ordinal", ordinal);
                command.Parameters.AddWithValue("$group", groupName);
                command.Parameters.AddWithValue("$relationship", relationship.ToString());
                command.Parameters.AddWithValue("$principal", principal);
            });
    }

    /// <summary>
    /// Records that a policy stores a credential in its own files.
    /// </summary>
    /// <remarks>
    /// Presence only. Neither the password nor the ciphertext is passed in or stored, because the
    /// key that protects it is public and writing it into the evidence would rebuild the
    /// vulnerability inside the audit.
    /// </remarks>
    /// <param name="gpoGuid">The policy the credential is stored in.</param>
    /// <param name="ordinal">Which of this policy's stored credentials this is.</param>
    /// <param name="relativePath">The file it is in, beneath the policy's folder.</param>
    /// <param name="elementType">The kind of preference that holds it.</param>
    /// <param name="accountName">The account it belongs to, where the file names one.</param>
    /// <param name="sourceAttribute">The attribute it was found on, where the file names one.</param>
    public void WriteGpoStoredCredential(
        Guid gpoGuid,
        int ordinal,
        string relativePath,
        string elementType,
        string? accountName,
        string? sourceAttribute)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(elementType);
        ThrowIfFinished();

        Execute(
            """
            INSERT INTO gpo_stored_credential (
                gpo_guid, ordinal, relative_path, element_type, account_name, source_attribute)
            VALUES ($gpo, $ordinal, $path, $element, $account, $attribute)
            """,
            command =>
            {
                command.Parameters.AddWithValue("$gpo", Text(gpoGuid));
                command.Parameters.AddWithValue("$ordinal", ordinal);
                command.Parameters.AddWithValue("$path", relativePath);
                command.Parameters.AddWithValue("$element", elementType);
                command.Parameters.AddWithValue("$account", (object?)accountName ?? DBNull.Value);
                command.Parameters.AddWithValue("$attribute", (object?)sourceAttribute ?? DBNull.Value);
            });
    }

    /// <summary>
    /// Records a file inside a policy that was opened and could not be understood.
    /// </summary>
    /// <remarks>
    /// Without this row a file that failed to parse produces the same evidence as a policy that
    /// configures nothing, and the rules would report the second when the truth is the first.
    /// </remarks>
    /// <param name="gpoGuid">The policy the file belongs to.</param>
    /// <param name="ordinal">Which of this policy's file errors this is.</param>
    /// <param name="relativePath">The file, beneath the policy's folder.</param>
    /// <param name="message">What went wrong reading it.</param>
    public void WriteGpoFileError(Guid gpoGuid, int ordinal, string relativePath, string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        ThrowIfFinished();

        Execute(
            "INSERT INTO gpo_file_error (gpo_guid, ordinal, relative_path, message) "
            + "VALUES ($gpo, $ordinal, $path, $message)",
            command =>
            {
                command.Parameters.AddWithValue("$gpo", Text(gpoGuid));
                command.Parameters.AddWithValue("$ordinal", ordinal);
                command.Parameters.AddWithValue("$path", relativePath);
                command.Parameters.AddWithValue("$message", message);
            });
    }

    /// <summary>
    /// One spelling for a policy identifier, so a row written by one method joins to a row written
    /// by another.
    /// </summary>
    private static string Text(Guid gpoGuid) => gpoGuid.ToString("D");

    /// <summary>
    /// Folds one parallel reader's finished database into this bundle.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The merge itself is <see cref="BundleMerge"/>; what is here is everything around it that
    /// only the writer can do.</b> There are three such things, and each of them would break a
    /// real run.
    /// </para>
    /// <para>
    /// <b>The transaction has to be let go of.</b> <see cref="Create"/> opens one transaction and
    /// holds it until <see cref="Complete"/>, and SQLite refuses <c>ATTACH DATABASE</c> inside a
    /// transaction - so the merge cannot run on this connection as it stands. The commit here is
    /// safe rather than merely necessary: what makes a bundle readable is the rename in
    /// <see cref="Complete"/>, not the commit, so a run that dies between two merges still leaves
    /// nothing by the name a reader opens.
    /// </para>
    /// <para>
    /// <b>The natural-key caches go stale, and this is the failure that is not obvious.</b>
    /// <c>_trustees</c> and <c>_descriptors</c> exist so that a repeated SID or a repeated
    /// descriptor costs a dictionary lookup rather than a query. They know nothing of rows the
    /// merge brought in - and SYSVOL is read through this writer <i>after</i> the merges, per
    /// <c>docs/decisions/0044</c>. A policy folder granting <c>BUILTIN\Administrators</c> would
    /// therefore insert a SID a domain shard had already placed, against <c>UNIQUE(sid)</c>. That
    /// fails loudly, which is the only reason it is not the worst defect here, and it would fail
    /// on every real forest.
    /// </para>
    /// <para>
    /// <b>Reloading only the absorbed shard's own range is exact, not an approximation.</b>
    /// <c>BundleMerge</c> copies a new trustee or descriptor keeping the identifier its shard gave
    /// it, and leaves an already-known one where it was; <c>RefuseForeignIdentifiers</c> has
    /// already proved every row of the shard carries that shard's numbers. So the rows in that
    /// range after a merge are exactly the rows the merge added, and the ones it did not add were
    /// already cached by whatever put them there.
    /// </para>
    /// </remarks>
    /// <param name="shardPath">The shard database one domain was read into, finished.</param>
    /// <param name="shard">Which shard wrote it, so the merge can check the identifiers.</param>
    /// <returns>What the shard contributed.</returns>
    /// <exception cref="InvalidOperationException">
    /// This writer is a shard rather than the bundle, or a partition attempt is still open.
    /// </exception>
    public BundleMergeResult Absorb(string shardPath, BundleShard shard)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(shardPath);
        ThrowIfFinished();

        if (Shard.Index != BundleShard.Whole.Index)
        {
            throw new InvalidOperationException(
                "This writer is a shard, not the bundle being assembled. A shard that absorbed "
                + "another would carry both domains' rows into the merge that folds it in, and "
                + "the second domain would be counted twice.");
        }

        if (_attempt is not null)
        {
            throw new InvalidOperationException(
                "A shard is being merged while a partition attempt is open. Committing now would "
                + "put the attempt's rows beyond the reach of the savepoint that exists to "
                + "discard them, so a restart would leave a partial read in the bundle.");
        }

        // The commit, and then nothing is in flight while the merge runs. ATTACH is refused inside
        // a transaction, which is the whole reason this method exists rather than the run driver
        // calling BundleMerge against the connection directly.
        _transaction!.Commit();
        _transaction.Dispose();
        _transaction = null;

        var merged = BundleMerge.Absorb(_connection, shardPath, shard);

        Recache("trustee", "sid", "trustee_id", shard, _trustees);
        Recache("security_descriptor", "sha256", "descriptor_id", shard, _descriptors);

        _transaction = _connection.BeginTransaction();

        return merged;
    }

    /// <summary>
    /// Reads back the rows a merge just added, so the cache in front of them stops being a lie.
    /// </summary>
    /// <remarks>
    /// Bounded by the absorbed shard's identifier range rather than reloading the table, because a
    /// bundle of nine domains would otherwise re-read every trustee and every distinct descriptor
    /// nine times over. See the remarks on <see cref="Absorb"/> for why that range is exactly the
    /// set of rows the merge added.
    /// </remarks>
    /// <param name="table">The table the merge remapped on a natural key.</param>
    /// <param name="naturalKey">The column the cache is keyed by.</param>
    /// <param name="key">The surrogate identifier, which the shard range is a range of.</param>
    /// <param name="shard">The shard just absorbed, whose range bounds the read.</param>
    /// <param name="cache">The cache to add to.</param>
    private void Recache(
        string table,
        string naturalKey,
        string key,
        BundleShard shard,
        Dictionary<string, long> cache)
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            $"SELECT {naturalKey}, {key} FROM {table} WHERE {key} BETWEEN $first AND $last";
        command.Parameters.AddWithValue("$first", shard.FirstId);
        command.Parameters.AddWithValue("$last", shard.LastId);

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            cache[reader.GetString(0)] = reader.GetInt64(1);
        }
    }

    /// <summary>
    /// Finishes one parallel reader's database so the merge can fold it into the bundle.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What it deliberately does not do is the whole of it.</b> A shard is not a bundle and must
    /// not resemble one:
    /// </para>
    /// <para>
    /// <b>No run-level rows.</b> <see cref="Complete"/> writes <c>bundle</c>, <c>domain_coverage</c>,
    /// <c>forest_partition_coverage</c>, <c>sysvol_gpo_coverage</c> and the reconciliation items -
    /// all of which describe the <i>run</i>, not the domain. Nine shards each writing their own
    /// would give the merged bundle nine contradictory accounts of one run, and
    /// <c>BundleMerge</c> refuses a shard carrying any of them. The run driver writes them once,
    /// into the bundle, after every shard has been folded in.
    /// </para>
    /// <para>
    /// <b>No backfill, and this is the one that would have produced a wrong answer rather than a
    /// mess.</b> <c>ResolveParentGuids</c> matches each object's parent name against every
    /// distinguished name it can see, and records a miss as <c>ParentContainer</c> /
    /// <c>DomainNotCaptured</c> - a permanent statement in the evidence that a container was never
    /// captured. Inside a shard it can only see one domain, so every cross-domain parent would be
    /// written as missing, and the merged bundle would report thousands of objects as orphaned by a
    /// forest that in fact held all of them. It runs once over the whole assembled bundle, where
    /// the question it is asking is the question it can actually answer.
    /// </para>
    /// <para>
    /// <b>No indexes and no seal.</b> Indexes are built once over the merged bundle rather than
    /// nine times and then merged into. The seal is a fingerprint of finished evidence, and a shard
    /// is never finished evidence - it is deleted as soon as its rows are in the bundle.
    /// </para>
    /// <para>
    /// <b>What it keeps is the commit and the checkpoint,</b> because both are about getting bytes
    /// safely onto disk under a name the merge can open. Reading a database whose recent writes are
    /// still in a write-ahead log means depending on the reader to find the sidecar; folding it back
    /// here makes the shard a single self-contained file.
    /// </para>
    /// </remarks>
    /// <returns>How long the commit and the checkpoint took.</returns>
    /// <exception cref="InvalidOperationException">
    /// This writer is writing the whole bundle rather than a shard of one.
    /// </exception>
    public BundleShardTimings CompleteShard()
    {
        ThrowIfFinished();

        if (Shard.Index == BundleShard.Whole.Index)
        {
            throw new InvalidOperationException(
                "This writer is writing the whole bundle, not a shard of one, so finishing it as a "
                + "shard would leave a bundle with no run-level rows, no indexes and no seal - a "
                + "file that is not evidence and that no reader can open. Call Complete instead.");
        }

        WriteUnreadableDescriptorCounts();

        var clock = System.Diagnostics.Stopwatch.StartNew();

        DisposeInsertCommands();
        _transaction!.Commit();
        _transaction.Dispose();
        _transaction = null;

        var commit = clock.Elapsed;
        clock.Restart();

        Pragma(_connection, "wal_checkpoint(TRUNCATE)");
        _connection.Close();
        SqliteConnection.ClearPool(_connection);

        _completed = true;

        return new BundleShardTimings(commit, clock.Elapsed);
    }

    /// <summary>
    /// Finishes the bundle: folds the write-ahead log back in, seals the file, and only then gives
    /// it the name a reader asks for.
    /// </summary>
    /// <remarks>
    /// The order is the whole design. Indexes are built now rather than during ingest, so several
    /// million inserts do not each pay to maintain a tree. The checkpoint comes before the hash,
    /// because a hash taken while changes are still in the write-ahead log covers a database that
    /// is not all there. The rename comes last, because it is the act that makes the bundle
    /// readable at all.
    /// </remarks>
    /// <param name="coverage">What the run declared and what became of each part of it.</param>
    /// <param name="completedUtc">When the run finished.</param>
    /// <summary>Finishes a bundle from a producer that did not perform continuation reconciliation.</summary>
    /// <returns>How long each part of sealing took.</returns>
    public BundleSealTimings Complete(RunCoverage coverage, DateTimeOffset completedUtc) =>
        Complete(coverage, completedUtc, ContinuationReconciliation.NotPerformed);

    /// <summary>Finishes a bundle with the capture's continuation-reference reconciliation.</summary>
    /// <param name="coverage">What the run declared and what became of each part of it.</param>
    /// <param name="completedUtc">When the run finished.</param>
    /// <param name="reconciliation">The comparison of received referrals with authorized scope.</param>
    /// <returns>
    /// How long each part of sealing took. Ignored by most callers; the run driver writes it to the
    /// log, because this is the stretch of a capture that had no account of itself at all.
    /// </returns>
    public BundleSealTimings Complete(
        RunCoverage coverage,
        DateTimeOffset completedUtc,
        ContinuationReconciliation reconciliation) =>
        Complete(coverage, completedUtc, reconciliation, CaptureObjectScope.Default);

    /// <summary>Finishes a bundle with its explicit object-class capture policy.</summary>
    /// <param name="coverage">The declared domain coverage and its outcomes.</param>
    /// <param name="completedUtc">When capture finished.</param>
    /// <param name="reconciliation">The comparison of received referrals with authorized scope.</param>
    /// <param name="objectScope">The class exclusions actually applied by capture.</param>
    public BundleSealTimings Complete(
        RunCoverage coverage,
        DateTimeOffset completedUtc,
        ContinuationReconciliation reconciliation,
        CaptureObjectScope objectScope) =>
        Complete(coverage, completedUtc, reconciliation, objectScope, CancellationToken.None);

    /// <summary>Prepares a bundle cooperatively, then publishes it only if cancellation has not won.</summary>
    /// <param name="coverage">The declared domain coverage and its outcomes.</param>
    /// <param name="completedUtc">When capture finished.</param>
    /// <param name="reconciliation">The comparison of received referrals with authorized scope.</param>
    /// <param name="objectScope">The class exclusions actually applied by capture.</param>
    /// <param name="cancellationToken">Cancellation until the final publication claim.</param>
    public BundleSealTimings Complete(
        RunCoverage coverage,
        DateTimeOffset completedUtc,
        ContinuationReconciliation reconciliation,
        CaptureObjectScope objectScope,
        CancellationToken cancellationToken) =>
        Complete(coverage, completedUtc, reconciliation, objectScope, cancellationToken, BundleSealing.Seal);

    /// <summary>Completes a bundle with a replaceable synchronous file-sealing operation.</summary>
    /// <param name="coverage">The declared domain coverage and its outcomes.</param>
    /// <param name="completedUtc">When capture finished.</param>
    /// <param name="reconciliation">The comparison of received referrals with authorized scope.</param>
    /// <param name="objectScope">The class exclusions actually applied by capture.</param>
    /// <param name="cancellationToken">Cancellation until the final publication claim.</param>
    /// <param name="seal">Prepares the seal and closes its files before returning; must not publish or leave background work.</param>
    public BundleSealTimings Complete(
        RunCoverage coverage,
        DateTimeOffset completedUtc,
        ContinuationReconciliation reconciliation,
        CaptureObjectScope objectScope,
        CancellationToken cancellationToken,
        Action<string, string, CancellationToken> seal)
    {
        ArgumentNullException.ThrowIfNull(coverage);
        ArgumentNullException.ThrowIfNull(reconciliation);
        ArgumentNullException.ThrowIfNull(objectScope);
        ArgumentNullException.ThrowIfNull(seal);
        ThrowIfFinished();

        // 0 = preparation, 1 = cancellation owns the ending, 2 = publication owns it.
        // This callback owns no file or connection, and cannot interrupt cleanup or rename.
        var publication = 0;
        using var stopping = cancellationToken.Register(() => Interlocked.CompareExchange(ref publication, 1, 0));
        cancellationToken.ThrowIfCancellationRequested();

        WriteUnreadableDescriptorCounts();

        foreach (var objectClass in objectScope.ExcludedClasses)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Execute("INSERT INTO capture_object_class_exclusion (class_name) VALUES ($class)",
                command => command.Parameters.AddWithValue("$class", objectClass));
        }

        Execute(
            """
            INSERT INTO bundle (
                schema_version, captured_attribute_catalog_version,
                schema_guid_catalog_version, security_descriptor_parser_version,
                capture_generation_id,
                forest_fqdn, capture_started_utc, capture_completed_utc,
                coverage_id, every_declared_unit_recorded_as_read,
                continuation_reconciliation_outcome)
            VALUES ($version, $attributes, $schemaGuids, $parser, $generation, $forest, $started, $completed,
                    $coverage, $complete, $reconciliation)
            """,
            command =>
            {
                command.Parameters.AddWithValue("$version", BundleSchema.Version);
                command.Parameters.AddWithValue("$attributes", CapturedAttributeCatalog.Version);
                command.Parameters.AddWithValue("$schemaGuids", SchemaGuidCatalog.Version);
                command.Parameters.AddWithValue("$parser", SecurityDescriptorParser.Version);
                command.Parameters.AddWithValue("$generation", _captureGeneration.ToString("D"));
                command.Parameters.AddWithValue("$forest", coverage.Declared.ForestFqdn);
                command.Parameters.AddWithValue("$started", _startedUtc.UtcDateTime.ToString("O"));
                command.Parameters.AddWithValue("$completed", completedUtc.UtcDateTime.ToString("O"));
                command.Parameters.AddWithValue("$coverage", coverage.Declared.Value);
                command.Parameters.AddWithValue(
                    "$complete", coverage.AllDeclaredUnitsAreComplete ? 1 : 0);
                command.Parameters.AddWithValue("$reconciliation", reconciliation.Outcome.ToString());
            });

        WriteReconciliationItems(
            "UnplannedNamingContext", reconciliation.UnplannedNamingContexts, cancellationToken);
        WriteReconciliationItems("UnreadableReference", reconciliation.UnreadableReferences, cancellationToken);
        WriteReconciliationItems("SuppressedUnit", reconciliation.UnitsWithSuppressedReferrals, cancellationToken);

        foreach (var domain in coverage.Domains)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Execute(
                "INSERT INTO domain_coverage (domain_fqdn, outcome, reason) "
                + "VALUES ($domain, $outcome, $reason)",
                command =>
                {
                    command.Parameters.AddWithValue("$domain", domain.DomainFqdn);
                    command.Parameters.AddWithValue("$outcome", domain.Outcome.ToString());
                    command.Parameters.AddWithValue(
                        "$reason", (object?)domain.Reason ?? DBNull.Value);
                });
        }

        foreach (var partition in coverage.ForestPartitions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Execute(
                "INSERT INTO forest_partition_coverage (naming_context_dn, kind, outcome, reason) "
                + "VALUES ($dn, $kind, $outcome, $reason)",
                command =>
                {
                    command.Parameters.AddWithValue("$dn", partition.NamingContextDn);
                    command.Parameters.AddWithValue("$kind", partition.Kind.ToString());
                    command.Parameters.AddWithValue("$outcome", partition.Outcome.ToString());
                    command.Parameters.AddWithValue(
                        "$reason", (object?)partition.Reason ?? DBNull.Value);
                });
        }

        // Written at the seal for the same reason the domain rows are: this is what became of the
        // read, and it is not known until the read is over. Unlike those rows it can legitimately
        // report failure in a bundle that exists at all - per docs/decisions/0044 a SYSVOL failure
        // does not end the run - so these rows are the only place a reader learns which policies
        // were not examined.
        foreach (var policy in coverage.Sysvol.Policies)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Execute(
                """
                INSERT INTO sysvol_gpo_coverage (
                    gpo_guid, display_name, file_sys_path, outcome, reason,
                    gpp_password_scan_outcome, gpp_password_scan_reason)
                VALUES ($gpo, $name, $path, $outcome, $reason, $gppOutcome, $gppReason)
                """,
                command =>
                {
                    command.Parameters.AddWithValue("$gpo", Text(policy.GpoGuid));
                    command.Parameters.AddWithValue("$name", policy.DisplayName);
                    command.Parameters.AddWithValue(
                        "$path", (object?)policy.FileSysPath ?? DBNull.Value);
                    command.Parameters.AddWithValue("$outcome", policy.Outcome.ToString());
                    command.Parameters.AddWithValue(
                        "$reason", (object?)policy.Reason ?? DBNull.Value);
                    command.Parameters.AddWithValue(
                        "$gppOutcome", policy.GppPasswordScanOutcome.ToString());
                    command.Parameters.AddWithValue(
                        "$gppReason", (object?)policy.GppPasswordScanReason ?? DBNull.Value);
                });
        }

        // EVERY PHASE FROM HERE IS TIMED, because this is the stretch the run log used to skip.
        // Stopwatch rather than the injected clock: these are durations rather than moments, and a
        // monotonic counter is the right instrument for one. It is also what the derivation and
        // judging phases already use.
        var clock = System.Diagnostics.Stopwatch.StartNew();

        cancellationToken.ThrowIfCancellationRequested();
        DisposeInsertCommands();
        _transaction!.Commit();
        _transaction.Dispose();
        _transaction = null;

        var commit = clock.Elapsed;
        clock.Restart();

        BundleSchema.CreateDeferredIndexes(_connection, cancellationToken);

        var indexes = clock.Elapsed;
        clock.Restart();

        // After the indexes, and deliberately. Both of these are set-based passes over every object
        // and both join on a column the deferred indexes have just created; run before, each would
        // be a scan per row.
        cancellationToken.ThrowIfCancellationRequested();
        ResolveParentGuids();
        cancellationToken.ThrowIfCancellationRequested();
        CountEntriesPerObject();
        var navigationObjects = NavigationStorage.Write(_connection, _bundleDirectory, _captureGeneration, cancellationToken);
        DashboardOverviewStorage.Write(_connection, _bundleDirectory, navigationObjects, cancellationToken);

        var backfill = clock.Elapsed;
        clock.Restart();

        cancellationToken.ThrowIfCancellationRequested();
        Pragma(_connection, "main.wal_checkpoint(TRUNCATE)");
        Pragma(_connection, "navigation.wal_checkpoint(TRUNCATE)");
        Pragma(_connection, "overview.wal_checkpoint(TRUNCATE)");
        _connection.Close();
        SqliteConnection.ClearPool(_connection);

        var checkpoint = clock.Elapsed;
        clock.Restart();

        cancellationToken.ThrowIfCancellationRequested();
        CreateAnnotationsSidecar();

        // Preparation has fully returned; nothing is left running that can publish later.
        // The claim is the cancellation boundary. Once claimed, rename errors remain errors,
        // and cancellation cannot relabel a successful rename as a cancelled capture.
        // The token is set before callbacks run; a different callback may still be blocking ours.
        AnalysisStoreLifecycle.PublishCapture(_bundleDirectory, _partialPath, _captureGeneration, navigationObjects, cancellationToken, seal, () =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.CompareExchange(ref publication, 2, 0) != 0)
                throw new OperationCanceledException(cancellationToken);
        });
        _completed = true;

        return new BundleSealTimings(commit, indexes, backfill, checkpoint, clock.Elapsed);
    }

    private void WriteReconciliationItems(string kind, IReadOnlyList<string> values, CancellationToken cancellationToken)
    {
        for (var ordinal = 0; ordinal < values.Count; ordinal++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Execute(
                "INSERT INTO continuation_reconciliation_item (kind, ordinal, value) "
                + "VALUES ($kind, $ordinal, $value)",
                command =>
                {
                    command.Parameters.AddWithValue("$kind", kind);
                    command.Parameters.AddWithValue("$ordinal", ordinal);
                    command.Parameters.AddWithValue("$value", values[ordinal]);
                });
        }
    }

    /// <summary>
    /// Writes each partition's tally of objects whose descriptor could not be read.
    /// </summary>
    /// <remarks>
    /// Held in memory and written once rather than incremented per object, because an UPDATE per
    /// unreadable descriptor would rewrite the same coverage row twenty thousand times on a domain
    /// like the one that produced <c>F-S20-16</c>.
    /// </remarks>
    private void WriteUnreadableDescriptorCounts()
    {
        foreach (var (coverageId, count) in _unreadableDescriptors)
        {
            Execute(
                "UPDATE partition_coverage SET unreadable_descriptors = $count "
                + "WHERE coverage_id = $id",
                command =>
                {
                    command.Parameters.AddWithValue("$count", count);
                    command.Parameters.AddWithValue("$id", coverageId);
                });
        }
    }

    /// <summary>
    /// Fills in each object's parent, and records the containers that were never captured.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One statement over the whole table, not a lookup per object.</b> A parent cannot be
    /// resolved while writing, because the container may not have been read yet - it is an ordinary
    /// object somewhere else in the same partition. So the edge is derived once at the end, by
    /// matching each object's <c>parent_dn</c> against <c>distinguished_name</c>, which the deferred
    /// index now serves. This is the predecessor's approach and its reasoning holds: an indexed
    /// self-join is one ordered pass where the obvious <c>LIKE</c> formulation is quadratic.
    /// </para>
    /// <para>
    /// <b>The parent name is read from the row rather than cut out here.</b> It was cut here, on the
    /// first comma, until <c>F-S30-1</c>: a comma inside a name is escaped and separates nothing, so
    /// <c>CN=Smith\, John</c> was given a container that does not exist and left outside the
    /// containment tree that inherited permissions travel down. <c>parent_dn</c> is written by
    /// <c>DnHelper.GetParentDn</c>, which knows the difference.
    /// </para>
    /// <para>
    /// <b>The rows it cannot fill are evidence, not leftovers.</b> An object whose parent DN matches
    /// nothing is an object whose container nothing ever saw - which is exactly the
    /// <see cref="UnresolvedReferenceKind.ParentContainer"/> case
    /// <c>docs/decisions/0022</c> asks to be recorded by reference. So the same pass that resolves
    /// the edge writes the gaps, and the two cannot disagree because they are one query.
    /// </para>
    /// <para>
    /// A naming context root has no parent inside the bundle and is not a gap. It is excluded by
    /// matching what capture recorded as a naming context, rather than by naming the roots, so a
    /// partition this product has never heard of behaves correctly. Excluding it by the absence of a
    /// comma - which is what this did until <c>F-S30-1</c> - held only for a root of a single label,
    /// and reported the root domain of substantially every real forest as a container the run failed
    /// to capture.
    /// </para>
    /// </remarks>
    private void ResolveParentGuids()
    {
        Execute(
            """
            UPDATE captured_object
            SET parent_guid = (
                SELECT parent.object_guid
                FROM captured_object AS parent
                WHERE parent.distinguished_name = captured_object.parent_dn)
            WHERE parent_dn IS NOT NULL
            """);

        Execute(
            """
            INSERT INTO unresolved_reference (object_id, ordinal, kind, reference, reason)
            SELECT
                child.object_id,
                COALESCE(
                    (SELECT MAX(existing.ordinal) + 1
                     FROM unresolved_reference AS existing
                     WHERE existing.object_id = child.object_id),
                    0),
                'ParentContainer',
                child.parent_dn,
                'DomainNotCaptured'
            FROM captured_object AS child
            WHERE child.parent_guid IS NULL
              AND child.parent_dn IS NOT NULL
              AND child.distinguished_name NOT IN (
                  SELECT naming_context_dn FROM partition_coverage)
              AND NOT EXISTS (
                  SELECT 1 FROM captured_object AS parent
                  WHERE parent.distinguished_name = child.parent_dn)
            """);
    }

    /// <summary>
    /// Fills in how many entries each object's descriptor holds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Derived rather than counted while writing, for the reason deduplication exists: one
    /// descriptor serves many objects, so counting per object would count the same entry set over
    /// and over, and setting the column per object would be an UPDATE on every row in the forest.
    /// </para>
    /// <para>
    /// It stays null for an object with no descriptor row - which includes every object whose
    /// descriptor could not be read. That is the point: null means <i>nobody knows</i> and zero
    /// means <i>this object grants nothing</i>, and collapsing them is the failure the whole
    /// descriptor half of this schema is arranged to prevent.
    /// </para>
    /// </remarks>
    private void CountEntriesPerObject()
    {
        Execute(
            """
            UPDATE captured_object
            SET ace_count = (
                SELECT COUNT(*)
                FROM descriptor_entry
                WHERE descriptor_entry.descriptor_id = (
                    SELECT link.descriptor_id
                    FROM object_security_descriptor AS link
                    WHERE link.object_id = captured_object.object_id))
            WHERE EXISTS (
                SELECT 1
                FROM object_security_descriptor AS link
                WHERE link.object_id = captured_object.object_id)
            """);
    }

    /// <summary>
    /// Closes the connection. A run that did not reach <see cref="Complete"/> leaves its
    /// <c>.partial</c> file exactly where it is.
    /// </summary>
    /// <remarks>
    /// Nothing is deleted. Reclaiming the disk on a failure path destroys the only record of how
    /// far the run got, on a judgement made by the code that has just failed - and the file has no
    /// name any reader asks for, so leaving it costs disk and never a wrong answer.
    /// </remarks>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        DisposeInsertCommands();
        _transaction?.Dispose();
        _connection.Dispose();
    }

    /// <summary>
    /// Refuses an attribute that says it did not come back while offering values.
    /// </summary>
    /// <remarks>
    /// The two states cannot both be true of one attribute, and storing the values anyway would let
    /// a reader treat withheld values as observed ones. This survived the move to typed columns as
    /// a check rather than a constraint, the column it used to be checked against having gone.
    /// </remarks>
    private static void RefuseValuesWithoutAnAnswer(string distinguishedName, EvidenceAttribute attribute)
    {
        if (attribute.Values.Count == 0)
            return;

        throw new InvalidOperationException(
            $"'{distinguishedName}' offers {attribute.Values.Count} value(s) for "
            + $"'{attribute.LdapDisplayName}' while stating that the attribute did not come "
            + "back. Storing both would let a reader treat withheld values as observed ones.");
    }

    /// <summary>
    /// The value to bind, having checked it is the kind of value the catalogue says it is.
    /// </summary>
    /// <remarks>
    /// <b>SQLite will not do this for us.</b> A column's declared type is an affinity rather than a
    /// constraint, so text bound to a <c>BLOB</c> column is stored as text and read back as text,
    /// with no error anywhere. The typed columns are therefore only as honest as this check: a
    /// descriptor or a SID arriving as a string is the mangled-value failure the storage split
    /// exists to prevent, and it has to be refused here or not at all.
    /// </remarks>
    private static object StorageMatched(
        string distinguishedName, CapturedAttribute attribute, EvidenceValue value)
    {
        if (attribute.Storage == AttributeStorage.Binary)
        {
            return value.Bytes is { } bytes
                ? bytes
                : throw new InvalidOperationException(
                    $"'{distinguishedName}' offers '{attribute.LdapDisplayName}' as text, and the "
                    + "catalogue declares it binary. Storing it would put a mangled string where "
                    + "bytes are expected, and SQLite would accept it silently.");
        }

        return value.Text is { } text
            ? text
            : throw new InvalidOperationException(
                $"'{distinguishedName}' offers '{attribute.LdapDisplayName}' as bytes, and the "
                + "catalogue declares it text.");
    }

    private void WriteAttributeValues(long objectId, string distinguishedName, EvidenceAttribute attribute)
    {
        var attributeDefinition = MultiValuedTables[attribute.LdapDisplayName];
        if (attribute.Values.Count == 0)
            return;

        if (!_attributeInserts.TryGetValue(attribute.LdapDisplayName, out var command))
        {
            var table = BundleSchema.ValueTableNameFor(attribute.LdapDisplayName);
            command = RetainInsert(ref command,
                $"INSERT INTO {table} (object_id, ordinal, value) VALUES ($object, $ordinal, $value)",
                ["$object", "$ordinal", "$value"]);
            _attributeInserts.Add(attribute.LdapDisplayName, command);
        }
        command.Transaction = _transaction;

        for (var ordinal = 0; ordinal < attribute.Values.Count; ordinal++)
        {
            var value = StorageMatched(distinguishedName, attributeDefinition, attribute.Values[ordinal]);
            command.Parameters[0].Value = objectId;
            command.Parameters[1].Value = ordinal;
            command.Parameters[2].Value = value;
            command.ExecuteNonQuery();
        }
    }

    /// <summary>
    /// Records that a descriptor holds one entry at one position, storing the entry itself only the
    /// first time this bundle has seen it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The ordinal goes on the link, and the entry carries no position at all.</b> The same entry
    /// sits at different positions in different lists, and Windows evaluates a DACL in stored order
    /// - accumulating granted and denied masks, and adding a deny only for rights that are not
    /// already granted (<c>[MS-ADTS] 5.1.3.3.2</c>). An order recorded on the shared entry would be
    /// one object's order imposed on every other object that carries it.
    /// </para>
    /// <para>
    /// <b>Identity is <c>ace_hash</c> and nothing else.</b> It is a SHA-256 over every field that
    /// distinguishes one entry from another - trustee, mask, type, the two GUIDs, inheritance,
    /// propagation and the callback condition bytes - and since canonicalization version 4 it names
    /// no object, which is what lets two objects be seen to hold one entry at all. As with the
    /// descriptor hash above, a collision here would not corrupt a row: it would quietly give one
    /// trustee another trustee's rights, so the hash is cryptographic on purpose.
    /// </para>
    /// </remarks>
    private void LinkEntry(long descriptorId, int ordinal, CanonicalAce ace)
    {
        var command = RetainInsert(ref _entryLinkInsert,
            "INSERT INTO descriptor_entry (descriptor_id, ordinal, entry_id) "
            + "VALUES ($descriptor, $ordinal, $entry)",
            ["$descriptor", "$ordinal", "$entry"]);
        command.Parameters[0].Value = descriptorId;
        command.Parameters[1].Value = ordinal;
        command.Parameters[2].Value = EntryId(ace);
        command.ExecuteNonQuery();
    }

    /// <summary>
    /// The identifier of an entry, adding it to the shared table the first time it is seen.
    /// </summary>
    /// <remarks>
    /// The same shape as <see cref="TrusteeId"/> and <see cref="EnsureDescriptor"/>, and for the
    /// same reason at a larger scale: a forest does not hold one entry per object, it holds a few
    /// hundred thousand distinct entries repeated across hundreds of millions of positions, almost
    /// all of it inheritance. The production capture of 2026-09-23 measured 294 positions per
    /// distinct entry.
    /// </remarks>
    private long EntryId(CanonicalAce ace)
    {
        if (_entries.TryGetValue(ace.AceHash, out var existing))
            return existing;

        var entryId = _nextEntryId++;
        var command = RetainInsert(ref _entryInsert,
            """
            INSERT INTO access_entry (
                entry_id, ace_type, trustee_id, access_mask, object_type_guid,
                inherited_object_type_guid, is_inherited, inheritance_flags, propagation_flags,
                application_data, ace_hash)
            VALUES ($entry, $type, $trustee, $mask, $objectType,
                    $inheritedType, $inherited, $inheritance, $propagation, $data, $hash)
            """,
            ["$entry", "$type", "$trustee", "$mask", "$objectType",
                "$inheritedType", "$inherited", "$inheritance", "$propagation", "$data", "$hash"]);
        command.Parameters[0].Value = entryId;
        command.Parameters[1].Value = ace.AceType.ToString();
        command.Parameters[2].Value = TrusteeId(ace.TrusteeSid);
        command.Parameters[3].Value = ace.AccessMask;
        command.Parameters[4].Value = (object?)ace.ObjectTypeGuid ?? DBNull.Value;
        command.Parameters[5].Value = (object?)ace.InheritedObjectTypeGuid ?? DBNull.Value;
        command.Parameters[6].Value = ace.IsInherited ? 1 : 0;
        command.Parameters[7].Value = ace.InheritanceFlags;
        command.Parameters[8].Value = ace.PropagationFlags;
        command.Parameters[9].Value = ace.ApplicationData.ToArray();
        command.Parameters[10].Value = ace.AceHash;
        command.ExecuteNonQuery();

        _entries[ace.AceHash] = entryId;
        return entryId;
    }

    /// <summary>
    /// The identifier of a trustee, adding it to the shared table the first time it is seen.
    /// </summary>
    /// <remarks>
    /// This is what survives of the previous product's per-payload string table, and it sees
    /// further: a domain's administrators appear in access control lists on hundreds of thousands
    /// of objects, and a table scoped to one object's payload could not look past that object.
    /// </remarks>
    private long TrusteeId(string sid)
    {
        if (_trustees.TryGetValue(sid, out var existing))
            return existing;

        var trusteeId = _nextTrusteeId++;
        var command = RetainInsert(ref _trusteeInsert,
            "INSERT INTO trustee (trustee_id, sid) VALUES ($id, $sid)",
            ["$id", "$sid"]);
        command.Parameters[0].Value = trusteeId;
        command.Parameters[1].Value = sid;
        command.ExecuteNonQuery();

        _trustees[sid] = trusteeId;
        return trusteeId;
    }

    /// <summary>
    /// Creates the annotations database at seal time, so that opening a bundle never writes to it.
    /// </summary>
    /// <remarks>
    /// It has to exist before it can be attached to a read connection, and creating it on first
    /// read means the read path writes a file into the bundle and takes a silent fallback on
    /// read-only media. Creating it here costs an empty file in every bundle and removes both.
    /// Its schema belongs to the read path and is not this row's to write.
    /// </remarks>
    private void CreateAnnotationsSidecar()
    {
        var path = BundleLayout.AnnotationsPath(_bundleDirectory);
        using var sidecar = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Pooling = false,
            }.ToString());

        sidecar.Open();
        sidecar.Close();
        SqliteConnection.ClearPool(sidecar);
    }

    private void ThrowIfFinished()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_completed)
        {
            throw new InvalidOperationException(
                "This bundle is sealed. Evidence is what a forest looked like at one moment, so "
                + "there is no way to add to it after that moment has been attested.");
        }
    }

    private SqliteCommand RetainInsert(ref SqliteCommand? command, string sql, ReadOnlySpan<string> parameters)
    {
        if (command is null)
        {
            var created = _connection.CreateCommand();
            try
            {
                created.CommandText = sql;
                foreach (var name in parameters)
                    created.Parameters.AddWithValue(name, DBNull.Value);
                _insertCommands.Add(created);
                command = created;
            }
            catch
            {
                created.Dispose();
                throw;
            }
        }

        // Absorb commits and replaces the transaction, but not this writer's connection.
        // Savepoint rollback keeps both; the next row must overwrite every binding either way.
        command.Transaction = _transaction;
        return command;
    }

    private void DisposeInsertCommands()
    {
        foreach (var command in _insertCommands)
        {
            command.Dispose();
            command.Parameters.Clear();
        }
        _insertCommands.Clear();
        _attributeInserts.Clear();
        _objectInsert = _descriptorInsert = _descriptorLinkInsert =
            _entryInsert = _entryLinkInsert = _trusteeInsert = null;
    }

    private void Execute(string sql, Action<SqliteCommand> bind)
    {
        using var command = _connection.CreateCommand();
        command.Transaction = _transaction;
        command.CommandText = sql;
        bind(command);
        command.ExecuteNonQuery();
    }

    /// <summary>
    /// A statement with nothing to bind: the set-based passes that run once when writing finishes.
    /// </summary>
    private void Execute(string sql)
    {
        using var command = _connection.CreateCommand();
        command.Transaction = _transaction;
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static void Pragma(SqliteConnection connection, string pragma)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA " + pragma;
        command.ExecuteNonQuery();
    }
}
