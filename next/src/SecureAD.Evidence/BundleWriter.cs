using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Naming;
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
    private static readonly Dictionary<string, CapturedAttribute> SingleValuedColumns =
        BundleSchema.SingleValuedColumns.ToDictionary(
            a => a.LdapDisplayName, StringComparer.OrdinalIgnoreCase);

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

    /// <summary>
    /// Distinct descriptors already stored, by the hexadecimal SHA-256 of their bytes. This is what
    /// makes the deduplication O(1) per object rather than a query per object.
    /// </summary>
    private readonly Dictionary<string, long> _descriptors = new(StringComparer.Ordinal);

    /// <summary>The partition each object was written against, so an unreadable descriptor can be counted against it.</summary>
    private readonly Dictionary<long, long> _objectCoverage = [];

    /// <summary>Objects per partition whose descriptor could not be read, written out in <see cref="Complete"/>.</summary>
    private readonly Dictionary<long, int> _unreadableDescriptors = [];
    private readonly Dictionary<long, Guid> _objectGuids = [];
    private readonly DateTimeOffset _startedUtc;

    private SqliteTransaction? _transaction;
    private long _nextObjectId = 1;
    private long _nextCoverageId = 1;
    private long _nextDescriptorId = 1;
    private long _nextTrusteeId = 1;
    private bool _completed;
    private bool _disposed;

    private BundleWriter(
        string bundleDirectory, string partialPath, SqliteConnection connection, DateTimeOffset startedUtc)
    {
        _bundleDirectory = bundleDirectory;
        _partialPath = partialPath;
        _connection = connection;
        _startedUtc = startedUtc;
    }

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
    public static BundleWriter Create(string bundleDirectory, DateTimeOffset startedUtc)
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

        var partialPath = BundleLayout.PartialPath(bundleDirectory);
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

        var writer = new BundleWriter(bundleDirectory, partialPath, connection, startedUtc);
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

        var key = (namingContextDn, controller);
        if (_coverageIds.ContainsKey(key))
        {
            throw new InvalidOperationException(
                $"'{namingContextDn}' on '{controller}' has already been opened. One pass reads "
                + "one partition on one controller, and a second row for the same pair would be a "
                + "second account of what was read.");
        }

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

        var columns = new List<string>();
        var columnValues = new List<object>();
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

                columns.Add(BundleSchema.ColumnNameFor(attribute.LdapDisplayName));
                columnValues.Add(StorageMatched(dn, single, attribute.Values[0]));
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

        var columnList = string.Concat(columns.Select(c => ", " + c));
        var parameterList = string.Concat(columns.Select((_, i) => $", $a{i}"));

        Execute(
            "INSERT INTO captured_object "
            + "(object_id, coverage_id, object_guid, distinguished_name, dn_reversed, "
            + $"parent_dn, parent_guid, domain_fqdn, captured_utc, ace_count{columnList}) "
            + "VALUES ($id, $coverage, $guid, $dn, $dnReversed, "
            + $"$parentDn, NULL, $domain, $captured, NULL{parameterList})",
            command =>
            {
                command.Parameters.AddWithValue("$id", objectId);
                command.Parameters.AddWithValue("$coverage", coverageId);
                command.Parameters.AddWithValue(
                    "$guid", (object?)evidenceObject.ObjectGuid?.ToString("D") ?? DBNull.Value);
                command.Parameters.AddWithValue("$dn", dn);
                command.Parameters.AddWithValue("$dnReversed", DnHelper.ReverseDn(dn));
                command.Parameters.AddWithValue(
                    "$parentDn", (object?)DnHelper.GetParentDn(dn) ?? DBNull.Value);
                command.Parameters.AddWithValue("$domain", DnHelper.DnToFqdn(dn));
                command.Parameters.AddWithValue(
                    "$captured", evidenceObject.CapturedUtc.UtcDateTime.ToString("O"));
                for (var i = 0; i < columnValues.Count; i++)
                    command.Parameters.AddWithValue($"$a{i}", columnValues[i]);
            });

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
    /// stored descriptor and one stored entry set, and the second object costs a hash and one row
    /// in <c>object_security_descriptor</c> rather than a parse and an insert per entry.
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

        Execute(
            "INSERT INTO object_security_descriptor (object_id, descriptor_id) "
            + "VALUES ($object, $descriptor)",
            command =>
            {
                command.Parameters.AddWithValue("$object", objectId);
                command.Parameters.AddWithValue("$descriptor", descriptorId);
            });
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
        Execute(
            """
            INSERT INTO security_descriptor (
                descriptor_id, sha256, byte_length, raw_bytes, owner_sid, group_sid,
                dacl_state, dacl_completeness, dacl_was_canonical,
                is_dacl_protected, ace_set_hash, canonicalization_version)
            VALUES ($id, $sha, $length, $raw, $owner, $group,
                    $dacl, $completeness, $canonical,
                    $protected, $setHash, $version)
            """,
            command =>
            {
                command.Parameters.AddWithValue("$id", descriptorId);
                command.Parameters.AddWithValue("$sha", sha256);
                command.Parameters.AddWithValue("$length", descriptorBytes.Length);
                command.Parameters.AddWithValue("$raw", descriptorBytes);
                command.Parameters.AddWithValue("$owner", (object?)normalization.OwnerSid ?? DBNull.Value);
                command.Parameters.AddWithValue("$group", (object?)normalization.GroupSid ?? DBNull.Value);
                command.Parameters.AddWithValue("$dacl", normalization.DaclState.ToString());
                command.Parameters.AddWithValue("$completeness", normalization.DaclCompleteness.ToString());
                command.Parameters.AddWithValue("$canonical", normalization.DaclWasCanonical ? 1 : 0);
                command.Parameters.AddWithValue("$protected", normalization.IsDaclProtected ? 1 : 0);
                command.Parameters.AddWithValue("$setHash", AceSetHash.Compute(normalization.Aces));
                command.Parameters.AddWithValue("$version", CanonicalizationVersionOf(normalization));
            });

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
            WriteAce(descriptorId, ordinal, normalization.Aces[ordinal]);
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
    public void Complete(RunCoverage coverage, DateTimeOffset completedUtc)
    {
        ArgumentNullException.ThrowIfNull(coverage);
        ThrowIfFinished();

        WriteUnreadableDescriptorCounts();

        Execute(
            """
            INSERT INTO bundle (
                schema_version, forest_fqdn, capture_started_utc, capture_completed_utc,
                coverage_id, every_declared_unit_recorded_as_read)
            VALUES ($version, $forest, $started, $completed, $coverage, $complete)
            """,
            command =>
            {
                command.Parameters.AddWithValue("$version", BundleSchema.Version);
                command.Parameters.AddWithValue("$forest", coverage.Declared.ForestFqdn);
                command.Parameters.AddWithValue("$started", _startedUtc.UtcDateTime.ToString("O"));
                command.Parameters.AddWithValue("$completed", completedUtc.UtcDateTime.ToString("O"));
                command.Parameters.AddWithValue("$coverage", coverage.Declared.Value);
                command.Parameters.AddWithValue(
                    "$complete", coverage.AllDeclaredUnitsAreComplete ? 1 : 0);
            });

        foreach (var domain in coverage.Domains)
        {
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
            Execute(
                """
                INSERT INTO sysvol_gpo_coverage (
                    gpo_guid, display_name, file_sys_path, outcome, reason)
                VALUES ($gpo, $name, $path, $outcome, $reason)
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
                });
        }

        _transaction!.Commit();
        _transaction.Dispose();
        _transaction = null;

        BundleSchema.CreateDeferredIndexes(_connection);

        // After the indexes, and deliberately. Both of these are set-based passes over every object
        // and both join on a column the deferred indexes have just created; run before, each would
        // be a scan per row.
        ResolveParentGuids();
        CountEntriesPerObject();

        Pragma(_connection, "wal_checkpoint(TRUNCATE)");
        _connection.Close();
        SqliteConnection.ClearPool(_connection);

        BundleSealing.Seal(_partialPath, BundleLayout.SealPath(_bundleDirectory));
        CreateAnnotationsSidecar();

        File.Move(_partialPath, BundleLayout.EvidencePath(_bundleDirectory));
        _completed = true;
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
                FROM ace
                WHERE ace.descriptor_id = (
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
        var table = BundleSchema.ValueTableNameFor(attribute.LdapDisplayName);

        for (var ordinal = 0; ordinal < attribute.Values.Count; ordinal++)
        {
            var value = StorageMatched(distinguishedName, attributeDefinition, attribute.Values[ordinal]);
            var position = ordinal;

            Execute(
                $"INSERT INTO {table} (object_id, ordinal, value) VALUES ($object, $ordinal, $value)",
                command =>
                {
                    command.Parameters.AddWithValue("$object", objectId);
                    command.Parameters.AddWithValue("$ordinal", position);
                    command.Parameters.AddWithValue("$value", value);
                });
        }
    }

    private void WriteAce(long descriptorId, int ordinal, CanonicalAce ace)
    {
        Execute(
            """
            INSERT INTO ace (
                descriptor_id, ordinal, ace_type, trustee_id, access_mask, object_type_guid,
                inherited_object_type_guid, is_inherited, inheritance_flags, propagation_flags, ace_hash)
            VALUES ($descriptor, $ordinal, $type, $trustee, $mask, $objectType,
                    $inheritedType, $inherited, $inheritance, $propagation, $hash)
            """,
            command =>
            {
                command.Parameters.AddWithValue("$descriptor", descriptorId);
                command.Parameters.AddWithValue("$ordinal", ordinal);
                command.Parameters.AddWithValue("$type", ace.AceType.ToString());
                command.Parameters.AddWithValue("$trustee", TrusteeId(ace.TrusteeSid));
                command.Parameters.AddWithValue("$mask", ace.AccessMask);
                command.Parameters.AddWithValue("$objectType", (object?)ace.ObjectTypeGuid ?? DBNull.Value);
                command.Parameters.AddWithValue(
                    "$inheritedType", (object?)ace.InheritedObjectTypeGuid ?? DBNull.Value);
                command.Parameters.AddWithValue("$inherited", ace.IsInherited ? 1 : 0);
                command.Parameters.AddWithValue("$inheritance", ace.InheritanceFlags);
                command.Parameters.AddWithValue("$propagation", ace.PropagationFlags);
                command.Parameters.AddWithValue("$hash", ace.AceHash);
            });
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
        Execute(
            "INSERT INTO trustee (trustee_id, sid) VALUES ($id, $sid)",
            command =>
            {
                command.Parameters.AddWithValue("$id", trusteeId);
                command.Parameters.AddWithValue("$sid", sid);
            });

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
