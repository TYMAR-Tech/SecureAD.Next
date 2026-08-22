using Microsoft.Data.Sqlite;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Evidence;

/// <summary>
/// What a bundle says about itself: the run's own account of what it captured.
/// </summary>
/// <remarks>
/// <para>
/// This is the <c>bundle</c> row, and it is a different question from the seal. The seal says
/// whether these bytes have changed since the run finished; this says what the run claimed to
/// have done. A sealed bundle whose capture reached one domain of nine is entirely possible, and
/// <see cref="EveryDeclaredUnitRecordedAsRead"/> is where a reader learns it.
/// </para>
/// <para>
/// <b><see cref="CoverageId"/> is the stored string and not a <see cref="Run.CoverageId"/>.</b>
/// That type carries the domains it hashed so a refusal can name them, and those domains are not
/// in this row - so reconstructing one here would mean handing back a coverage identity with an
/// empty declaration, which is the half-populated value <see cref="Run.CoverageId"/> exists to
/// prevent.
/// </para>
/// </remarks>
/// <param name="SchemaVersion">The schema this bundle was written against.</param>
/// <param name="ForestFqdn">The forest the run captured.</param>
/// <param name="CaptureStartedUtc">When the run started.</param>
/// <param name="CaptureCompletedUtc">When it finished.</param>
/// <param name="CoverageId">The evidence identity the run recorded, as stored.</param>
/// <param name="EveryDeclaredUnitRecordedAsRead">
/// Whether every domain and forest partition the run declared was recorded as read. False means
/// the bundle is sealed evidence of an incomplete capture, which is a fact about the run and never
/// about the forest.
/// </param>
public sealed record BundleDescription(
    int SchemaVersion,
    string ForestFqdn,
    DateTimeOffset CaptureStartedUtc,
    DateTimeOffset CaptureCompletedUtc,
    string CoverageId,
    bool EveryDeclaredUnitRecordedAsRead);

/// <summary>
/// The one way a bundle gets read.
/// </summary>
/// <remarks>
/// <para>
/// <b>A bundle that does not verify is not opened.</b> <see cref="Open"/> verifies the seal first
/// and returns a failure for every state but <see cref="SealState.Intact"/>, per
/// <see cref="SealVerdict.MayBeOpened"/>. There is no lenient mode and no argument that suppresses
/// the check: a reader that can be asked to skip verification is a reader that will be, on the one
/// bundle where it mattered.
/// </para>
/// <para>
/// <b>The three refusals keep their own codes because their remedies differ.</b>
/// <see cref="SealState.Unreadable"/> means something happened to the seal - copy the bundle
/// again. <see cref="SealState.Mismatch"/> means the evidence changed after the run declared
/// itself finished - this is no longer the evidence. <see cref="SealState.Absent"/> means the
/// directory was assembled by something other than a capture. Collapsing them into one apology
/// would throw away what an operator needs to act on.
/// </para>
/// <para>
/// <b>Two further refusals follow the seal, and they are about versions rather than damage.</b>
/// <c>SchemaVersionUnsupported</c> means this build cannot read the tables.
/// <c>CanonicalizationVersionUnsupported</c> means it can read them perfectly and cannot reproduce
/// the hashes in them, because <see cref="AceCanonicalization.Version"/> has moved since the run.
/// They are separate numbers on purpose - one describes the storage, the other describes the
/// Kernel's own output, and F-S1-1 records the coupling that was removed to keep them apart - so
/// they are separate checks with separate remedies. Both refuse rather than warn, because a bundle
/// whose stored hashes cannot be recomputed will compare equal to nothing and unequal to
/// everything, and it would do it silently.
/// </para>
/// <para>
/// <b>The seal is not a signature and is not called one.</b> There is no key in this product, so
/// what it proves is accident - a truncated copy between the build machine and the lab, a failing
/// disk - and not a determined party. Nothing rendering these refusals may say otherwise.
/// </para>
/// <para>
/// <b>Opening is read-only, and the file is never written to.</b> The seal covers the evidence
/// exactly as it was sealed, so a reader that let SQLite journal into the directory would
/// invalidate the proof by the act of reading it. Annotations live outside the seal, in
/// <see cref="BundleLayout.AnnotationsFileName"/>, and are not this type's business.
/// </para>
/// <para>
/// <b>Every method here is synchronous</b>, for the reason
/// <see cref="BundleWriter"/> gives: SQLite has no asynchronous I/O, and an <c>async</c> surface
/// would await nothing and mislead every caller about what it costs.
/// </para>
/// </remarks>
public sealed class BundleReader : IDisposable
{
    private readonly SqliteConnection _connection;
    private bool _disposed;

    private BundleReader(
        string bundleDirectory, SqliteConnection connection, BundleDescription description)
    {
        BundleDirectory = bundleDirectory;
        _connection = connection;
        Description = description;
    }

    /// <summary>The directory this bundle was opened from.</summary>
    public string BundleDirectory { get; }

    /// <summary>What the run recorded about itself.</summary>
    public BundleDescription Description { get; }

    /// <summary>
    /// The open evidence database, for the readers built on top of this one.
    /// </summary>
    /// <remarks>
    /// Internal because a connection handed outside the assembly is a connection something can
    /// write through, and the whole guarantee here is that reading a bundle does not touch it.
    /// </remarks>
    internal SqliteConnection Connection
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _connection;
        }
    }

    /// <summary>
    /// Verifies the seal on <paramref name="bundleDirectory"/> and, only if it is intact, opens
    /// the evidence for reading.
    /// </summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    /// <returns>
    /// The open reader, or an <see cref="AuditError"/> saying which of the four seal states was
    /// hit - or that the evidence was sealed and still could not be read.
    /// </returns>
    public static Result<BundleReader> Open(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var verdict = BundleSealing.Verify(bundleDirectory);
        if (!verdict.MayBeOpened)
            return Refused(verdict, bundleDirectory);

        var evidencePath = BundleLayout.EvidencePath(bundleDirectory);
        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = Immutable(evidencePath),
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());

        try
        {
            connection.Open();
            var description = ReadDescription(connection, evidencePath);

            if (description.SchemaVersion != BundleSchema.Version)
            {
                connection.Dispose();
                return Failure(
                    "SchemaVersionUnsupported",
                    $"The bundle was written against schema version {description.SchemaVersion} "
                    + $"and this build reads version {BundleSchema.Version}. Nothing in this "
                    + "product is kept backward compatible, so a bundle from another build is "
                    + "captured again rather than migrated.",
                    evidencePath);
            }

            var canonicalizations = CanonicalizationVersionsIn(connection);
            if (canonicalizations.Any(version => version != AceCanonicalization.Version))
            {
                connection.Dispose();
                return Failure(
                    "CanonicalizationVersionUnsupported",
                    $"The bundle's access control entries were canonicalised by version "
                    + $"{string.Join(", ", canonicalizations)} and this build canonicalises to "
                    + $"version {AceCanonicalization.Version}. Every ace_hash and ace_set_hash in "
                    + "it was produced by a recipe this build no longer implements, so "
                    + "deduplication and run-to-run comparison would rest on values that cannot be "
                    + "reproduced. The descriptors themselves are undamaged - raw_bytes is what "
                    + "arrived from the directory - but this product does not migrate a bundle, so "
                    + "the forest is captured again.",
                    evidencePath);
            }

            return new BundleReader(bundleDirectory, connection, description);
        }
        catch (SqliteException error)
        {
            connection.Dispose();
            return Failure(
                "EvidenceUnreadable",
                $"The seal on '{bundleDirectory}' is intact and the evidence could not be read: "
                + $"{error.Message}. The bytes are the bytes that were sealed, so this is a defect "
                + "in this build rather than damage to the bundle.",
                evidencePath);
        }
        catch (InvalidBundleException error)
        {
            connection.Dispose();
            return Failure("EvidenceUnreadable", error.Message, evidencePath);
        }
    }

    /// <summary>
    /// Rebuilds the directory tree from the names this bundle holds.
    /// </summary>
    /// <remarks>
    /// Recomputed on each call rather than cached. The evidence is immutable and the tree is a
    /// pure function of it, so a cache would buy a second copy of the same answer and an
    /// obligation to keep it in step with nothing.
    /// </remarks>
    public DirectoryTree ReadTree() => DirectoryTreeReader.Read(Connection);

    /// <summary>
    /// Reads the findings this bundle carries, beside the rules that were run to produce them.
    /// </summary>
    /// <remarks>
    /// <b>Check <see cref="Findings.StoredFindings.DidNotRun"/> before reporting that nothing was
    /// found.</b> An empty findings list from a bundle no rule has been run over is not a clean
    /// forest, and per <c>docs/decisions/0002</c> must never be presented as one.
    /// </remarks>
    public Findings.StoredFindings ReadFindings() => Findings.FindingReader.Read(Connection);

    /// <summary>
    /// Reads how much of the forest this run covered, one entry per declared domain.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Recomputed on each call, for the reason <see cref="ReadTree"/> gives. It reads a handful of
    /// declaration rows rather than walking the captured objects, so it is cheap enough to run when
    /// a selection changes.
    /// </para>
    /// <para>
    /// <b>A refusal is a value here rather than an exception</b>, because every caller of this has
    /// something useful to say when coverage cannot be established - that it could not be - and
    /// none of them can do anything about it. It also keeps the count members below out of gate 4's
    /// reach honestly: a bare number cannot say whether it was measured, and wrapping the whole
    /// answer is what lets these be plain integers without <c>0 of 0 domains</c> ever reaching a
    /// screen as though it were a measurement.
    /// </para>
    /// <para>
    /// <b>An outcome this build does not recognise is refused, not guessed at.</b> Reporting it as
    /// unread would invent a failure and reporting it as read would invent a success.
    /// </para>
    /// </remarks>
    /// <returns>What became of each declared domain, or why that could not be established.</returns>
    public Result<RunScope> ReadScope()
    {
        using var command = Connection.CreateCommand();
        command.CommandText =
            "SELECT domain_fqdn, outcome, reason FROM domain_coverage ORDER BY domain_fqdn";

        var domains = new List<DomainCoverage>();

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var domain = reader.GetString(0);
            var outcome = reader.GetString(1);
            var reason = reader.IsDBNull(2) ? null : reader.GetString(2);

            var covered = AsCoverage(domain, outcome, reason);
            if (!covered.IsSuccess)
                return Result<RunScope>.Failure(covered.Error);

            domains.Add(covered.Value);
        }

        if (domains.Count == 0)
        {
            return Result<RunScope>.Failure(ScopeError(
                "CoverageAbsent",
                "This run records no domain at all. Every bundle carries one row per declared "
                + "domain, so an empty table means the run's coverage was never written rather "
                + "than that the forest has no domains."));
        }

        return Result<RunScope>.Success(RunScope.Of(Description.CoverageId, domains));
    }

    /// <summary>
    /// Turns one stored coverage row back into the type the rest of the product reads.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A sealed bundle cannot honestly say a domain was not read</b>, and one that does is
    /// refused rather than reported. Capture is fail-fast per
    /// <c>docs/decisions/0003</c>: a unit that could not be read returns before the seal, so the
    /// row cannot arise from a run this product completed. <c>UnreadOutcomeIsUnreachableTests</c>
    /// holds that invariant over the whole product, and reconstructing the state here would be the
    /// first thing to break it.
    /// </para>
    /// <para>
    /// A partially read domain is a different matter and is read back: the run reached it, said so,
    /// and <see cref="RunScope.ShortfallCount"/> carries it.
    /// </para>
    /// </remarks>
    private Result<DomainCoverage> AsCoverage(string domain, string outcome, string? reason)
    {
        switch (outcome)
        {
            case "Read":
                return Result<DomainCoverage>.Success(DomainCoverage.Read(domain));

            case "PartiallyRead":
                return Stated(domain, outcome, reason, r =>
                    DomainCoverage.PartiallyRead(domain, r));

            case "ExcludedByChoice":
                return Stated(domain, outcome, reason, r =>
                    DomainCoverage.Excluded(domain, ExclusionKind.ByChoice, r));

            case "ExcludedForWantOfCandidates":
                return Stated(domain, outcome, reason, r =>
                    DomainCoverage.Excluded(domain, ExclusionKind.ForWantOfCandidates, r));

            case "NotRead":
                return Result<DomainCoverage>.Failure(ScopeError(
                    "CoverageImpossible",
                    $"This run records {domain} as not read, which a sealed bundle cannot honestly "
                    + "say: a domain that could not be read ends the run before its evidence is "
                    + "sealed. The bundle was written by something other than this product, or it "
                    + "has been altered, so what the run covered cannot be established."));

            default:
                return Result<DomainCoverage>.Failure(ScopeError(
                    "CoverageUnrecognised",
                    $"This run records '{outcome}' for {domain}, which this build does not "
                    + "recognise. The bundle was written by a version that knew an outcome this "
                    + "one does not, so what the run covered cannot be established here."));
        }
    }

    /// <summary>
    /// Applies <paramref name="build"/> to a stated reason, refusing a row that has none.
    /// </summary>
    /// <remarks>
    /// The writer requires a reason for every outcome that is not <c>Read</c>, so its absence means
    /// the row was not written by this product. Supplying the missing half here would present a
    /// reader's guess as the run's own statement.
    /// </remarks>
    private Result<DomainCoverage> Stated(
        string domain, string outcome, string? reason, Func<string, DomainCoverage> build) =>
        string.IsNullOrWhiteSpace(reason)
            ? Result<DomainCoverage>.Failure(ScopeError(
                "CoverageUnexplained",
                $"This run records '{outcome}' for {domain} without saying why, and the writer "
                + "requires a reason. Supplying one here would present a guess as the run's own "
                + "statement."))
            : Result<DomainCoverage>.Success(build(reason));

    /// <summary>Builds a refusal naming this bundle, so a screen can say which run it means.</summary>
    private AuditError ScopeError(string reason, string description) =>
        AuditError.Create(
            ErrorCategory.Evidence, reason, ErrorSeverity.Failed, description, BundleDirectory);

    /// <summary>
    /// Lists one page of the objects captured in <paramref name="containerDn"/>.
    /// </summary>
    /// <param name="containerDn">The container the operator selected.</param>
    /// <param name="scope">How much of what is beneath it to include.</param>
    /// <param name="pageNumber">The page to fetch, counting from one.</param>
    public ObjectPage ListObjects(string containerDn, ListingScope scope, int pageNumber) =>
        ObjectListingReader.Read(Connection, containerDn, scope, pageNumber);

    /// <summary>
    /// Reads the permissions this bundle holds for one object.
    /// </summary>
    /// <param name="distinguishedName">The object the operator selected.</param>
    /// <returns>
    /// What the bundle holds, or null when it captured no object by that name. Null is the answer
    /// to a different question from an object with no entries, and is kept apart from it for the
    /// reason <see cref="DescriptorAvailability"/> gives.
    /// </returns>
    public ObjectPermissions? ReadPermissions(string distinguishedName) =>
        ObjectPermissionsReader.Read(Connection, distinguishedName);

    /// <summary>
    /// Reads every attribute value this bundle holds for one object.
    /// </summary>
    /// <param name="distinguishedName">The object the operator selected.</param>
    /// <returns>
    /// The whole catalogue, with a value where one arrived and none where it did not, or null when
    /// this bundle captured no object by that name. Null is the answer to a different question from
    /// an object whose attributes are all empty, for the reason <see cref="ObjectAttribute"/> gives.
    /// </returns>
    public ObjectAttributes? ReadObjectAttributes(string distinguishedName) =>
        ObjectAttributesReader.Read(Connection, distinguishedName);

    /// <summary>
    /// Reads the schema-GUID catalogue this run captured, laid over the shipped one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Read once for a bundle, not once for an object.</b> A forest's schema runs to thousands
    /// of definitions, and an access control entry names a GUID on nearly every row of every
    /// object - so resolving names per object would re-read the whole schema for each screen.
    /// </para>
    /// <para>
    /// A run refused the schema partition returns the shipped table alone, and
    /// <see cref="SchemaGuidCatalog.HasCapturedEntries"/> is how a caller tells that apart from a
    /// forest whose schema was read and happened to add nothing.
    /// </para>
    /// </remarks>
    public SchemaGuidCatalog ReadSchemaGuids()
    {
        var captured = CapturedSchemaGuidReader.Read(Connection);

        return SchemaGuidCatalog.CapturedOver(
            captured.Entries, SchemaGuidCatalog.Embedded, captured.PropertySetMembers);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
            return;

        _connection.Close();
        _connection.Dispose();
        _disposed = true;
    }

    /// <summary>
    /// Every distinct canonicalisation version the bundle's descriptors were normalised by.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The column is stored per descriptor rather than per run, so this is a set.</b> One run
    /// writes one version, so a healthy bundle answers with one value or - when the run captured no
    /// readable descriptor at all - with none. More than one is itself a defect, and the refusal
    /// names them all rather than picking one to report.
    /// </para>
    /// <para>
    /// <b>An empty answer opens.</b> A bundle holding no descriptors holds no hash that could be
    /// stale, and refusing it would report a version problem to an operator whose actual problem is
    /// that nothing was captured - which <c>partition_coverage</c> already states, in the terms
    /// they can act on.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<int> CanonicalizationVersionsIn(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT DISTINCT canonicalization_version FROM security_descriptor "
            + "ORDER BY canonicalization_version";

        var versions = new List<int>();

        using var reader = command.ExecuteReader();
        while (reader.Read())
            versions.Add(reader.GetInt32(0));

        return versions;
    }

    private static Result<BundleReader> Refused(SealVerdict verdict, string bundleDirectory) =>
        Failure(ReasonFor(verdict.State), verdict.Detail, bundleDirectory);

    /// <summary>
    /// The evidence file as a URI SQLite is told cannot change under it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Read-only is not enough on its own.</b> A bundle is left in write-ahead logging mode -
    /// that is a fact stored in the file's header, and the seal covers the header - so a plain
    /// read-only open creates a <c>-wal</c> and a <c>-shm</c> beside the evidence and leaves them
    /// there. Nothing about the sealed bytes changes, but a bundle that grows two files every time
    /// somebody looks at it is not the artefact this product promises, and the next reader cannot
    /// tell those files from the remains of an interrupted write.
    /// </para>
    /// <para>
    /// <c>immutable=1</c> is the accurate statement rather than a trick to suppress them: the seal
    /// has just been verified, so the file demonstrably cannot be changing while it is read. It is
    /// set only after <see cref="SealVerdict.MayBeOpened"/> has said so, and would be a lie
    /// anywhere else.
    /// </para>
    /// <para>
    /// The path is escaped whole. SQLite decodes <c>%XX</c> out of a URI, so a directory holding a
    /// <c>?</c> or a <c>#</c> - both legal in a Windows path and both meaningful in a URI - reaches
    /// it as the character the operator typed.
    /// </para>
    /// </remarks>
    private static string Immutable(string evidencePath) =>
        "file:" + Uri.EscapeDataString(evidencePath.Replace('\\', '/')) + "?immutable=1";

    /// <summary>
    /// The reason code one seal state is refused under. One per state, because an operator acts
    /// differently on each.
    /// </summary>
    private static string ReasonFor(SealState state) => state switch
    {
        SealState.Absent => "SealAbsent",
        SealState.Unreadable => "SealUnreadable",
        SealState.Mismatch => "SealMismatch",
        _ => throw new InvalidOperationException(
            $"{state} may be opened and is not a refusal. Only SealVerdict.MayBeOpened decides "
            + "which states those are, and this switch has fallen out of step with it."),
    };

    private static Result<BundleReader> Failure(
        string reason, string description, string context) =>
        Result<BundleReader>.Failure(
            AuditError.Create(
                ErrorCategory.Evidence, reason, ErrorSeverity.Failed, description, context));

    private static BundleDescription ReadDescription(
        SqliteConnection connection, string evidencePath)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT schema_version, forest_fqdn, capture_started_utc, capture_completed_utc,
                   coverage_id, every_declared_unit_recorded_as_read
            FROM bundle
            """;

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            // Unreachable for a bundle this product wrote: BundleWriter.Complete inserts this row
            // before it seals. Seeing it means the file was sealed by something else.
            throw new InvalidBundleException(
                $"'{evidencePath}' has no row in its 'bundle' table, so it does not say which "
                + "forest it captured or when. Every bundle this product writes records that "
                + "before it is sealed.");
        }

        return new BundleDescription(
            reader.GetInt32(0),
            reader.GetString(1),
            ParseUtc(reader.GetString(2)),
            ParseUtc(reader.GetString(3)),
            reader.GetString(4),
            reader.GetInt64(5) != 0);
    }

    /// <summary>
    /// Reads a time the writer stored in round-trip form.
    /// </summary>
    /// <remarks>
    /// Exact, and never a best effort. A time this build cannot parse is a disagreement between
    /// the writer and the reader in one assembly, and a lenient parse would render it as some
    /// other moment rather than as the defect it is.
    /// </remarks>
    private static DateTimeOffset ParseUtc(string stored) =>
        DateTimeOffset.ParseExact(
            stored,
            "O",
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal
            | System.Globalization.DateTimeStyles.AdjustToUniversal);

    /// <summary>
    /// A sealed file that is not a bundle this product wrote. Private to the open path, which
    /// turns it into the failure a caller sees.
    /// </summary>
    private sealed class InvalidBundleException(string message) : Exception(message);
}
