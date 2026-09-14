using Microsoft.Data.Sqlite;
using SecureAD.Evidence.Inventory;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.GroupPolicy;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using System.Globalization;
using System.Resources;

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
    int CapturedAttributeCatalogVersion,
    int SchemaGuidCatalogVersion,
    int SecurityDescriptorParserVersion,
    string ForestFqdn,
    DateTimeOffset CaptureStartedUtc,
    DateTimeOffset CaptureCompletedUtc,
    string CoverageId,
    bool EveryDeclaredUnitRecordedAsRead,
    ContinuationReconciliationOutcome ContinuationReconciliationOutcome);

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
    private (long ObjectId, string Dn)? _streamedIdentity;
    private bool? _streamedNamesAreUnambiguous;

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

    /// <summary>The capture's persisted continuation-reference reconciliation.</summary>
    public ContinuationReconciliation ContinuationReconciliation => ReadReconciliation(_connection);

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
                DataSource = ImmutableDataSource(evidencePath),
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());

        try
        {
            connection.Open();

            // THE VERSION IS READ ON ITS OWN, AND BEFORE ANYTHING ELSE. Every check below compares
            // a number that lives in a column some earlier build did not write, so reading the
            // whole description first makes the version gate unreachable for exactly the bundles it
            // exists to refuse: the SELECT throws on the missing column and the failure falls
            // through to the SqliteException handler, which reports a raw SQLite error and blames
            // this build.
            //
            // SEEN 2026-09-03. A schema 8 bundle opened against this schema 9 build said "no such
            // column: captured_attribute_catalog_version" and "this is a defect in this build
            // rather than damage to the bundle" - neither of which was true, and the operator went
            // looking for a defect that was not there. schema_version has existed in every version
            // of this table, so asking for it alone always works.
            var storedVersion = ReadSchemaVersion(connection, evidencePath);

            if (storedVersion != BundleSchema.Version)
            {
                connection.Dispose();
                return Failure(
                    "SchemaVersionUnsupported",
                    $"The bundle was written against schema version {storedVersion} "
                    + $"and this build reads version {BundleSchema.Version}. Nothing in this "
                    + "product is kept backward compatible, so a bundle from another build is "
                    + "captured again rather than migrated.",
                    evidencePath);
            }

            var description = ReadDescription(connection, evidencePath);

            if (description.CapturedAttributeCatalogVersion != CapturedAttributeCatalog.Version)
            {
                connection.Dispose();
                return Failure(
                    "CapturedAttributeCatalogVersionUnsupported",
                    $"The bundle captured attribute catalogue version "
                    + $"{description.CapturedAttributeCatalogVersion} and this build uses version "
                    + $"{CapturedAttributeCatalog.Version}. The bundle cannot establish that its "
                    + "attribute scope matches this build, so the forest must be captured again.",
                    evidencePath);
            }

            if (description.SchemaGuidCatalogVersion != SchemaGuidCatalog.Version)
            {
                connection.Dispose();
                return Failure(
                    "SchemaGuidCatalogVersionUnsupported",
                    $"The bundle used shipped schema GUID catalogue version "
                    + $"{description.SchemaGuidCatalogVersion} and this build uses version "
                    + $"{SchemaGuidCatalog.Version}. Stored permission projections cannot be "
                    + "attributed to this build's catalogue, so the forest must be captured again.",
                    evidencePath);
            }

            if (description.SecurityDescriptorParserVersion != SecurityDescriptorParser.Version)
            {
                connection.Dispose();
                return Failure(
                    "SecurityDescriptorParserVersionUnsupported",
                    $"The bundle parsed security descriptors with semantic version "
                    + $"{description.SecurityDescriptorParserVersion} and this build implements "
                    + $"version {SecurityDescriptorParser.Version}. The stored interpretation is "
                    + "not compatible with this build, so the forest must be captured again.",
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

    /// <summary>Reads failed-controller history; an unreadable history never means no failures.</summary>
    public Result<IReadOnlyList<DomainCaptureFailure>> ReadDomainCaptureFailures()
    {
        try
        {
            using var command = Connection.CreateCommand();
            command.CommandText =
                """
                SELECT naming_context_dn, controller, attempt, started_utc, failed_utc,
                       error_category, error_code, error_severity, error_description, error_context
                FROM domain_capture_failure ORDER BY naming_context_dn, attempt
                """;
            using var reader = command.ExecuteReader();
            var failures = new List<DomainCaptureFailure>();
            while (reader.Read())
            {
                failures.Add(new DomainCaptureFailure(
                    reader.GetString(0), reader.GetString(1), reader.GetInt32(2),
                    ParseUtc(reader.GetString(3)), ParseUtc(reader.GetString(4)),
                    new AuditError(
                        Enum.Parse<ErrorCategory>(reader.GetString(5)), reader.GetString(6),
                        Enum.Parse<ErrorSeverity>(reader.GetString(7)), reader.GetString(8),
                        reader.IsDBNull(9) ? null : reader.GetString(9))));
            }

            return Result<IReadOnlyList<DomainCaptureFailure>>.Success(failures);
        }
        catch (SqliteException error)
        {
            var resources = new ResourceManager("SecureAD.Evidence.Resources.CaptureFailover", typeof(BundleReader).Assembly);
            var text = resources.GetString("HistoryUnreadable", CultureInfo.CurrentUICulture)
                ?? throw new MissingManifestResourceException("HistoryUnreadable");
            return Result<IReadOnlyList<DomainCaptureFailure>>.Failure(ScopeError(
                "DomainCaptureHistoryUnreadable",
                string.Format(CultureInfo.CurrentCulture, text, error.Message)));
        }
    }

    /// <summary>
    /// Reads the exact roots and kinds of captured naming contexts from partition coverage.
    /// Absence means no captured root, not an empty partition or permission denial.
    /// Conflicting kinds for one root are refused rather than resolved by row order.
    /// </summary>
    public Result<IReadOnlyDictionary<string, NamingContextKind>> ReadNamingContexts()
    {
        var resources = new ResourceManager("SecureAD.Evidence.Resources.NamingContextReading", typeof(BundleReader).Assembly);
        string Text(string name) => resources.GetString(name, CultureInfo.CurrentUICulture) ?? throw new MissingManifestResourceException(name);
        try
        {
            using var command = Connection.CreateCommand();
            command.CommandText = "SELECT DISTINCT naming_context_dn, naming_context_kind FROM partition_coverage ORDER BY naming_context_dn";
            using var reader = command.ExecuteReader();
            var roots = new Dictionary<string, NamingContextKind>(StringComparer.OrdinalIgnoreCase);
            while (reader.Read())
            {
                var dn = reader.GetString(0);
                if (string.IsNullOrWhiteSpace(dn) || !Enum.TryParse<NamingContextKind>(reader.GetString(1), out var kind)
                    || !Enum.IsDefined(kind) || roots.TryGetValue(dn, out var previous) && previous != kind)
                    return Result<IReadOnlyDictionary<string, NamingContextKind>>.Failure(ScopeError("NamingContextScopeInvalid", Text("Invalid")));
                roots[dn] = kind;
            }
            return Result<IReadOnlyDictionary<string, NamingContextKind>>.Success(roots);
        }
        catch (SqliteException error)
        {
            return Result<IReadOnlyDictionary<string, NamingContextKind>>.Failure(ScopeError("NamingContextScopeUnreadable",
                string.Format(CultureInfo.CurrentCulture, Text("Unreadable"), error.Message)));
        }
    }

    /// <summary>
    /// Every object in the bundle, streamed, beside whether the run that captured them read
    /// everything it declared.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>For a caller that has to look at all of them.</b> <see cref="ReadObjectAttributes"/> is
    /// the right shape for one object a person clicked on and the wrong shape for a forest: it
    /// fetches an object row and its batched values separately for each requested object.
    /// This walks the object table and each value table once, in step.
    /// </para>
    /// <para>
    /// <b>It is lazy, and the connection must outlive the enumeration.</b> Nothing is held but the
    /// object being assembled, so a caller may walk a forest without the bundle ever being in
    /// memory - but disposing this reader part way through invalidates the sequence.
    /// </para>
    /// </remarks>
    public BundleObjects StreamObjects() =>
        new(Description.EveryDeclaredUnitRecordedAsRead,
            ObjectStreamReader.Stream(Connection, (id, dn) => _streamedIdentity = (id, dn)));

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
    /// Counts what this run captured, per domain, beside what it was able to read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>It goes through <see cref="ReadScope"/> rather than counting the object table alone.</b>
    /// A count of objects cannot say whether a domain is missing from it because it held nothing or
    /// because nobody could read it, and those two render identically as a zero. The coverage is
    /// the only thing that tells them apart, so the counts are never produced without it.
    /// </para>
    /// <para>
    /// A run whose coverage cannot be established yields a failure rather than counts. A number
    /// whose denominator is unknown is worse than no number, because it looks like an answer.
    /// </para>
    /// </remarks>
    /// <returns>What the forest held, or why that could not be established.</returns>
    public Result<ForestInventory> ReadInventory() =>
        InventoryReader.Read(Connection, Description, ReadScope());

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
    /// The name a security identifier is known by in this bundle, for showing a principal a rule
    /// found by identifier alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Microsoft's table first, then what this run captured, and nowhere else.</b> The same order
    /// <c>ObjectPermissions</c> resolves a trustee in, and for the same reason: a well-known
    /// identifier means the same thing in every forest and has no captured object worth preferring,
    /// while everything else is only a name if this run read the object holding it.
    /// </para>
    /// <para>
    /// <b>Null is an answer and not a failure.</b> A principal from a trusted forest, or one left
    /// behind by a deleted object, has no name here - and showing the identifier is then the honest
    /// thing rather than inventing one.
    /// </para>
    /// <para>
    /// <b>Cheap only because the identifier is indexed</b>, from bundle schema 10. Before that this
    /// was a full table scan, and a caller resolving a membership path per finding would have made
    /// the product unusable on a large forest. See <c>P-128</c>.
    /// </para>
    /// </remarks>
    /// <param name="sid">The security identifier, as the directory writes it.</param>
    public string? PrincipalNameFor(string sid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);

        if (WellKnownSidCatalog.FindBySid(sid) is { } wellKnown)
            return wellKnown.DisplayName;

        if (Sid.ToBytes(sid) is not { } bytes)
            return null;

        using var command = Connection.CreateCommand();
        command.CommandText =
            "SELECT distinguished_name FROM captured_object WHERE objectsid = $sid LIMIT 1";
        command.Parameters.Add("$sid", SqliteType.Blob).Value = bytes;

        return command.ExecuteScalar() is string dn ? DnHelper.ExtractFirstRdn(dn) : null;
    }

    /// <summary>
    /// Reads the machine-side registry settings this bundle holds for one Group Policy Object.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The user scope is never returned.</b> A policy carries both halves and they configure
    /// different things; a caller asking for a machine setting that is only present under the user
    /// scope has its answer, and returning the user value would silently substitute one for the
    /// other.
    /// </para>
    /// <para>
    /// <b>The bytes are decoded by the caller rather than here.</b> <c>value_data</c> is stored raw
    /// because a REG_MULTI_SZ holds several strings and a REG_BINARY holds none, so rendering at
    /// capture would decide a question the reader is better placed to answer.
    /// <see cref="RegistryPolicyEntry.AsString"/> does that decoding, and returns null for a type
    /// that is not a string - which is a different answer from the value being absent.
    /// </para>
    /// <para>
    /// <b>Ordered by <c>ordinal</c>, which is the order the file stated them in.</b> A policy may
    /// set the same value twice, and the last one is what a machine applies.
    /// </para>
    /// </remarks>
    /// <param name="gpoGuid">The policy whose settings to read.</param>
    /// <returns>
    /// The entries, beside a statement of whether the policy's files were read. The two are
    /// returned together because an empty list otherwise means three different things - a policy
    /// that configures nothing, one whose files could not be read, and a bundle captured without
    /// SYSVOL - and a caller reading the first for the others would report a policy as harmless
    /// when nobody looked.
    /// </returns>
    public GpoRegistrySettings ReadGpoMachineRegistrySettings(Guid gpoGuid)
    {
        var identifier = gpoGuid.ToString("D");
        var (outcome, reason) = SysvolCoverageOf(identifier);

        if (outcome is GpoSettingsOutcome.NotCaptured or GpoSettingsOutcome.Unreadable)
            return new GpoRegistrySettings([], outcome, reason);

        using var command = Connection.CreateCommand();
        command.CommandText =
            """
            SELECT key_path, value_name, registry_type, value_data
            FROM gpo_registry_setting
            WHERE gpo_guid = $gpo AND scope = 'Machine'
            ORDER BY ordinal
            """;
        command.Parameters.AddWithValue("$gpo", identifier);

        var settings = new List<RegistryPolicyEntry>();
        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            settings.Add(new RegistryPolicyEntry(
                reader.GetString(0),
                reader.GetString(1),
                (uint)reader.GetInt64(2),
                (byte[])reader[3]));
        }

        return new GpoRegistrySettings(settings, outcome, reason);
    }

    /// <summary>
    /// What capture recorded about reading one policy's files, or that it never looked.
    /// </summary>
    /// <remarks>
    /// <b>A policy absent from the coverage table was never offered to the SYSVOL read at all</b>,
    /// which is what a capture taken without SYSVOL looks like from here. That is reported as
    /// <see cref="GpoSettingsOutcome.NotCaptured"/> rather than as an unreadable policy, because
    /// the two send an operator to different places.
    /// </remarks>
    private (GpoSettingsOutcome Outcome, string? Reason) SysvolCoverageOf(string gpoGuid)
    {
        using var command = Connection.CreateCommand();
        command.CommandText =
            "SELECT outcome, reason FROM sysvol_gpo_coverage WHERE gpo_guid = $gpo LIMIT 1";
        command.Parameters.AddWithValue("$gpo", gpoGuid);

        using var reader = command.ExecuteReader();

        if (!reader.Read())
            return (GpoSettingsOutcome.NotCaptured, "This capture did not read SYSVOL.");

        var reason = reader.IsDBNull(1) ? null : reader.GetString(1);

        return reader.GetString(0) switch
        {
            "Read" => (GpoSettingsOutcome.Read, null),
            "PartiallyRead" => (GpoSettingsOutcome.PartiallyRead, reason),
            _ => (GpoSettingsOutcome.Unreadable, reason),
        };
    }

    /// <summary>
    /// Reads the permissions this bundle holds for one object.
    /// </summary>
    /// <param name="distinguishedName">The object the operator selected.</param>
    /// <returns>
    /// What the bundle holds, or null when it captured no object by that name. Null is the answer
    /// to a different question from an object with no entries, and is kept apart from it for the
    /// reason <see cref="DescriptorAvailability"/> gives.
    /// </returns>
    public ObjectPermissions? ReadPermissions(string distinguishedName)
    {
        var connection = Connection;
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);

        if (_streamedIdentity is { } identity
            && string.Equals(identity.Dn, distinguishedName, StringComparison.Ordinal)
            && StreamedNamesAreUnambiguous())
            return ObjectPermissionsReader.ReadAt(connection, identity.ObjectId, identity.Dn);

        return ObjectPermissionsReader.Read(connection, distinguishedName);
    }

    private bool StreamedNamesAreUnambiguous()
    {
        if (_streamedNamesAreUnambiguous is { } known)
            return known;

        // Checked once with SQLite's own NOCASE rules, not .NET's Unicode case folding.
        // Ambiguous evidence keeps the original name lookup and its original selection.
        using var command = Connection.CreateCommand();
        command.CommandText =
            "SELECT 1 FROM captured_object GROUP BY distinguished_name COLLATE NOCASE "
            + "HAVING COUNT(*) > 1 LIMIT 1";
        using var reader = command.ExecuteReader();
        var unambiguous = !reader.Read();
        _streamedNamesAreUnambiguous = unambiguous;
        return unambiguous;
    }

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

    /// <summary>
    /// Reads the forest's <c>dSHeuristics</c> string, which holds one forest-wide setting per
    /// character position.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Read once for a bundle, not once for an object.</b> There is one <c>nTDSService</c> object
    /// in a forest and its answer is the same for every object judged against it.
    /// </para>
    /// <para>
    /// <b>Three states, and the third is why this does not return a bare string.</b> A forest that
    /// never set the attribute answers with the empty string, which is a real answer — MS-ADTS says
    /// every character then takes its documented default. A bundle whose configuration partition was
    /// never read answers <c>null</c>, which is not an answer at all. Collapsing the two would let a
    /// run that could not look report the forest's defaults, which is the shape
    /// <c>docs/decisions/0002</c> exists to prevent, and here it would decide whether an owner keeps
    /// the right to rewrite an object's permissions.
    /// </para>
    /// </remarks>
    /// <returns>
    /// The attribute's value, the empty string where the service object carries none, or null where
    /// no service object was captured.
    /// </returns>
    public string? ReadForestHeuristics()
    {
        // A BUNDLE WITH NO CAPTURED OBJECTS HELD NONE, so nothing was read and null is the honest
        // answer rather than an exception. Asked explicitly instead of catching the error, because
        // swallowing a SQL failure would also swallow a real one.
        //
        // THIS CHECK ONCE NAMED THE WRONG TABLE AND HID A DEFECT FOR EXACTLY THAT REASON. Written
        // against 'object' rather than 'captured_object', it returned null for every bundle, so
        // SEC-031 and SEC-060 refused every computer object in the forest with "the forest setting
        // was never read" - and the refusal looked like correct caution. Recorded as F-S45-5. The
        // table name is now the one BundleSchema creates, and the reader is exercised against a
        // real bundle rather than only against fixtures.
        using (var exists = Connection.CreateCommand())
        {
            exists.CommandText =
                "SELECT 1 FROM sqlite_master "
                + "WHERE type = 'table' AND name = 'captured_object' LIMIT 1";

            if (exists.ExecuteScalar() is null)
                return null;
        }

        using var command = Connection.CreateCommand();

        command.CommandText =
            $"""
            SELECT o.{BundleSchema.ColumnNameFor("dSHeuristics")}
            FROM captured_object AS o
            WHERE (SELECT v.value FROM objectclass_value AS v
                   WHERE v.object_id = o.object_id
                   ORDER BY v.ordinal DESC LIMIT 1) = 'nTDSService' COLLATE NOCASE
            LIMIT 1
            """;

        using var reader = command.ExecuteReader();

        if (!reader.Read())
            return null;

        return reader.IsDBNull(0) ? string.Empty : reader.GetString(0);
    }

    /// <summary>
    /// Reads the schema partition's attribute definitions, so a caller can tell an attribute this
    /// forest withholds from one a machine simply does not carry.
    /// </summary>
    /// <remarks>
    /// <b>Read once for a bundle, exactly as <see cref="ReadSchemaGuids"/> is.</b> The answer is the
    /// same for every object in the forest, so asking it per object would re-read the whole schema
    /// for each computer judged.
    /// </remarks>
    /// <returns>
    /// Every schema definition captured, with whether the schema partition was read at all - which
    /// is a different answer from a forest that withholds nothing.
    /// </returns>
    public SchemaAttributeReading ReadSchemaAttributes() =>
        CapturedSchemaAttributeReader.Read(Connection);

    /// <summary>
    /// Lists the computers beneath one container with their LAPS state, for the inventory.
    /// </summary>
    /// <remarks>
    /// <b>Every computer, including the ones the LAPS rules exclude.</b> The rules are silent about
    /// a domain controller and about a disabled account; an operator who could not see them here
    /// would have no way to tell a machine the product deliberately ignored from one it never
    /// captured.
    /// </remarks>
    /// <param name="containerDn">The container the operator selected.</param>
    /// <param name="scope">How much of what is beneath it to include.</param>
    /// <param name="pageNumber">The page to fetch, counting from one.</param>
    public LapsPage ListLapsComputers(string containerDn, ListingScope scope, int pageNumber) =>
        LapsInventoryReader.Read(Connection, containerDn, scope, pageNumber);

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
    internal static string ImmutableDataSource(string evidencePath) =>
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

    /// <summary>
    /// The schema version alone, asked for before anything else in the bundle is read.
    /// </summary>
    /// <remarks>
    /// <b>One column, because it is the only one that can be relied on to exist.</b> Every other
    /// column in this table arrived in some particular version, so a query naming them cannot be
    /// used to discover which version wrote the file - it fails first, and on a bundle from an older
    /// build it fails with a message about a missing column rather than about the version. This is
    /// the check that lets the refusal above say the true thing.
    /// </remarks>
    private static int ReadSchemaVersion(SqliteConnection connection, string evidencePath)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT schema_version FROM bundle";

        using var reader = command.ExecuteReader();

        if (!reader.Read())
        {
            throw new InvalidBundleException(
                $"'{evidencePath}' has no row in its 'bundle' table, so it does not say which "
                + "schema version wrote it. Every bundle this product writes records that before "
                + "it is sealed.");
        }

        return reader.GetInt32(0);
    }

    private static BundleDescription ReadDescription(
        SqliteConnection connection, string evidencePath)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT schema_version, forest_fqdn, capture_started_utc, capture_completed_utc,
                   coverage_id, every_declared_unit_recorded_as_read,
                   captured_attribute_catalog_version, schema_guid_catalog_version,
                   security_descriptor_parser_version, continuation_reconciliation_outcome
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
            reader.GetInt32(6),
            reader.GetInt32(7),
            reader.GetInt32(8),
            reader.GetString(1),
            ParseUtc(reader.GetString(2)),
            ParseUtc(reader.GetString(3)),
            reader.GetString(4),
            reader.GetInt64(5) != 0,
            Enum.Parse<ContinuationReconciliationOutcome>(reader.GetString(9)));
    }

    private static ContinuationReconciliation ReadReconciliation(SqliteConnection connection)
    {
        using var outcomeCommand = connection.CreateCommand();
        outcomeCommand.CommandText = "SELECT continuation_reconciliation_outcome FROM bundle";
        var outcome = Enum.Parse<ContinuationReconciliationOutcome>((string)outcomeCommand.ExecuteScalar()!);

        IReadOnlyList<string> Items(string kind)
        {
            using var command = connection.CreateCommand();
            command.CommandText =
                "SELECT value FROM continuation_reconciliation_item WHERE kind = $kind ORDER BY ordinal";
            command.Parameters.AddWithValue("$kind", kind);

            var values = new List<string>();
            using var reader = command.ExecuteReader();
            while (reader.Read())
                values.Add(reader.GetString(0));

            return values;
        }

        return new ContinuationReconciliation(
            outcome,
            Items("UnplannedNamingContext"),
            Items("UnreadableReference"),
            Items("SuppressedUnit"));
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
