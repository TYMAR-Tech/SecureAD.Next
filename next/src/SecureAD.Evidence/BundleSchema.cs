using Microsoft.Data.Sqlite;
using SecureAD.Kernel.Capture;

namespace SecureAD.Evidence;

/// <summary>
/// Every table in a bundle, and the indexes built once writing is done.
/// </summary>
/// <remarks>
/// <para>
/// <b>All schema lives here.</b> No writer creates its own table, so <c>CREATE TABLE</c> appears
/// in one place and a writer cannot quietly invent a column that nothing else knows to read.
/// </para>
/// <para>
/// <b>The rule the shape of this schema follows.</b> Per <c>docs/decisions/0002</c> a missing
/// answer is a fact about the capture and never about the forest, and that question arrives here
/// one level lower down: an object with no permission rows either had no permissions or was never
/// read, and those are opposite findings that look identical if the only evidence is an empty
/// result.
/// </para>
/// <para>
/// So <b>coverage is recorded positively, as rows, and never inferred from their absence</b>. What
/// was read has a <c>partition_coverage</c> row; what was not read has none. An attribute that did
/// not come back is stored, with <c>NotReturned</c>, rather than being left out. A security
/// descriptor that failed to parse stores its errors, because zero permission rows with no errors
/// means <i>this object grants nothing</i> while zero with errors means <i>nobody knows what this
/// object grants</i>.
/// </para>
/// <para>
/// <b>Indexes are created after writing, not before.</b> A forest is millions of objects, and an
/// index maintained during ingest is paid for on every insert and read by nobody until the run is
/// over.
/// </para>
/// <para>
/// There is no migration path and no column added conditionally on open. Per
/// <c>docs/decisions/0001</c> nothing is kept backward compatible, and per
/// <c>docs/decisions/0013</c> the bundle is not a contract with anything, so a schema mismatch is
/// a broken build rather than an old file.
/// </para>
/// </remarks>
public static class BundleSchema
{
    /// <summary>
    /// The schema version stamped into every bundle.
    /// </summary>
    /// <remarks>
    /// Recorded so that a reader can refuse a bundle it does not understand, rather than
    /// misreading one. It is not a migration hook: there is nothing to migrate from.
    /// <para>
    /// <b>Raised to 6 when <c>finding</c> was added.</b> A version 5 bundle has no findings table,
    /// so a build that read one without refusing it would report no findings and be telling the
    /// truth about the table while lying about the forest. Refusing is what
    /// <c>docs/decisions/0001</c> intends and what <see cref="BundleReader"/> already does.
    /// </para>
    /// <para>
    /// <b>Raised to 7 when the password policy attributes were added.</b> The columns of
    /// <c>captured_object</c> and the per-attribute value tables are generated from
    /// <c>CapturedAttributeCatalog</c>, so widening the catalogue changes the schema whether or not
    /// a table is named here. A version 6 bundle has no column for <c>minPwdLength</c>, and a build
    /// that read one without refusing it would answer <i>no policy</i> where the truthful answer is
    /// <i>this bundle was never allowed to look</i>.
    /// </para>
    /// <para>
    /// <b>Raised to 8 when <c>finding</c> and <c>evaluated_rule</c> left.</b> Per
    /// <c>docs/decisions/0085</c> judgement writes beside the evidence rather than into it, so the
    /// three tables that held what a rule concluded now belong to the judgement store. A version 7
    /// bundle has them, and a build that read one without refusing it would be reading findings out
    /// of the sealed evidence - which is the arrangement the decision exists to end.
    /// </para>
    /// </remarks>
    /// <para>
    /// <b>Raised to 9 for capture provenance and continuation reconciliation.</b> Version 8 cannot
    /// state which catalogue and parser semantics produced it, or whether its continuation
    /// references were reconciled against the authorized plan.
    /// </para>
    // 11 records 0040's failed-controller history separately from successful partition coverage.
    // 12 records the classes deliberately excluded from this capture (P-224).
    //
    // 13 REPLACED `ace` WITH `access_entry` AND `descriptor_entry` (P-272), and this number had to
    // move with them. A version 12 bundle has a table this build does not query and lacks two it
    // does, so a build reading one without refusing it would fail on a missing table somewhere
    // downstream of having already said the bundle was readable.
    //
    // It was missed on the first pass, and the way it was nearly not caught is the point: the
    // canonicalisation gate would have refused those bundles anyway, because their entries carry
    // version 3 and this build canonicalises to 4. That is refusal by luck. The schema gate runs
    // first, it is the one that exists to say "this build cannot read these tables", and leaving it
    // at 12 meant it returned a pass on exactly the bundles it is there to stop - a check that goes
    // green while measuring nothing. The two numbers answer different questions and neither may
    // stand in for the other; F-S1-1 records the coupling that was removed to keep them apart.
    // 14 records the per-policy outcome of the optional SEC-083 XML scan. Version 13 always ran
    // that scan and cannot state whether a later capture deliberately omitted it.
    // 15 records the corrected Enatel storage-class scope; old V3-name scopes are not relabelled.
    // 16 adds the owner-approved account-class exclusion without relabelling storage-only captures.
    // 17 binds the first-class captured navigation product to its atomic capture root.
    public const int Version = 17;

    /// <summary>
    /// The catalogue attributes that are already columns on <c>captured_object</c> by another
    /// name, and are therefore not derived a second time.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both are identity rather than evidence, and both are typed by hand because of it.
    /// <c>distinguishedName</c> is <c>NOT NULL</c> where every derived column is nullable, and
    /// <c>objectGUID</c> is stored as text in its canonical form rather than as the bytes the
    /// catalogue asks for, because it is the value two bundles are joined on and a join wants one
    /// spelling.
    /// </para>
    /// <para>
    /// Held as a list so it can be checked. An exclusion that outlives its reason is invisible
    /// otherwise: <c>BundleSchemaTests</c> asserts every name here is really in the catalogue and
    /// really a column on <c>captured_object</c>, so removing either end fails rather than
    /// silently dropping an attribute out of the schema.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> StructurallyStoredAttributes { get; } =
    [
        "distinguishedName",
        "objectGUID",
    ];

    /// <summary>
    /// The tables that exist whatever the catalogue says.
    /// </summary>
    private static readonly string[] FixedTableNames =
    [
        "bundle",
        "capture_object_class_exclusion",
        "partition_coverage",
        "domain_capture_failure",
        "domain_coverage",
        "forest_partition_coverage",
        "continuation_reference",
        "continuation_reconciliation_item",
        "unread_partition",
        "excluded_domain",
        "captured_object",
        "security_descriptor",
        "object_security_descriptor",
        "security_descriptor_error",
        "unreadable_security_descriptor",
        "unresolved_reference",
        "trustee",
        "access_entry",
        "descriptor_entry",
        "sysvol_gpo_coverage",
        "gpo_registry_setting",
        "gpo_security_setting",
        "gpo_restricted_group",
        "gpo_stored_credential",
        "gpo_file_error",
        "sysvol_path_security_descriptor",
        "unreadable_sysvol_descriptor",
    ];

    /// <summary>
    /// Every single-valued attribute that becomes a column on <c>captured_object</c>.
    /// </summary>
    /// <remarks>
    /// Derived from the catalogue rather than listed, so the schema cannot describe a different
    /// set of attributes from the one capture asks for. A hand-written list agrees with the
    /// catalogue on the day it is written and stops agreeing the first time an attribute is added.
    /// </remarks>
    public static IReadOnlyList<CapturedAttribute> SingleValuedColumns { get; } =
        CapturedAttributeCatalog.All
            .Where(a => a.Cardinality == AttributeCardinality.SingleValued)
            .Where(a => !StructurallyStoredAttributes.Contains(a.LdapDisplayName, StringComparer.OrdinalIgnoreCase))
            .ToArray();

    /// <summary>
    /// Every multi-valued attribute, and the table it gets to itself.
    /// </summary>
    /// <remarks>
    /// <see cref="CapturedAttributeCatalog.RangeLiable"/> is the same set under the name capture
    /// uses for it: an attribute that can exceed the server's value limit is exactly an attribute
    /// that cannot be one column. Read from there rather than re-derived, so the two cannot drift.
    /// </remarks>
    public static IReadOnlyList<CapturedAttribute> MultiValuedTables { get; } =
        CapturedAttributeCatalog.RangeLiable;

    /// <summary>
    /// Every table a bundle contains.
    /// </summary>
    /// <remarks>
    /// Named here as data rather than left implicit in the DDL text, so that the document
    /// describing the schema can be compared against it in both directions - a table in the
    /// document and not in the code fails, and so does the reverse.
    /// </remarks>
    public static IReadOnlyList<string> TableNames { get; } =
        FixedTableNames
            .Concat(MultiValuedTables.Select(a => ValueTableNameFor(a.LdapDisplayName)))
            .ToArray();

    /// <summary>
    /// The column or table identifier one attribute is stored under: its <c>lDAPDisplayName</c>
    /// lowercased, with hyphens turned into underscores.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Deliberately not snake_case.</b> Splitting <c>sAMAccountName</c> on its capitals invents
    /// word boundaries the directory does not have and produces <c>s_am_account_name</c>; the same
    /// rule turns <c>nTSecurityDescriptor</c> into <c>n_t_security_descriptor</c>. Lowercasing
    /// keeps the name the directory owns, so a reader can map a column back to an attribute by eye
    /// rather than by guessing where the boundaries were.
    /// </para>
    /// <para>
    /// <b>It cannot collide.</b> The catalogue already treats names case-insensitively, so two
    /// entries differing only in case are one entry before this is reached. The remaining risk is a
    /// name that already contains an underscore, which would be reachable from two different
    /// display names - no catalogued attribute does, and <c>BundleSchemaTests</c> asserts it.
    /// </para>
    /// </remarks>
    /// <param name="ldapDisplayName">The attribute, as the catalogue names it.</param>
    public static string ColumnNameFor(string ldapDisplayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ldapDisplayName);
        return ldapDisplayName.ToLowerInvariant().Replace('-', '_');
    }

    /// <summary>
    /// The table one multi-valued attribute's values are stored in.
    /// </summary>
    /// <param name="ldapDisplayName">The attribute, as the catalogue names it.</param>
    public static string ValueTableNameFor(string ldapDisplayName) =>
        ColumnNameFor(ldapDisplayName) + "_value";

    /// <summary>
    /// The SQLite storage class one attribute's values are held in.
    /// </summary>
    /// <remarks>
    /// Text and bytes are kept apart at the column rather than reconciled later. A value that is
    /// bytes and gets stored as text is not an error that surfaces - it is a mangled string that
    /// looks like data, and <c>objectSid</c> and the descriptors deciding who can take an identity
    /// over are all bytes.
    /// </remarks>
    /// <param name="storage">How the catalogue says the attribute arrives.</param>
    private static string SqlTypeFor(AttributeStorage storage) =>
        storage == AttributeStorage.Binary ? "BLOB" : "TEXT";

    private static readonly string[] TablesBeforeObject =
    [
        // Only the run writer records history, after domain attempts finish. An empty table in
        // this schema means no controller attempt failed, not that capture omitted the history.
        """
        CREATE TABLE domain_capture_failure (
            naming_context_dn TEXT NOT NULL,
            controller TEXT NOT NULL,
            attempt INTEGER NOT NULL CHECK (attempt > 0),
            started_utc TEXT NOT NULL,
            failed_utc TEXT NOT NULL,
            error_category TEXT NOT NULL,
            error_code TEXT NOT NULL,
            error_severity TEXT NOT NULL,
            error_description TEXT NOT NULL,
            error_context TEXT NULL,
            PRIMARY KEY (naming_context_dn, attempt)
        )
        """,

        """
        CREATE TABLE capture_object_class_exclusion (
            class_name TEXT NOT NULL COLLATE NOCASE PRIMARY KEY
        )
        """,

        // One row, written when the run finishes. The bundle's own account of itself.
        //
        // This is a different question from the seal and the two must not be confused. The seal
        // says whether these bytes have changed; this row says what the run claimed to have done.
        // A sealed bundle whose capture failed is entirely possible, and a reader must be able to
        // tell.
        """
        CREATE TABLE bundle (
            schema_version           INTEGER NOT NULL,
            captured_attribute_catalog_version INTEGER NOT NULL,
            schema_guid_catalog_version INTEGER NOT NULL,
            security_descriptor_parser_version INTEGER NOT NULL,
            capture_generation_id    TEXT    NOT NULL,
            forest_fqdn              TEXT    NOT NULL,
            capture_started_utc      TEXT    NOT NULL,
            capture_completed_utc    TEXT    NOT NULL,
            coverage_id              TEXT    NOT NULL,
            every_declared_unit_recorded_as_read INTEGER NOT NULL,
            continuation_reconciliation_outcome TEXT NOT NULL
                                     CHECK (continuation_reconciliation_outcome IN
                                            ('NotPerformed', 'Complete', 'Incomplete')),
            only_one_row             INTEGER NOT NULL DEFAULT 1
                                     CHECK (only_one_row = 1),
            PRIMARY KEY (only_one_row)
        )
        """,

        """
        CREATE TABLE continuation_reconciliation_item (
            kind                     TEXT    NOT NULL
                                     CHECK (kind IN
                                            ('UnplannedNamingContext', 'UnreadableReference',
                                             'SuppressedUnit')),
            ordinal                  INTEGER NOT NULL,
            value                    TEXT    NOT NULL,
            PRIMARY KEY (kind, ordinal)
        )
        """,

        // What became of each domain the forest declared when the run started.
        //
        // This is the denominator a bundle's coverage is measured against, and before it existed a
        // sealed bundle recorded no such thing: a run that reached one domain of nine sealed a
        // bundle that said only which forest it was, and nothing a reader could use to tell that
        // eight domains were never contacted. That is F-S28-1 at the artefact.
        //
        // Every declared domain has a row, including those that were not read, because a domain
        // nobody looked at must not be indistinguishable from one that held nothing.
        """
        CREATE TABLE domain_coverage (
            domain_fqdn              TEXT    NOT NULL,
            outcome                  TEXT    NOT NULL,
            reason                   TEXT    NULL,
            PRIMARY KEY (domain_fqdn)
        )
        """,

        // What an operator stated when a domain was left out of this run.
        //
        // docs/decisions/0062-what-an-exclusion-attestation-asks-for.md requires the whole
        // attestation reach the bundle: the reason, the free text, both names and the time. An
        // exclusion that governed a run but was not stored with it is a fact about the audit that
        // the audit does not carry, and the first person to need it is an auditor reading the run
        // months later with the operator unavailable and the screen long gone.
        //
        // NO ROWS MEANS NO DOMAIN WAS EXCLUDED. It does not mean the attestation was not recorded.
        // Every table says what its absence means, per the rule what-a-bundle-holds.md binds.
        //
        // kind separates a domain the operator took out from one the forest named no writable
        // controller for. Both are exclusions under 0054, and
        // docs/decisions/0063-excluded-never-looks-like-unreachable.md forbids them being merged -
        // here most of all, because a bundle is read without a screen or an operator to ask.
        //
        // reason is a stable identifier and never the sentence shown on screen. The wording may be
        // improved; what a value means may not change, because runs already recorded carry it -
        // the footing docs/decisions/0024-a-rule-identifier-is-permanent.md sets for rules.
        //
        // authorised_by IS NOT VALIDATED AND CANNOT BE. It is a typed string and a statement of
        // accountability, not an identity. Nothing reading it may present it as verified.
        """
        CREATE TABLE excluded_domain (
            naming_context_dn        TEXT    NOT NULL,
            kind                     TEXT    NOT NULL,
            reason                   TEXT    NOT NULL,
            note                     TEXT    NULL,
            run_by                   TEXT    NOT NULL,
            authorised_by            TEXT    NOT NULL,
            attested_utc             TEXT    NOT NULL,
            PRIMARY KEY (naming_context_dn)
        )
        """,

        // And what became of the two partitions belonging to the forest rather than to any domain.
        // Held apart from domain_coverage per docs/decisions/0035: a run that could not read the
        // schema partition has failed outright rather than found a domain with a problem, and per
        // docs/decisions/0014 nothing in the bundle can be interpreted without it.
        """
        CREATE TABLE forest_partition_coverage (
            naming_context_dn        TEXT    NOT NULL,
            kind                     TEXT    NOT NULL,
            outcome                  TEXT    NOT NULL,
            reason                   TEXT    NULL,
            PRIMARY KEY (kind)
        )
        """,

        // One row per naming context actually read. This is the positive record of coverage:
        // an object's absence means something only because the partition it would have come from
        // either has a row here or does not.
        //
        // referrals_suppressed is carried rather than folded into
        // continuation_references_are_complete, because a unit that
        // asked a controller not to generate continuation references cannot read an empty
        // reference list as "there is nothing below here" - it means "we asked not to be told".
        //
        // connection_security is the rung this partition was actually read over. A Windows Server
        // 2025 controller strips confidential attributes from an unencrypted search and returns no
        // error to the client, so a partition read over 'Signed' can be missing values that nothing
        // else in the bundle records as absent. Without this column a reader would take that
        // silence for a fact about the forest, which is what docs/decisions/0002 forbids. F-S24-1.
        """
        CREATE TABLE partition_coverage (
            coverage_id              INTEGER PRIMARY KEY,
            naming_context_dn        TEXT    NOT NULL,
            naming_context_kind      TEXT    NOT NULL
                                     CHECK (naming_context_kind IN ('Domain', 'Configuration', 'Schema')),
            controller               TEXT    NOT NULL,
            connection_security      TEXT    NOT NULL
                                     CHECK (connection_security IN
                                            ('Ldaps', 'SignedAndSealed', 'Signed', 'Unprotected')),
            pages_read               INTEGER NOT NULL,
            objects_read             INTEGER NOT NULL,
            attribute_blocks_fetched INTEGER NOT NULL,
            unreadable_descriptors   INTEGER NOT NULL DEFAULT 0,
            referrals_suppressed     INTEGER NOT NULL CHECK (referrals_suppressed IN (0, 1)),
            continuation_references_are_complete
                                     INTEGER NOT NULL
                                     CHECK (continuation_references_are_complete IN (0, 1)),
            UNIQUE (naming_context_dn, controller)
        )
        """,

        // Continuation references a controller returned. Stored as rows rather than counted,
        // because a count of them answers no question anybody asks.
        """
        CREATE TABLE continuation_reference (
            coverage_id              INTEGER NOT NULL REFERENCES partition_coverage(coverage_id),
            ordinal                  INTEGER NOT NULL,
            referral                 TEXT    NOT NULL,
            PRIMARY KEY (coverage_id, ordinal)
        )
        """,

        // The application directory partitions the forest declares and this product does not read -
        // in practice the DNS zone partitions, which every forest has. Its own table rather than a
        // row in partition_coverage, which docs/decisions/0035 makes the positive record of what a
        // capture unit read: nothing here was read, so that table's controller, pages, objects and
        // connection rung have no value, and rows carrying none of them would make every existing
        // count of partitions read wrong without an error.
        //
        // Recorded at all because the alternative is silence. The run prints these to the console
        // and the console is gone by the time anyone opens the evidence, so a reader could not tell
        // a forest whose DNS partitions were skipped from a forest that has none - the inference
        // docs/decisions/0002 forbids being available, about a part of the directory
        // docs/decisions/0052 requires a run to state it did not reach. F-S31-5.
        //
        // No reason column. Every row has the same cause - the DNS scope decision of 2026-08-11,
        // which puts DNS zones and records out of scope - so a reason would ship as a vocabulary
        // with one hardcoded literal filling it, which is F-S30-2 rebuilt in a new table. A second
        // cause is when the column earns its place.
        """
        CREATE TABLE unread_partition (
            naming_context_dn        TEXT NOT NULL PRIMARY KEY
        )
        """,

        ];

        /// <summary>
        /// One row per object read, with one column per single-valued attribute the catalogue asks for.
        /// </summary>
        /// <remarks>
        /// <para>
        /// object_guid is the identity, and object_id is not. A distinguished name changes when an
        /// object is renamed or moved, and object_id is local to this file, so two bundles joined on
        /// either would report a moved object as one deleted and one created. The GUID is the only
        /// identifier that survives both, which is why capture asks for it on every object.
        /// </para>
        /// <para>
        /// It is nullable because per <c>docs/decisions/0002</c> a value that did not arrive is not
        /// invented. An object with no GUID cannot take part in a comparison, and a reader must be able
        /// to see that rather than be handed a placeholder.
        /// </para>
        /// <para>
        /// <b>Every derived column is nullable, and there is no column recording why.</b> Per
        /// <c>docs/decisions/0022</c> an attribute that did not arrive and one the object never had are
        /// the same emptiness on the wire: Active Directory omits an absent attribute without saying
        /// whether the caller was refused it, so a column claiming to tell the two apart would be
        /// recording a guess. What a run could not see is recorded by reference and by coverage, where
        /// it is observable, rather than per attribute, where it is not.
        /// </para>
        /// <para>
        /// <b>Six columns are adopted from the predecessor rather than derived from the catalogue</b>,
        /// because each answers a question about the object's place in the forest rather than about one
        /// of its attributes. <c>dn_reversed</c> turns "everything under this organisational unit" from
        /// a scan into an indexed range. <c>parent_dn</c> is the name of the container one level up,
        /// written by <c>DnHelper.GetParentDn</c> as each object is stored, and <c>parent_guid</c> is
        /// the containment edge it resolves to in one pass when writing finishes rather than guessed
        /// at read time. The parent name is a column rather than something SQL derives, because a
        /// distinguished name looks like a delimited list and is not one - <c>CN=Smith\, John</c>
        /// carries a comma that separates nothing, and SQL has no way to tell it from one that does
        /// (<c>F-S30-1</c>).
        /// row because a forest-wide question should not have to parse a distinguished name.
        /// <c>captured_utc</c> is per row because a capture of a large forest is not an instant, and a
        /// reader comparing two runs needs to know how far apart two objects were actually read.
        /// <c>ace_count</c> is null until a descriptor is written and stays null for an object whose
        /// descriptor could not be read - which is a different thing from zero, and the distinction the
        /// whole descriptor half of this schema exists to keep.
        /// </para>
        /// <para>
        /// <b>The deleted flag does not come across.</b> It was instructed until 2026-08-12 and capture
        /// never reads <c>isDeleted</c>, so the column would have been false on every row of every
        /// bundle forever (<c>F-S20-1</c>).
        /// </para>
        /// </remarks>
        private static string CapturedObjectDdl()
        {
            var columns = SingleValuedColumns
                .Select(a => $"    {ColumnNameFor(a.LdapDisplayName),-40} {SqlTypeFor(a.Storage),-4} NULL")
                .ToList();

            return "CREATE TABLE captured_object ("
                + Environment.NewLine
                + "    object_id                                INTEGER PRIMARY KEY,"
                + Environment.NewLine
                + "    coverage_id                              INTEGER NOT NULL REFERENCES partition_coverage(coverage_id),"
                + Environment.NewLine
                + "    object_guid                              TEXT NULL,"
                + Environment.NewLine
                + "    distinguished_name                       TEXT NOT NULL,"
                + Environment.NewLine
                + "    dn_reversed                              TEXT NOT NULL,"
                + Environment.NewLine
                + "    parent_dn                                TEXT NULL,"
                + Environment.NewLine
                + "    parent_guid                              TEXT NULL,"
                + Environment.NewLine
                + "    domain_fqdn                              TEXT NOT NULL,"
                + Environment.NewLine
                + "    captured_utc                             TEXT NOT NULL,"
                + Environment.NewLine
                + "    ace_count                                INTEGER NULL"
                + (columns.Count > 0 ? "," + Environment.NewLine : Environment.NewLine)
                + string.Join("," + Environment.NewLine, columns)
                + Environment.NewLine
                + ")";
        }

        /// <summary>
        /// One table per multi-valued attribute, each holding that attribute's values in the order the
        /// controller sent them.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>Its own table rather than one shared one.</b> A single table keyed by attribute name
        /// would need a text column and a blob column with a constraint that exactly one is set,
        /// because <c>sIDHistory</c> is bytes and <c>memberOf</c> is text - which is the untyped shape
        /// <c>docs/decisions/0022</c> replaced, under a new name. One table per attribute gives each
        /// one the storage class its values actually have.
        /// </para>
        /// <para>
        /// No index is created for these. The primary key is <c>(object_id, ordinal)</c> and SQLite
        /// will use its leading column, so the lookup every reader performs - every value for one
        /// object - is already served.
        /// </para>
        /// </remarks>
        private static IEnumerable<string> ValueTableDdl() =>
            MultiValuedTables.Select(a =>
                $"CREATE TABLE {ValueTableNameFor(a.LdapDisplayName)} ("
                + Environment.NewLine
                + "    object_id                INTEGER NOT NULL REFERENCES captured_object(object_id),"
                + Environment.NewLine
                + "    ordinal                  INTEGER NOT NULL,"
                + Environment.NewLine
                + $"    value                    {SqlTypeFor(a.Storage)} NOT NULL,"
                + Environment.NewLine
                + "    PRIMARY KEY (object_id, ordinal)"
                + Environment.NewLine
                + ")");

        private static readonly string[] TablesAfterObject =
        [

        // One row per DISTINCT security descriptor in the forest, keyed on the SHA-256 of the bytes
        // the controller sent.
        //
        // Deduplicated because a forest does not have one descriptor per object - it has a few
        // thousand distinct ones repeated across millions of objects, mostly by inheritance. Storing
        // one row per object measured 4.81 GB per 100k objects against 1.24 GB here, and removed
        // three quarters of the parsing and inserting along with it.
        //
        // The hash is cryptographic, and that is not caution about a rare event. A collision does
        // not corrupt a row: it silently attributes one object's permissions to another, which is
        // the single failure an audit tool cannot have. byte_length sits beside it because a length
        // is free and makes a collision need to agree on two things rather than one.
        //
        // raw_bytes is the descriptor exactly as it arrived. It costs about 13% on top of the
        // parsed entries, against a raw form that is smaller than what parsing produces, and it buys
        // the difference between recovering from a parser defect by re-analysis and recovering from
        // it by asking a customer to re-run a capture over his whole forest.
        //
        // dacl_state is stored as its own value because a null DACL and an empty DACL mean opposite
        // things - one grants everyone everything, the other grants nobody anything - and both
        // produce zero rows in `descriptor_entry`. 'Unreadable' is the third way to produce zero rows and was
        // added by docs/decisions/0037: without it, a DACL nobody could read was recorded as one
        // that denies everybody, so an object the run failed to read looked like the safest object
        // in the forest.
        //
        // dacl_completeness answers the case a state cannot: a DACL that yielded three of the five
        // entries it declared is genuinely 'Present', and the shortfall has nowhere else to live.
        // It is an outcome and not a count because a count cannot say whether it was measured -
        // gate 4 refused the count, and the first draft of 0037 really had recorded a truncated
        // header as an empty DACL.
        //
        // dacl_was_canonical is required by docs/decisions/0038. Windows evaluates a DACL in stored
        // order and stops at the first match, so an allow placed before a deny grants what the
        // canonical form denies. Normalisation sorts every DACL, so this is the only record that
        // the directory held it differently. Exact order is not stored: raw_bytes is the authority
        // and re-parsing recovers it.
        //
        // ace_set_hash is required by docs/decisions/0015 and is what lets two runs be compared
        // without reading every ACE of every object. Comparison is the only verification path left
        // since docs/decisions/0008.
        //
        // canonicalization_version says which recipe produced this descriptor's ace_hash values and
        // its ace_set_hash. It is not the same number as schema_version and must not be folded into
        // it: that one describes these table shapes, this one describes the Kernel's output, and
        // F-S1-1 records the coupling that was removed to keep them apart. A build can therefore
        // read every column here and still be unable to reproduce a single hash. BundleReader.Open
        // refuses on that, under CanonicalizationVersionUnsupported. It was written here from the
        // start and read by nothing until 2026-08-19, which is how a version 2 bundle could open
        // silently under a version 3 build.
        """
        CREATE TABLE security_descriptor (
            descriptor_id            INTEGER PRIMARY KEY,
            sha256                   TEXT    NOT NULL UNIQUE,
            byte_length              INTEGER NOT NULL,
            raw_bytes                BLOB    NOT NULL,
            owner_sid                TEXT    NULL,
            group_sid                TEXT    NULL,
            dacl_state               TEXT    NOT NULL
                                     CHECK (dacl_state IN ('Present', 'Null', 'Empty', 'Unreadable')),
            dacl_completeness        TEXT    NOT NULL
                                     CHECK (dacl_completeness IN ('Complete', 'Incomplete', 'Unknown')),
            dacl_was_canonical       INTEGER NOT NULL CHECK (dacl_was_canonical IN (0, 1)),
            is_dacl_protected        INTEGER NOT NULL CHECK (is_dacl_protected IN (0, 1)),
            ace_set_hash             TEXT    NOT NULL,
            canonicalization_version INTEGER NOT NULL
        )
        """,

        // Which objects were read with which descriptor.
        //
        // A table rather than a column on `captured_object`, because an object is written before
        // its descriptor is read. A column would mean an UPDATE per object after the fact - a row
        // rewrite on every object in the forest, which is most of what deduplication just saved.
        // The predecessor did exactly that (DirectAceWriter's UPDATE of dim_object) and paid it.
        //
        // Three states are readable here and all three are needed. A row means a descriptor was
        // read. No row, with a row in `unreadable_security_descriptor`, means the object has one
        // and this run could not get it. No row and no error means nothing was attempted.
        """
        CREATE TABLE object_security_descriptor (
            object_id                INTEGER PRIMARY KEY REFERENCES captured_object(object_id),
            descriptor_id            INTEGER NOT NULL REFERENCES security_descriptor(descriptor_id)
        )
        """,

        // Why a descriptor could not be fully parsed. Per descriptor, not per object, for the same
        // reason the entries are.
        //
        // Without this table a descriptor that failed to parse and an object that grants nothing
        // are the same thing: no rows in `descriptor_entry`. One of those is a fact about the forest and the
        // other is the absence of one, and reporting the second as the first would tell a customer
        // an object is safe when nobody knows whether it is.
        """
        CREATE TABLE security_descriptor_error (
            descriptor_id            INTEGER NOT NULL REFERENCES security_descriptor(descriptor_id),
            ordinal                  INTEGER NOT NULL,
            message                  TEXT    NOT NULL,
            PRIMARY KEY (descriptor_id, ordinal)
        )
        """,

        // An object whose security descriptor could not be read at all.
        //
        // This is not the same as a descriptor that failed to parse, and it is not the same as an
        // object that grants nothing - and before this table existed all three looked identical,
        // because all three produce no entries. A production domain returned 19,927 of 100,000
        // objects with no readable descriptor (F-S20-16); the predecessor's writer returned early
        // on them and its only counter sat below the return, so nothing recorded that a fifth of
        // the domain was unknown rather than empty.
        //
        // The reason is free text because it is a transport-level failure - what the controller or
        // the client said - and there is no closed set of those. That is a different question from
        // why a *reference* could not be resolved, which does have one; see unresolved_reference.
        """
        CREATE TABLE unreadable_security_descriptor (
            object_id                INTEGER PRIMARY KEY REFERENCES captured_object(object_id),
            reason                   TEXT    NOT NULL
        )
        """,

        // Every distinct trustee named by an entry, once for the whole forest.
        //
        // This is what survives of the previous product's per-payload string table, and it is
        // strictly stronger: a domain's administrators appear in ACLs on hundreds of thousands of
        // objects, and a table scoped to one object's payload could not see past the object it was
        // inside.
        //
        // unresolved_reason says why a trustee could not be resolved to an object in this bundle,
        // and is null for one that was. It is drawn from the same closed set as
        // unresolved_reference, because "this SID belongs to a domain nobody captured" is the same
        // fact whether the SID was found in an ACL or in a group.
        """
        CREATE TABLE trustee (
            trustee_id               INTEGER PRIMARY KEY,
            sid                      TEXT    NOT NULL UNIQUE,
            unresolved_reason        TEXT    NULL
                                     CHECK (unresolved_reason IS NULL OR unresolved_reason IN
                                            ('DomainNotCaptured', 'AnotherForest', 'OrphanedIdentifier', 'Unreadable'))
        )
        """,

        // Something one object pointed at that nothing in this run ever saw.
        //
        // Recorded by reference rather than by self-report, per docs/decisions/0022: a group member,
        // a permission trustee, a parent container or a primary group. The bundle can only know
        // what was pointed at, so that is what it records.
        //
        // The reason is a closed set with no free text beside it. The predecessor carried both a
        // typed category and a prose reason, and the prose was fine - the defect was that the
        // category was reachable by omission, defaulted to 'Undetermined' in the C# record AND in
        // the column, so anything that forgot to classify silently claimed no opinion. Here there
        // is no default and no member to fall back to.
        //
        // There is deliberately no 'Undetermined'. The predecessor needed one because a re-analysis
        // of a saved capture does not know the forest's domain list, and docs/next/S-15 removed
        // re-analysis: every bundle is now written by the run that read the forest, so the domain
        // list is always known and "no claim made" is not a state this product can be in.
        """
        CREATE TABLE unresolved_reference (
            object_id                INTEGER NOT NULL REFERENCES captured_object(object_id),
            ordinal                  INTEGER NOT NULL,
            kind                     TEXT    NOT NULL
                                     CHECK (kind IN
                                            ('GroupMember', 'PermissionTrustee', 'ParentContainer', 'PrimaryGroup')),
            reference                TEXT    NOT NULL,
            reason                   TEXT    NOT NULL
                                     CHECK (reason IN
                                            ('DomainNotCaptured', 'AnotherForest', 'OrphanedIdentifier', 'Unreadable')),
            PRIMARY KEY (object_id, ordinal)
        )
        """,

        // One row per DISTINCT access control entry in the whole bundle, hanging off nothing.
        //
        // This is the other half of deduplication and the larger half: the entries are what there
        // are millions of. An entry is a trustee, a mask, a type, its inheritance and - for a
        // callback entry - its condition bytes; ace_hash is that identity as one value, and it is
        // what the row is unique on.
        //
        // THE REASON THIS IS ITS OWN TABLE WAS MEASURED, not anticipated. Entries used to hang off
        // the descriptor, which is deduplicated by the SHA-256 of its whole binary form - so two
        // objects shared storage only if their permission lists were byte-identical end to end.
        // Under deep inheritance no two ever are: each container adds entries that everything below
        // it carries, so every descendant's list differs from its neighbour's by a little and is
        // stored again in full. The first production capture (2026-09-23) held 141,706,338 entry
        // rows saying 481,967 distinct things - each written 294 times - in an evidence file of
        // 51.08 GB that is 96% permissions and does not fit on a customer's laptop. The owner
        // raised this risk while the schema was being designed and was told the design was sound.
        // It was not, at production scale. See P-269 through P-272.
        //
        // application_data is stored because ace_hash covers it. It went into the hash in
        // canonicalization version 3 so that two entries granting the same rights under different
        // conditions could not collide, but nothing stored it - which was harmless while a row
        // belonged to one object and is not once the hash is the key. Without it two genuinely
        // different conditional entries are identical to read, and no reader could reproduce the
        // key the row is stored under.
        //
        // Inherited entries are stored. Skipping them was a defensible size saving - the
        // predecessor's 0093b571 measured 80-90% - and it is reversed because it makes the graph
        // provably wrong: containment is modelled nowhere in derivation, so a principal holding
        // control on a container produced no edges to anything beneath it, and paths, chokepoint
        // counts and Tier 0 reachability were all computed from a graph missing most of its edges
        // (F-S20-14). That owes D7 the suppression of expected grants, or the graph drowns in edges
        // from `Domain Admins` and `SYSTEM` (F-S20-15).
        """
        CREATE TABLE access_entry (
            entry_id                    INTEGER PRIMARY KEY,
            ace_type                    TEXT    NOT NULL,
            trustee_id                  INTEGER NOT NULL REFERENCES trustee(trustee_id),
            access_mask                 INTEGER NOT NULL,
            object_type_guid            TEXT    NULL,
            inherited_object_type_guid  TEXT    NULL,
            is_inherited                INTEGER NOT NULL CHECK (is_inherited IN (0, 1)),
            inheritance_flags           INTEGER NOT NULL,
            propagation_flags           INTEGER NOT NULL,
            application_data            BLOB    NOT NULL,
            ace_hash                    TEXT    NOT NULL UNIQUE
        )
        """,

        // Which entries a descriptor holds, and in what order.
        //
        // THE ORDINAL IS ON THE LINK AND NOT ON THE ENTRY, and that is load-bearing rather than
        // tidy. The same entry sits at different positions in different lists - a deny that comes
        // first on one object is fourth on another - and Windows evaluates a DACL by accumulating
        // granted and denied masks in stored order, adding a deny only for rights not already
        // granted ([MS-ADTS] 5.1.3.3.2). An order stored on the shared entry would therefore be one
        // object's order imposed on every other object carrying it, which changes what the
        // permissions mean.
        //
        // A descriptor's list is exactly its rows here in ordinal order, so reconstructing it needs
        // no knowledge of how the entries came to be shared.
        """
        CREATE TABLE descriptor_entry (
            descriptor_id            INTEGER NOT NULL REFERENCES security_descriptor(descriptor_id),
            ordinal                  INTEGER NOT NULL,
            entry_id                 INTEGER NOT NULL REFERENCES access_entry(entry_id),
            PRIMARY KEY (descriptor_id, ordinal)
        )
        """,

        // Every Group Policy object the directory declared, and what became of its files.
        //
        // The tables below carry gpo_guid without declaring a foreign key to this one, and the
        // reason is ordering rather than laxity: a policy's settings and permissions are written
        // while it is being read, and its row here states the outcome, which is not known until the
        // read is over. It is the same ordering domain_coverage has, and foreign keys are enforced
        // in this database, so a declared reference would refuse every settings row written before
        // the seal.
        //
        // This is the SYSVOL denominator, and having one is the whole reason SYSVOL is allowed to
        // record coverage at all. docs/decisions/0044 widens docs/decisions/0035 on exactly one
        // condition - that the incompleteness has knowable edges - and SYSVOL meets it because this
        // list comes from LDAP before a single file is opened. A run that could not read three
        // policy folders out of four hundred knows which three.
        //
        // Every declared policy has a row, read or not, for the reason domain_coverage has one per
        // domain: a policy nobody could open must not be indistinguishable from a policy that
        // configures nothing.
        //
        // display_name is stored here even though the GPO is also a captured object carrying it.
        // The duplication is deliberate and narrow: this table is read to tell an operator which
        // policies were missed, by name and GUID, and a name reachable only by joining to the
        // object table is a name that disappears in exactly the degraded run this table exists to
        // describe.
        //
        // reason is free text and is null for a policy that was read. It is what the file system
        // said - access denied, path not found, the share not answering - and there is no closed
        // set of those. It is never invented: a failure that arrives without a usable reason says
        // so.
        """
        CREATE TABLE sysvol_gpo_coverage (
            gpo_guid                 TEXT    NOT NULL PRIMARY KEY,
            display_name             TEXT    NOT NULL,
            file_sys_path            TEXT    NULL,
            outcome                  TEXT    NOT NULL
                                     CHECK (outcome IN ('Read', 'PartiallyRead', 'Unreadable')),
            reason                   TEXT    NULL
                                     CHECK ((outcome = 'Read') = (reason IS NULL)),
            gpp_password_scan_outcome TEXT   NOT NULL
                                     CHECK (gpp_password_scan_outcome IN
                                            ('NotRequested', 'Read', 'PartiallyRead', 'Unreadable')),
            gpp_password_scan_reason TEXT    NULL
                                     CHECK ((gpp_password_scan_outcome IN ('NotRequested', 'Read'))
                                            = (gpp_password_scan_reason IS NULL))
        )
        """,

        // The registry-backed settings a policy applies, out of Registry.pol.
        //
        // value_data is kept as the raw bytes rather than as text. A REG_MULTI_SZ holds several
        // strings and a REG_BINARY holds none, so rendering at capture time would decide a
        // question the reader is better placed to answer, and would lose everything after the
        // first value of a multi-string. RegistryPolicyEntry does that rendering on the way out.
        """
        CREATE TABLE gpo_registry_setting (
            gpo_guid                 TEXT    NOT NULL,
            ordinal                  INTEGER NOT NULL,
            scope                    TEXT    NOT NULL CHECK (scope IN ('Machine', 'User')),
            key_path                 TEXT    NOT NULL,
            value_name               TEXT    NOT NULL,
            registry_type            INTEGER NOT NULL,
            value_data               BLOB    NOT NULL,
            PRIMARY KEY (gpo_guid, ordinal)
        )
        """,

        // The settings out of GptTmpl.inf, the security template: the privileges a policy grants,
        // and the signing and channel-binding settings it can weaken. SEC-064 and SEC-066 read
        // these.
        //
        // section is carried rather than being split into a table per section, because the file's
        // own sections are what the rules are written against and a new section must not need a
        // schema change to be recorded.
        """
        CREATE TABLE gpo_security_setting (
            gpo_guid                 TEXT    NOT NULL,
            ordinal                  INTEGER NOT NULL,
            section                  TEXT    NOT NULL,
            name                     TEXT    NOT NULL,
            value                    TEXT    NOT NULL,
            PRIMARY KEY (gpo_guid, ordinal)
        )
        """,

        // Restricted Groups: a policy putting a principal into a privileged group on every machine
        // it applies to. SEC-065 reads these.
        //
        // Recorded one principal per row rather than as a list, so the question "what does this
        // policy put into the local Administrators group" is a query rather than a parse.
        //
        // relationship is the direction, and both directions exist in the file format. 'Member'
        // means this principal is placed into the named group; 'MemberOf' means the named group is
        // placed into this principal. Collapsing them would invert half the memberships, which is
        // the difference between a policy that grants administrative rights and one that receives
        // them.
        """
        CREATE TABLE gpo_restricted_group (
            gpo_guid                 TEXT    NOT NULL,
            ordinal                  INTEGER NOT NULL,
            group_name               TEXT    NOT NULL,
            relationship             TEXT    NOT NULL
                                     CHECK (relationship IN ('Member', 'MemberOf')),
            principal                TEXT    NOT NULL,
            PRIMARY KEY (gpo_guid, ordinal)
        )
        """,

        // Where a policy stores a credential in its own files - the Group Policy Preferences
        // cpassword defect of MS14-025, which SEC-083 reports. The key is public, so anything
        // stored this way is readable by every authenticated user in the domain.
        //
        // Presence only. No column here holds the password or the ciphertext, and none ever
        // should: the finding is that a credential is there, and storing it would rebuild the
        // vulnerability inside the evidence file.
        """
        CREATE TABLE gpo_stored_credential (
            gpo_guid                 TEXT    NOT NULL,
            ordinal                  INTEGER NOT NULL,
            relative_path            TEXT    NOT NULL,
            element_type             TEXT    NOT NULL,
            account_name             TEXT    NULL,
            source_attribute         TEXT    NULL,
            PRIMARY KEY (gpo_guid, ordinal)
        )
        """,

        // A file inside a policy that was opened and could not be understood.
        //
        // Same shape and same reason as security_descriptor_error one table up. A GptTmpl.inf that
        // failed to parse produces no settings, and so does a policy that assigns none; without
        // this table those are the same evidence, and the rules would report a policy as granting
        // no dangerous privilege when the truth is that nobody knows what it grants.
        """
        CREATE TABLE gpo_file_error (
            gpo_guid                 TEXT    NOT NULL,
            ordinal                  INTEGER NOT NULL,
            relative_path            TEXT    NOT NULL,
            message                  TEXT    NOT NULL,
            PRIMARY KEY (gpo_guid, ordinal)
        )
        """,

        // The file permissions on a policy's folders and files, joined to the same descriptor and
        // entry tables the directory's permissions use.
        //
        // Reusing security_descriptor and ace rather than adding a parallel pair is what lets one
        // question be asked once: SEC-082 is about who can rewrite a policy, and a trustee found
        // in a file DACL is judged by the same classifier as one found in a directory DACL. The
        // predecessor had a separate fact_sysvol_ace with its own writer and its own transaction,
        // and the two could disagree about what an access mask meant.
        //
        // relative_path is empty for the policy's own folder. What else appears here is set by
        // docs/decisions/0043: every folder beneath it, every file whose contents were read, and
        // every file under Machine\Scripts and User\Scripts - because a logon script anybody can
        // rewrite runs on every machine the policy reaches.
        """
        CREATE TABLE sysvol_path_security_descriptor (
            gpo_guid                 TEXT    NOT NULL,
            relative_path            TEXT    NOT NULL,
            descriptor_id            INTEGER NOT NULL REFERENCES security_descriptor(descriptor_id),
            PRIMARY KEY (gpo_guid, relative_path)
        )
        """,

        // A path inside a policy whose permissions could not be read at all, which is the file-share
        // counterpart of unreadable_security_descriptor and exists for the same reason: no rows in
        // descriptor_entry means "this path grants nothing" and must not also mean "nobody could look".
        """
        CREATE TABLE unreadable_sysvol_descriptor (
            gpo_guid                 TEXT    NOT NULL,
            relative_path            TEXT    NOT NULL,
            reason                   TEXT    NOT NULL,
            PRIMARY KEY (gpo_guid, relative_path)
        )
        """,

        // NOTHING A RULE CONCLUDED IS STORED HERE. docs/decisions/0085 puts findings, the evidence
        // they rest on and the record of which rules ran into the judgement store, beside the
        // evidence rather than inside it, so that the evidence fingerprint is taken once and re-
        // judging a bundle under a better rule catalogue cannot alter what the directory said.
        // A finding table here would put findings in two places, and would mean improving a rule
        // either cannot be applied to an existing bundle or re-seals the evidence to apply it.
    ];

    /// <summary>
    /// Every <c>CREATE TABLE</c>, in an order that satisfies the foreign keys.
    /// </summary>
    private static IReadOnlyList<string> TableDdl { get; } =
    [
        .. TablesBeforeObject,
        CapturedObjectDdl(),
        .. ValueTableDdl(),
        .. TablesAfterObject,
    ];

    private static readonly string[] DeferredIndexDdl =
    [
        "CREATE INDEX ix_captured_object_dn ON captured_object(distinguished_name)",
        "CREATE INDEX ix_captured_object_guid ON captured_object(object_guid)",

        // The reason dn_reversed exists. Everything under an organisational unit shares a prefix
        // once the name is reversed, so a subtree question becomes a range scan on this index
        // instead of a LIKE across every object in the forest.
        "CREATE INDEX ix_captured_object_dn_reversed ON captured_object(dn_reversed)",
        "CREATE INDEX ix_captured_object_parent ON captured_object(parent_guid)",

        // ASKED FOR ONCE PER TRUSTEE ON EVERY SECURITY DESCRIPTOR READ, and until 2026-09-03 it was
        // a full table scan. ObjectPermissions.ResolveTrustees looks a trustee up by identifier to
        // put a name against it, and this table was indexed on the distinguished name, the object
        // identifier and the parent - but not on the security identifier that lookup uses.
        //
        // MEASURED, BECAUSE THE COST IS NOT OBVIOUS FROM READING IT. On an 8,367-object bundle a
        // lookup took 0.287 ms and the planner said SCAN; with this index it took 0.026 ms and said
        // SEARCH. The 11x is not the point - a scan grows with the number of objects while a b-tree
        // seek grows with its logarithm, so the scan gets worse exactly as a customer gets bigger.
        // Extrapolated to a million objects, one computer's descriptor took about four seconds to
        // read, which put SEC-090 across a hundred thousand computers at several days.
        //
        // Built after writing with the others, so the cost is one sort at the end rather than
        // maintenance on every insert during capture.
        "CREATE INDEX ix_captured_object_sid ON captured_object(objectsid)",

        // No index on descriptor_entry(descriptor_id): the primary key leads with it, so "this
        // descriptor's entries, in order" is already a range scan on the table itself.
        //
        // This one is the other direction - which descriptors hold a given entry - and it is the
        // question the old shape could not be asked at all, because an entry belonged to exactly
        // one descriptor.
        "CREATE INDEX ix_descriptor_entry_entry ON descriptor_entry(entry_id)",
        "CREATE INDEX ix_access_entry_trustee ON access_entry(trustee_id)",

        // NOTHING INDEXES ace_hash, and that is not an omission. It is UNIQUE on access_entry, so
        // SQLite already keeps an index for it; a second would be the same 64 hexadecimal
        // characters stored twice. The old shape had one over every entry row rather than over
        // every distinct entry, which on the production capture was 141,706,338 of them.
        "CREATE INDEX ix_object_security_descriptor ON object_security_descriptor(descriptor_id)",
        "CREATE INDEX ix_sysvol_path_descriptor ON sysvol_path_security_descriptor(descriptor_id)",
        "CREATE INDEX ix_security_descriptor_set_hash ON security_descriptor(ace_set_hash)",

        // A partial index, because docs/decisions/0038 expects the answer to be zero on most
        // forests and the question to be asked forest-wide. Indexing only the rows that are not
        // canonical means the index costs nothing on a healthy forest and still answers "show me
        // every object whose permissions are in non-standard order" without a scan.
        """
        CREATE INDEX ix_security_descriptor_non_canonical
            ON security_descriptor(descriptor_id) WHERE dacl_was_canonical = 0
        """,

        // Same shape, same reason: the interesting rows are the ones that are not Complete.
        """
        CREATE INDEX ix_security_descriptor_incomplete
            ON security_descriptor(descriptor_id) WHERE dacl_completeness <> 'Complete'
        """,
    ];

    /// <summary>
    /// Creates every table. Called once, when a bundle is created.
    /// </summary>
    /// <param name="connection">An open read-write connection to the evidence database.</param>
    public static void CreateTables(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        Execute(connection, TableDdl, CancellationToken.None);
    }

    /// <summary>
    /// Creates the indexes, once the writing is finished.
    /// </summary>
    /// <param name="connection">An open read-write connection to the evidence database.</param>
    public static void CreateDeferredIndexes(SqliteConnection connection) =>
        CreateDeferredIndexes(connection, CancellationToken.None);

    /// <summary>Builds indexes with cooperative cancellation between synchronous SQLite statements.</summary>
    /// <param name="connection">The open evidence connection.</param>
    /// <param name="cancellationToken">Cancellation that prevents the next statement from starting.</param>
    public static void CreateDeferredIndexes(SqliteConnection connection, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        Execute(connection, DeferredIndexDdl, cancellationToken);
    }

    private static void Execute(SqliteConnection connection, IEnumerable<string> statements, CancellationToken cancellationToken)
    {
        foreach (var statement in statements)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var command = connection.CreateCommand();
            command.CommandText = statement;
            command.ExecuteNonQuery();
        }
    }
}
