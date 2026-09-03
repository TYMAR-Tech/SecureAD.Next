using Microsoft.Data.Sqlite;

namespace SecureAD.Derivation;

/// <summary>
/// Every table in a derivation store, and the indexes built once writing is done.
/// </summary>
/// <remarks>
/// <para>
/// <b>A third file beside the evidence and the judgement, and it is neither.</b> The evidence is
/// what the directory said, sealed once at capture. A judgement is what the rules concluded. This
/// is what was worked out from the evidence before any rule ran - group nesting, membership
/// closures, the identities a principal carries - and it is an input to judging rather than a
/// product of it.
/// </para>
/// <para>
/// <b>It is separate from the judgement store because the two have different lifetimes.</b> A
/// judgement is rebuilt from scratch whenever a bundle is judged. Derived facts cost far more to
/// produce - expanding group membership over a forest is the most expensive thing the product
/// does - and nothing about them changes when a rule does. Keeping them in their own file is what
/// lets a bundle be judged many times having been derived once.
/// </para>
/// <para>
/// <b>The store is disposable, and that shapes the schema.</b> It can be deleted and rebuilt from
/// the evidence at any time, so there is nothing here to preserve across a schema change: no
/// migration, no column added conditionally, no compatibility to keep. A version mismatch is a
/// file to delete and derive again.
/// </para>
/// </remarks>
internal static class DerivationSchema
{
    /// <summary>
    /// The schema version stamped into every derivation store.
    /// </summary>
    /// <remarks>
    /// Recorded so a reader can refuse a store it does not understand rather than misreading one.
    /// Cheap to raise, for the reason the judgement schema gives: a store that cannot be read is
    /// deleted and the bundle derived again, and nothing is lost because the evidence was never
    /// touched.
    /// <para>
    /// <b>2 - the SID dictionary gained a scope</b>, per
    /// <c>docs/decisions/0087-a-sid-is-unique-within-its-scope.md</c>. A version 1 store keyed
    /// principals by SID alone and so merged every domain's built-in groups into one.
    /// </para>
    /// <para>
    /// <b>3 - completeness is recorded.</b> Before it, a store said nothing about what its closures
    /// did not cover, so one built under a hit budget or missing a whole domain was
    /// indistinguishable from a clean one. The judgement specification requires that "a partial
    /// answer is never serialized as a complete closure"; until version 3 this store did exactly
    /// that.
    /// </para>
    /// <para>
    /// <b>5 - attribute visibility is recorded.</b> SEC-091 and SEC-094 read a LAPS timestamp, and
    /// an absent value means either <i>this machine is unmanaged</i> or <i>this forest withheld the
    /// attribute</i>. Those are opposite answers and only the schema partition tells them apart, so
    /// the answer is derived once and handed to the rules rather than assumed from what Microsoft
    /// ships.
    /// </para>
    /// <para>
    /// <b>6 - membership cycles are recorded.</b> The expansion has always found them, because
    /// condensing the nesting graph is how it avoids walking one forever, but it discarded them
    /// afterwards. Microsoft states that <i>group membership may have loops</i>, and two groups in
    /// a loop are permanently one group as far as authorization is concerned - a fact about the
    /// directory that no tool shows and that nothing in this store could previously carry.
    /// </para>
    /// </remarks>
    public const int Version = 6;

    private static readonly string[] TableDdl =
    [
        // One row, written when deriving starts and completed when it finishes. The derivation's
        // own account of itself.
        //
        // EVIDENCE_SEAL IS WHAT BINDS THIS FILE TO ONE CAPTURE, for the same reason the judgement
        // store carries it. Two captures of one forest produce bundles with the same file names
        // holding mostly the same objects, so derived facts dropped into the wrong bundle would
        // resolve most of their SIDs and be wrong about all of them. A membership closure is worse
        // than a finding here: a finding names an object an operator can go and look at, while a
        // closure is consulted silently by every rule that rests on it.
        //
        // DERIVATION_GENERATION_ID NAMES THIS DERIVE RUN, so a later reader can tell facts produced
        // by one run from facts produced by another. It is recorded once, here, rather than on
        // every derived row: a store holds exactly one derivation, so a per-row copy would be a
        // second answer to a question this row already answers, and two copies can disagree.
        //
        // state is the run's own outcome and is a different question from the seal. The seal says
        // whether these bytes have changed. This says what the deriving claimed to have done, and
        // unlike a judgement it has a Degraded state of its own, because phases are fault-isolated:
        // one phase failing leaves the others' facts usable and must not be reported as a clean
        // derivation.
        //
        // A READER OF A NAMED derivation.db SHOULD NEVER SEE Running OR Failed, for the reason the
        // judgement store gives: deriving writes to derivation.db.partial and renames only when
        // every phase has finished, so those two states live in a file no reader asks for.
        //
        // THERE IS NO evaluation_as_of, AND THAT IS DELIBERATE. A judgement needs one because rules
        // about stale accounts ask what the time is. Nothing derived here is temporal - group
        // nesting is what it is whenever you look - so a reference time would be a column that is
        // always ignored, which teaches every reader to ignore it.
        """
        CREATE TABLE derivation (
            schema_version           INTEGER NOT NULL,
            evidence_seal            TEXT    NOT NULL,
            derivation_generation_id TEXT    NOT NULL,
            deriving_started_utc     TEXT    NOT NULL,
            deriving_completed_utc   TEXT        NULL,
            state                    TEXT    NOT NULL,
            only_one_row             INTEGER NOT NULL DEFAULT 1
                                     CHECK (only_one_row = 1),
            PRIMARY KEY (only_one_row)
        )
        """,

        // Every SID this store has anything to say about, once, with a small integer standing in
        // for it everywhere else.
        //
        // THIS TABLE IS THE REASON THE REST OF THE STORE FITS. A SID renders as about forty-five
        // characters, and the tables above this one are edge lists and closures that name two SIDs
        // per row and hold more rows than anything else the product writes. Storing the text in
        // them costs roughly five to ten times what an integer pair costs, and the cost is paid
        // four times over: in file size, in pages read per query, in how many rows fit in a B-tree
        // page - which decides how deep the index is - and in comparing a string under a collation
        // rather than comparing two integers.
        //
        // IT ALSO REMOVES A DISAGREEMENT ABOUT WHAT EQUAL MEANS. The predecessor deduplicated SIDs
        // in memory with OrdinalIgnoreCase while its closure table's primary key compared them
        // under SQLite's default binary collation. SIDs are conventionally upper case so the two
        // probably never parted company, but they are two notions of equality over one identifier
        // and only one of them can be right. Integers have exactly one.
        //
        // sid IS THE TEXT FORM AND IS STORED ONCE. It is kept rather than discarded because a
        // finding has to name something an operator can look up, and because an ACE naming a SID
        // has to be matched against this table by text.
        //
        // scope IS PART OF THE IDENTITY, NOT DECORATION. A SID is unique within its scope and not
        // within a forest: S-1-5-32-544 is BUILTIN\Administrators in every domain, and those are
        // different groups holding different members. So a built-in SID carries the domain it was
        // captured from and every other SID carries the empty string, and two rows may share a sid
        // while naming different principals. See docs/decisions/0087.
        //
        // IT IS EMPTY RATHER THAN NULL FOR A FOREST-WIDE PRINCIPAL, and that is load-bearing:
        // SQLite treats NULLs as distinct from one another in a unique index, so a nullable scope
        // would let the dictionary hold one forest-wide SID any number of times and the index
        // below would never object. The empty string compares equal to itself and the check holds.
        """
        CREATE TABLE sid (
            sid_id INTEGER NOT NULL,
            sid    TEXT    NOT NULL,
            scope  TEXT    NOT NULL,
            PRIMARY KEY (sid_id)
        )
        """,

        // Which principal each SID identifies, and how.
        //
        // A PRINCIPAL HAS MORE THAN ONE SID AND THIS IS WHERE THAT IS RECORDED. Its current
        // objectSid is one identity; every value in its sIDHistory is another, carried from a
        // migration, and an ACE naming an old SID grants access to the migrated principal through
        // it. Both kinds resolve to the same principal and the store has to be able to say which
        // kind matched, because "matched current SID" and "matched SIDHistory" are different
        // sentences to put in front of an operator.
        //
        // SIDHISTORY IS NOT A MEMBERSHIP EDGE AND IS NOT STORED AS ONE. It is an additional
        // authorization identity carried by one principal, not a relationship between two, and
        // filing it beside group nesting would let a closure walk through it as though the
        // principal were a member of something.
        //
        // principal_sid_id IS THE PRINCIPAL'S CURRENT SID, so a row where it equals sid_id is the
        // principal's own identity and any other row is history pointing at it.
        """
        CREATE TABLE sid_identity (
            sid_id           INTEGER NOT NULL REFERENCES sid(sid_id),
            principal_sid_id INTEGER NOT NULL REFERENCES sid(sid_id),
            identity_kind    TEXT    NOT NULL,
            PRIMARY KEY (sid_id)
        )
        """,

        // Everything about one principal that deciding a membership question needs, other than its
        // edges.
        //
        // IS_GROUP AND GROUP_TYPE ARE TWO SIGNALS AND NEITHER IS THE OTHER. is_group says
        // objectClass called it a group. group_type is the flags word, which says whether that
        // group is security-enabled and what scope it has - and it is nullable, because a group
        // whose groupType was not captured is a group whose type we do not know. Deriving is_group
        // from "group_type is not null" would turn a missing attribute into a claim the object is
        // not a group, which is the boolean-answer-to-an-unknown-question failure this stage is
        // supposed to avoid.
        //
        // GROUP_TYPE IS STORED RAW AND THE ANSWERS FROM IT ARE NOT. Security-enabled is one bit of
        // it and scope is three more; both are computed by whoever asks. Storing the answers as
        // well would be a second copy that can drift from the flags it came from.
        //
        // PRIMARY_GROUP_SID_ID IS HOW PRIMARY-GROUP MEMBERSHIP IS HELD, AND IT IS DELIBERATELY NOT
        // AN EDGE. Microsoft's specifications are clear that primaryGroupID names a group the
        // account is a member of, and equally clear that neither the account's memberOf nor the
        // group's member attribute carries the relationship - so it is real membership and a
        // traversal that ignores it is incomplete.
        //
        // But it is also the most uniform fact in the directory: nearly every user's primary group
        // is Domain Users, so materialising it into nesting_edge would add one row per account in
        // the forest, every one of them pointing at the largest group there is. That is the biggest
        // table in the store made bigger by rows that all say the same thing, and if Domain Users
        // is nested anywhere the closure over those edges resolves to the entire directory. Held
        // here it is one nullable column on a row that already exists, and the traversal folds it
        // in as it goes.
        """
        CREATE TABLE principal (
            sid_id               INTEGER NOT NULL REFERENCES sid(sid_id),
            object_guid          TEXT    NOT NULL,
            is_group             INTEGER NOT NULL,
            group_type           INTEGER     NULL,
            primary_group_sid_id INTEGER     NULL REFERENCES sid(sid_id),
            PRIMARY KEY (sid_id)
        )
        """,

        // One row per directory nesting relationship, as a pair of dictionary ids.
        //
        // THIS IS THE DIRECTORY FACT AND NOTHING MORE. Whether an edge can carry authorization,
        // whether SDProp follows it, whether it would matter if a distribution group were
        // converted - all three are questions asked of this table, and none of them is answered in
        // it. They are three different products derived from one set of edges, which is why the
        // edges are stored once and plainly.
        //
        // THERE IS NO edge_kind COLUMN, AND ITS ABSENCE IS THE POINT. What makes a hop
        // authorization-bearing is whether the containing group is security-enabled, and that is a
        // property of the group, recorded once on principal.group_type. Copying it onto every edge
        // the group appears in would be the same fact stored many times, free to disagree with
        // itself, and the closures would then be reading a cached answer rather than the flags.
        //
        // THERE IS NO path COLUMN. The predecessor's closure carried one and wrote NULL into it on
        // every row.
        """
        CREATE TABLE nesting_edge (
            group_sid_id  INTEGER NOT NULL REFERENCES sid(sid_id),
            member_sid_id INTEGER NOT NULL REFERENCES sid(sid_id),
            PRIMARY KEY (group_sid_id, member_sid_id)
        )
        """,

        // One row per principal caught in a membership cycle, grouped by cycle_id.
        //
        // WHY THIS IS STORED WHEN THE TRANSITIVE CLOSURE IS NOT. The closure is quadratic and every
        // consumer asks about a handful of named principals, so it is walked on demand from
        // nesting_edge instead. Cycles are the opposite shape: tiny, expensive to rediscover -
        // finding them is the whole reason the graph is condensed - and needed by a rule rather
        // than by a lookup. Recomputing them per question would repeat the one pass this store
        // exists to avoid repeating.
        //
        // A CYCLE IS A SET, NOT A PATH, and the rows say so. Tarjan's algorithm yields the strongly
        // connected component: every principal in it reaches every other, but the particular route
        // is not unique and storing one route would invite a reader to believe it was the only one.
        //
        // A CYCLE OF ONE NEVER REACHES THIS TABLE, AND THAT IS A KNOWN GAP RATHER THAN A DECISION.
        // The expander keeps a strongly connected component only when it holds more than one
        // principal, so a group that contained itself would be a component of one and would be
        // dropped before it got here. Whether Active Directory permits that at all is unsettled -
        // Microsoft states only that loops may exist, and the one source claiming self-membership
        // is refused carries no citation. If the lab shows a self-loop is possible, the filter in
        // AuthorizationMembershipExpander has to go before this table can claim to hold every
        // cycle. See next/tools/Test-LabOpenQuestions.ps1.
        """
        CREATE TABLE nesting_cycle (
            cycle_id INTEGER NOT NULL,
            sid_id   INTEGER NOT NULL REFERENCES sid(sid_id),
            PRIMARY KEY (cycle_id, sid_id)
        )
        """,

        // One row per phase that was scheduled, whatever became of it.
        //
        // THIS TABLE IS WHAT MAKES A THIN STORE READABLE, for the reason the judgement store's
        // rule_execution table exists. A store holding no closure rows because no phase ran and a
        // store holding none because every group was genuinely empty are opposite facts, and
        // without this table both look like a forest with no nesting in it.
        //
        // PHASES ARE FAULT-ISOLATED, WHICH IS WHY THIS IS PER PHASE RATHER THAN PER RUN. A phase
        // that throws is recorded by name and the run continues, because the facts the other
        // phases derived are still true and still worth having. What must not happen is the run
        // then calling itself complete - the header's state carries Degraded for exactly this.
        //
        // error is set only when outcome is Failed, and is kept because a phase failing is the
        // thing most likely to need diagnosing later.
        """
        CREATE TABLE derivation_phase (
            phase   TEXT NOT NULL,
            outcome TEXT NOT NULL,
            error   TEXT     NULL,
            PRIMARY KEY (phase)
        )
        """,

        // What the derivation does not cover, which the judgement specification requires every
        // derived closure to record: "a partial answer is never serialized as a complete closure".
        //
        // ONE ROW FOR THE WHOLE DERIVATION RATHER THAN ONE PER PRODUCT. All three products come
        // from one graph built by one pass over one bundle, so their coverage is the same coverage.
        // Three copies would be three things that can disagree about one fact.
        //
        // THE GENERATION ID IS NOT REPEATED HERE. The specification asks each closure to record
        // which derive run produced it, and the derivation header above holds that once, for the
        // run all three closures came from. A second copy is a second thing to keep in step.
        //
        // is_complete IS NOT DERIVABLE FROM THE LISTS BELOW. A domain the capture never read leaves
        // no unresolved trustee and no partial group - there is nothing in the graph to be short
        // of - so a reader computing completeness from what it can see would call that store whole.
        """
        CREATE TABLE derivation_completeness (
            is_complete       INTEGER NOT NULL,
            expansion_limit   TEXT    NOT NULL,
            collapsed_stubs   INTEGER NOT NULL,
            unscoped_builtins INTEGER NOT NULL,
            only_one_row      INTEGER NOT NULL DEFAULT 1
                              CHECK (only_one_row = 1),
            PRIMARY KEY (only_one_row)
        )
        """,

        // Groups whose membership was never worked out, because a budget stopped the expansion
        // first. Held as dictionary ids like everything else that names a principal.
        """
        CREATE TABLE completeness_partial_group (
            sid_id INTEGER NOT NULL REFERENCES sid(sid_id),
            PRIMARY KEY (sid_id)
        )
        """,

        // Names a group claimed as a member that no captured object answers to. Text rather than an
        // id, and that is the point: there is no principal to give an id to, which is what makes it
        // unresolved.
        """
        CREATE TABLE completeness_unresolved_trustee (
            distinguished_name TEXT NOT NULL,
            PRIMARY KEY (distinguished_name)
        )
        """,

        // Declared domains the capture did not read in full, each carrying why.
        //
        // THE WHOLE COVERAGE ROW IS KEPT, not a list of names. A domain left out by an operator's
        // choice and one nobody could reach are both absent from the graph and are not the same
        // fact - and the remedy differs, so an operator told only that a domain is missing cannot
        // act on it.
        //
        // The reason is NOT NULL because only domains that were not read in full reach this table,
        // and every one of those carries why: a refusal that names no cause is one an operator
        // cannot act on.
        """
        CREATE TABLE completeness_missing_partition (
            domain_fqdn TEXT NOT NULL,
            outcome     TEXT NOT NULL,
            reason      TEXT NOT NULL,
            PRIMARY KEY (domain_fqdn)
        )
        """,

        """
        CREATE TABLE adminsd_catalogue_entry (
            catalogue_entry_id       INTEGER NOT NULL,
            name                     TEXT    NOT NULL,
            scope                    TEXT    NOT NULL,
            rid                      INTEGER NOT NULL,
            principal_status         TEXT    NOT NULL,
            principal_provenance     TEXT    NOT NULL,
            principal_source_id      TEXT    NOT NULL,
            propagation_status       TEXT    NOT NULL,
            propagation_provenance   TEXT    NOT NULL,
            propagation_source_id    TEXT    NOT NULL,
            mask_excludable          INTEGER NOT NULL,
            PRIMARY KEY (catalogue_entry_id)
        )
        """,

        """
        CREATE TABLE adminsd_derivation (
            catalogue_version INTEGER NOT NULL,
            mask_outcome      TEXT    NOT NULL,
            mask_character    TEXT        NULL,
            stated_limits     INTEGER NOT NULL,
            only_one_row      INTEGER NOT NULL DEFAULT 1 CHECK (only_one_row = 1),
            PRIMARY KEY (only_one_row)
        )
        """,

        """
        CREATE TABLE protected_principal (
            sid_id                   INTEGER NOT NULL REFERENCES sid(sid_id),
            evaluation               TEXT    NOT NULL,
            basis_kind               TEXT        NULL,
            basis_catalogue_entry_id INTEGER     NULL REFERENCES adminsd_catalogue_entry(catalogue_entry_id),
            unknown_reasons          INTEGER NOT NULL,
            PRIMARY KEY (sid_id)
        )
        """,

        """
        CREATE TABLE protected_principal_path (
            sid_id      INTEGER NOT NULL REFERENCES protected_principal(sid_id),
            ordinal     INTEGER NOT NULL,
            path_sid_id INTEGER NOT NULL REFERENCES sid(sid_id),
            PRIMARY KEY (sid_id, ordinal)
        )
        """,

        // One row, written when the attribute-visibility phase produces a product at all.
        //
        // THIS ROW IS WHAT MAKES AN EMPTY attribute_visibility TABLE READABLE, exactly as
        // rule_execution does for an empty finding table in a judgement. No rows and no row here
        // means the phase never ran; no rows beside this row means the phase ran and the capture
        // held no schema partition. Those lead a rule to opposite behaviour - the first refuses the
        // whole judging, the second makes every rule reading a schema answer stay silent - so a
        // reader must be able to tell them apart without inferring it.
        //
        // attributes_read IS NOT A CACHED COUNT OF THE TABLE BELOW. It is what the phase says it
        // read, and the table is what was stored. They agree in every run that worked, and a run
        // where they disagree is one this product wants to be able to notice rather than one it has
        // arranged to look tidy.
        """
        CREATE TABLE attribute_visibility_derivation (
            attributes_read INTEGER NOT NULL,
            only_one_row    INTEGER NOT NULL DEFAULT 1 CHECK (only_one_row = 1),
            PRIMARY KEY (only_one_row)
        )
        """,

        // What the forest's schema says about each attribute's visibility.
        //
        // THE TWO FLAGS ARE STORED RAW AND THE ANSWER IS NOT, which is the rule the delegation,
        // pre-authentication and SID history tables all follow. Whether an attribute is withheld is
        // searchFlags bit 128 unless systemFlags marks a base schema object, and a stored answer
        // would be a second copy of that computation able to disagree with the values beside it.
        //
        // BOTH ARE NULLABLE AND NULL IS NOT ZERO. Zero means this forest withholds nothing, which
        // is a real statement about the schema. Null means nobody read the value, and a rule
        // treating that as zero would report an attribute as readable on no evidence at all - the
        // one direction that turns a gap in the capture into a claim about the forest.
        """
        CREATE TABLE attribute_visibility (
            ldap_display_name TEXT    NOT NULL,
            search_flags      INTEGER     NULL,
            system_flags      INTEGER     NULL,
            PRIMARY KEY (ldap_display_name)
        )
        """,
    ];

    // Built after writing rather than during it, for the reason the evidence and judgement schemas
    // both give: an index maintained through ingest is paid for on every insert and read by nobody
    // until the run is over. The saving is larger here than in a judgement, because the tables this
    // store fills are the largest the product writes outside the capture itself.
    private static readonly string[] DeferredIndexDdl =
    [
        // Text to id, for resolving an ACE trustee or an operator's search against the dictionary.
        //
        // UNIQUE IS DOING TWO JOBS. It serves the lookup, and it is the only thing that proves the
        // interner did its job: the dictionary is built in memory and nothing in the table shape
        // stops two rows carrying one SID. Building this at the end turns a broken interner into a
        // failed derivation rather than a store that silently holds one principal twice.
        //
        // IT COVERS THE SCOPE BECAUSE THE SCOPE IS PART OF THE IDENTITY. Over sid alone it forbade
        // something the directory does on purpose - one built-in SID per domain - and that is how
        // the first multi-domain capture ended: UNIQUE constraint failed. Over the pair it still
        // catches an interner that lost track of a principal, which is what it is for.
        "CREATE UNIQUE INDEX ux_sid_text ON sid(sid, scope)",

        // Every identity one principal carries, which is the direction SIDHistory is read in:
        // given a principal, what else could an ACE have named to reach it?
        //
        // The primary key on sid_identity already answers the other direction - given a SID, whose
        // is it - so only this one has to be built.
        "CREATE INDEX ix_sid_identity_principal ON sid_identity(principal_sid_id)",

        // Member to groups. The primary key on nesting_edge already answers the other direction -
        // given a group, who is directly in it - which is the direction the closure is built in.
        // This one serves the question an object view asks: what is this principal directly in?
        "CREATE INDEX ix_nesting_edge_member ON nesting_edge(member_sid_id)",

        // Every account whose primary group is a given group, which is the direction the closure
        // needs: expanding a group means asking who names it, and primaryGroupID points the other
        // way. Without this that question is a scan of every principal per group expanded.
        //
        // Partial, because the column is null for everything that is not an account, and those
        // rows can never satisfy the lookup.
        "CREATE INDEX ix_principal_primary_group ON principal(primary_group_sid_id) "
        + "WHERE primary_group_sid_id IS NOT NULL",
    ];

    /// <summary>
    /// Creates every table. Called once, when a derivation store is created.
    /// </summary>
    /// <param name="connection">An open read-write connection to the derivation store.</param>
    public static void CreateTables(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        Execute(connection, TableDdl);
    }

    /// <summary>
    /// Creates the indexes, once the writing is finished.
    /// </summary>
    /// <param name="connection">An open read-write connection to the derivation store.</param>
    public static void CreateDeferredIndexes(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        Execute(connection, DeferredIndexDdl);
    }

    private static void Execute(SqliteConnection connection, IEnumerable<string> statements)
    {
        foreach (var statement in statements)
        {
            using var command = connection.CreateCommand();
            command.CommandText = statement;
            command.ExecuteNonQuery();
        }
    }
}
