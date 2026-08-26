using Microsoft.Data.Sqlite;

namespace SecureAD.Judgement;

/// <summary>
/// Every table in a judgement store, and the indexes built once writing is done.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is not the evidence schema and must never become it.</b> The evidence is sealed at the
/// end of capture, before any rule has run, and nothing writes to it again. Everything here is what
/// the product <i>concluded</i>, which is a different kind of claim from what the directory
/// <i>said</i>, and keeping the two in separate files is what lets a bundle be judged many times
/// while still proving what was captured once.
/// </para>
/// <para>
/// <b>The store is disposable, and that shapes the schema.</b> It can be deleted and rebuilt from
/// the evidence at any time, so there is nothing here to preserve across a schema change: no
/// migration, no column added conditionally, no compatibility to keep. A version mismatch is a file
/// to delete and regenerate rather than a file to upgrade.
/// </para>
/// <para>
/// <b>Nothing derived from the graph is stored, because nothing derives it yet.</b> Group
/// expansion, control edges and reachability are unbuilt, so there is no generation identifier and
/// no capability catalogue version on an execution record. A column that is always null teaches
/// every reader to ignore it, and would still be null a year from now. They arrive in the stage
/// that fills them.
/// </para>
/// </remarks>
public static class JudgementSchema
{
    /// <summary>
    /// The schema version stamped into every judgement store.
    /// </summary>
    /// <remarks>
    /// Recorded so a reader can refuse a store it does not understand rather than misreading one.
    /// Unlike the evidence version this is cheap to raise: a store that cannot be read is deleted
    /// and the bundle judged again, and nothing is lost because the evidence was never touched.
    /// </remarks>
    public const int Version = 1;

    private static readonly string[] TableDdl =
    [
        // One row, written when judging starts and completed when it finishes. The judgement's own
        // account of itself.
        //
        // EVIDENCE_SEAL IS WHAT BINDS THIS FILE TO ONE CAPTURE, and it is the reason the store can
        // be copied without becoming dangerous. Two captures of one forest produce bundles with the
        // same file names holding mostly the same objects, so a judgement dropped into the wrong
        // bundle would resolve most of its findings and be wrong about all of them. The seal over
        // evidence.db is a permanent fingerprint of exactly one capture, taken once and never
        // reissued, so a reader can check this rather than trust it.
        //
        // state is the run's own outcome and is a different question from the seal, exactly as
        // bundle.every_declared_unit_recorded_as_read is different from the evidence seal. The seal
        // says whether these bytes have changed. This says what the judging claimed to have done.
        //
        // A READER OF A NAMED judgement.db SHOULD NEVER SEE Running OR Failed. Judging writes to
        // judgement.db.partial and renames only after every scheduled rule has finished, so those
        // two states live in a file no reader asks for. Finding one under the finished name means
        // the file was assembled by something other than a judging run.
        //
        // evaluation_as_of is the reference time temporal rules were evaluated against, recorded
        // rather than taken from the clock at read time. Without it a rule about stale accounts
        // gives a different answer every time the same sealed evidence is opened, and nothing says
        // why.
        """
        CREATE TABLE judgement (
            schema_version           INTEGER NOT NULL,
            evidence_seal            TEXT    NOT NULL,
            judging_started_utc      TEXT    NOT NULL,
            judging_completed_utc    TEXT        NULL,
            state                    TEXT    NOT NULL,
            evaluation_as_of         TEXT    NOT NULL,
            only_one_row             INTEGER NOT NULL DEFAULT 1
                                     CHECK (only_one_row = 1),
            PRIMARY KEY (only_one_row)
        )
        """,

        // One row per rule that was scheduled, whatever became of it.
        //
        // THIS TABLE IS WHAT MAKES AN EMPTY finding TABLE READABLE. No findings and no rows here
        // means nobody judged this bundle; no findings beside rows here means every rule ran and
        // nothing matched. Those are opposite answers and a screen would print both as a clean
        // forest, which is the failure this product exists to avoid.
        //
        // A ROW IS WRITTEN FOR A RULE THAT DID NOT RUN, which is why outcome carries DidNotRun
        // rather than the row being absent. A rule missing from a run because it threw during
        // scheduling is a fact about the judgement, and absence cannot state it.
        //
        // objects_judged and objects_not_judged are counted separately and neither is derived from
        // the other, because their sum is not the object count: a rule is only offered objects of
        // the kind it applies to. A rule that reached a verdict on 40 objects and could not reach
        // one on 4,000 has said almost nothing about the forest, and an outcome of Succeeded with
        // no findings would otherwise present that as clean.
        //
        // error is set only when outcome is Error. A throwing rule does not stop the others, per
        // the write contract, so its message has to be kept somewhere a reader can reach.
        """
        CREATE TABLE rule_execution (
            rule_id                  TEXT    NOT NULL,
            rule_version             INTEGER NOT NULL,
            outcome                  TEXT    NOT NULL,
            objects_judged           INTEGER NOT NULL,
            objects_not_judged       INTEGER NOT NULL,
            error                    TEXT        NULL,
            PRIMARY KEY (rule_id)
        )
        """,

        // Which declared inputs were missing, and on how many objects.
        //
        // A rule declares the attributes it reads, so when it cannot reach a verdict it can say
        // exactly what was absent instead of falling silent. Recording it per attribute rather than
        // as one count turns "SEC-010 could not judge 4,000 objects" into "primaryGroupID was not
        // captured", which is the difference between a mystery and an instruction.
        //
        // NO ROWS BESIDE A NON-ZERO objects_not_judged IS A DEFECT, not an absence with a meaning.
        // Every object a rule could not judge was refused for a named attribute.
        """
        CREATE TABLE rule_execution_missing_input (
            rule_id                  TEXT    NOT NULL REFERENCES rule_execution(rule_id),
            attribute                TEXT    NOT NULL,
            objects_affected         INTEGER NOT NULL,
            PRIMARY KEY (rule_id, attribute)
        )
        """,

        // One thing a rule found, about one object.
        //
        // THE UNIQUE CONSTRAINT IS THE IDENTITY: the rule, the subject and the object. The object is
        // identified by object_guid because it is immutable in Active Directory and survives both
        // rename and move, so a finding is recognisable months later and an acceptance made against
        // it stays attached. A surrogate row identifier would be meaningless in the next run.
        //
        // THE RULE VERSION IS NOT HERE. It sits on rule_execution, once, because one rule executes
        // once at one version in one judgement - so a copy on every finding could only ever agree
        // with it or be wrong. Severity is here rather than there because the model allows a rule to
        // vary severity between findings, and a schema that forbade it would be deciding that
        // question by accident.
        //
        // coverage records whether the evidence behind this finding was complete. It is NOT NULL and
        // has no default: a finding that does not say must not be storable, because keeping "clean"
        // apart from "we may not have seen everything" is the whole point.
        """
        CREATE TABLE finding (
            finding_id               INTEGER PRIMARY KEY,
            rule_id                  TEXT    NOT NULL REFERENCES rule_execution(rule_id),
            subject_kind             TEXT    NOT NULL,
            subject_key              TEXT    NOT NULL,
            object_guid              TEXT    NOT NULL,
            severity                 TEXT    NOT NULL,
            distinguished_name       TEXT    NOT NULL,
            detail                   TEXT    NOT NULL,
            coverage                 TEXT    NOT NULL,
            UNIQUE (rule_id, subject_kind, subject_key, object_guid)
        )
        """,

        // What an unconstrained delegation finding rests on, in the shape
        // UnconstrainedDelegationEvidence declares.
        //
        // ONE TABLE PER KIND OF EVIDENCE is the price of refusing a schemaless context blob. The
        // predecessor carried one that three components read undeclared keys out of, and the helper
        // parsing it swallowed every exception, so a malformed value silently downgraded an edge to
        // a principal action - a wrong answer rather than an error.
        //
        // NO ROW FOR A FINDING OF THIS KIND IS A DEFECT. Every finding SEC-010 or SEC-011 produces
        // has one.
        //
        // THE THREE SIGNALS ARE STORED RAW AND THE TWO ANSWERS ARE NOT. IsDomainController and
        // SignalsDisagree are computed from these three columns, so storing them as well would
        // create a second copy that can disagree with the first. A reader re-derives them; that
        // cannot drift.
        """
        CREATE TABLE finding_unconstrained_delegation (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            user_account_control                INTEGER NOT NULL,
            is_computer                         INTEGER NOT NULL,
            server_trust_account_bit            INTEGER NOT NULL,
            primary_group_is_domain_controller  INTEGER NOT NULL,
            under_domain_controllers_ou         INTEGER NOT NULL,
            PRIMARY KEY (finding_id)
        )
        """,
    ];

    // Built after writing rather than during it, for the reason the evidence schema gives: an index
    // maintained through ingest is paid for on every insert and read by nobody until the run is
    // over. A judgement is smaller than a capture, so the saving is smaller - but the two files are
    // written by the same kind of code and there is no reason for them to differ.
    private static readonly string[] DeferredIndexDdl =
    [
        "CREATE INDEX ix_finding_rule ON finding(rule_id)",
        "CREATE INDEX ix_finding_object ON finding(object_guid)",
        "CREATE INDEX ix_finding_severity ON finding(severity)",
    ];

    /// <summary>
    /// Creates every table. Called once, when a judgement store is created.
    /// </summary>
    /// <param name="connection">An open read-write connection to the judgement store.</param>
    public static void CreateTables(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        Execute(connection, TableDdl);
    }

    /// <summary>
    /// Creates the indexes, once the writing is finished.
    /// </summary>
    /// <param name="connection">An open read-write connection to the judgement store.</param>
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
