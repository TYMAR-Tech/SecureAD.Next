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
/// <b>Derived evidence names the generation it came from.</b> Membership-route findings also carry
/// their supporting chains, catalogue version and completeness, so reading one never substitutes a
/// newer derivation's explanation. The initial control-edge slice is stored separately from findings;
/// the remaining control capabilities and reachability are not yet built.
/// </para>
/// </remarks>
public static class JudgementSchema
{
    /// <summary>
    /// The schema version stamped into every judgement store.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Recorded so a reader can refuse a store it does not understand rather than misreading one.
    /// Unlike the evidence version this is cheap to raise: a store that cannot be read is deleted
    /// and the bundle judged again, and nothing is lost because the evidence was never touched.
    /// </para>
    /// <para>
    /// <b>28 is required because stored meaning changed while stored shape did not.</b> Under
    /// decision 0116 discovery runs before detailed assessment and decides its scope, so
    /// <c>ControlEdgePage</c>'s counts cover the objects that were assessed rather than the whole
    /// captured forest. A 27 file and a 28 file would otherwise be indistinguishable while meaning
    /// different things, and a reader would present a scoped count as a forest-wide total - which is
    /// the product telling a customer something false. Older generations are re-judged for current
    /// readback rather than migrated or relabelled.
    /// </para>
    /// <para>
    /// <b>29 records whether discovery scoped the run.</b> Schema 28 changed what the counts mean; 29
    /// lets a reader tell which meaning a given file holds. Without it a scoped product and a
    /// forest-wide one are the same rows with the same columns, and the screen would either omit the
    /// scope caveat where it is needed or show it where it is not - understating real coverage.
    /// </para>
    /// <para>
    /// <b>30 changes how every stored proof is written, without changing one column.</b> Enums were
    /// serialised as ordinals, so a fingerprint or a rehydrated proof meant what it meant only
    /// because of the order somebody typed the members in. They are now written as names, per
    /// <c>docs/decisions/0119-a-stored-proof-records-enum-names.md</c>. A 29 file therefore holds
    /// proofs this build would write differently: its fingerprints would not match on replay, and a
    /// rehydrated flags value could read back as a different limitation entirely. Refused rather
    /// than reinterpreted; re-judge, and nothing is lost because the evidence was never touched.
    /// </para>
    /// <para>31 retains fixed path-input anchors and individually scoped discovery gaps. Existing
    /// ownership seeds include members and are not interchangeable with zero-distance targets.</para>
    /// <para>32 adds a source-bound path calculation and separate membership/terminal-control predecessors.
    /// Terminal permission authority is not a membership-transfer or account-takeover step.</para>
    /// <para>33 retains explicit requester WRITE_DAC proofs in the versioned path certificate.
    /// Existing table layouts and named-holder permission semantics are unchanged.</para>
    /// <para>34 adds separate own-account membership-obtainability proofs and inferred operation steps.
    /// Ordinary Add readiness and the physical table layout remain unchanged.</para>
    /// <para>35 distinguishes ordinary Write Members from Self-Membership in explicit operation requests
    /// and saves separate ordered requester authorization evidence without changing holder counts.</para>
    /// <para>36 saves combined membership-to-DACL proofs with a separate post-membership authorization
    /// context; the physical layout and captured-only requester semantics are unchanged.</para>
    /// <para>37 records offline requester selection sources, questions and independent coverage
    /// within the path certificate; production scheduling and physical tables are unchanged.</para>
    /// <para>38 binds enterprise CA registration/host classification to the captured configuration
    /// context and admits those fixed targets; permission and path-operation semantics are unchanged.</para>
    /// <para>39 saves complete Tier-0 classifications rather than only their fingerprints, so path
    /// readback does not reclassify captured objects. Older formats are refused, never replayed or migrated.</para>
    /// <para>40 saves all-computer LAPS inventory answers and the expected lengths of LAPS finding routes.</para>
    /// <para>41 saves all-object per-right permission classifications and their schema support.</para>
    /// <para>42 stores each distinct reading once in permission_classification_reading and links to it.</para>
    /// <para>43 stores each distinct access control entry once in permission_entry and links to it, so
    /// the row no longer names the object it was found on and the ordinal lives on the link (P-279).</para>
    /// <para>44 stores the shared form of an entry's trustee, so <c>S-1-5-10</c> is held as the
    /// catalogue's own name rather than as <c>This object (Alice)</c> and is resolved against the
    /// target on read (P-285). Every occurrence fingerprint is taken over that shared form, so a
    /// version 43 store's fingerprints do not verify against this build - refused on version rather
    /// than reported as tampered proofs, which is what the number is for.</para>
    /// <para>45 binds each occurrence to the reading that explains it, by folding that reading's
    /// digest into the occurrence's own fingerprint (P-283). Until then <c>reading_id</c> was
    /// covered by nothing, so an allow <c>WRITE_DAC</c> could be repointed at a deny entry's
    /// reading and classify <c>NotDangerous</c> with every check still passing. No column was
    /// added: a separate binding would have cost 32 bytes on each of the production capture's
    /// 330,856,576 occurrences.</para>
    /// <para>46 keys the saved permission classification per <b>descriptor</b> rather than per
    /// object (P-280), because the interpretation of an entry is a function of the entry and the
    /// run's catalogue and of nothing about the object carrying it. On the production capture
    /// 940,067 objects carry 267,550 distinct descriptors, so the occurrences fall from 330,856,576
    /// to 141,693,937; <c>position</c> is dropped as recoverable rank-by-ordinal, the entry-derived
    /// columns move onto one row per distinct entry, and the occurrence becomes
    /// <c>WITHOUT ROWID</c> on <c>(descriptor_id, ordinal)</c>. The per-occurrence fingerprint is
    /// replaced by one per descriptor over its whole ordered list, which is both far cheaper and
    /// stronger, and an object's descriptor is supplied by the <b>evidence</b> on every read.</para>
    /// <para>47 saves separate per-question path-risk qualification and coverage, bound to the
    /// original path calculation and captured pre-change authority; it adds no finding or permission semantics.</para>
    /// <para>48 stores each original requester proof once beside its qualification, with a certificate
    /// fingerprint over the complete proof set, and publishes SEC-071 findings and bound summary counts.</para>
    /// <para>49 retains qualified nested global-group requester witnesses in selected questions and
    /// ordered permission proofs; member attribution and the other operation families are unchanged.</para>
    /// <para>50 saves captured group-nesting reasons for assessing membership-edit permissions and
    /// separates obtained-group continuation witnesses from the user's captured membership proof.</para>
    /// <para>51 binds captured requester authorization to declared forest domains and the target's
    /// domain, retaining scoped global/universal/domain-local membership without widening operation proofs.</para>
    /// <para>52 stores path calculation, node and requester proofs as ordered UTF-8 JSON fragments,
    /// retaining their exact fingerprints without whole-document text materialization.</para>
    /// <para>53 binds membership and requester source proofs through versioned component fingerprints,
    /// retaining complete source coverage without rehashing shared schema/domain/target data per question.</para>
    /// <para>54 binds one obtained global membership's continuation to the captured same-forest
    /// resource domain, retaining scope-qualified nesting and pre-change operation proof.</para>
    /// <para>55 saves per-object supported distances and bound whole-run path/classification totals,
    /// with separate unresolved, unassessed and requester-check coverage.</para>
    /// <para>56 saves a separately graded best evaluated route while retaining shortest distance
    /// and original candidate proof references.</para>
    /// <para>57 saves SEC-052 circular membership sets and their original direct witnesses.</para>
    /// <para>58 indexes each cycle's involved groups for object/domain/container finding filters,
    /// while retaining one finding per component.</para>
    /// <para>59 stores captured group metadata and direct recorded-member counts for selected-only
    /// browsing without group expansion.</para>
    /// <para>60 saves distinct structural member totals and separate missing-reference and evidence
    /// limitations, using member links only and excluding the starting group.</para>
    /// </remarks>
    // Format 69 retains independent original-source hashes beside delegation metadata and resource-scope references.
    public const int Version = 69;

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
            judgement_generation_id  TEXT    NOT NULL,
            derivation_generation_id TEXT        NULL,
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
        // objects_judged, objects_not_applicable and objects_not_judged are three different answers
        // and none is derived from the others.
        //
        // NOT APPLICABLE IS NOT A GAP. A rule declares the classes it is about, and an
        // organisational unit offered to a delegation rule is not an object the rule failed to
        // read - it is an object the rule has nothing to say about. Counting the two together is
        // what this column exists to stop: judged against a real forest on 2026-08-26 the
        // delegation rules called 6,279 of 8,361 objects unreadable on that account, three in four,
        // which would have reported every judging as degraded for ever.
        //
        // objects_not_judged is the real gap: an object the rule IS about, missing something the
        // rule declared it reads. That still degrades the run, and still should.
        //
        // error is set only when outcome is Error. A throwing rule does not stop the others, per
        // the write contract, so its message has to be kept somewhere a reader can reach.
        """
        CREATE TABLE rule_execution (
            rule_id                  TEXT    NOT NULL,
            rule_version             INTEGER NOT NULL,
            outcome                  TEXT    NOT NULL,
            objects_judged           INTEGER NOT NULL,
            objects_not_applicable   INTEGER NOT NULL,
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
        //
        // SEVERITY IS STORED TWICE, AS A WORD AND AS A RANK, AND THE RANK IS WHAT ORDERS A GRID.
        // The word is what a person reads and what survives a renumbering of the enum. Ordering on
        // it sorts alphabetically - Critical, High, Low, Medium - which puts Low above Medium and
        // reads as a working screen. Found 2026-08-26 by reading the predecessor, whose grid sorts
        // correctly only because its view does not order on the text.
        //
        // THE DISPLAY COLUMNS ARE STORED RATHER THAN RESOLVED. The predecessor's grid joined
        // dim_principal and dim_object for these, which it could do because findings and objects
        // shared one file. They do not here: evidence is sealed in another database that a
        // judgement must never write to. The alternative is a lookup per row per page, so what the
        // grid shows is written when the finding is made, from the object already in hand.
        //
        // They are a record of what was true when the judging ran, which is what a judgement is.
        """
        CREATE TABLE finding (
            finding_id               INTEGER PRIMARY KEY,
            rule_id                  TEXT    NOT NULL REFERENCES rule_execution(rule_id),
            subject_kind             TEXT    NOT NULL,
            subject_key              TEXT    NOT NULL,
            object_guid              TEXT    NOT NULL,
            severity                 TEXT    NOT NULL,
            severity_rank            INTEGER NOT NULL,
            distinguished_name       TEXT    NOT NULL,
            principal_name           TEXT    NOT NULL,
            domain_fqdn              TEXT    NOT NULL,
            object_class             TEXT    NOT NULL,
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

        // What SEC-030 rested on, per the rule above.
        //
        // ONE COLUMN, AND IT IS THE IDENTITY THE DERIVATION WAS ASKED ABOUT. The rule's other two
        // inputs are already elsewhere: adminCount had to be 1 or there would be no finding, and
        // the blocked DACL is in the evidence beside this bundle. Copying either here would create
        // a second account of the same fact that can disagree with the first.
        //
        // THERE IS NO DELETED COLUMN. Capture does not read isDeleted (F-S20-1), so every object a
        // bundle carries is live, and a column recording that would be false on every row forever -
        // which is the fault that had the flag removed from the evidence schema in the first place.
        // docs/decisions/0091 puts tombstones outside this rule; P-108 tracks capturing them.
        """
        CREATE TABLE finding_admincount_without_protection (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            sid                                 TEXT    NOT NULL,
            PRIMARY KEY (finding_id)
        )
        """,

        // What SEC-022 rested on: the whole userAccountControl value the pre-authentication flag
        // was read from.
        //
        // THE WHOLE VALUE, NOT THE ONE BIT. A column saying only "the flag was set" would be true
        // of every row in the table and would therefore record nothing. The rest of the integer is
        // what lets a reader tell a disabled account from a live one without going back to the
        // evidence file, which a judgement must never write to and may not be beside.
        //
        // NO DISABLED COLUMN. ADS_UF_ACCOUNTDISABLE is 0x2 of the value already here, so a column
        // would be a second account of one fact and the two could disagree. The reader re-derives
        // it, exactly as the delegation table leaves its two computed answers out.
        """
        CREATE TABLE finding_user_account_control (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            user_account_control                INTEGER NOT NULL,
            PRIMARY KEY (finding_id)
        )
        """,

        // What SEC-027 rested on: the account's own identifier, with its SID history in the child
        // table below.
        //
        // OBJECT_SID IS NULLABLE AND THAT IS NOT SLOPPINESS. An account whose own identifier could
        // not be read still carries the history that was read. Refusing to record the finding, or
        // storing an empty string as though it were a SID, would either suppress a true escalation
        // or invent a principal - and the second is worse, because S-1-5-21-... prefixes are
        // compared against this column to say the privilege came from another domain.
        """
        CREATE TABLE finding_privileged_sid_history (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            object_sid                          TEXT    NULL,
            unreadable_values                   INTEGER NOT NULL,
            PRIMARY KEY (finding_id)
        )
        """,

        // Every value of sIDHistory the object carried, one row each, in the order captured.
        //
        // THE UNMATCHED VALUES ARE STORED TOO, AND THAT IS THE POINT OF THIS TABLE. SEC-027 ranks a
        // value by its relative identifier, which it can only do for the identifiers Microsoft
        // documents. Storing only the matches would show an operator a filtered view of the account
        // he is being told about and leave him believing it carries nothing else. The rule document,
        // section 6, is the argument.
        //
        // ONLY THE SID IS STORED. The relative identifier is the last sub-authority of the text in
        // this column, whether the value is privileged is that identifier against the rule's set,
        // and the name is that identifier against WellKnownSidCatalog. Three answers, all of them
        // recomputed by the reader, none of them able to disagree with the value they came from.
        // The delegation and pre-authentication tables leave their computed answers out for exactly
        // this reason.
        """
        CREATE TABLE finding_privileged_sid_history_value (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            ordinal                             INTEGER NOT NULL,
            sid                                 TEXT    NOT NULL,
            PRIMARY KEY (finding_id, ordinal)
        )
        """,

        // What SEC-021 rested on: the identity the derivation was asked about, and the whole
        // userAccountControl the disabled state is read from.
        //
        // THE UAC VALUE DECIDES NOTHING AND IS STORED ANYWAY. SEC-021 reports a disabled account,
        // because no Microsoft source establishes that a key distribution centre refuses a service
        // ticket for one. The value is here so the finding can say the account is disabled and so a
        // reader can see its other flags without a second finding in front of him. IsDisabled is
        // recomputed from it rather than stored beside it.
        """
        CREATE TABLE finding_kerberoastable_account (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            object_sid                          TEXT    NOT NULL,
            user_account_control                INTEGER NOT NULL,
            unreadable_service_names            INTEGER NOT NULL,
            protection_catalogue_version        INTEGER NULL,
            direct_protection_entry_id          INTEGER NULL,
            direct_protection_name              TEXT NULL,
            PRIMARY KEY (finding_id)
        )
        """,

        // Every service name the account carried, one row each, in the order captured.
        //
        // ALL OF THEM, BECAUSE THE OPERATOR'S QUESTION IS WHETHER THE ACCOUNT REALLY RUNS A SERVICE.
        // The commonest real case is a stale name left over from a test, and that is the only case
        // whose remedy is simply to remove it - which he cannot judge from one name out of four.
        """
        CREATE TABLE finding_kerberoastable_account_spn (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            ordinal                             INTEGER NOT NULL,
            service_principal_name              TEXT    NOT NULL,
            PRIMARY KEY (finding_id, ordinal)
        )
        """,

        // What SEC-091 and SEC-094 rested on: both LAPS expiration timestamps and what the machine
        // could run.
        //
        // ONE TABLE FOR TWO RULES. The rules are separate so that an estate running legacy
        // emulation mode can silence one without silencing the other, but the evidence an operator
        // needs is identical: which timestamps this machine carries and what it was capable of.
        // finding_user_account_control is already shared the same way.
        //
        // BOTH TIMESTAMPS ARE STORED WHATEVER THE FINDING WAS. A SEC-091 finding stores two nulls
        // and says something by doing so: this machine carries neither. Storing only the attribute
        // that decided the finding would leave a reader to guess at the other, and the pair is the
        // question he is actually asking.
        //
        // THE RAW FILETIME, NOT A DATE. The directory stores these as a Windows FILETIME in a text
        // attribute, and the decoded date is recomputed by the reader. A stored date would be a
        // second copy of the value beside it, able to disagree - and it would also throw away the
        // difference between an attribute that was absent and one whose value could not be decoded,
        // which is the distinction those rules turn on.
        //
        // CAPABILITY_KIND IS NOT NULL AND IS THE DISCRIMINATOR. The reader tells this evidence kind
        // from the others by a column that is never null on a row that exists, which is what P-112
        // was about: evidence read by column position from two queries with different column lists.
        //
        // CAPABILITY_BASIS IS STORED BESIDE IT AND IS NOT DECORATION. A capability decided from a
        // build number and the same answer guessed from an operating system name are not equally
        // good, and a bundle sealed before operatingSystemVersion was captured can only be judged
        // the second way. The finding records which it was.
        """
        CREATE TABLE finding_laps_deployment (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            windows_laps_expiration             TEXT        NULL,
            legacy_laps_expiration              TEXT        NULL,
            capability_kind                     TEXT    NOT NULL,
            capability_basis                    TEXT    NOT NULL,
            operating_system                    TEXT        NULL,
            operating_system_version            TEXT        NULL,
            PRIMARY KEY (finding_id)
        )
        """,

        // What SEC-090 rested on: a principal broad in every organisation that can read a machine's
        // LAPS password, and the access control entry that let it.
        //
        // ONE ROW PER BROAD PRINCIPAL REACHED, NOT PER ENTRY. An operator's question is "who can
        // read this password", and one delegation can reach two broad principals by two routes.
        // Collapsing them to the entry would hide one of the answers.
        //
        // RIGHTS IS NOT A BOOLEAN, BECAUSE THREE OF ITS FOUR STATES ARE NOT FINDINGS. Microsoft
        // requires READ_PROPERTY *and* CONTROL_ACCESS to read a confidential attribute, and all the
        // LAPS password attributes are confidential. The predecessor tested the second alone and so
        // named principals who cannot retrieve the password. Storing which rights were actually
        // held is what lets a reader see that distinction rather than trust it.
        //
        // REACH DISTINGUISHES AN ENTRY NAMING THIS ATTRIBUTE FROM ONE OVER EVERY ATTRIBUTE, and it
        // comes from ACE_OBJECT_TYPE_PRESENT rather than from whether the GUID is null. Those are
        // different questions; conflating them reports the wrong population in both directions.
        //
        // INHERITED_FROM IS A FACT AND NOT A VERDICT. A grant inherited from the domain root may be
        // deliberate - the customer configuration that prompted P-123 is exactly that - so the
        // scope is recorded and left for the operator to recognise.
        //
        // EXPANSION_WAS_COMPLETE IS WHY AN EMPTY RESULT IS NOT REASSURANCE. A walk that stopped at a
        // budget can find no broad principal while one is still inside.
        //
        // TRUSTEE_SID IS NOT NULL AND IS THE DISCRIMINATOR, per P-112: a row that exists always has
        // one, so the reader never keys this evidence kind off a legitimately null column.
        """
        CREATE TABLE finding_laps_password_reader (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            trustee_sid                         TEXT    NOT NULL,
            trustee_name                        TEXT        NULL,
            broad_principal_sid                 TEXT    NOT NULL,
            broad_principal_name                TEXT        NULL,
            attribute                           TEXT    NOT NULL,
            rights                              TEXT    NOT NULL,
            reach                               TEXT    NOT NULL,
            inherited_from                      TEXT        NULL,
            expansion_was_complete              INTEGER NOT NULL,
            route_length                        INTEGER NOT NULL CHECK (route_length >= 0),
            PRIMARY KEY (finding_id)
        )
        """,

        // The membership path, one principal per row, from the delegated principal down to the
        // broad one.
        //
        // THE PATH IS THE FINDING AND NOT AN ORNAMENT. At depth six, naming the broad principal does
        // not tell an operator which link to cut, which is why P-123 requires the path outright. A
        // stored conclusion without it would be unactionable, and the expansion is not repeatable
        // from the judgement store alone - the nesting lives in the derivation.
        //
        // THE NAME IS STORED BESIDE THE IDENTIFIER RATHER THAN RESOLVED WHEN SHOWN. The identifier
        // is what survives a rename and what a later run recognises; the name is the only part an
        // operator can act on, and a path of raw identifiers is unactionable. Resolving at display
        // time would be one lookup per row per page, which is the thing the finding table's own
        // remarks refused - measured at about three seconds a page on a million objects. It is
        // nullable because a principal from a trusted forest has no name in this bundle.
        """
        CREATE TABLE finding_laps_password_reader_path (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            ordinal                             INTEGER NOT NULL,
            sid                                 TEXT    NOT NULL,
            name                                TEXT        NULL,
            PRIMARY KEY (finding_id, ordinal)
        )
        """,

        // SEC-060: an object a principal broad in every organisation can take control of.
        //
        // TRUSTEE_SID IS NOT NULL AND IS THE DISCRIMINATOR, per P-112: a row that exists always has
        // one, so the reader never keys this evidence kind off a legitimately null column.
        //
        // RIGHT IS STORED BECAUSE THE THREE ARE NOT INTERCHANGEABLE. WriteDacl and GenericAll grant
        // control of the list directly. WriteOwner reaches it in two steps, through becoming the
        // owner, and that second step depends on the forest not having blocked an owner's implicit
        // rights - so an operator reading a stored finding has to be able to tell which one this
        // was. Flattening them to "takeover" would lose the distinction that decides whether the
        // finding is even true on a hardened forest.
        """
        CREATE TABLE finding_object_takeover (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            trustee_sid                         TEXT    NOT NULL,
            trustee_name                        TEXT        NULL,
            broad_principal_sid                 TEXT    NOT NULL,
            broad_principal_name                TEXT        NULL,
            takeover_right                      TEXT    NOT NULL,
            inherited_from                      TEXT        NULL,
            expansion_was_complete              INTEGER NOT NULL,
            PRIMARY KEY (finding_id)
        )
        """,

        // The membership path for SEC-060, one principal per row, for the reason the LAPS path
        // table gives in full: the path is the finding, and the nesting lives in the derivation so
        // it cannot be recomputed from the judgement store alone.
        """
        CREATE TABLE finding_object_takeover_path (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            ordinal                             INTEGER NOT NULL,
            sid                                 TEXT    NOT NULL,
            name                                TEXT        NULL,
            PRIMARY KEY (finding_id, ordinal)
        )
        """,

        // SEC-031 and SEC-032: an object whose owner is not an administrative principal.
        //
        // ONE TABLE FOR TWO RULES, AND THAT IS NOT A SHORTCUT. The two rules record identical facts
        // and differ only in the claim they make about them - SEC-031 reports latent authority over
        // an ordinary object at Low, SEC-032 reports a route to privilege over an AdminSDHolder
        // protected object at High. The finding row already carries the rule identifier, so which
        // claim was made is never in doubt. The rules cover disjoint sets of objects, so no object
        // appears here twice.
        //
        // OWNER_SID IS NOT NULL AND IS THE DISCRIMINATOR, per P-112. A descriptor that was read
        // always has an owner - MS-ADTS 6.1.3 states the owner SID cannot be null - and a
        // descriptor carrying none is refused rather than reported, so a row that exists has one.
        //
        // STANDING IS STORED BECAUSE THE TWO STATES CARRY OPPOSITE REMEDIES. An owner that exists
        // can be asked to hand ownership over. An owner that has been deleted cannot, and the
        // object is orphaned - which is a different sentence to put in front of an operator.
        //
        // OBJECT_CLASS IS STORED RATHER THAN LOOKED UP. It decides whether the forest's
        // owner-rights hardening could have applied at all, and a stored finding has to stay
        // readable without re-opening the evidence it came from.
        """
        CREATE TABLE finding_object_ownership (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            owner_sid                           TEXT    NOT NULL,
            owner_name                          TEXT        NULL,
            standing                            TEXT    NOT NULL,
            object_class                        TEXT    NOT NULL,
            membership_was_complete             INTEGER NOT NULL,
            PRIMARY KEY (finding_id)
        )
        """,

        // SEC-093: the Group Policy Object whose authorized LAPS password decryptor is, or
        // contains, a principal broad in every organisation.
        //
        // THERE IS NO MACHINE COLUMN, AND THAT IS A REFUSAL RATHER THAN AN OMISSION. Microsoft
        // states the authorized decryptor "can't be changed after a password is encrypted", so a
        // password already in the directory was encrypted against whatever the policy named when
        // it was written - a value the directory does not record. Naming the machines affected
        // would assert something about the past that no evidence establishes.
        //
        // CONFIGURED_VALUE IS NOT NULL AND IS THE DISCRIMINATOR, per P-112. It is also what an
        // operator searches the policy for, so it is stored verbatim rather than normalised.
        //
        // DECRYPTOR_SID AND BROAD_PRINCIPAL_SID ARE BOTH NULLABLE, because this table carries two
        // findings about different problems. A resolved decryptor containing a broad principal
        // means the password is protected against too many people. An unresolvable one means
        // Microsoft's documented failure applies - the password is not backed up at all - and
        // reporting that as the first would send an operator to fix the wrong thing.
        //
        // FORM IS STORED BECAUSE IT DECIDES WHAT UNRESOLVED MEANS. An identifier this capture
        // cannot place is a principal from somewhere unread; a name it cannot place may be the
        // typo that stopped the policy working.
        //
        // EXPANSION_WAS_COMPLETE IS WHY AN EMPTY RESULT IS NOT REASSURANCE, for the reason the
        // SEC-090 table gives.
        """
        CREATE TABLE finding_laps_decryptor (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            policy_display_name                 TEXT        NULL,
            configured_value                    TEXT    NOT NULL,
            form                                TEXT    NOT NULL,
            decryptor_sid                       TEXT        NULL,
            decryptor_name                      TEXT        NULL,
            broad_principal_sid                 TEXT        NULL,
            broad_principal_name                TEXT        NULL,
            expansion_was_complete              INTEGER NOT NULL,
            route_length                        INTEGER NOT NULL CHECK (route_length >= 0),
            PRIMARY KEY (finding_id)
        )
        """,

        // The route from the configured decryptor down to the broad principal, one per row.
        //
        // THE ROUTE IS THE FINDING, for a reason particular to this rule: Windows LAPS encrypts
        // against exactly one principal, and Microsoft's documented way to authorize more than one
        // is a wrapper group. So the supported configuration is a group, and the finding is almost
        // always about what ended up nested inside it. Naming only the endpoints would not say
        // which link to cut.
        """
        CREATE TABLE finding_laps_decryptor_path (
            finding_id                          INTEGER NOT NULL REFERENCES finding(finding_id),
            ordinal                             INTEGER NOT NULL,
            sid                                 TEXT    NOT NULL,
            name                                TEXT        NULL,
            PRIMARY KEY (finding_id, ordinal)
        )
        """,
    ];

    // Built after writing rather than during it, for the reason the evidence schema gives: an index
    // maintained through ingest is paid for on every insert and read by nobody until the run is
    // over. A judgement is smaller than a capture, so the saving is smaller - but the two files are
    // written by the same kind of code and there is no reason for them to differ.
    //
    // THE FIRST INDEX IS THE GRID'S OWN SORT, TIE-BREAKER AND ALL. Keyset paging asks for the rows
    // after the last one shown, in the sort order, so an index that stops short of the tie-breaker
    // leaves the database sorting the remainder on every page. The tie-breaker is not decoration:
    // rows that sort equal can straddle a page boundary and be shown twice or not at all, which is
    // silent and close to unreproducible. Learned from the predecessor's KeysetQueryBuilder.
    private static readonly string[] DeferredIndexDdl =
    [
        "CREATE INDEX ix_finding_grid ON finding(severity_rank DESC, rule_id, distinguished_name)",
        "CREATE INDEX ix_finding_rule ON finding(rule_id)",
        "CREATE INDEX ix_finding_object ON finding(object_guid)",
        "CREATE INDEX ix_finding_domain ON finding(domain_fqdn)",

        // Asked once for every object an operator opens, to fill the findings section of the object
        // view. Without it that is a scan of every finding in the forest per object opened, which is
        // the shape of a screen that feels fine in a lab and stalls on a real directory.
        //
        // The grid index above leads on severity_rank, so it cannot serve an exact name lookup.
        "CREATE INDEX ix_finding_name ON finding(distinguished_name)",
    ];

    /// <summary>
    /// Creates every table. Called once, when a judgement store is created.
    /// </summary>
    /// <param name="connection">An open read-write connection to the judgement store.</param>
    public static void CreateTables(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        Execute(connection, TableDdl);
        SecureAD.Storage.MembershipRouteStorage.CreateTables(connection);
        ControlEdgeStorage.CreateTables(connection);
        SelfMembershipStorage.CreateTables(connection);
        PathInputStorage.CreateTables(connection);
        Tier0PathStorage.CreateTables(connection);
        CircularMembershipStorage.CreateTables(connection);
        DuplicateSpnStorage.CreateTables(connection);
        GroupMembershipFindingStorage.CreateTables(connection);
        GroupMembershipReviewFindingStorage.CreateTables(connection);
        DelegationConfigurationFindingStorage.CreateTables(connection);
        ServiceAccountFindingStorage.CreateTables(connection);
        AttributeWriteFindingStorage.CreateTables(connection);
        GroupInventoryStorage.CreateTables(connection);
        PathRequesterRiskStorage.CreateTables(connection);
        Tier0RouteFindingStorage.CreateTables(connection);
        LapsInventoryStorage.CreateTables(connection);
        PermissionClassificationStorage.CreateTables(connection);
    }

    /// <summary>
    /// Creates the indexes, once the writing is finished.
    /// </summary>
    /// <param name="connection">An open read-write connection to the judgement store.</param>
    public static void CreateDeferredIndexes(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        Execute(connection, DeferredIndexDdl);
        LapsInventoryStorage.CreateIndexes(connection);
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
