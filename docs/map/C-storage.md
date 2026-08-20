# C — Storage (write path)

**Owns:** everything between "a capture has data to persist" and "a sealed, signed run bundle exists
on disk that a later session can open." The schema of `audit.db`, the connections that write and read
it, the files that make up a run bundle, and the bookkeeping a run writes about itself. It ends where
querying begins.

**Not covered in this file:** the read/query path — `ObjectQueryService` (1,317),
`GridSummaryQueryService` (366), `DashboardQueryService` (331), `OfflineTreeService` (250),
`FindingSummaryService` (44), `AuditObjectLocator` (90), `LowSignalOuRecommendationService` (101), and
all of `Infrastructure/Paging/` (~1,400). That is the second half of branch C. The seam is C2: the
write path authors the views, the read path consumes them, and nothing crosses between them except
view names.

## The flow

1. **`SecurityModeCaptureService.RunAsync`** (or `ExistingCaptureAnalysisService` for re-analysis) is
   the entry point. It resolves a run directory under the library and hands off to
   `DirectCaptureRunner`.
2. **`DirectCaptureRunner` computes `runDir` and `Path.Combine(runDir, "audit.db")`** (`:167`), then
   writes `preflight.json` into the bundle before any LDAP traffic (`:165`) — so the DC selection that
   produced the run is recorded even if the run never finishes.
3. **`DerivedStore.Open(dbPath)`** creates the directory, opens one `ReadWriteCreate` connection with
   `Pooling = false`, applies write pragmas (`journal_mode = WAL`, `synchronous = NORMAL`,
   `foreign_keys = ON`, `busy_timeout = 120000`), and executes **all** base and security table DDL
   unconditionally.
4. **`RunControlWriter.CreateRun`** writes the `run` row, `run_domain_discovered`, and
   `run_domain_declaration` — the run's own statement of what it set out to cover, including a
   `coverage_id` that is nullable rather than defaulted.
5. **Capture writes into `shard-N.db` files** beside `audit.db`, one per DC, then merges. The
   `Direct*Writer` family that does this belongs to **branch B**; C owns the tables they write into.
6. **`DiskSpaceMonitor` polls every 60 s** during capture, warning below 500 MB and cancelling below
   100 MB.
7. **`store.CreateDeferredIndexes()`** runs after bulk ingest (`DirectCaptureRunner.cs:543`) — indexes
   are deliberately not present during the write, so inserts do not pay for them.
8. **`DerivedAnalysisPipeline`** (branch D) derives analysis tables, calls `store.CreateViews()` as one
   phase among many, and seals a `pipeline_phase_derived_health` key into `dim_database_metadata` as
   its last act.
9. **`AttestationVerifier.Verify`** tests every "this excluded domain is empty" claim against
   `dim_unresolved_group_member`, and `RunControlWriter.RecordAttestationVerification` writes back any
   contradiction. A claim becomes a control by being falsifiable.
10. **`DerivedStore.Dispose`** checkpoints the WAL with `TRUNCATE`, so the `-wal` file is folded into
    `audit.db` before any read connection opens.
11. **`DatabaseIntegrityService.Sign(dbPath)`** hashes the file with SHA-256 and writes `audit.db.sig`
    plus `audit.db.sig.cache`. From here `audit.db` is immutable evidence.
12. **On failure instead**, `FailedRunCleanup.Reclaim` deletes the whole bundle directory at the point
    of failure — the account of the failure lives in the separate log tree and survives.
13. **Later, on open**, `DatabaseConnectionFactory.OpenReadOnly` opens `SqliteOpenMode.ReadOnly` and
    then composes the connection: `ATTACH` the sidecar (creating `suppressions.db` if absent), create
    the suppression-dependent views as temp views, and create the asset-tier precedence temp views
    that shadow `main.dim_asset_tier`.

Step 13 is the one worth naming: **the read path physically cannot write `audit.db`, but it does
create a file in the bundle.** That is deliberate — the sidecar must exist before `ATTACH` can succeed
on a read-only main, and creating it there is what keeps acceptances out from under the signature.

## Components

### C1 — Audit database schema (tables and indexes)
- **Layer:** Infrastructure
- **Owns:** the DDL for every table in `audit.db`, and the deferred indexes created after ingest.
- **Implemented by:** `Storage/DerivedStoreSchema.cs` (667)
- **Non-obvious:** DDL is genuinely centralised — `git grep -l "CREATE TABLE" -- src` returns exactly
  two files, this and `SuppressionSidecar.cs`. Nothing creates a table ad hoc. The `BaseTableDdl` /
  `SecurityTableDdl` split is organisational only; see Would-do-differently §1.

### C2 — View definitions
- **Layer:** Infrastructure
- **Owns:** the DDL for all `v_grid_*` and `v_export_*` views, plus the two temp-view families created
  per read connection.
- **Depends on:** C1
- **Implemented by:** `Storage/DerivedStoreSchema.Views.cs` (1,045)
- **Non-obvious:** **this is the branch's largest cross-branch seam.** Views are authored here, created
  by a phase of branch D, consumed entirely by the read path and by J.
  `CreateTempViewGridEscalationPaths` is derived from the persistent constant by string-replacing the
  `CREATE` clause rather than being a second hand-maintained copy — the comment says why: two copies of
  a sixty-line body would drift, and the drift would show up as a grid disagreeing with an export. The
  persistent copy is kept in `SecurityViewDdl` anyway, so `sqlite_master` existence probes keep
  answering the same way.

### C3 — Write connection & session
- **Layer:** Infrastructure
- **Owns:** the single `ReadWriteCreate` connection a capture or re-analysis holds, its pragmas, schema
  creation, index creation, view creation, metadata writes, and the WAL checkpoint on dispose.
- **Depends on:** C1, C2
- **Implemented by:** `Storage/DerivedStore.cs` (330)
- **Non-obvious:** `Dispose` checkpoints `wal_checkpoint(TRUNCATE)` and swallows failure — without it a
  later `ReadOnly` connection would not see rows still sitting in the `-wal`. `AddColumnIfMissing` is a
  small `ALTER TABLE` migration path for six `fact_escalation_path` columns; see
  Would-do-differently §6.

### C4 — Read connection chokepoint & per-connection composition
- **Layer:** Infrastructure
- **Owns:** the one place a read connection to an audit database is opened, and everything that must be
  set up per connection because it cannot live in the file.
- **Depends on:** C2, C5, C6
- **Implemented by:** `Storage/DatabaseConnectionFactory.cs` (340), `Storage/ConnectionDiagnostics.cs`
  (121)
- **Non-obvious:** `ConfigureReadConnection` exists as a *named seam*, not as tidiness — temp views are
  per-connection, so the sidecar attach and the two temp-view families have nowhere else to go. Its own
  remarks record that routing every read site through here was done first precisely so that this method
  could exist. `SqliteConnectionChokepointTests` forbids direct `new SqliteConnection` outside it.
  `ConnectionDiagnostics` is off unless `SECUREAD_DIAG_CONNECTIONS=1` and costs a cached boolean when
  off.

### C5 — Suppression sidecar
- **Layer:** Infrastructure
- **Owns:** `suppressions.db` — its schema, its creation, its stamped identity, and the scope test an
  import must pass.
- **Depends on:** C4
- **Implemented by:** `Storage/SuppressionSidecar.cs` (478)
- **Non-obvious:** the reason it exists is arithmetic, not taste: writing an acceptance into `audit.db`
  invalidates the signature that proves the capture is unmodified. A separate file restores that proof
  for free, and an attached database inherits the main connection's read-only flag, so the read path
  *physically* cannot write it. `SidecarIdentity.IsSameScopeAs` gates on `CoverageId` and treats **two
  absent coverage ids as a non-match** — the previous test reduced to `ForestFqdn` inside a picker
  already restricted to one forest, so it could not refuse anything it was offered.

### C6 — Asset tier storage split
- **Layer:** Infrastructure
- **Owns:** the division of `dim_asset_tier` into derived rows (evidence, in `audit.db`, under the
  signature) and policy rows (opinion, in the sidecar), and the temp view that makes the split
  invisible to readers.
- **Depends on:** C1, C2, C5
- **Implemented by:** `Storage/AssetTierWriter.cs` (119), `CreateTempViewAssetTierPrecedence` and
  `CreateTempViewGridEscalationPaths` in C2, `dim_asset_tier_policy` in C5
- **Non-obvious:** `main.` is load-bearing in the precedence view — unqualified, the derived branch
  would resolve to the view and recurse. And a view stored in `main` binds to `main`, which is *why*
  `v_grid_escalation_paths` has to be recreated as a temp view for a tier override to show on that
  grid, while `EscalationPathRuleEvaluator` deliberately says `main.dim_asset_tier` so a policy tier
  cannot retroactively change what a signed snapshot found. `AssetTierWriter` classification is
  branch D; the storage split is C's.

### C7 — Run control records
- **Layer:** Infrastructure
- **Owns:** writing the run's own lifecycle bookkeeping into `audit.db` — the `run` row, phases,
  checkpoints, and coverage.
- **Depends on:** C1, C3, C8
- **Implemented by:** `Storage/RunControlWriter.cs` (475), `Storage/RunStateNames.cs` (38)
- **Non-obvious:** `assessment_mode` is written as the hardcoded constant `"Security"` (`:20, :102`).
  The column, its readers, and compare's mode check all survive; the enum that once supplied it does
  not — see decision 0007.

### C8 — Domain declaration & coverage identity
- **Layer:** Infrastructure
- **Owns:** what a run declared it would cover, why each discovered domain was in or out, what was
  attested about an excluded one, and whether that attestation later proved false.
- **Depends on:** C1
- **Implemented by:** `Storage/DomainDeclaration.cs` (296), `Storage/AttestationVerifier.cs` (127)
- **Non-obvious:** construction of `DomainDeclarationState` is private and routed through three
  factories, so *an exclusion carrying no attestation is unrepresentable* rather than merely rejected.
  `AttestationVerifier` is what turns a click-through waiver into a control — it falsifies "this
  excluded domain holds no privilege elsewhere" against `dim_unresolved_group_member`, and only
  `InForestNotCaptured` counts as falsifying. This also gave `dim_unresolved_group_member` its first
  consumer. **Cross-branch:** `coverage_id` is what C5's import gate reads, and what G (Compare) reads
  to decide two runs are comparable.

### C9 — Run-control readback
- **Layer:** Infrastructure
- **Owns:** reading a bundle's own account of itself — run state, coverage, and whether derived analysis
  finished — without going near the grid query path.
- **Depends on:** C1, C4, C7
- **Implemented by:** `Storage/RunCoverageReader.cs` (314), `Storage/RunCoverageResolver.cs` (115),
  `Storage/RunDatabaseInspector.cs` (75), `Storage/DerivedHealthReader.cs` (170),
  `Storage/DerivedPhaseVerdicts.cs` (137)
- **Non-obvious:** `DerivedHealthState.Unrecorded` is treated as *weaker* than `Degraded`, not
  healthier — a run that did not state whether its analysis finished has not stated that it did. This
  is the mechanism behind decision 0002: readers never probe for individual views, they read one health
  verdict with a reason, so a degraded bundle names the failed phase instead of showing an empty grid.
  `RunCoverageReader`'s guards carry comments explaining they are *not* optional-table guards —
  `BaseTableDdl` runs unconditionally, so an absent table means a broken read, not an old bundle.

### C10 — Bundle layout & lifecycle on disk
- **Layer:** Infrastructure (+ Core types)
- **Owns:** the on-disk shape of a run — where bundles live, what files a bundle contains, session
  versus library, and reclaiming a failed one.
- **Depends on:** C11
- **Implemented by:** `RunLibrary/RunLibraryService.cs` (435) + `.Metadata.cs` (539),
  `Storage/RunMetadataService.cs` (282), `Storage/InvocationSerializer.cs` (75),
  `Storage/FailedRunCleanup.cs` (80), `Storage/BaselineEligibility.cs` (87),
  `Core/RunLibrary/RunStorageLocation.cs`, `Core/RunLibrary/RunMetadata.cs` (115)
- **Non-obvious:** the layout is `%LOCALAPPDATA%\SecureAD\Runs\{session|library}\<runId>\`, and it is
  **hardcoded in two constructors**, not read from configuration. A bundle contains `audit.db`,
  `audit.db.sig`, `audit.db.sig.cache`, `suppressions.db`, `invocation.json`, `preflight.json`,
  `user_metadata.json`, and transiently `shard-N.db` and `audit.db-wal`. `run-summary.json` is **not**
  in the bundle. `FailedRunCleanup.Reclaim` never throws — it runs on a failure path, and a cleanup
  that raised its own exception would replace the error the user needs to see.

### C11 — Integrity signature
- **Layer:** Infrastructure
- **Owns:** proving `audit.db` is unchanged since capture sealed it.
- **Implemented by:** `Storage/DatabaseIntegrityService.cs` (113)
- **Non-obvious:** the `.sig.cache` sidecar keys on file size plus last-write time so reopening a 17 GB
  bundle does not re-hash it. Its failure path is silent by design — a lost cache costs a re-hash, not
  a wrong verdict. `Unsigned` and `Modified` are distinct outcomes, and a malformed signature JSON
  degrades to `Unsigned` rather than `Modified`. **Cross-branch:** I (Output) refuses to export from a
  `Modified` bundle.

### C12 — Materialized ACL payload codec
- **Layer:** Infrastructure
- **Owns:** the binary encoding of `fact_object_acl_materialized.payload`.
- **Depends on:** C1
- **Implemented by:** `Storage/MaterializedAclPayload.cs` (160)
- **Non-obvious:** a magic header `SACL\2`, a per-payload string table, and 7-bit-encoded ints. This
  exists because a forest's ACEs re-serialised per object as JSON is the difference between a large
  database and an unusable one — trustee SIDs and GUIDs repeat heavily within one object's ACL, so the
  string table is most of the win. Written by branch B's `DirectAceWriter`; the *format* is C's.

### C13 — Capture-time disk guard
- **Layer:** Infrastructure
- **Owns:** refusing to start, and cancelling mid-flight, when the volume holding the bundle cannot hold
  the run.
- **Implemented by:** `Storage/DiskSpaceMonitor.cs` (197)
- **Non-obvious:** `RecommendedBytes = 25 GB` is **measured, not derived from an object count** — its
  remarks record ~140k objects across nine domains producing a 17 GB end-of-run database. That number
  is the single most useful fact in this branch for sizing a rebuild.

### C14 — Run logs & performance telemetry
- **Layer:** Infrastructure
- **Owns:** the per-run log folder, the run-scoped logger, `run-summary.json`, and phase timing.
- **Implemented by:** `Storage/RunLogService.cs` (222), `Storage/PerfLogWriter.cs` (128)
- **Non-obvious:** these write to `%LOCALAPPDATA%\SecureAD\Logs\runs\<ts>\`, a **separate tree from the
  bundle**, pruned to the newest 25 folders on construction. That separation is what lets
  `FailedRunCleanup` delete a failed bundle without destroying the account of why it failed — and it is
  also what produces the retention inversion in Would-do-differently §5.

### C15 — Write-path entry points
- **Layer:** Infrastructure
- **Owns:** the two public ways a database gets written: a fresh forest capture, and re-analysis of an
  existing one.
- **Depends on:** C3, C7, C10, C11
- **Implemented by:** `Storage/SecurityModeCaptureService.cs` (202),
  `Storage/ExistingCaptureAnalysisService.cs` (323)
- **Non-obvious:** re-analysis ends in a **fresh** `DatabaseIntegrityService.Sign`, not a verification —
  so a re-analysed bundle is signed as of the re-analysis, and the original capture signature is gone.
  That is correct given the derived tables genuinely changed, but it means the signature attests
  "unmodified since last analysis", not "unmodified since capture".

## Naming & taxonomy

### 1. `DerivedStore` and `DerivedStoreSchema` name a distinction the product no longer has

Both types open with the same doctrine: *"audit.db is rebuildable, disposable, and never authoritative.
Evidence is authoritative; SQLite is derived."* There is no evidence store. Capture writes direct to
SQLite (`DirectCaptureRunner`), the only durable artefacts are the bundle files, and `audit.db` is
signed precisely *because* it is the authoritative record. The comment describes a design that was
removed, and it describes the current one backwards.

The type is also not a "store" in the sense the name implies. It owns one connection, its pragmas, and
schema creation, for the duration of one write session.

**Rename:** `AuditDatabase` (or `AuditDatabaseWriter`) and `AuditSchema`. Delete the doctrine comment
rather than repairing it.

**Why it matters:** the comment currently licenses exactly the wrong instinct — that losing `audit.db`
is recoverable. It is not; it is the run.

### 2. `run` and `dim_run` are two different tables about runs

`run` is capture-time lifecycle control, created in `BaseTableDdl`. `dim_run` is saved-run display
metadata, created in `SecurityTableDdl`, indexed by `completed_utc`. Nothing in either name says which
is which, and `dim_run` picks up the `dim_` prefix that everywhere else in this schema means "dimension
of the captured directory".

**Rename:** `run` → `run_control`; `dim_run` → `run_display` or fold it into `run` outright.

**Why it matters:** `SELECT ... FROM run` and `SELECT ... FROM dim_run` are both plausible-looking
answers to "what runs are in this file", and they return different sets.

### 3. `RunDatabaseInspector` has a `Legacy` state that decision 0001 says cannot exist

`Inspect` probes `sqlite_master` for the `run` table and returns `RunDatabaseStateInfo.Legacy` when it
is absent, documented as *"falls back cleanly for legacy databases that do not contain the new
run-control tables."* Decision 0001 states the product has never shipped and nothing is kept backward
compatible, and `RunCoverageReader` says so explicitly in four places — `[run]` is in `BaseTableDdl`,
executed unconditionally, so no bundle this build writes can lack it.

The behaviour is fine (`Legacy` is blocked identically to a crashed run). The *name* is the problem: it
says "old version", when what it actually means is "this file is not one of ours, or is corrupt".

**Rename:** `Legacy` → `NotAnAuditDatabase`, or `Unrecognised`. Same for the doc comment.

### 4. `dim_asset_tier.sid` holds values that are not SIDs

`AssetTierWriter` classifies SID-less objects — the domain root, `AdminSDHolder`, the Domain Controllers
OU, which are among the most privileged objects in a forest — and stores them under the key
`$"guid:{guid}"` in a column named `sid` (`AssetTierWriter.cs:81`). `git grep "guid:" -- src` returns
that one line and nothing else: **no reader anywhere knows the prefix exists.**

**Rename:** the column to `subject_key`, with a companion `subject_kind` of `Sid | ObjectGuid`. Or,
better, do not encode a type into a string prefix at all.

**Why it matters:** this is a naming problem with a correctness shadow. See Would-do-differently §3.

### 5. `Base` and `Security` no longer name a distinction

`BaseTableDdl` / `SecurityTableDdl`, `BaseViewDdl` / `SecurityViewDdl`, `BaseDeferredIndexes` /
`SecurityDeferredIndexes`. Every consumer executes both halves, on adjacent lines. The prefixes now
mean "the first list" and "the second list".

**Rename:** collapse each pair into one array — `TableDdl`, `ViewDdl`, `DeferredIndexes`. This is the
rename, not the restructure; see Would-do-differently §1 for that.

### 6. `RunMetadataService` and `RunLibraryService` are the same responsibility under two names

Both own the `session/` and `library/` layout, both know `user_metadata.json`, both expose
`SessionPath` and `LibraryPath`, and the folder-name constants are duplicated verbatim in both.
`RunMetadataService.cs:12` even carries the comment *"Use user_metadata.json to align with
RunLibraryService"* — an alignment note is what you write when two things should have been one.

**Rename:** keep `RunLibraryService`; the other's surviving behaviour merges into it.

### 7. `DatabaseConnectionFactory` understates itself in the opposite direction to branch A's `LdapConnectionManager`

Branch A found a "Manager" that was really a factory. Here is a "Factory" that is really a composition
root: it opens the connection *and* attaches a second database, *and* creates four temp views, *and*
creates the sidecar file if it is missing. Its own remarks are clear about this; its name is not.

**Rename:** `AuditDatabaseAccess`, or split into `AuditConnectionFactory` (opens) and
`ReadConnectionComposer` (configures).

## Would-do-differently

### 1. The base/security schema split is inert, and it costs six arrays and a habit

Every consumer runs both halves adjacently: `DerivedStore.Open` (`:263, :269`), `CreateViews`
(`:172, :175`), `CreateDeferredIndexes` (`:71, :74`), and `SyntheticDbGenerator` (`:206-215`). There is
no code path that produces a base-only database.

**Addition to `docs/review/00a-product-identity.md`, sequencing item 6.** That item pairs the
`AssessmentMode` enum with the schema split and says test fixtures pass `AssessmentMode.Configuration`
"to get a lighter schema" (naming `KeysetPagingTests`, `AcesGridViewModelTests`,
`SyntheticAuditDbGenerator`). **The first half is already done and the stated reason for keeping the
second half no longer holds:** `git grep "enum AssessmentMode" -- src` returns nothing, and
`git grep "AssessmentMode.Configuration" -- src tests` returns nothing. The identifier survives only as
a column name and the string literal `"Security"`. The same claim is repeated in
`.github/copilot-instructions.md`, which is now stale on this point.

**Ideal:** one `TableDdl`, one `ViewDdl`, one `DeferredIndexes`. The deletion is smaller and much safer
than item 6 anticipated.

### 2. Configuration describes a storage layout the product does not use

`StorageSettings` exposes `RunBundlesPath`, `SessionRunsPath`, and `RegistryDbPath`, defaulted in
`appsettings.json`, validated as *critical* by `SettingsValidator`, and covered by five tests.
`git grep` shows **none of the three is ever read to build a path.** The real root is hardcoded in
`RunLibraryService`'s default constructor and again in `MainViewModel` at two call sites.
`run_registry.db` appears in `StorageSettings.cs`, `appsettings.json`, and one assertion — and nowhere
else in `src/`. No such file is ever opened.

**Ideal:** either the settings are load-bearing or they are deleted. Today a user editing
`RunBundlesPath` gets a validated, tested setting that does nothing, and `run_registry.db` is a design
that was specified and then not built. Related to `docs/review/S3-removed-design-residue.md` in kind,
though not among its ten findings.

### 3. Tier-0 objects with no SID are written where nothing can read them

`AssetTierWriter` classifies the domain root, `AdminSDHolder`, and the Domain Controllers OU under
`guid:<object_guid>` keys, in a column every consumer joins as a SID. `docs/DATA-MODEL.md` describes
`dim_asset_tier` as "per SID" and states that a domain root object's SID *is* the domain SID with no
well-known RID, which is exactly why the classifier is asked with `(sid, dn, objectClass)`. The
classification is right; the storage key throws part of it away.

**Addition to `docs/DATA-MODEL.md`.** The document states `Tier0ObjectTable` and `AssetTierWriter` are
the only two places the Tier-0 question is answered — true — but does not record that one of the two
writes SID-less answers to an unreachable key. This is a claim to verify against the branch-D session
before acting on it: `Tier0ObjectTable` materialises `temp.tier0_object` by asking the classifier
directly, so the *rule engine* may well be unaffected and the loss confined to `dim_asset_tier`
consumers such as `v_grid_high_value_targets`. That distinction is worth establishing before anyone
calls it a defect.

**Ideal:** `(subject_kind, subject_key)` as the primary key, and consumers that join on the right one.

### 4. The read path creates a file in the bundle

`OpenReadOnly` → `AttachSuppressionSidecar` → `EnsureCreated` writes `suppressions.db` into the run
directory if it is absent. This is a deliberate, well-reasoned decision — an attached database inherits
the read-only flag, so it must exist first — and its comments say so. It is nonetheless the thing
invariant I-2 is about, arrived at from a different direction, and `docs/INVARIANTS.md` records a long
history of I-2 being overstated and then narrowed.

**Ideal:** create the sidecar at seal time, alongside `DatabaseIntegrityService.Sign`, where a bundle is
being written anyway. Then `OpenReadOnly` attaches or falls back and never creates. The current design
also means opening a bundle from read-only media takes the fallback path silently.

### 5. Log retention is inverted, and the separation that causes it is otherwise correct

`RunLogService` prunes to the newest 25 run folders on construction. The bundle — 17 GB, per C13's
measurement — is kept until explicitly deleted. So the thing that costs gigabytes is kept forever and
the few-KB explanation of it is pruned, and after 25 runs a bundle's own account of how it was produced
is gone. This is F-01-19 in `docs/review/01-infrastructure-storage.md`, still open; recorded here
because it is a *structural* consequence of C14 living in a different tree from C10, not an isolated
bug.

The separation itself is right — it is what lets `FailedRunCleanup` delete a failed bundle without
destroying the reason it failed.

**Ideal:** the log folder is copied into the bundle at seal, and the pruned tree stays the working copy.
Retention then follows the artefact it describes.

### 6. `AddColumnIfMissing` is a migration engine in a product that has decided not to migrate

`EnsureSecurityTableColumns` `ALTER TABLE`s six columns onto `fact_escalation_path` on every open, each
with a `DEFAULT`. Decision 0001 says nothing is kept backward compatible. Against a fresh database this
is six `PRAGMA table_info` scans that always find the column, because the same build's `CREATE TABLE`
just made it.

**Ideal:** the columns move into `CreateFactEscalationPath` and the method goes. If a migration path is
genuinely wanted later, it should be a versioned migration story, not six defaults that quietly paper
over a schema mismatch that decision 0001 says cannot occur.

### 7. This was right, keep it: the sidecar split

Moving user-editable state — acceptances and policy tiers — out of `audit.db` into `suppressions.db`,
and resolving the tier split behind a temp view that shadows the base table, is the best structural
decision in this branch and possibly in the codebase.

It bought three things at once. The signature became meaningful, because nothing a user does can touch
the signed file. The read path became provably non-mutating, because an attached database inherits the
read-only flag — enforced by SQLite, not by convention. And **consumers did not have to change**,
because a temp view outranks a base table of the same name, so every query still reads `dim_asset_tier`
and gets the effective tier.

The one place it did not hide the split is where it must not: `EscalationPathRuleEvaluator` deliberately
says `main.dim_asset_tier`, so a policy tier set today cannot retroactively change what a signed
snapshot found. That is the distinction between an overlay and a rewrite, and it is stated in the schema
comments rather than left to be rediscovered.

Keep the design, keep the comments explaining `main.`, and keep `TempViewShadowingTests` — the whole
thing rests on a SQLite name-resolution rule that is not obvious and would not survive a refactor that
did not know about it.
