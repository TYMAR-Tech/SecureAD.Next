# B — Capture

**Owns:** everything between "we know which domains and DCs we are pointed at" and "every fact the
directory stated is in `audit.db`, with a coverage record saying how much of it we actually got." It
begins where A ends and stops at `merge_shards` plus capture coverage.

## The flow

1. **`AuditOrchestrator.BuildShards`** turns the selected domains in the audit dialog into one
   `ShardDefinition` per domain — domain FQDN, effective DC, naming context DN, `Subtree`.
   `ApplyDialogSettings` folds the dialog's QPS choice and OU exclusions into a `CaptureSettings`.
2. **`SecurityModeCaptureService.RunDirectSecurityAuditAsync`** (C15) hands both to
   `DirectCaptureRunner.ExecuteAsync`.
3. **`DiskSpaceMonitor.CheckPreCapture`** (C13) runs before anything touches disk. It is **advisory** —
   a failed check logs an error and the capture proceeds anyway.
4. The run directory is created directly in `library/`, `preflight.json` is written from A8's results,
   and a `CancellationTokenSource` bridge is registered so a critical-space signal mid-run actually
   cancels the capture.
5. `DerivedStore.Open` (C3) creates `audit.db`; `RunControlWriter.CreateRun` (C7) records the run row,
   the discovered forest, and the declarations resolved from A7's topology plus the user's exclusion
   attestations.
6. **Shard fan-out.** Up to `MaxDomainConcurrency` shards run in parallel. **Each shard writes to its
   own `shard-N.db` file**, not to `audit.db` — the comment at `:242` says why: zero WAL contention.
7. Per shard, `CreateShardTables` creates a hand-picked subset of C1's DDL, and
   `RunControlWriter.WriteDiscoveredDomains` seeds the forest's domain list into the shard so
   `DirectGroupMemberWriter` can classify an unresolved member without reading the main database
   across threads.
8. **`DirectCaptureModule.ExecuteAsync`** runs three passes over one domain on one DC: objects →
   `dim_object` + `dim_delegation`; group memberships → `fact_group_membership_direct`; security
   descriptors → `fact_ace` + `fact_object_acl_materialized`. Each pass is paged, rate-limited per DC,
   and emits its own `CoverageV1`.
9. **`CaptureSysvolSettingsAsync`** then reads Group Policy from SYSVOL over SMB into `dim_gpo_setting`
   and `fact_sysvol_ace`. It is failure-isolated: any exception becomes a `Failed` Sysvol coverage
   record and the shard continues.
10. When all shards complete, **`MergeShardDatabases`** attaches each shard file one at a time and
    `INSERT OR IGNORE`s seven tables into `audit.db`, then `wal_checkpoint(TRUNCATE)` and deletes the
    shard files.
11. **Post-merge capture completion** (still B): deferred group-membership replay across domain
    boundaries, `AttestationVerifier` (C8), principal resolution, parent-GUID population, password
    policies, trusts, metadata, and `fact_coverage` for the capture modules.
12. Everything from `store.CreateDeferredIndexes()` at `:543` onward — derived analysis, findings,
    escalation-path coverage — is **D and E**, invoked from inside this method.
13. At `:641`, after the pipeline, `LowSignalOuRecommendationService.Query` (**C27**) runs on the write
    connection. B owns the call site; C owns the query.

Step 6 is the decision that shapes the whole branch. A single WAL-mode `audit.db` written by concurrent
shards was the original design — the comment block at `:212–215` still describes it — and it was
replaced by file-per-shard plus merge. The old comment survives directly above the code that
contradicts it.

## Components

### B1 — Capture settings & load profile
- **Layer:** Core
- **Owns:** every tunable the operator can set for a capture, and the three named presets that set them.
- **Implemented by:** `Core/Configuration/CaptureSettings.cs` (145), `CaptureProfile.cs` (19),
  `CaptureProfileMap.cs` (44), `SettingsValidator.cs` (capture section)
- **Non-obvious:** presets adjust **only** `PerDcQpsLimit` — 15/25/40 — and `CaptureProfileMap.ToSettings`
  explicitly documents that everything else comes from defaults. Five of the eighteen properties are
  never read by any capture code; see Would-do-differently §2. The three `With*` methods are
  hand-written copy constructors on a type that could be a record.

### B2 — Captured attribute catalogue
- **Layer:** Core
- **Owns:** which LDAP attributes are requested per object class, the two object-class filters, and the
  version stamp that identifies the set.
- **Implemented by:** `Core/Discovery/CapturedAttributeCatalog.cs` (318)
- **Non-obvious:** "no capture-everything strategy" is a stated design position, not an accident — the
  attribute set is enumerated and versioned (`CatalogVersion = 10`) so a bundle can say what it was
  allowed to see. `GetBroadCaptureQuery` deliberately strips `member` from the group attribute set
  because group membership has its own pass with range retrieval. The comments explaining that name
  `GroupEdgeCaptureModule`, which no longer exists (Naming §3). This file lives in `Core/Discovery` and
  is branch B's; A's Would-do-differently §1 already flagged it.

### B3 — OU exclusion filter
- **Layer:** Core
- **Owns:** deciding whether a DN falls under an operator-excluded container, and refusing to honour an
  exclusion that would hide something security-relevant.
- **Implemented by:** `Core/Configuration/OuExclusionFilter.cs` (79)
- **Non-obvious:** `IsProtectedContainer` silently **drops** `CN=Managed Service Accounts` from the
  exclusion list at construction — an operator cannot exclude it even by asking. That is a deliberate
  refusal, and it is the same guard C27 re-checks in C# because SQL cannot express it. The filter is
  applied at three separate sites — object capture, SD capture, and group *member* DNs
  (`DirectCaptureModule.cs:236`) — and the third exists because a non-excluded group can hold members
  inside an excluded OU, which would otherwise surface as unresolved members rather than as exclusions.

### B4 — Shard definition
- **Layer:** Core
- **Owns:** the unit of capture parallelism — one domain, one DC, one search base, one scope.
- **Implemented by:** `Core/Discovery/ShardDefinition.cs` (16), `ShardResult.cs` (22),
  `Core/Progress/ShardState.cs`
- **Non-obvious:** `ShardResult` has **no production consumer**. `git grep ShardResult -- src tests`
  returns its own declaration and `ShardRecordTests`. It is the obvious name for what
  `DirectCaptureResult` actually is, and it is occupied by a dead type (Naming §5).

### B5 — Shard fan-out & isolation
- **Layer:** Infrastructure
- **Owns:** running N domain captures concurrently, each against its own SQLite file, and aggregating
  their results back on one thread.
- **Depends on:** A2, A9, B1, B4, B6, B17, C13
- **Implemented by:** `Storage/DirectCaptureRunner.cs:212–421`
- **Non-obvious:** the isolation is the design. Each shard gets `shard-{index}.db` with
  `Pooling = false` so the file lock releases on dispose, its own pragmas, and its own
  `DirectCaptureModule`. Results are collected into a pre-sized `?[]` indexed by shard, then folded on
  the main thread — there is no lock, because nothing shared is written concurrently. The
  `RunControlWriter.WriteDiscoveredDomains` seed at `:268` is load-bearing and its comment says why: an
  empty domain list is read by `DirectGroupMemberWriter` as "the forest is unknown," which would
  silently downgrade every cross-domain member the shard could not resolve.

### B6 — Per-domain LDAP capture module
- **Layer:** Infrastructure
- **Owns:** the three LDAP passes over one domain — objects, group memberships, security descriptors —
  and the coverage record each produces.
- **Depends on:** A2, B1, B2, B3, B7, B8, B9, B10, B11, B18
- **Implemented by:** `Ldap/DirectCaptureModule.cs` (384), `.GroupMembership.cs` (156),
  `.SecurityDescriptors.cs` (291)
- **Non-obvious:** SDs are fetched with an explicit `SecurityDescriptorFlagControl(Owner | Group | Dacl)`
  — **no SACL**, so a capture needs no `SeSecurityPrivilege` and works as an ordinary authenticated
  user. `LdapException` is caught per pass, recorded as an `errorSummary`, and **falls through to normal
  completion**; only cancellation rethrows. That is what lets a run that lost three domains at hour two
  still end `Sealed` (Would-do-differently §5). The `searchExecutor` constructor parameter is a test
  seam — it is the only way `DirectCaptureModuleTests` runs without a directory.

### B7 — LDAP paging, retry & per-DC rate limiting
- **Layer:** Infrastructure
- **Owns:** issuing a paged LDAP search politely enough that a production DC does not notice, and
  retrying the transient failures.
- **Depends on:** A2, B1
- **Implemented by:** `Ldap/DirectCaptureModule.SecurityDescriptors.cs:120–291` (shared helpers),
  `Ldap/DcRateLimiter.cs` (73)
- **Non-obvious:** the rate limiter is a **token bucket per DC hostname**, so throttling one DC does not
  slow the others — which matters because shards run in parallel against different DCs. Its placement
  is odd: the shared paging helpers for the whole module live in the file named `.SecurityDescriptors`,
  and `DcRateLimiter` lives in `Ldap/` beside the connection types rather than with capture. A new
  `DcRateLimiter` is constructed per shard (`:272`) and again per SYSVOL builder (`.Sysvol.cs:34`), so
  the two passes against the same DC do **not** share a budget.

### B8 — LDAP attribute extraction
- **Layer:** Infrastructure
- **Owns:** turning `SearchResultEntry` attribute values into typed C# — GUIDs, SIDs, integers,
  multi-valued and binary attributes.
- **Depends on:** B2
- **Implemented by:** `Ldap/LdapAttributeHelper.cs` (124), `Ldap/LdapCaptureUtilities.cs` (150)
- **Non-obvious:** these are **two files doing one job**, split along no visible line — both extract
  SIDs from binary attributes, and `LdapCaptureUtilities` also holds group-type bit tests and
  unresolved-member logging. `LdapCaptureUtilities`'s own summary says it was "relocated from the
  removed ObjectEnumerationModule and GroupEdgeCaptureModule," which is the real explanation: it is a
  sediment layer from two deletions, not a designed component. A's watch-list flagged both names; the
  contents confirm it.

### B9 — Object writer
- **Layer:** Infrastructure
- **Owns:** `dim_object` and `dim_delegation` rows, and the pending password-policy and principal-SID
  sets an object pass collects on the side.
- **Depends on:** B8, C1
- **Implemented by:** `Storage/DirectObjectWriter.cs` (520)
- **Non-obvious:** batched at 5,000 rows with prepared statements and one transaction per batch, and it
  owns a `_faulted` flag so a mid-batch failure does not commit a partial batch. `PopulateParentGuids`
  is a **static** method on this type invoked long after any instance is gone
  (`DirectCaptureRunner.cs:500`) — the parent link cannot be resolved during capture because the parent
  may be in a page not yet read, or a shard not yet merged. `dn_reversed` is written here and is what
  makes C's subtree paging possible.

### B10 — ACE writer
- **Layer:** Infrastructure
- **Owns:** parsing `nTSecurityDescriptor` into explicit `fact_ace` rows, the SD metadata on
  `dim_object`, and the materialized ACL blob.
- **Depends on:** B8, C1, C12
- **Implemented by:** `Storage/DirectAceWriter.cs` (304)
- **Non-obvious:** it writes the same ACL **twice, deliberately** — normalized explicit ACEs for
  querying, and a compressed full ACL payload in C12's format for exact object-detail display.
  Inherited ACEs are counted and skipped from `fact_ace` (`InheritedSkipped`), which is why C21 has to
  reconstruct inheritance at read time. It also harvests every trustee SID it sees into
  `CollectedPrincipalSids`, which is the entire input to B12. It executes
  `DerivedStoreSchema.CreateFactObjectAclMaterialized` in its own constructor — a writer creating a
  table, which is the one place C1's DDL centralisation leaks.

### B11 — Group membership writer & unresolved-member classification
- **Layer:** Infrastructure
- **Owns:** resolving member DNs to SIDs, and — where it cannot — recording *why* in a form that
  coverage and attestation can act on.
- **Depends on:** B3, C1
- **Implemented by:** `Storage/DirectGroupMemberWriter.cs` (361)
- **Non-obvious:** `UnresolvedMemberCategory` is the load-bearing part. Its four values distinguish *the
  forest list is unknown*, *in-forest but not captured*, *genuinely cross-forest*, and *captured domain,
  DN missing* — and only `InForestNotCaptured` counts against coverage or falsifies an exclusion
  attestation (C8). The enum's own remarks record why it is typed: behaviour was previously derived from
  the wording of the display `Reason` string, so **rewording a message silently changed a metric and a
  UI column**. `DomainFqdn` on `UnresolvedGroupMemberDn` is the *group's* domain, not the member's — the
  two are separately carried because a captured group holding a member in an uncaptured domain is
  precisely the case attestation verification exists for.

### B12 — Principal resolution writer
- **Layer:** Infrastructure
- **Owns:** turning the SIDs collected during capture into `dim_principal` rows with a resolution status.
- **Depends on:** B9, B10, C1
- **Implemented by:** `Storage/DirectPrincipalWriter.cs` (158)
- **Non-obvious:** it resolves **only against `dim_object`** — no directory call. It therefore emits two
  states, `Resolved` and `Unresolved`, while `fact_principal_resolution_status` supports richer ones.
  The live SID lookup that could fill those in is `LiveSidResolutionService`, invoked by C15 *after*
  capture, which is branch H.

### B13 — Password policy writer
- **Layer:** Infrastructure
- **Owns:** domain and fine-grained password policy rows.
- **Depends on:** B9, C1
- **Implemented by:** `Storage/DirectPasswordPolicyWriter.cs` (85)
- **Non-obvious:** policies are collected per shard by `DirectObjectWriter` but written once,
  forest-wide, after the merge (`DirectCaptureRunner.cs:476–487`), and the whole phase is skipped when
  the list is empty — so a forest with no readable policy produces no `password_policy_write` phase row
  at all, rather than one with zero rows.

### B14 — SYSVOL & Group Policy capture
- **Layer:** Infrastructure
- **Owns:** reading each GPO's on-disk policy files and folder DACL from SYSVOL into `dim_gpo_setting`
  and `fact_sysvol_ace`.
- **Depends on:** A2, B1, B7, B15, B16, B18, C1
- **Implemented by:** `Sysvol/SysvolCaptureModule.cs` (297), `Sysvol/GpoCaptureTargetBuilder.cs` (193),
  `Sysvol/GpoCaptureTarget.cs` (18), `Sysvol/SysvolSettingWriter.cs` (254),
  `Sysvol/SysvolAceWriter.cs` (189), `Storage/DirectCaptureRunner.Sysvol.cs` (79)
- **Non-obvious:** **supplementary by contract** — `CaptureSysvolSettingsAsync` catches everything
  except cancellation and returns a `Failed` Sysvol coverage record, so a domain with SMB blocked yields
  a degraded audit rather than a dead shard. The module smart-filters on each GPO's
  `gPCMachineExtensionNames` so it only opens files the GPO claims to have. Settings are stored
  **losslessly as text** with binary values base64-encoded, and interpretation is deferred to findings at
  query time. `CaptureGppPasswords` is off by default and its 11-line justification is the
  best-documented default in the branch: the cpassword scan is the only sub-scan that walks every XML
  file under every GPO, and MS14-025 made it mostly empty in 2014. When off, a `_scan_state` row is
  written so SEC-083 reports *not scanned* rather than *clean* — a suppressed scan is never mistaken for
  a verified-absent result.

### B15 — SYSVOL file-access seam
- **Layer:** Infrastructure
- **Owns:** the only place capture touches SMB.
- **Implemented by:** `Sysvol/ISysvolFileReader.cs` (50), `Sysvol/SmbSysvolFileReader.cs` (316)
- **Non-obvious:** three methods — read file, read security descriptor, enumerate relative paths —
  chosen so `SysvolCaptureModule` is fully unit-testable with `InMemorySysvolFileReader` and no network.
  Authentication is the process's own Windows token: SYSVOL is readable by Authenticated Users, so
  capture requires no elevation. This is the cleanest boundary in the branch
  (Would-do-differently §7).

### B16 — Group Policy file parsers
- **Layer:** Core
- **Owns:** the on-disk Group Policy formats — `Registry.pol`, `GptTmpl.inf`, and GPP XML.
- **Implemented by:** `Core/GroupPolicy/RegistryPolicyParser.cs` (222), `SecurityTemplateParser.cs` (152),
  `GroupPolicyPreferenceParser.cs` (168), `GpoClientSideExtensions.cs` (132), plus eight small
  record/enum files
- **Non-obvious:** pure, I/O-free, and in Core — which is why they carry the densest unit tests in the
  branch. `GpoClientSideExtensions` is what makes B14's smart filter possible: it decodes the CSE GUID
  list so the module can skip a GPO that declares no registry or security settings without opening a
  single file.

### B17 — Shard schema & merge
- **Layer:** Infrastructure
- **Owns:** which of C1's tables a shard database gets, and folding N shard databases into `audit.db`.
- **Depends on:** C1, C3
- **Implemented by:** `Storage/DirectCaptureRunner.Merge.cs:367–463`
- **Non-obvious:** `CreateShardTables` is a **hand-maintained list of seven DDL constants** with no
  structural link to what shard-scoped code actually executes — a writer could reference an eighth table
  and nothing would fail until an audit was attempted. `ShardSchemaCompletenessTests` closes that by
  *scanning source* for anything taking a `SqliteConnection` and deriving the reachable table set,
  precisely because reflection cannot see a consumer that has not been written yet. The merge is
  `INSERT OR IGNORE` for six tables and `INSERT OR REPLACE` for the materialized ACL, one shard attached
  at a time because SQLite's ATTACH limit is 10. Each shard is WAL-checkpointed by a **separate
  throwaway connection** before it is attached, or ATTACH would read a truncated file.

### B18 — Capture coverage recording
- **Layer:** Infrastructure
- **Owns:** the `fact_coverage` row for every capture module × domain, and the per-OU failure detail
  attached to it.
- **Depends on:** B6, B11, B14, C1, C7
- **Implemented by:** `Storage/DirectCaptureRunner.Coverage.cs:10–137, 216–341`,
  `Ldap/OuFailureTracker.cs` (70)
- **Non-obvious:** group coverage is written **twice**. The shard's record is superseded after the merge
  by `RefreshGroupCoverageRecords`, because cross-domain members that looked unresolved inside one shard
  may resolve once every shard is merged — so the first number is provisional by construction.
  `OuFailureTracker` aggregates per-object failures by nearest OU ancestor and reports the top ten,
  which turns "1,400 objects failed" into "this OU is unreadable." `PersistControlEdgeCoverage` and
  `PersistEscalationPathCoverage` live in this same file but describe **derived** modules and belong
  to D.

### B19 — Capture progress emission
- **Layer:** Core types + Infrastructure emission
- **Owns:** what capture tells the UI while it is running — run state, per-shard state, per-module
  counts.
- **Depends on:** B5, B6
- **Implemented by:** `Core/Progress/ShardProgressEvent.cs`, `ShardState.cs`, `ModuleProgressEvent.cs`,
  `ModuleState.cs`; emission in `DirectCaptureRunner.cs:707–744` and `DirectCaptureModule.cs:104–144`
- **Non-obvious:** the publisher is nullable throughout and both emitters no-op on a null publisher or a
  null run id, so capture runs headless without a branch anywhere. `AnalysisProgressEvent` is also
  published from `DirectCaptureRunner`, but it describes D's phases — the runner reports on branches it
  does not own. The publisher transport and the UI rendering are K and J; B owns only the emission and
  the shard/module event shapes.

### B20 — Capture run bookkeeping & guards
- **Layer:** Infrastructure
- **Owns:** the run directory, the preflight evidence file, the disk-space cancellation bridge,
  memory/WAL diagnostics, and reclamation of a failed run.
- **Depends on:** A8, C10, C13, C14
- **Implemented by:** `Storage/DirectCaptureRunner.cs:100–177, 695–705, 746–822`
- **Non-obvious:** the `criticalSpaceSignal` → `cancellationScope.Cancel` registration at `:172–175` is
  what makes C13 able to *stop* a capture rather than merely warn — `CancellationScope` does not expose
  its token source, so a bridge source is the only route. `FailedRunCleanup.Reclaim` is deliberately in
  the **outer** `ExecuteAsync` catch, not the inner one, because the inner arms still hold the database
  open and a recursive delete would fail against its own file lock. Cancellation is reclaimed on the
  same terms as failure, including application shutdown: a partial capture is unusable however it ended.

### B21 — Trust & metadata persistence
- **Layer:** Infrastructure
- **Owns:** writing A7's trust graph and the run's own capture parameters into the bundle.
- **Depends on:** A7, B1, C1
- **Implemented by:** `Storage/DirectCaptureRunner.Merge.cs:11–48` (`InsertTrusts`), `:301–358`
  (`InsertMetadata`)
- **Non-obvious:** trusts are **not captured** — they are copied from the `ForestTopology` object A7
  already built, and the phase is skipped entirely when the topology is null or trust-free. So
  `dim_trust` is A's evidence persisted by B, and a re-analysis with no topology produces a bundle with
  no trusts rather than an error. `InsertMetadata` is what makes `CaptureSettings` and `CatalogVersion`
  recoverable from a bundle, which is the whole reason B1 and B2 are versioned.

### B22 — Post-capture database profiler
- **Layer:** Infrastructure
- **Owns:** an opt-in census of what the capture produced, for calibrating the synthetic database
  generator.
- **Implemented by:** `Storage/DirectCaptureRunner.Merge.cs:54–299` (`LogDbSummary`),
  `DirectCaptureRunner.cs:796–801`
- **Non-obvious:** 245 lines — the single largest block in `Merge.cs` — gated behind
  `SECUREAD_DB_PROFILE=1` and off by default because the queries are expensive on a real database. It is
  a **development tool living in the production capture path**, and it is the origin of the sizing
  numbers C13's `RecommendedBytes` is built on.

### B23 — Capture setup UI
- **Layer:** UI
- **Owns:** turning the audit dialog's selections into shards and settings.
- **Depends on:** A10, B1, B4
- **Implemented by:** `ViewModels/AuditOrchestrator.cs` (41), `ViewModels/ForestAuditViewModel.cs`
  (`BuildCaptureSettings`, `GetExcludedOUs` — `:314–362`), `ViewModels/SettingsViewModel.cs` (capture
  section)
- **Non-obvious:** `AuditOrchestrator` is three static methods and holds no state despite being a sealed
  class with a name suggesting it runs the audit; `MainViewModel.RunSecurityAuditInDialogAsync` owns the
  lifecycle, and its own summary says so. `SettingsViewModel` and `ForestAuditViewModel` **each**
  independently reverse-map a `CaptureSettings` back to a `CaptureProfile` by comparing `PerDcQpsLimit`
  against the presets (`:228` and `:353`) — two copies of the same inference.

## Naming & taxonomy

### 1. "Direct" contrasts with nothing that still exists

`DirectCaptureRunner`, `DirectCaptureModule`, `DirectObjectWriter`, `DirectAceWriter`,
`DirectGroupMemberWriter`, `DirectPrincipalWriter`, `DirectPasswordPolicyWriter`, `DirectCaptureResult`.
"Direct" once distinguished direct-to-SQLite writing from a staged path — the summaries still say
"direct-to-SQLite capture pipeline." There is no other path. Seven types carry a qualifier that
partitions nothing.

"Module" is worse: `DirectCaptureModule` and `SysvolCaptureModule` do the work, while
`DirectCaptureRunner` orchestrates. "Module" and "Runner" are both content-free, and which is which has
to be learned.

**Rename:** drop `Direct` everywhere. `DirectCaptureRunner` → **`CaptureRun`** or `ForestCapture`;
`DirectCaptureModule` → **`DomainCapture`**; the writers → `ObjectWriter`, `AceWriter`,
`GroupMemberWriter`, `PrincipalWriter`, `PasswordPolicyWriter`.

**Why it matters:** A's watch-list predicted this from the name alone. Every reader spends a moment
looking for the indirect capture, and finds a deleted design.

### 2. `LdapAttributeHelper` and `LdapCaptureUtilities` are the same component under two names

Both extract typed values from `SearchResultEntry`. Both parse SIDs from binary attributes. Neither name
says which one to look in, because "Helper" and "Utilities" are the same word. The split is historical —
one file is sediment from `ObjectEnumerationModule`, the other from `GroupEdgeCaptureModule`.

**Rename:** merge into **`LdapEntryReader`** (or `AttributeReader`), with the group-type predicate moved
to B6 where it is the only caller and the unresolved-member logging moved to B11.

**Why it matters:** two grab bags with interchangeable names is how a third one gets created.

### 3. `GroupEdgeCaptureModule` is named in five comments and does not exist

`git grep GroupEdgeCaptureModule -- src tests` returns eight hits, all comments, across
`CapturedAttributeCatalog.cs`, `LdapCaptureUtilities.cs` and a test. Three of them tell a reader that
`member` is excluded from broad capture "because `GroupEdgeCaptureModule` handles it with proper range
retrieval." The reasoning is still correct — `DirectCaptureModule.GroupMembership` does exactly that —
but the type it names was deleted.

`ObjectEnumerationModule` is in the same position, named once in `LdapCaptureUtilities.cs:9`.

**Rename:** update the comments to name `DirectCaptureModule.CaptureGroupMembershipsAsync`.

**Why it matters:** a comment that names a type is checkable; a reader who greps for it and finds
nothing has to decide whether the comment or the code is wrong.

### 4. Capture writes coverage module ids that only an alias table understands

`DirectCaptureModule.SecurityDescriptors.cs:106` writes `ModuleId: "SecurityDescriptorRetrieval"` as a
string literal, while `CoverageModules.SecurityDescriptors` is `"SecurityDescriptors"`.
`CoverageModuleId.Aliases` exists to reconcile them, and also carries `"ObjectEnumeration"` and
`"GroupEdgeCapture"` — the ids of the two deleted modules.

So capture *today* writes a legacy id, and a compatibility table translates it on every read. Given the
standing position that pre-existing bundle shapes need no back-compat, the alias table is translating
for a producer that is still in the tree.

**Rename:** write `CoverageModules.SecurityDescriptors` at the emission site; reduce `Aliases` to
identity or delete it.

**Why it matters:** a canonicalisation layer that is load-bearing for *current* output is
indistinguishable from one that is load-bearing for history, and nobody can safely delete either.

### 5. `ShardResult` is a dead type holding the right name

`ShardResult` — domain, DC, state, coverage records, duration, error summary — is exactly what a shard
produces, and nothing produces it. The type that *is* produced is `DirectCaptureResult`, declared inside
the Ldap namespace.

**Rename:** delete `ShardResult` and rename `DirectCaptureResult` → **`ShardResult`**, moved to
`Core/Discovery` beside `ShardDefinition`.

### 6. `SysvolCaptureModule` is named after a file share

What it captures is Group Policy. SYSVOL is where the files happen to live — as `ISysvolFileReader`
demonstrates, since it is the only piece for which the share is actually the subject. The module also
writes `fact_sysvol_ace`, which is a GPO folder DACL.

**Rename:** `SysvolCaptureModule` → **`GroupPolicyCapture`**; `SysvolSettingWriter` → `GpoSettingWriter`;
`SysvolAceWriter` → `GpoAclWriter`. `ISysvolFileReader` and `SmbSysvolFileReader` keep their names — for
them, the share is the point. The `Sysvol` coverage module id stays, since it is written into bundles.

### 7. `AuditOrchestrator` orchestrates nothing

Three static methods, no state, and its own summary says `MainViewModel.RunSecurityAuditInDialogAsync`
"owns the run lifecycle itself."

**Rename:** **`AuditSetup`**, or fold the three methods into `ForestAuditViewModel`, which supplies all
their input.

**Why it matters:** "Orchestrator" is where orchestration accumulates. This one already lost the
argument to `MainViewModel`; leaving the name invites a second attempt.

## Would-do-differently

### 1. `DirectCaptureRunner` runs three branches and is named after one

`ExecuteCoreAsync` is 580 lines. Capture ends at `merge_shards` (`:342`). It then runs D's entire
derived pipeline (`:553`), E's findings generation (`:575`), coverage resolution, sealing, and C27's
recommendation query — and returns an `AuditRunResult` describing all of it.

The cost is concrete rather than aesthetic. `docs/review/01-infrastructure-storage.md` records that
**no test constructs `DirectCaptureRunner`**, which is why the covered-domain wiring at `:659` is
unverified and why the disk-space gap survived the deletion of the only runner that used it without a
single test failing. A type that spans three branches has no seam small enough to test.

**Ideal:** capture returns a `CaptureResult` — bundle path, coverage records, counts — and a caller above
it drives analysis, findings and sealing in sequence. Each becomes independently testable against a
fixture bundle. This is the boundary ruling's finding, recorded here as it directed.

### 2. Five capture settings are configured, validated, persisted and never read

`MaxInFlightRequestsPerDc`, `FailoverEnabled`, `ModuleTimeoutMinutes`, `ShardTimeoutMinutes` and
`LdapTimeoutSeconds` have **no consumer in capture**. `git grep` across `src/` finds each only in
`CaptureSettings.cs`, `SettingsValidator.cs`, `appsettings.json`, and `SettingsViewModel`. They are
range-validated, shipped as defaults, editable in the Settings dialog, and written into
`dim_database_metadata` by B21 — so a bundle records that a capture ran with a 60-minute shard timeout
that was never enforced.

`FailoverEnabled` is the sharpest: capture builds one connection per pass from the shard's assigned DC
and never fails over, so the flag describes a capability that does not exist. (A's Would-do-differently
§3 established that capture bypasses the routing layer; this is the settings-side consequence.)

**Ideal:** delete the four with no meaning; wire `LdapTimeoutSeconds` into A1's `LdapConnectionSettings`,
which is where the operator plainly believes it goes.

**Addition to `docs/review/01-infrastructure-storage.md`:** that document reviews capture extensively and
does not raise this. Recorded here as an addition, not a contradiction.

### 3. The shard database is a hand-maintained subset of the real schema

`CreateShardTables` names seven DDL constants. `MergeShardDatabases` names seven tables. Both lists are
maintained by hand, and they must agree with each other and with whatever the writers touch.

The test that guards this is genuinely good — `ShardSchemaCompletenessTests` *scans source* for anything
accepting a `SqliteConnection` and derives the reachable table set, explicitly so that a writer nobody
has written yet is covered. But a test that exists to detect drift in a list is evidence that the list
should not be hand-maintained.

**Ideal:** the shard tables are a declared property of the writers — each writer states which tables it
needs, and shard creation and merge are both computed from that set. The completeness test then has
nothing to check.

### 4. Two capture passes read the same objects twice

The object pass and the SD pass each run a full paged search over the same DN set with the same filter,
differing only in requested attributes. On a nine-domain forest that is two full enumerations per domain.

The reason is real — SDs need `SecurityDescriptorFlagControl` and are large enough that batching them
with the identity attributes would balloon page sizes — but it is undocumented, so it reads as an
accident.

**Ideal:** either merge the passes and page smaller, or record the measurement that justifies two. Right
now the decision has no stated basis, which makes it un-revisitable.

### 5. Losing a domain does not change how the run ends

`LdapException` is caught per pass and the shard completes. The run is then sealed on **derived
analysis** health, not on capture coverage — `derivedHealth.IsDegraded ? Degraded : Sealed`. A forest
capture that lost three of twelve domains at hour two ends `Sealed`.

`docs/review/01-infrastructure-storage.md` documents this at length as a *profile identity* problem — the
run's `ProfileId` asserts full forest coverage regardless. The capture-side half is that `fact_coverage`
**already holds the truth**, per module per domain, written by B18, and the seal simply does not consult
it.

**Ideal:** seal state is a function of coverage as well as analysis health. B's output already contains
everything needed; nothing new has to be captured.

### 6. Group coverage is written twice because it cannot be right the first time

`RefreshGroupCoverageRecords` overwrites each shard's group coverage after the merge, because a member
that looked unresolved inside one shard may resolve once its home domain is merged. The shard-time
number is provisional by construction, and the code carries that fact only as a method name.

**Ideal:** don't emit provisional coverage. A shard reports raw diagnostics; coverage is computed once,
forest-wide, after the merge. Same result, one writer, no window in which the database holds a number
that is knowably wrong.

### 7. The SYSVOL file seam was right — keep it

`ISysvolFileReader` is three methods, and it is the only network boundary in the branch that is
abstracted at all. The consequence is measurable: `SysvolCaptureModule`, `SysvolSettingWriter`,
`SysvolAceWriter`, `GpoCaptureTargetBuilder` and all four Group Policy parsers have real unit tests
running against `InMemorySysvolFileReader`, with no directory and no share. Compare
`DirectCaptureRunner`, which no test constructs.

The seam is narrow enough to be honest — it is a file reader, not an "SMB service" — and it was drawn at
the one place where the untestable thing actually lives. Whatever else changes, this shape should be
repeated: **put the seam at the I/O primitive, not around the component that uses it.**

The parsers being pure and in `Core`, with the interop confined to `SmbSysvolFileReader`, is the same
decision applied twice. It is why B14's failure isolation is trustworthy: the code that decides what a
failure means is separately tested from the code that fails.

### 8. Failure isolation is per-module, and the operator is never told

SYSVOL failure becomes a `Failed` coverage record. An `LdapException` in any pass becomes an
`errorSummary`. Both are logged and persisted, and neither surfaces at the end of the run:
`AuditRunResult.Errors` is populated **only** from derived-analysis and findings phases (`:591–602`). A
capture that lost SYSVOL in every domain returns an empty error list.

**Ideal:** the result carries capture degradation alongside analysis degradation. The data exists; it is
simply not read on the way out.

## Cross-branch dependencies

**Inputs.** A supplies everything capture starts from: the connection factory (A2), the domain list and
trust graph (A7), the per-domain DC assignment that becomes a shard (A4/A5), and the preflight evidence
written into the bundle (A8). C supplies the schema every writer targets (C1), the ACL payload format
(C12), the write connection (C3), and the disk guard (C13).

**Outputs.** C owns everything B persists into. D consumes `dim_object`, `fact_ace`,
`fact_group_membership_direct` and `dim_asset_tier` to build control edges and escalation paths. E
consumes `dim_gpo_setting` and `fact_sysvol_ace` for the GPO rules, and every finding evaluator reads
tables B wrote. F reads the `run`, `run_phase` and `run_coverage` rows B populates through C7. G compares
two bundles on the `coverage_id` B computed at run creation. H's live verification re-reads a subset of
what B captured.

**Call sites B owns but does not implement:** `LowSignalOuRecommendationService.Query` (C27) at
`DirectCaptureRunner.cs:641`; `DiskSpaceMonitor` (C13) at `:148` and `:174`; `AttestationVerifier` (C8)
at `:442`; `LiveSidResolutionService` (H) via C15 after capture returns.

## Reading notes

`DirectCaptureRunner` is 1,764 lines across four partial files — `.cs` 866, `.Merge` 478, `.Coverage`
341, `.Sysvol` 79. (The brief's figures of 774/437/298/69 match
`Get-Content | Measure-Object -Line`, which discards blank lines.)

Read in full: `DirectCaptureRunner.cs` (1–866, in six overlapping passes), `.Sysvol.cs`,
`DirectCaptureModule.cs`, `ISysvolFileReader.cs`, `OuExclusionFilter.cs`, `AuditOrchestrator.cs`,
`ShardDefinition.cs`, `ShardResult.cs`, `CaptureProfile.cs`, `CaptureProfileMap.cs`.

Read in part: `.Merge.cs` 1–180 and 360–478 plus a member listing — the ~180 lines of profiler query
bodies inside `LogDbSummary` were not read line by line. `.Coverage.cs` 60–140 plus a full member
listing; the derived-coverage half (139–341) was read by signature only, as it belongs to D.
`.SecurityDescriptors.cs` 1–120 of 291. `.GroupMembership.cs` by reference from its callers.
`CaptureSettings.cs` 1–130 of 145, `CapturedAttributeCatalog.cs` 1–80 of 318. The writers, the Sysvol
components and the Group Policy parsers were read by header and summary rather than in full.
