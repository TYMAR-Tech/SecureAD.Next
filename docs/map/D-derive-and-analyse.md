# D — Derive & Analyse

**Owns:** everything between "every fact the directory stated is in `audit.db`" and "every fact the
directory did *not* state is in `audit.db` too" — the GUID catalogue, delegation-bundle matches,
transitive group closure, control edges, asset tiers, escalation paths and chokepoints. It begins
where B ends and stops where a rule is evaluated against what it produced.

## The flow

1. **`DirectCaptureRunner` calls `store.CreateDeferredIndexes()`** (`:543`). B's ruling puts everything
   from here onward in D and E. The indexes are C1's DDL; the decision to defer them until after
   ingest is D's precondition — every phase below is a full-table read.
2. **`DerivedAnalysisPipeline.ExecuteAsync`** is constructed (`:553`) and runs nine phases in fixed
   order. Each is wrapped by `RunPhase`/`RunPhaseAsync`, which catches everything except
   `OperationCanceledException`, records a `pipeline_phase_*` metadata row, and **continues to the next
   phase**. A failed phase degrades the run; it does not stop it.
3. **`ANALYZE`** — SQLite statistics, so the eight phases that follow get sane query plans against
   tables that were empty when the indexes were declared.
4. **`Create views`** — `DerivedStore.CreateViews()` executes C2's view DDL. C owns the text; this is
   the moment it exists. Everything from the chokepoint builder to every grid in J depends on this one
   phase having succeeded.
5. **`GUID map`** — `GuidCatalog.AllEntries` plus `GetOverlayEntries()` into `dim_guid_map`.
6. **`Delegation bundle matches`** — `DelegationBundleIngestService` walks every object with ACEs and
   matches the built-in bundle pack against its canonical ACE set into `fact_delegation_bundle_match`.
7. **`Group expansion`** — `GroupExpansionService.BulkExpandAceTrusteesAsync` takes every group that is
   an ACE trustee *or* appears in `fact_group_membership_direct`, BFS-expands each under an
   `ExpansionBudget`, and writes `fact_group_membership_closure` plus a per-group
   `fact_expansion_status`. Then `EnsureExpansionGroupsResolved` backfills `dim_principal` for group
   SIDs the expansion surfaced that B never resolved.
8. **`Control edges`** — `ControlEdgeService.BuildAllEdgesAsync` reads every allow ACE, derives zero or
   more `ControlType`s from its access mask and object-type GUID, cancels each against the deny set,
   and writes `fact_control_edge`. A second pass adds an `Owns` edge per `dim_object.owner_sid`. Both
   passes stamp each row with whether that object's domain has complete `Objects` +
   `SecurityDescriptors` coverage.
9. **`Asset tier classification`** — `Tier0ObjectTable.Populate` materialises the Tier-0 *object* set
   into a temp table; `DerivedAssetTierClassifier.Build` runs six promotion queries over the closure and
   the edges; a `tier-policy.json` beside the database, if present, layers `PolicyAssetTierClassifier`
   on top; `AssetTierWriter.Classify` walks `dim_principal` and `dim_object` and writes
   `dim_asset_tier`.
10. **`Escalation paths`** — `EnrichedHighValueClassifier.Build` re-populates the Tier-0 object table and
    loads its own two promotion sets. `EscalationPathService.BuildAllPathsAsync` loads the control
    graph, injects `MemberOf` edges from **direct** membership, compacts it to integer-indexed arrays,
    runs one reverse BFS from all high-value targets to get a distance index, then reconstructs
    **exactly one representative path per reachable principal**. `EscalationPathRetentionPolicy.Apply`
    dedupes and ranks; the survivors replace `fact_escalation_path` in one transaction.
11. **`Escalation chokepoints`** — `EscalationChokepointService` reads back `v_grid_escalation_paths`,
    parses each `path_detail` JSON into steps, groups steps by (edge, control type, source, target),
    ranks by how many distinct targets each step unlocks, and writes the top 10,000 to
    `fact_escalation_chokepoint`.
12. `derived_health` is written — `Complete`, or `Degraded:` plus the failed phase names. Roughly forty
    further `dim_database_metadata` keys carry counts, budgets and per-stage durations.
13. **Back in `DirectCaptureRunner`**, `PersistControlEdgeCoverage` and `PersistEscalationPathCoverage`
    write one `fact_coverage` row per domain for the two derived modules, deriving each row's state from
    the capture modules it depended on. These live in `DirectCaptureRunner.Coverage.cs` alongside B18 and
    are D's.
14. **`ExecuteFindingsAsync`** then runs — E.
15. **Second entry point:** `ExistingCaptureAnalysisService.AnalyzeAsync` copies a completed `audit.db`
    into a fresh bundle, calls `ResetForReanalysis` to `DELETE FROM` eight derived tables, and runs both
    pipeline halves again. It does **not** run step 13.

The shape of the branch is set by step 2. Nine phases, no dependency declaration between them, ordered
by a hand-written sequence of nine statements, each individually fault-tolerant — so phase 9 runs
against whatever phase 7 left behind whether phase 7 succeeded or not.

## Components

### D1 — Derived analysis pipeline
- **Layer:** Infrastructure
- **Owns:** the ordered sequence of derived phases, the fault isolation between them, and the run's
  verdict on its own derived output.
- **Depends on:** B (all of it — every fact it reads), C1, C2, C3, D3–D19
- **Implemented by:** `Storage/DerivedAnalysisPipeline.cs` (631)
- **Non-obvious:** the fault tolerance is per-phase and **unconditional on ordering**, which is not the
  same as being safe. `ClassifyAssetTiers` runs whether or not `ExpandGroupMembershipsAsync` succeeded,
  so a run whose group expansion threw produces a `dim_asset_tier` missing every transitive Tier-0
  promotion — and records that as `Degraded: Group expansion`, not as an asset-tier problem. The
  dependency is real and only the phase list encodes it. `ExecuteFindingsAsync` is a **second** entry
  point on the same type with its own health record: the pipeline is two pipelines sharing a class.

### D2 — Derived phase health & run telemetry
- **Layer:** Infrastructure
- **Owns:** what the pipeline records about its own completeness, and the vocabulary for reading it back.
- **Depends on:** C1, C3, D1
- **Implemented by:** `Storage/DerivedHealthReader.cs` (170), `Storage/DerivedPhaseVerdicts.cs` (137),
  `RecordPhase`/`RecordMetadata`/`RecordControlEdgeDiagnostics`/`RecordEscalationPathDiagnostics` in D1
- **Non-obvious:** this is the answer to "what does a missing view mean", and it is a genuinely good
  answer. `DerivedHealthState.Unrecorded` is treated as *weaker* than `Degraded`, not healthier — a run
  that did not say its analysis finished has not said that it did. `PhaseKeyPrefix` is a shared constant
  with a documented reason: `GetPipelinePhaseDiagnostic` once filtered `phase_%` against keys all
  beginning `pipeline_phase_`, returned null for every bundle ever produced, and no test noticed.
  **Cross-branch output:** read by I (`ForestReportGenerator`, `DelegationReportGenerator`,
  `VouchedCount`) and J (`DashboardQueryService`, `ObjectsGridViewModel`).

### D3 — GUID catalogue materialisation
- **Layer:** Core catalogue + Infrastructure write
- **Owns:** turning schema and extended-right GUIDs into names a bundle can be read with, without the
  directory.
- **Depends on:** C1, D1
- **Implemented by:** `Core/Catalogs/GuidCatalog.cs` (255), `GuidCatalogEntry.cs` (55),
  `Infrastructure/Schema/GuidCatalogService.cs` (114), `PopulateGuidMap` in D1
- **Non-obvious:** the write has **two** sources and only one of them is deterministic. The embedded
  catalogue is a frozen dictionary. The second loop reads `GuidCatalog.GetOverlayEntries()` — a
  **process-global mutable static** whose only producer is `LiveDiagnosticsService.LoadSchemaGuidsAsync`,
  called from exactly one place: `MainViewModel` after the live directory tree loads (`:605`). So what
  `dim_guid_map` contains depends on whether the operator browsed live earlier in the same session, and
  will be permanently empty once branch H's Inspect view is deleted per sequencing item 4. See
  Would-do-differently §3.

### D4 — Delegation bundle matching
- **Layer:** Core matcher + Infrastructure ingest
- **Owns:** recognising a known delegation pattern in an object's ACE set and recording the match with
  its state.
- **Depends on:** B10, C1, D1
- **Implemented by:** `Core/Delegation/BuiltInBundles.cs` (585), `DelegationBundleMatcher.cs` (217),
  `DelegationBundle.cs` (51), `DelegationBundlePack.cs` (67), `BundleMatchState.cs`,
  `DelegationBundleMatchResult.cs`, `Storage/DelegationBundleIngestService.cs` (224)
- **Non-obvious:** the matcher is pure and in Core, the ingest is a loop in Infrastructure, and the seam
  between them is exactly the shape B15 got right — which is why `BuiltInBundles`'s 585 lines of pattern
  data are testable without a database. The ingest walks `SELECT DISTINCT object_guid FROM fact_ace` and
  issues **three queries per object** (coverage, ACEs, then inserts); on a forest-scale bundle that is
  the phase most exposed to object count. Match state is recorded even for non-matches, so an absent row
  means "not evaluated" rather than "no match" — a distinction the bundle can express and most of D
  cannot.

### D5 — Group membership closure expansion
- **Layer:** Core budget + Infrastructure BFS
- **Owns:** the transitive closure of every group that could matter, and an explicit per-group statement
  of whether that closure is complete.
- **Depends on:** B11, B12, C1, D1
- **Implemented by:** `Infrastructure/GroupExpansion/GroupExpansionService.cs` (660),
  `Core/GroupExpansion/ExpansionBudget.cs` (32), `ExpansionResult.cs` (34), `ExpansionState.cs`,
  `ExpansionStatusRecord.cs`, `EffectiveSidSet.cs` (29)
- **Non-obvious:** `fact_expansion_status` is the branch's best instance of a partial answer that admits
  it. Each group records its state, a reason code, the depth reached, and whether the budget was
  exhausted — and when the *global* `MaxTime` trips mid-run, every unprocessed group gets a `Partial` /
  `GlobalMaxTimeExceeded` row rather than silently no row. The bulk path is a separate implementation
  from `ExpandGroupAsync`, with a precomputed group-SID set, a member cache, and prepared statements
  reused across all groups inside one transaction; the per-group path issues a query per member and
  survives only for `GetEffectiveSidsAsync`, whose sole consumer is `EffectiveAccessService`.
  **Cross-branch output:** the closure is read by D9, E's rule evaluators, and J's Group Expansion grid —
  but *not* by D13, which walks direct membership itself.

### D6 — Expansion principal backfill
- **Layer:** Infrastructure
- **Owns:** giving every group SID that expansion surfaced a row in `dim_principal`, resolved or
  explicitly unresolved.
- **Depends on:** B12, D5
- **Implemented by:** `EnsureExpansionGroupsResolved` in D1 (`:282–370`)
- **Non-obvious:** it writes into B's table from D, and it is right to. Expansion can name a SID that no
  capture pass ever collected — a cross-domain nested group in a domain the run did not reach. The
  fallback row is written with `state = 'Unresolved'` and `source = 'GroupExpansion'`, so the provenance
  survives; a missing row would have read as a missing group. Its sibling `BackfillFindingPrincipals`
  does the same thing for E and is E's.

### D7 — Control edge derivation
- **Layer:** Core vocabulary + Infrastructure derivation
- **Owns:** turning an ACE into the set of concrete control relationships it grants, and cancelling those
  a deny ACE removes.
- **Depends on:** B9, B10, B12, C1, D1, D17
- **Implemented by:** `Infrastructure/ControlEdges/ControlEdgeService.cs` (433),
  `ControlEdgeService.Persistence.cs` (342), `Core/ControlEdges/ControlType.cs` (90),
  `ControlTypeLabels.cs` (113), `ControlEdge.cs` (41), `ControlEdgeBuildResult.cs` (31)
- **Non-obvious:** three things worth carrying forward. **(a)** The deny model is *named in the bundle* —
  `control_edge_deny_model = BestEffortSameObjectTrusteeObjectTypeMaskWithSidHistory` — so a reader knows
  which approximation produced the graph rather than having to infer it. **(b)** The `[IMP-WK-GUID]`
  comment records that three GUID literals here were wrong for an unknown period: `member` pointed at the
  *group object-class* GUID, `userAccountControl` at the *computer object-class* GUID. Both were silent
  false negatives in a security graph. They are now sourced from `WellKnownAdGuids`. **(c)** SID history
  is reversed into a map so an ACE naming an old SID grants control to the current principal — a real
  attack path that a naive join loses. The entire read surface (`GetEdgesBySource`, `GetEdgesByType`,
  `HasControl`, `GetEdgeStatistics`) has **no production consumer**: `git grep IControlEdgeService -- src`
  returns the interface declaration and the implementing class only. J reads `v_grid_control_edges`.

### D8 — Tier and high-value policy
- **Layer:** Core
- **Owns:** the static definition of what counts as Tier 0 or high-value, on all three dimensions the
  answer needs.
- **Implemented by:** `Core/EscalationPaths/StaticAssetTierClassifier.cs` (135),
  `IAssetTierClassifier.cs`, `HighValueTargets.cs` (146), `DefaultHighValueClassifier.cs` (23),
  `IHighValueClassifier.cs`, `HighValueClass.cs`, `TierReasonCatalog.cs` (68),
  `Core/Principals/Tier0RidCatalog.cs` (144)
- **Non-obvious:** the policy is genuinely three-dimensional — well-known RID, object class
  (`domainDNS`, `nTDSDSA`, `trustedDomain`), and DN pattern (`CN=AdminSDHolder`, the Domain Controllers
  OU, the domain root) — and only the classifier interface owns all three. `TierReasonCatalog` exists
  because the promotion reasons are written by D9 and *read back and matched on* by E's SEC-076/SEC-077
  evaluators, so a reworded string would silently empty a finding. `Tier0RidCatalog.BuildSqlPredicate`
  emits the RID test as SQL once instead of per query; `01-infrastructure-storage.md:479` records that
  three view bodies still hand-write RIDs and disagree with it. **There are two parallel hierarchies
  here** — `IAssetTierClassifier` and `IHighValueClassifier` — see Would-do-differently §4.

### D9 — Derived tier promotion
- **Layer:** Infrastructure
- **Owns:** promoting a principal above its static tier on the evidence of what the run just derived.
- **Depends on:** D5, D7, D8
- **Implemented by:** `EscalationPaths/DerivedAssetTierClassifier.cs` (244),
  `EnrichedHighValueClassifier.cs` (141), `Tier0ObjectTable.cs` (114)
- **Non-obvious:** `Tier0ObjectTable` is the best-argued small type in the branch, and its remarks explain
  a defect class rather than a mechanism. Both classifiers used to ask "is this control target Tier 0?"
  as `o.sid LIKE '%-NNN'` — which a **domain root object can never match, because its SID *is* the domain
  SID** — and neither could any `nTDSDSA` or `trustedDomain` object or the AdminSDHolder container.
  Control of the domain root went unreported. The note is explicit that widening the RID set could not
  have fixed it: the dimension was wrong, not the membership. It is a temp table rather than an in-memory
  set so the filter stays a SQL join with the same collation as the join it replaced, and
  `fact_control_edge` is never pulled into managed memory. It is **rebuilt** rather than reused because
  the two callers run in different phases over one shared connection. `DerivedAssetTierClassifier` loads
  its six causes in priority order so the highest-severity reason wins for a SID flagged twice.

### D10 — Tier policy overlay
- **Layer:** Core parse + Infrastructure application
- **Owns:** a `tier-policy.json` beside the database overriding derived tiers by rule.
- **Depends on:** D8, D9
- **Implemented by:** `Core/EscalationPaths/TierPolicy.cs` (112),
  `EscalationPaths/PolicyAssetTierClassifier.cs` (173)
- **Non-obvious:** this is a *file-based* policy layer, distinct from the *UI-set* tier overrides that
  live in `dim_asset_tier_policy` in the sidecar (C5, C6). They are two separate override mechanisms with
  different storage, different lifetimes and no relationship to each other. The JSON one is applied at
  classification time and bakes into signed evidence; the sidecar one is resolved at read time by a temp
  view and deliberately cannot alter what a sealed run found.

### D11 — Asset tier classification pass
- **Layer:** Infrastructure
- **Owns:** running a classifier across every principal and object and persisting the non-default results.
- **Depends on:** C1, C6, D8, D9, D10
- **Implemented by:** `Storage/AssetTierWriter.cs` (119), `ClassifyAssetTiers` in D1 (`:397–416`)
- **Non-obvious:** `Tier2` — the default — is deliberately not written, so `dim_asset_tier` holds only
  departures from normal and stays small. Objects can *promote* an existing SID classification but never
  demote it. **This pass runs twice per capture.** `DirectCaptureRunner.cs:470` calls
  `AssetTierWriter.Classify` with the bare `StaticAssetTierClassifier` under its own
  `asset_tier_classification` run phase, before the pipeline exists; D1 then calls it again with the
  derived-and-possibly-policy-layered classifier. The second is a superset and `INSERT OR REPLACE`
  supersedes the first, so the outcome is correct and the first pass is pure duplicated work over
  `dim_principal` and `dim_object`. See Would-do-differently §2. **C6 owns the main/sidecar split of the
  table this writes into;** D owns only the classification.

### D12 — Escalation graph loading & compaction
- **Layer:** Infrastructure
- **Owns:** turning the persisted control edges and memberships into a traversable in-memory graph, and
  the lookup maps a path needs to be describable.
- **Depends on:** B9, B11, B12, D5, D7
- **Implemented by:** `EscalationPaths/EscalationPathService.DataAccess.cs` (612)
- **Non-obvious:** `MemberOf` edges are injected from **`fact_group_membership_direct`**, not from D5's
  closure — the traversal re-walks membership one hop at a time so a path can *show* the group chain,
  which a closure row cannot. `BuildCompactGraph` re-indexes the whole graph to integer ids with
  `CompactEdge[][]` forward and `int[][]` reverse adjacency, because the string-keyed dictionary form does
  not survive forest scale. `LoadReverseControlGraphAsync` builds a *third* representation and is used
  only by `FindPathsToAsync`, which has no production caller.

### D13 — Escalation path discovery
- **Layer:** Infrastructure
- **Owns:** finding, for each non-privileged principal, a concrete route to a high-value target.
- **Depends on:** D8, D9, D12, D14, D17
- **Implemented by:** `EscalationPaths/EscalationPathService.cs` (1,060) — production path at
  `:685–905`, `BuildCompactGraph` `:260`, `ComputeReverseDistanceIndex` `:343`, `BuildRepresentativePath`
  `:385`
- **Non-obvious:** the algorithm is not the exhaustive BFS the class summary claims (*"using BFS path
  discovery"*). It is: one reverse BFS from all high-value targets producing a distance-to-target index; a
  filter keeping only principals within `maxDepth`; then **exactly one** greedy representative path
  reconstructed per surviving principal. `AnalysisMode = "Representative"` is stamped into metadata, which
  is the only place the distinction is recorded. The reverse-distance filter is what makes it tractable —
  principals that cannot reach anything are eliminated before any reconstruction, and the count is
  reported as `escalation_path_principals_skipped_reverse`. The **exhaustive** BFS
  (`FindPathsFromInternal`, `FindPathsFromAsync`, `FindPathsToAsync`, ~370 lines with dominance pruning
  and per-path cycle prevention) still exists and has no production caller; see Would-do-differently §1.

### D14 — Escalation path retention & evidence grading
- **Layer:** Core grading + Infrastructure retention
- **Owns:** which discovered paths survive into the bundle, why each survived, and how confident the run
  is in each.
- **Depends on:** D8, D13
- **Implemented by:** `EscalationPaths/EscalationPathRetentionPolicy.cs` (129),
  `Core/EscalationPaths/EscalationPathEvidenceClassifier.cs` (118), `EscalationEdgeWeights.cs` (44),
  `EscalationEdgeMetadata.cs` (98), `EscalationHealthCheck.cs` (148), `EscalationPathEvidenceLevel.cs`,
  `EscalationPathClassification.cs` (25), `EscalationConfidence.cs`, `EscalationFeasibility.cs`,
  `EscalationPathFeasibility.cs` (16)
- **Non-obvious:** retention is deterministic by construction — sort by high-value target, then danger
  score, then path length, then canonical signature — so two runs over the same data retain the same
  paths, and `RetentionReason` records *which* rule saved each one. But the two caps it enforces,
  `MaxPerSourceTarget = 5` and `MaxPerSource = 20`, **can never bind**, because D13 produces one path per
  source. Only the signature dedupe can drop anything. Both caps are nonetheless written into bundle
  metadata as though they described the run. They are D13's abandoned exhaustive mode showing through.

### D15 — Escalation path model & persistence
- **Layer:** Core model + Infrastructure write
- **Owns:** what a path *is* as a record, and getting the retained set into `fact_escalation_path`
  atomically.
- **Depends on:** C1, C3, D14
- **Implemented by:** `Core/EscalationPaths/EscalationPath.cs` (72), `EscalationStep.cs` (54),
  `EscalationRunResult.cs` (117), `EscalationPathKind.cs`, `EscalationPathValidationState.cs`,
  `ClearPaths`/`InsertPath` in D13
- **Non-obvious:** persistence is delete-then-insert in one transaction with an explicit rollback, so a
  failed write leaves the previous path set rather than a partial one — the same all-or-nothing shape D7
  uses. Steps are serialised to a JSON `path_detail` column rather than a child table, which is what
  makes D16 a JSON parse rather than a join, and what makes a malformed path a *countable* condition
  (`escalation_chokepoints_malformed_paths`) rather than a missing row. `EscalationRunResult` carries 25
  diagnostic fields; every one is written to metadata by D2.

### D16 — Chokepoint aggregation
- **Layer:** Core model + Infrastructure aggregation
- **Owns:** which single edges, if removed, would break the most escalation paths.
- **Depends on:** C1, C2, D15
- **Implemented by:** `EscalationPaths/EscalationChokepointService.cs` (359),
  `Core/EscalationPaths/EscalationChokepoint.cs` (58), `EscalationChokepointType.cs`
- **Non-obvious:** this is the one phase that reads its input back **through a view**
  (`v_grid_escalation_paths`) rather than from the table D15 just wrote — so it is transitively dependent
  on the `Create views` phase four steps earlier, and a `CreateViews` failure surfaces here as a
  chokepoint failure. It re-executes C1's `CreateFactEscalationChokepoint` constant in `EnsureSchema`
  rather than trusting `DerivedStore.Open`; it does at least reference the shared constant, so the two
  cannot drift. Ranking is by distinct **targets** unlocked first, not by path count — the remediation
  question is "how many things does this reach", not "how many routes exist". Capped at 10,000.

### D17 — Derived-fact coverage stamping
- **Layer:** Infrastructure
- **Owns:** marking each derived row with whether the capture it was derived from was complete for that
  object's domain.
- **Depends on:** B18, C1
- **Implemented by:** `ControlEdgeCoverageSnapshot` in `ControlEdgeService.Persistence.cs:162,322–340`,
  `EscalationCoverageSnapshot` in `EscalationPathService.DataAccess.cs:200–226,530–600`
- **Non-obvious:** this is why a derived fact can be trusted at row granularity rather than run
  granularity. Control edges require `Objects` + `SecurityDescriptors` complete for the target's domain;
  escalation paths require `ControlEdges` + `Principals`. Both read B18's `fact_coverage` and stamp
  `coverage_complete` per row, so a nine-domain forest that lost one domain still produces trustworthy
  edges for the other eight, individually marked. The two snapshot types are near-identical
  implementations of the same idea in two files. The escalation one additionally consults
  `ICoverageEnforcementService`, which is shared with E and is not mapped here — see the boundary ruling.

### D18 — Derived module coverage records
- **Layer:** Infrastructure
- **Owns:** the `fact_coverage` row per domain for `ControlEdges` and `EscalationPaths`, and deriving its
  state from the capture modules those depended on.
- **Depends on:** B18, C1, C7, D1, D7, D13
- **Implemented by:** `Storage/DirectCaptureRunner.Coverage.cs:139–341`,
  `ControlEdgeCoverageRequirements`/`EscalationPathCoverageRequirements` in `DirectCaptureRunner.cs:25–36`
- **Non-obvious:** state is **inherited by max severity** from the required capture modules — if
  `SecurityDescriptors` was `Partial` for a domain, `ControlEdges` is `Partial` for that domain, with an
  error summary naming which module and why. That is exactly the right propagation and it is done in the
  one place. It lives in B18's file and B mapped it here deliberately; **B18 is the capture half of the
  same file.** The count query for control edges drives from `dim_object` (indexed on `domain_fqdn`) with
  an `EXISTS`, with a comment saying why: driving from a multi-million-row `fact_control_edge` would scan
  it per domain. **Neither method runs on the re-analysis path (D20)**, so a re-analysed bundle carries no
  coverage row for either derived module — and the seal logic reads `fact_coverage`. See
  Would-do-differently §5.

### D19 — Analysis progress emission
- **Layer:** Core types + Infrastructure emission
- **Owns:** what derived analysis tells the UI while it runs.
- **Depends on:** D1
- **Implemented by:** `Core/Progress/AnalysisPhase.cs` (13), `AnalysisProgressEvent.cs` (12),
  `PublishAnalysisProgress` in `DirectCaptureRunner.cs:731`
- **Non-obvious:** the granularity is not the pipeline's. `AnalysisPhase` has five members; D1 has eleven
  phases; and the events are published by **`DirectCaptureRunner`, not by the pipeline** — so nine derived
  phases are reported to the user as one `ControlEdge` event going `Running` then `Complete`.
  `AnalysisPhase.Escalation` is **never published**:
  `git grep "PublishAnalysisProgress(runId, AnalysisPhase.Escalation"` returns nothing, yet
  `ForestAuditViewModel.Configuration.cs` gives it a label ("Escalation path analysis") and a progress
  percentage (92). The single longest phase in the branch is a UI state that cannot be reached. B19
  established that B owns capture progress emission and noted this file publishes D's events; D owns the
  shapes, K the transport, J the rendering.

### D20 — Re-analysis entry point
- **Layer:** Infrastructure
- **Owns:** re-running derived analysis over an already-captured bundle without touching a directory.
- **Depends on:** C3, C7, C10, C11, D1
- **Implemented by:** `Storage/ExistingCaptureAnalysisService.cs` (323), `ResetForReanalysis` in D1
  (`:94–109`)
- **Non-obvious:** it **refuses** a source whose run state is not `Complete`, rather than analysing a
  partial capture. Its `CreateRun` deliberately declares nothing and discovers nothing, with a comment
  explaining the circularity that avoids: passing the saved capture's own captured domains would
  manufacture a coverage claim out of the evidence being re-read. The reset deletes from `main` only,
  which is why sidecar policy tiers survive — recorded as the fix for `F-01-11` in
  `01-infrastructure-storage.md`, guarded by `PolicyTierSurvivesReanalysisTests`. `ReanalysisTables` is a
  **hand-maintained list of eight table names** with `TableExists` guards, and it includes `fact_finding`
  (E's) but not `fact_escalation_chokepoint` (D's) — so a re-analysis rebuilds paths and leaves the
  chokepoints of the previous path set in place until `Persist` overwrites them.

## Naming & taxonomy

### 1. `DerivedAnalysisPipeline` is two pipelines and one of them is E's

`ExecuteAsync` runs nine derived phases; `ExecuteFindingsAsync` runs two findings phases; they write
separate health rows and are called at separate points with other work between them. The name covers
both, which is how `FindingsPhase` and `BackfillFindingPrincipalsPhase` came to be constants on a type
called *derived analysis*.

**Rename:** split rather than rename — **`DerivedFactPipeline`** and **`FindingsPipeline`**, each with
its own health record.

**Why it matters:** the shared type is the only thing making the D/E boundary look arguable. Split, the
boundary is a project reference.

### 2. `EscalationPathService` describes an algorithm it no longer runs

Its summary says *"using BFS path discovery"*. Production is a reverse-distance index plus one greedy
representative path per principal. The exhaustive BFS the summary describes is still in the file and
unreachable.

**Rename:** **`RepresentativeEscalationPathBuilder`**, and delete the exhaustive path
(Would-do-differently §1).

**Why it matters:** "escalation paths" in the UI reads as *all* paths. It is one path per principal, and
only metadata says so.

### 3. `AssetTierWriter` classifies; `AssetTierWriter.Classify` writes

The type is named for the smaller half of what it does. It runs three full scans, applies a classifier,
resolves promotion precedence between principals and objects, and then writes. `Classify` is the whole
pass.

**Rename:** **`AssetTierClassificationPass`**, with `Run` returning a count.

**Why it matters:** the name is why it reads as harmless to call twice (Would-do-differently §2). A
"writer" called twice is idempotent; a "classification pass" called twice is a question.

### 4. `EnrichedHighValueClassifier` and `DerivedAssetTierClassifier` are the same idea named twice

Both wrap a static classifier, both call `Tier0ObjectTable.Populate`, both load transitive Tier-0
membership from the closure with the same predicate, both load dangerous control over Tier-0 objects from
the same edges with the same control-type list. They differ in the enum they return.

**Rename:** unify on one — **`DerivedPrivilegeClassifier`** — returning one classification with both
facets.

**Why it matters:** two implementations of one query pair is two places for the RID set to drift, and it
has drifted before: both files carry a remark that the query "used to name 512, 518 and 519 only",
missing Key Admins, Enterprise Key Admins, RODCs and `BUILTIN\Administrators`. The same bug was fixed
twice.

### 5. `fact_group_membership_closure` is a closure of *some* groups

It holds the closure of groups that are ACE trustees or appear in direct membership, subject to a
depth/node/time budget. `fact_expansion_status` says so per group, honestly. The table name does not.

**Rename:** keep the table (it is written into bundles) but rename the pair in code to
**`GroupClosureBuilder`** / `group_closure` + `group_closure_status`, so "status" reads as attached
rather than incidental.

**Why it matters:** a consumer joining the closure without checking the status table gets a silently
truncated answer, and the names give no reason to check.

### 6. `ControlEdgeService` and `EscalationPathService` are builders wearing service names

Each has one production method (`BuildAllEdgesAsync`, `BuildAllPathsAsync`) called once per run from D1.
The remaining public surface — six query methods across the two — is dead.

**Rename:** **`ControlEdgeBuilder`**, **`EscalationPathBuilder`**; delete `IControlEdgeService` and
`IEscalationPathService`, which are never used as types.

**Why it matters:** "Service" implies a queryable thing worth injecting, which is why both grew a query
API nobody wanted. Naming them builders makes the dead surface obvious rather than plausible.

## Would-do-differently

### 1. Two escalation algorithms ship, one runs

`EscalationPathService.cs` is 1,060 lines. The production algorithm is roughly `:685–905` plus three
helpers. `FindPathsFromInternal` (`:72–225`) is a complete exhaustive BFS with dominance pruning,
per-path cycle prevention, deterministic edge ordering and cumulative danger scoring; `FindPathsToAsync`
(`:559–685`) is a second one working backwards; `LoadReverseControlGraphAsync` (~80 lines) exists only
for the latter. `git grep` finds no production caller for any of them — only `IEscalationPathService`,
itself unused as a type, and 29 test references.

The cost is not the dead lines. It is that **D14's retention policy was written for the dead algorithm
and still runs.** `MaxPerSourceTarget = 5` and `MaxPerSource = 20` presuppose many paths per source;
production emits one. Both constants are written into every bundle's metadata as though they shaped the
result. A reader reconstructing what the run did from its own diagnostics would get it wrong.

**Ideal:** delete the exhaustive path and its retention caps. Keep the dedupe and the deterministic sort,
which do work. If per-source multiplicity is wanted back, it is a decision to re-take with a measurement,
not a policy to leave lying next to code that cannot trigger it.

### 2. Asset tiers are classified twice per capture

`DirectCaptureRunner.cs:470` runs `AssetTierWriter.Classify` with the bare static classifier, under its
own `asset_tier_classification` run phase with its own perf entry and its own row count. D1 then runs it
again with the derived classifier. Because the derived classifier wraps the static one and never demotes,
the second is a strict superset and `INSERT OR REPLACE` makes the result correct.

So this is not a correctness bug — it is three full scans of `dim_principal` and `dim_object` whose
entire output is overwritten, on the largest tables in the bundle, and a `run_phase` row claiming a phase
that did not need to happen.

It is also the exact shape B's ruling was drawn to catch: a D operation sitting inside B's method because
that is where the code grew, and then being invisible when D acquired its own phase for the same work.

**Ideal:** one classification pass, in D1, after group expansion and control edges. Delete the `:470`
call and its run phase. Zero behaviour change.

### 3. What a bundle records about GUIDs depends on where the user clicked

`PopulateGuidMap` writes the embedded catalogue and then `GuidCatalog.GetOverlayEntries()`. The overlay is
a static `Dictionary` on a static class, mutated by `GuidCatalog.LoadOverlay`, whose only caller is
`LiveDiagnosticsService.LoadSchemaGuidsAsync`, whose only caller is `MainViewModel` after the live
directory tree finishes loading.

Two consequences. **First**, two captures of the same forest in the same session can produce different
`dim_guid_map` contents depending on whether the operator opened the Inspect view first, and nothing in
the bundle records which happened. **Second**, sequencing item 4 of `00a-product-identity.md` deletes the
Inspect view — after which the overlay is permanently empty and the second loop is dead code, silently
reducing what future bundles can name.

That is a schema-specific GUID going unnamed in a security bundle because of a UI navigation choice.

**Ideal:** schema GUID load is a capture concern. Read it once during preflight (A8) into the run's own
state, write it into `dim_guid_map` from that state, and record in metadata whether the load succeeded.
Delete the mutable static.

**Addition to `docs/review/00a-product-identity.md`:** decision 2's disposition table lists live
capabilities to keep or remove and does not note that removing the Inspect view silently removes schema
GUID enrichment from capture. Recorded here as an addition, not a contradiction.

### 4. Two classifier hierarchies answer one question

`IAssetTierClassifier` returns `AssetTier`; `IHighValueClassifier` returns `HighValueClass`. Each has a
static Core implementation and a derived Infrastructure implementation. The two derived implementations
run the same two queries — transitive Tier-0 membership from the closure, dangerous control over Tier-0
objects from the edges — differing only in what they return, and both call `Tier0ObjectTable.Populate` on
the same connection in different phases, which is why that type documents needing to be *rebuilt* rather
than reused.

The evidence that this is a real cost rather than a stylistic one is in the code: both files carry the
same remark about the same defect (the RID set naming only 512/518/519), fixed independently in both
places. And `F-01-12` records the downstream version — `ActionPriorityCalculator` treats `dim_asset_tier`
as advisory while `EscalationPathRuleEvaluator` treats it as authoritative, so demoting a principal
produces a split result across two screens.

**Ideal:** one derived classifier, one Tier-0 object materialisation per run, one classification record
with both facets. `HighValueClass` becomes a projection of `AssetTier`, not a parallel enum.

### 5. Re-analysis produces a bundle that cannot state its own derived coverage

`ExistingCaptureAnalysisService` runs both pipeline halves and marks the run `Complete`. It does not call
`PersistControlEdgeCoverage` or `PersistEscalationPathCoverage` — those live in
`DirectCaptureRunner.Coverage.cs` as private static methods on the capture runner.

So a re-analysed bundle has `fact_coverage` rows for every capture module, inherited from the source
database it copied, and **none** for the two derived modules it just rebuilt. D17's per-row stamping still
works, because it reads the capture modules. But the module-level answer to "was control edge derivation
complete for this domain" is absent rather than negative — and `RunCoverageResolver` on the capture path
consults exactly those rows.

This is the same structural cause as B's Would-do-differently §1: the capture runner owns phases belonging
to two other branches, so the second entry point into those branches inherits only the parts that happened
to be factored out.

**Ideal:** derived coverage is written by D1 at the end of `ExecuteAsync`, where the phase health it
depends on already lives. Both entry points then get it for free, and `DirectCaptureRunner.Coverage.cs`
goes back to being about capture.

### 6. Nine phases, no declared dependencies

`ExecuteAsync` is nine statements. Each phase is individually fault-tolerant and none declares what it
needs. But the dependencies are real and severe: D9 is meaningless without D5's closure and D7's edges;
D13 is meaningless without D7; D16 reads a view created in phase 2 and a table written in phase 8.

When phase 7 fails, phase 9 still runs — over an empty `fact_control_edge` — and produces a bundle with
zero escalation paths, correctly recorded as `Degraded: Control edges` and *incorrectly* readable as
"this forest has no escalation paths" by anything that does not consult D2. D2 exists precisely because
that confusion was found once already.

**Ideal:** each phase declares its inputs and outputs; the pipeline computes the order and, when a phase
fails, marks its dependents `Skipped — depends on Control edges` rather than running them against
nothing. `Skipped` is a state `fact_coverage` already has and the bundle can already express. The
distinction between "ran and found nothing" and "could not run" is the one this product is most careful
about everywhere else.

### 7. The phase-health record was right — keep it

`DerivedHealthReader` is the piece of this branch that most deserves to survive a rebuild, and the reason
is in its own remarks. It replaced eight independent per-call-site `ViewExists` probes, each of which
answered "is this view here?" with an empty result — eight separate guesses at "is this run degraded?",
none of which could give a reason. It also replaced `view_hash`, which was written by `CreateViews` itself
and so was absent from exactly the bundles whose views were missing and present in every bundle whose
views were present: inert in both branches.

What replaced them is one row, written unconditionally, naming the failed phases. And the modelling of the
third state is the part to copy: `Unrecorded` is treated as *weaker* than `Degraded`, never as healthier,
because a run that did not state whether its analysis finished has not stated that it did.
`DerivedPhaseVerdicts` then reads the same keys at per-phase granularity from the same shared prefix
constant, so a reader can say *which* section is missing and why — which is what lets a degraded report
print a reason instead of an empty table.

The general shape: **the producer records its own completeness once, with a reason, and consumers read
that instead of inferring it from the absence of its output.** That principle would repair items 5 and 6
above as well, and it is already proven here.
