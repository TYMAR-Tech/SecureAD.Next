# F — Run model & lifecycle

**Owns:** what a run *is* as a durable object — its identity, its lifecycle state, the moment it
closes, whether it may be trusted, and how a user finds it again. It begins where B's capture ends
and C's tables are written, and stops at the point G, I and J ask "may I use this run?"

**Boundary note:** three edges were settled before this file was written and are honoured rather
than relitigated. C owns the run-control *tables* and the persistence mechanics (`run`,
`run_phase`, `run_checkpoint`, `run_coverage` DDL created by `DerivedStore.Open`); F owns the
lifecycle *semantics*. E10 owns suppression semantics and C5 owns the sidecar as storage; F owns
only whether a sealed run may accept new suppressions (F17). E1 owns `findings_health` and D1 owns
`derived_health`; F owns what a degraded run is allowed to be used for (F4).

Two further edges were arguable and are stated rather than chosen silently. F claims
`RunCoverageReader` / `RunCoverageResolver` / `RunCoverageSnapshot` (F9) against the alternative of
D, on the ground that they answer "what may this run be used for" and that none of their four
consumers is D; `fact_coverage` DDL stays with C and the per-cell `CoverageState` matrix stays with
D. `CompareCompatibilityValidator` is left to G.

## The flow

1. **`AuditOrchestrator.ProfileFor(forestRootFqdn)`** (`:28`) computes
   `ProfileId.ForSecurityModeFromForestFqdn`, a SHA-256 over `"Security|{forest}"` truncated to 16
   hex chars. This is the only producer.
2. **`RunControlWriter.CreateRun`** (`:109`) inserts the `run` row with `run_state = 'InProgress'`,
   alongside `run.coverage_id` — `CoverageId.ForDeclaredCoverage(forest, declaredDomains,
   excludedOus)` — and the `run_domain_discovered` / `run_domain_declaration` rows.
3. **Capture and derived phases run.** Phase-level progress goes to `run_phase`;
   `RunState.Capturing` is published to the dashboard.
4. **`MarkRunFinalizing`** (`DirectCaptureRunner.cs:536`) moves `run_state` to `'Finalizing'`
   before index build and derived analysis. This transition is *not* terminal: `completed_utc` is
   left alone.
5. **`AttestationVerifier`** tests each `AttestedEmpty` exclusion claim against
   `dim_unresolved_group_member` and reassigns the declaration set. A falsified claim becomes
   `AttestedDegraded`.
6. **The seal decision** (`DirectCaptureRunner.cs:602–624`). Errors are collected from
   `derivedHealth.FailedPhases` and `findingsHealth.FailedPhases`. If **any** exist, `FailRun`
   writes `run_state = 'Failed'`. Otherwise `CompleteRun` writes `'Complete'`, bracketed by a
   `finalization` phase row.
7. **`RunCoverageResolver.Resolve`** computes the run-level `RunCoverage` axis from discovery
   confidence, the discovered set, the declared set, the covered set and module completeness.
8. **`AuditRunResult` is returned with `State: RunState.Sealed` — unconditionally** (`:676`). The
   literal is on the success return path, which is also reached after step 6 wrote `'Failed'`. The
   in-memory result and the persisted row disagree for every degraded run.
9. **`SecurityModeCaptureService` runs a post-seal epilogue**, gated on
   `result.State is RunState.Sealed` — which step 8 guaranteed. It opens `audit.db` **read-write**
   twice: live SID resolution against a GC (`:153`), and preflight metadata persistence (`:118`).
   Then it WAL-checkpoints, then signs.
10. **`DatabaseIntegrityService.Sign(dbPath)`** SHA-256s the `audit.db` bytes and writes
    `audit.db.sig` — a JSON record of hash, algorithm and timestamp — plus `audit.db.sig.cache`,
    keyed on file size and last-write time.
11. **The save dialog** offers `SavedRunRecord.GenerateDefaultName`, and
    `RunMetadataService.SaveMetadata` writes `user_metadata.json` into the bundle. Written *after*
    signing, and outside it.
12. **On next launch, `ReclaimAbandonedRunsAsync`** walks the library, and for any bundle whose raw
    `run_state` is `InProgress` or `Finalizing`, hands it to `FailedRunCleanup.Reclaim`. Safe only
    because single-instance is enforced and it runs before any capture starts.
13. **`RunLibraryService.ListLibraryRunsAsync` / `ListSessionRunsAsync`** enumerate directories and
    call `ExtractMetadataAsync` per bundle, which resolves `audit.db` across four candidate paths,
    reads `dim_database_metadata` and the newest `run` row, derives a coverage label through
    `RunCoverageReader`, overlays `invocation.json` and then `user_metadata.json`, and maps
    `run_state` to `RunLifecycleState`.
14. **`Open` is gated** by `OutputEligibilityEvaluator.Evaluate(dbPath, Kind.Open)`
    (`MainViewModel.cs:641`), which blocks unless
    `RunDatabaseInspector.Inspect(dbPath).IsFinalizedComplete`.
15. **Integrity is verified, and then ignored.** `DatabaseIntegrityService.Verify` runs on the open
    path (`:661`) and its result lands in `DatabaseIntegrity`, bound to one `DataTrigger` in
    `StatusBar.xaml:35`. Nothing blocks on `Modified`.
16. **Reports and exports are gated** by `EnsureEligible` in the three report generators and
    `ExportCoordinator`, which additionally attach a coverage warning built from
    `FindingsService.GetRunCoverageState()`.
17. **Baseline marking** goes through `BaselineEligibility.Evaluate`, which refuses any run that
    knowingly excluded a populated domain, and refuses a bundle it cannot read.
18. **Compare and acceptance-import selection** filter on `RunLifecycleState.Sealed` in the view
    models — a second gate, unrelated to `OutputEligibilityEvaluator`.

The shape of the branch is set by steps 6, 8 and 9. `Sealed` is a word used by three subsystems
that do not agree on it: the `run` row says `Failed`, the in-memory result says `Sealed`, and the
signing epilogue trusts the second.

## Components

### F1 — Run target identity
- **Layer:** Core
- **Owns:** which forest a run assessed, as a value that can be recomputed rather than stored.
- **Depends on:** —
- **Implemented by:** `Core/Assessment/ProfileId.cs` (92)
- **Non-obvious:** the entire design turns on **recoverability**. The profile is a pure function of
  the forest FQDN, which is why `RunLibraryService.Metadata.cs:201` can re-derive it for a bundle
  whose `user_metadata.json` was never written. Its own remarks record why the two-argument
  `ForSecurityMode(forestFqdn, forestRootDn)` was deleted: nothing checked the DN was the FQDN's
  transform, so two callers could compute different profiles for one forest, and such a run would
  not match its own re-derived value — landing in a group of one, never offered as a compare
  baseline or acceptance source, silently.

  **`ProfileId.FromComponents` does not exist.** `git grep` finds it only in
  `docs/work/RUN-MODEL-DESIGN.md` and in `ProfileIdTests.cs:105–112`, which asserts by reflection
  that no member of that name is present. There is no read path that reconstructs a
  Configuration-mode profile; scoped capture left no residue here. The `⚙ Config —` summary string
  is gone with it.

### F2 — Evidence identity
- **Layer:** Core
- **Owns:** which evidence a run declared it would gather — the domain set plus the OU exclusions —
  as the key that decides comparability.
- **Depends on:** A (`OuExclusionFilter` normalisation)
- **Implemented by:** `Core/Assessment/CoverageId.cs` (208)
- **Non-obvious:** kept separate from F1 for a reason that only shows up at the read sites. F1 is
  re-derivable from the forest name; F2 can only be read back from where the run recorded it
  (`run.coverage_id`). A combined identity would force a half-populated instance at exactly the
  sites that re-derive the profile — "which is how a wrong key comes to silently group runs that
  must not be compared."

  It **hashes the declared set, not the achieved one**, so a DC dying at hour two does not give the
  run a private identity and strand it on a permanent comparison island. `NormalizeExclusions`
  deliberately mirrors `OuExclusionFilter`'s constructor line for line, and deliberately does *not*
  normalise internal whitespace, because the filter matches DNs by raw suffix comparison — claiming
  an equivalence the capture does not honour would be the worse error. `excludedOus` is a required
  parameter rather than optional for the same reason: an omitted list silently produces the
  identity of a differently-shaped run.

### F3 — Lifecycle state vocabulary
- **Layer:** Core (the enums) / Infrastructure (the persisted strings)
- **Owns:** the words for "did this run finish", and the separation of that question from coverage
  and from analysis health.
- **Depends on:** —
- **Implemented by:** `Core/Assessment/RunState.cs` (28), `Core/Assessment/RunCoverage.cs` (37),
  `Core/Assessment/AnalysisHealth.cs` (22), `Core/RunLibrary/RunLifecycleState.cs` (22),
  `Infrastructure/Storage/RunStateNames.cs` (38)
- **Non-obvious:** **there are four state vocabularies for one concept, and no two have the same
  members.** `RunState` has seven (`Draft`, `Capturing`, `Merging`, `Finalizing`, `Sealed`,
  `Failed`, `Corrupt`); `RunStateNames` persists five (`InProgress`, `Finalizing`, `Complete`,
  `Failed`, `Cancelled`); `RunLifecycleState` presents five (`InProgress`, `Sealed`, `Failed`,
  `Corrupt`, `Interrupted`). `Draft`, `Capturing` and `Merging` are never persisted; `Cancelled`
  collapses into `Failed` on read; `Interrupted` is reachable only from the `*.part.ndjson`
  fallback branch.

  `RunStateNames` is the one piece of this that earns its existence, and its remarks say why: the
  strings were private to `RunControlWriter` while four readers matched bare literals, so a rename
  changed what was written without changing what was read, and the library funnelled the
  unrecognised value into `InProgress` — a sealed run degraded silently and vanished from every
  picker filtering on `Sealed`. It also deliberately refuses to collect phase, checkpoint and
  `fact_coverage` state words, which happen to share `"Complete"`.

  **`AnalysisHealth` and `RunCoverage` exist only in memory.** `git grep` over `src/` finds
  `AnalysisHealth` at seven sites: the enum, `AuditRunResult`, two producers, and one consumer —
  `ForestAuditViewModel.Configuration.cs:299`, which picks a completion sentence. Neither axis is
  written to the `run` table and neither is read by the run library. The "three independent axes"
  model is real in the type system and absent from the persisted record, where everything collapses
  back to `run_state`.

### F4 — Seal transition
- **Layer:** Infrastructure
- **Owns:** the write that moves a run to a terminal state, and the decision of which terminal
  state.
- **Depends on:** C (the `run` table), D1 (`derived_health`), E1 (`findings_health`), F3
- **Implemented by:** `Infrastructure/Storage/RunControlWriter.cs` — `MarkRunFinalizing` /
  `CompleteRun` / `FailRun` / `CancelRun` (`:246–262`), `UpdateRunState` (`:439–471`); the decision
  at `Infrastructure/Storage/DirectCaptureRunner.cs:602–624`
- **Non-obvious:** **`Sealed` is advisory in the strongest sense: there is no transition guard at
  all.** `UpdateRunState`'s `WHERE` clause is `WHERE run_id = $runId`, with no predicate on the
  current state. Nothing prevents a `Complete` run being moved back to `InProgress`, and nothing
  prevents a second `CompleteRun` overwriting `completed_utc`. The distinction between terminal and
  non-terminal exists only in which *columns* are written — terminal sets `completed_utc` and
  `finalization_utc`, non-terminal coalesces the error summary — not in what is *allowed*.

  **A degraded run is `Failed`, not `Sealed`.** `errors.Count > 0` is true whenever any derived
  phase or any findings phase failed, and the branch calls `FailRun`. `docs/DATA-MODEL.md:157` and
  `AnalysisHealth.cs`'s own remarks both assert "a degraded run is still `Sealed`" — that is true
  of the in-memory `AuditRunResult` and false of the row on disk. Since every downstream gate reads
  the row, the practical answer to "what may a degraded run be used for" is: **nothing**. It cannot
  be opened, exported, reported on, or compared. It can still be marked as a baseline (see F10).

### F5 — Post-seal capture epilogue
- **Layer:** Infrastructure
- **Owns:** the work that happens between the seal write and the signature.
- **Depends on:** F4, F7, A (`liveSidResolver`)
- **Implemented by:** `Infrastructure/Storage/SecurityModeCaptureService.cs` (202) — `:69–100` (the
  three gated blocks), `PersistPreflightMetadata` (`:104+`), `ResolveSidsViaLdapAsync`
- **Non-obvious:** **this is the complete answer to "find every write path that runs after a run is
  sealed", and there are exactly two.** `git grep` for `SqliteOpenMode.ReadWrite` across `src/`
  returns five hits; three are `ReadWriteCreate` on capture/analysis paths that own the file, and
  the remaining two are both here — `:118` and `:153`. Both open `audit.db` for writing after
  `run_state` is already terminal. Both are then covered by the signature, because signing comes
  last.

  All three blocks gate on `result.State is RunState.Sealed`, which `DirectCaptureRunner:676` sets
  unconditionally. **So a degraded run — persisted `Failed`, refused by every output gate — is
  still LDAP-resolved, still has preflight metadata written into it, and is still issued an
  integrity signature.** The product's strongest claim is made about a bundle it will not let
  anyone open. `docs/review/01-infrastructure-storage.md` reached the same conclusion for the
  *re-analysis* path and closed it by refusing torn sources; the capture path was not covered by
  that fix.

### F6 — Run state read-back
- **Layer:** Infrastructure
- **Owns:** reading a bundle's lifecycle state without opening it as a working database.
- **Depends on:** C4 (`DatabaseConnectionFactory`), F3
- **Implemented by:** `Infrastructure/Storage/RunDatabaseInspector.cs` (75)
- **Non-obvious:** the single chokepoint every gate in F reaches through, which is what makes those
  gates consistent. Two things it conflates. First, `catch { return Legacy; }` is unqualified, so a
  *corrupt* database and a database *without the run table* return the same sentinel — and
  `OutputEligibilityEvaluator` then reports both as "required run metadata is missing". Second,
  `ORDER BY started_utc DESC LIMIT 1` means only the newest run row is inspected; a bundle
  re-analysed after a failure presents only its latest attempt, which is correct here but is the
  same query shape `ReadDatabaseMetadata` uses for facts where "newest" is a different question.

  `IsFinalizedComplete` is the property that everything actually depends on, and it is a string
  comparison against `RunStateNames.Complete` — the reason F3's shared-constants argument matters.

### F7 — Capture integrity signature
- **Layer:** Infrastructure
- **Owns:** the claim that a bundle's `audit.db` has not changed since capture.
- **Depends on:** —
- **Implemented by:** `Infrastructure/Storage/DatabaseIntegrityService.cs` (113)
- **Non-obvious:** **it is not a signature.** It is an unkeyed SHA-256 of the file bytes, stored as
  plaintext JSON in `audit.db.sig` next to the file it describes. There is no key, no certificate,
  and no `HMAC` anywhere in `src/`. Anyone who can modify `audit.db` can recompute the hash and
  rewrite the sidecar. It detects accidental modification and file corruption, which is a real and
  useful property; it does not detect tampering, which is what the word "signed" is read as
  meaning — including in `docs/DATA-MODEL.md:7` and in the in-app help.

  **What it covers, verified from the code:** `ComputeHash(filePath)` streams exactly one file.
  Nothing else in the bundle is hashed. This *does* confirm E10's mechanism from the signing side —
  writing `suppressions.db`, `user_metadata.json` or `invocation.json` cannot change the verdict,
  because they are not inputs. Anything written into `audit.db` after signing would invalidate it,
  and nothing does, because the two post-seal writers (F5) run *before* `Sign`.

  **`Verify` is advisory.** One production caller, `MainViewModel.cs:661`; one consumer of the
  result, a `DataTrigger` in `StatusBar.xaml:35`. `IntegrityStatus.Modified` changes a colour. The
  run opens.

  **The cache can mask a modification.** `GetCachedOrComputeHash` returns the cached hash when file
  size and `LastWriteTimeUtc` both match. An edit that preserves both — trivially achievable, and
  achievable accidentally by any tool that restores timestamps — returns `Verified` without
  rehashing. The cache is written by `Sign` too, so the first `Verify` after capture never hashes
  the file at all.

### F8 — Output eligibility
- **Layer:** Infrastructure
- **Owns:** the single question "may this run produce output", and the sentence explaining a
  refusal.
- **Depends on:** F6, E4 (`GetRunCoverageState`), C (`DashboardQueryService`)
- **Implemented by:** `Infrastructure/Export/OutputEligibilityEvaluator.cs` (178) — the evaluator,
  `OutputEligibilityKind`, `OutputEligibilityResult`
- **Non-obvious:** **what it actually gates is `IsFinalizedComplete` and nothing else.** All three
  block messages are variations on one check; the coverage material is a *warning*, never a block.
  It does not consult the signature, `derived_health`, `findings_health`, `RunCoverage`, or
  `CoverageId`.

  **Five of its six kinds have production call sites; `Compare` has none.** `git grep
  OutputEligibilityKind.Compare` over `src/` returns only the evaluator's own three switch arms.
  The only other hits are in `OutputEligibilityCheckerTests.cs`, which parameterises over the enum
  and asserts the message text. This is precisely the pattern
  `docs/review/01-infrastructure-storage.md:573` warns about — the test exercises a code path no
  consumer reaches, and passing tells you nothing about whether compare is gated. **Compare is
  gated separately**, by `State == RunLifecycleState.Sealed` checks scattered across
  `RunLibraryViewModel` (`:434`, `:438`, `:464`, `:465`) and `MainViewModel.Drift.cs:112`. Two
  definitions of the same rule, one tested and unreached, one reached and untested as a gate.

  **The two-argument `Evaluate(connection, dbPath, kind)` can only ever return `CanProceed: true`.**
  If `dbPath` is null or in-memory it skips the file check entirely; if the file check passes it
  falls through to the warning-only return. It cannot block on anything the file-path overload
  would not have caught. `ExportCoordinator` is its only caller and passes a real path, so this is
  latent rather than live — but the overload's shape invites a caller that passes null and believes
  it has been gated.

### F9 — Run coverage verdict
- **Layer:** Core (the snapshot and its rules) / Infrastructure (the reader and resolver)
- **Owns:** the run-level verdict on how much of the forest it saw, and the phrasing of any
  exclusion claim the capture falsified.
- **Depends on:** C (`run_domain_declaration`, `run_domain_discovered`, `fact_coverage`), D
  (`dim_unresolved_group_member`), F2
- **Implemented by:** `Core/Coverage/RunCoverageSnapshot.cs` (220),
  `Core/Coverage/ContradictedExclusions.cs` (77), `Infrastructure/Storage/RunCoverageReader.cs`
  (314), `Infrastructure/Storage/RunCoverageResolver.cs` (115),
  `Infrastructure/Storage/DomainDeclaration.cs` (296),
  `Infrastructure/Storage/AttestationVerifier.cs`,
  `Core/Assessment/DomainExclusionAttestation.cs` (46)
- **Non-obvious:** **this claims the run-level coverage verdict for F**, against the alternative of
  D. The argument: `fact_coverage` rows are D's output and the per-cell `CoverageState` matrix is
  D's model, but `RunCoverageSnapshot` answers one question and it is F's — *may this run be used
  for X*. Its four consumers are `BaselineEligibility` (F10), `RunLibraryService.Metadata` (F12),
  `AcceptanceImportService` and `StructuralCompareEngine`. None of them is D.

  The design decision worth carrying forward is that **the resolver is computed once at seal and
  recomputed identically from the database afterwards** — `RunCoverageReader.Read` calls
  `RunCoverageResolver.Resolve` rather than re-deriving. `RunLibraryService.Metadata.cs:349` goes
  through the same reader for a one-line library label it barely needs, explicitly so the row
  "cannot disagree with what compare and acceptance import see."

  `AttestationVerifier` runs after capture and reassigns `AttestedEmpty` to `AttestedDegraded`
  where `dim_unresolved_group_member` proves the domain was populated. `DirectCaptureRunner:693`
  projects the *verified* declarations, not the pre-capture ones — the comment records why: the
  pre-capture set would report every claim as holding, because nothing had yet been captured to
  falsify one.

### F10 — Baseline eligibility
- **Layer:** Infrastructure (the decision) / Core (the result)
- **Owns:** whether a run may serve as the thing later runs are measured against.
- **Depends on:** F9, C4
- **Implemented by:** `Infrastructure/Storage/BaselineEligibility.cs` (87),
  `Core/Assessment/SetBaselineResult.cs` (60)
- **Non-obvious:** the one place in F that **fails closed on purpose**, and says so: "Every other
  coverage reader degrades toward a weaker claim, but this one would degrade toward *fit to be a
  baseline*, which is the single conclusion it exists to be able to withhold." A bundle that cannot
  be opened is refused, not admitted.

  It is shared rather than inlined because there are two doors — the run library and the post-audit
  save dialog — and "a rule enforced at one door and not the other is not enforced." That reasoning
  is right, and it makes the omission below sharper.

  **Its summary says "decides whether a *sealed* run may serve as baseline" and it never checks the
  state.** `Evaluate` reads coverage only. Neither does its caller: `SetAsBaselineAsync`
  (`RunLibraryService.Metadata.cs:413`) checks `metadata.ProfileId is not null` and then
  eligibility. Neither does the UI: `CanSetBaseline` (`RunLibraryViewModel.cs:263`) is
  `SelectedRun is not null && !SelectedRun.IsBaseline`. So a `Failed`, `Corrupt` or `Interrupted`
  run whose coverage rows happen to read eligible can be made the profile's baseline — and
  `CanCompareToBaseline` (`:372`) then requires `BaselineRun is { State: Sealed }`, so it reads
  false forever. The profile ends up with a baseline it can never be compared against, and the
  refusal names no cause because there is no refusal.

### F11 — Bundle layout and storage tiers
- **Layer:** Infrastructure
- **Owns:** where a run lives on disk, the session/library distinction, and promotion between them.
- **Depends on:** F6
- **Implemented by:** `Core/RunLibrary/RunStorageLocation.cs` (19),
  `Infrastructure/RunLibrary/RunLibraryService.cs` (435) — constructor, `PromoteToLibraryAsync`,
  `TryResolveBundlePath`, `TryResolveRunId`, `IsSafeRunId`, `IsChildPathOf`
- **Non-obvious:** the path-containment work is the substantive part and is well done —
  `IsChildPathOf` normalises both sides, requires a trailing separator, and rejects the root
  itself; `IsSafeRunId` rejects rooted paths, both separators, `.`, `..` and invalid filename
  characters. Every public entry point that takes a caller-supplied path routes through
  `TryResolveBundlePath` first. This is a real traversal defence, not a gesture.

  `PromoteToLibraryAsync` is the only F operation that enforces sealing before acting (`:97`), and
  it does so by inspecting the database rather than by trusting `RunMetadata.State`.
  `RunStorageLocation`'s doc comment still says "Default for Configuration Mode" — residue of
  scoped capture, removed 2026-08-02. Nothing selects `Session` on that basis any more.

### F12 — Bundle discovery and metadata extraction
- **Layer:** Infrastructure (the extractor) / Core (the record)
- **Owns:** turning a directory on disk into a described, listable run.
- **Depends on:** F1, F3, F6, F9, F13, C4
- **Implemented by:** `Infrastructure/RunLibrary/RunLibraryService.Metadata.cs` (539),
  `Core/RunLibrary/RunMetadata.cs` (144), `Core/Services/IRunLibraryService.cs` (101)
- **Non-obvious:** the most fallback-heavy code in the branch, and the fallbacks are layered five
  deep: `audit.db` is searched across four candidate paths (three labelled "legacy"); metadata
  comes from `dim_database_metadata`, then the `run` row, then `invocation.json`, then
  `user_metadata.json`; `mode` defaults to `"Security"`; the profile is re-derived from the FQDN
  when absent. Given `docs/decisions/0001-no-backward-compatibility.md` and the standing
  instruction that no older bundles exist in the field, **three of the four `audit.db` locations
  cannot occur.**

  Two decisions here are precisely right and worth naming. `TryReadCoverageId` and
  `TryReadCoverageLabel` are guarded *separately* from the main metadata read, with the reason
  written down: widening the main `SELECT` would mean a bundle lacking one optional column throws
  and loses five other facts. And `ListRunsByProfileAsync` groups a profile-less run under
  `"unknown:{runId}"` rather than pooling all unknowns, because "not knowing a run's profile is not
  evidence that it shares one with every other unidentified run, and pooling them would offer them
  to each other as acceptance sources."

  The `_ => RunLifecycleState.Corrupt` arm carries a comment recording the bug it fixed: it
  previously resolved to `InProgress`, making an unreadable run indistinguishable from a running
  one, so it left every `Sealed`-filtered picker without an error and the user was told nothing.

  `RunMetadata.EffectiveDisplayName` recomputes the save dialog's default name rather than showing
  a raw run id, because failed and cancelled runs never reach that dialog and are never cleaned out
  of the library.

### F13 — User-authored bundle metadata
- **Layer:** Infrastructure (the two writers) / Core (the record)
- **Owns:** the display name, notes and baseline flag a user attaches to a run.
- **Depends on:** F1, F11
- **Implemented by:** `Core/Assessment/SavedRunRecord.cs` (104),
  `Infrastructure/Storage/RunMetadataService.cs` (282), `UpdateUserMetadataAsync` in
  `Infrastructure/RunLibrary/RunLibraryService.Metadata.cs` (`:477–539`),
  `UI/ViewModels/SaveRunDialogViewModel.cs` (112)
- **Non-obvious:** **one file, `user_metadata.json`, has two writers with different serialisation
  models.** `RunMetadataService` serialises a whole `SavedRunRecord` with snake_case naming;
  `UpdateUserMetadataAsync` builds a `Dictionary<string, object>` by hand with five known keys.
  `RunLibraryService.Metadata.cs:170` contains a comment acknowledging the collision — "Also check
  `run_name` (written by `RunMetadataService` with snake_case naming)."

  **The dictionary writer does not round-trip the record writer's output.** It reads existing JSON
  through a `ValueKind` switch: `Number => GetInt32()`, and everything not string/bool/number
  `=> prop.Value.ToString()`. `SavedRunRecord.ObjectCount` and `AceCount` are `long`, and
  `DcPreflightResults` is an array. So marking a baseline on a run saved through the dialog either
  throws on a large count — and the `catch { }` then discards *all* prior user metadata — or
  rewrites the preflight array as a stringified blob. The two writers were aligned on filename and
  not on format.

  `SavedRunRecord.GenerateDefaultName(profile, timestamp)` takes a `ProfileId`, null-checks it, and
  ignores it — delegating straight to `GenerateDefaultSecurityName(timestamp)`. Security is the
  only mode, so the parameter describes a variation that no longer exists.

### F14 — Bundle manifest
- **Layer:** Infrastructure
- **Owns:** nothing. There is no producer.
- **Depends on:** —
- **Implemented by:** *no production file*
- **Non-obvious:** **`manifest.json` is read in two places and written in none.** `git grep
  '"manifest.json"'` over `src/` returns `RunLibraryService.Metadata.cs:40` and
  `RunLibraryService.cs:298`; the only writers are seven lines in `RunLibraryServiceTests.cs`, all
  writing `"{}"`. `ExportManifest` / `export_manifest.json` is a different artefact belonging to I,
  and is genuinely produced.

  Two live behaviours depend on a file that never exists. `ExtractMetadataAsync:93` treats a bundle
  with no run table but a manifest as `Sealed` — declaring a run complete on the strength of a JSON
  file's existence, with no check of its contents (the tests' `"{}"` would satisfy it). And
  `ShouldDeleteSessionRun:298` refuses to clean up a session bundle that has a manifest. Neither
  branch can fire in production.

  `HelpViewModel.Content.cs:818` tells the user the bundle contains "manifest.json — artifact
  listing with SHA-256 hashes." That artefact does not exist, and the only SHA-256 in the bundle is
  F7's single-file hash.

### F15 — Abandoned-run reclamation
- **Layer:** Infrastructure
- **Owns:** what happens to a bundle whose process died mid-capture.
- **Depends on:** F6, F11, K (single-instance enforcement)
- **Implemented by:** `ReclaimAbandonedRunsAsync` and `IsAbandonedCapture` in
  `Infrastructure/RunLibrary/RunLibraryService.cs` (`:230–278`),
  `Infrastructure/Storage/FailedRunCleanup.cs` (80), `CleanupStaleSessionRunsAsync` /
  `CleanupAllSessionRunsAsync` / `ShouldDeleteSessionRun` / `GetLastActivityUtc`
- **Non-obvious:** the correctness argument is external to the code and is written down: safe
  **only** because a single application instance is enforced at startup and this runs before any
  capture begins, so a bundle still marked in-flight cannot belong to a live capture. Its remarks
  state the consequence — "Must be called before any capture starts, or it will delete that
  capture's own bundle." That is a temporal precondition with no compile-time or runtime
  enforcement.

  `IsAbandonedCapture` deliberately matches raw `run_state` strings rather than the resolved
  `RunLifecycleState`, because that mapping collapses `InProgress` and `Finalizing` into one value
  and only the raw form distinguishes a capture still gathering evidence from one already sealing.
  An unrecognised state resolves to `Corrupt` and matches nothing, so a bundle this build cannot
  describe is never reclaimed.

  `GetLastActivityUtc` skips `-wal` and `-shm` files when computing staleness, so an abandoned WAL
  does not keep a dead bundle looking alive.

### F16 — Run library UX
- **Layer:** UI
- **Owns:** presenting the library, grouping by profile, and refusing an action in words the user
  can act on.
- **Depends on:** F10, F12, F13, F17
- **Implemented by:** `UI/ViewModels/RunLibraryViewModel.cs` (583) — including `RunCard` and
  `ProfileGroup`, `UI/RunLibraryWindow.xaml.cs` (137), `UI/RunLibraryWindow.xaml` (224)
- **Non-obvious:** the refusal design is the strongest thing in this component and is unusually
  deliberate. `SetBaselineAsync` surfaces `result.Reason` on `StatusMessage` rather than
  `ErrorMessage`, with the reason recorded: "the refusal is the system working, so it must not
  appear in the same red slot as *the library could not be read*." And `IsSelectedRunOpen` is kept
  out of `CanDelete` on the argument that a capture in progress announces itself on the row so a
  disabled button reads as a visible consequence, whereas an open run looks like every other sealed
  run and would be an unexplained dead button — so the command refuses and says why instead.

  `CanDelete` excludes only `InProgress`, because the capture holds `audit.db` open; the remark
  notes this guard was only addable *because* F15 exists, since otherwise a crashed run would be
  permanently undeletable. The XAML carries a comment distinguishing the state word from coverage:
  "Sealed says the bundle is closed, not that it saw everything."

### F17 — Run selection for downstream branches
- **Layer:** UI
- **Owns:** which runs are offered as a compare partner, a compare baseline, or an acceptance
  source.
- **Depends on:** F2, F3, F12
- **Implemented by:** `CanCompareToBaseline` / `CanCompareToPrevious` / `CanCompareWith` /
  `RequestCompare` in `UI/ViewModels/RunLibraryViewModel.cs` (`:196–210`, `:370–470`, `:515+`),
  `UI/ViewModels/ImportAcceptancesViewModel.cs:175`, `UI/ViewModels/MainViewModel.Drift.cs:112`
- **Non-obvious:** **this is where F actually answers G and E10, and it does so entirely in the UI
  layer.** Four separate `State == RunLifecycleState.Sealed` predicates, in three files, none of
  which consults `OutputEligibilityEvaluator`. Add F10's missing state check and the count of
  independent "is this run usable" rules in the branch reaches five.

  `RequestCompare` normalises the pair to oldest-first using `SealedUtc ?? CreatedUtc`, so the
  direction of a diff never depends on click order. `RunLibraryViewModel.cs:492` phrases the
  `CoverageId`-mismatch refusal — "at least one of these runs did not record what coverage it
  declared, so they cannot be shown to have assessed the same evidence" — which is F2's
  null-is-not-a-match rule reaching the user in words. `ImportAcceptancesViewModel:175` filters on
  `State == Sealed && DbPath is not null`.

  **F imposes no restriction on suppression.** Nothing in `SuppressionService`,
  `SuppressionSidecar` or `AcceptanceImportService` reads run state. A sealed run accepts new
  suppressions freely, which is correct and is the whole point of C5's sidecar — verified from F7's
  signing code, which hashes one file and therefore cannot notice.

## Naming & taxonomy

| Current | Proposed | Why it matters |
|---|---|---|
| `DatabaseIntegrityService.Sign` / `.sig` / `SignatureRecord` | `SealHash` / `.hash` / `CaptureHashRecord` | The word promises tamper-evidence and delivers corruption detection. It is unkeyed and stored in the clear beside the file it describes. The naming has already propagated into `docs/DATA-MODEL.md:7` ("signed at capture") and into the in-app help, so the misreading is now the documented behaviour. This is the single most consequential name in the branch. |
| `RunState` vs `RunLifecycleState` vs `RunStateNames` | `CaptureProgress` (in-flight, UI) vs `RunState` (the persisted five) — and delete the third | Three types, three member sets, one concept. `RunState` mixes transient progress (`Capturing`, `Merging`) with durable outcome (`Sealed`, `Failed`), which is why `RunLifecycleState` had to exist to present the durable half. If the persisted vocabulary were an enum rather than strings, `RunStateNames` would be unnecessary. |
| `RunState.Sealed` ↔ persisted `"Complete"` | one word, either | The mapping is real code (`RunLibraryService.Metadata.cs:72`, `ExistingCaptureAnalysisService.cs:285`) and exists only because the enum and the string were named by different people. Every reader has to hold both words. |
| `SavedRunRecord` vs `RunMetadata` | `RunUserAnnotations` vs `RunListing` | Near-synonyms for unrelated things — what a user typed into a dialog versus a library row assembled from five sources. `SavedRunRecord`'s own summary has to say "Distinct from `Core.RunLibrary.RunMetadata`", which is a name apologising for itself. |
| `RunMetadataService` | `RunAnnotationStore` | It does not manage run metadata; it reads and writes `user_metadata.json`. F12 is what actually produces run metadata, and does not use this type. |
| `OutputEligibilityEvaluator` | `FinalizedRunGate` | "Output eligibility" implies a policy surface — coverage, health, integrity. It checks one boolean. The broad name is why `Kind.Compare` looks like a gate that exists. |
| `ExportManifest` vs bundle `manifest.json` | `ExportPackageIndex` | Same word, two artefacts, opposite fates: one is written on every export, the other has no producer at all. |
| `RunCoverage` vs `Coverage.CoverageState` | `RunCoverageVerdict` vs `ModuleCoverageState` | Both have a `Partial` member and they describe different subjects at different granularities. `RunCoverage`'s own remarks have to spend a paragraph disclaiming the collision. |
| `SavedRunRecord.GenerateDefaultName(profile, timestamp)` | delete; callers use `GenerateDefaultSecurityName` | The `profile` parameter is null-checked and discarded. A required argument that cannot change the result is a false signal that the result varies by profile. |
| `RunDatabaseStateInfo.Legacy` | `Unreadable` | It is returned both for a database with no `run` table and for one that threw. "Legacy" names a cause that, per decision 0001, cannot occur. |

## Would-do-differently

**Sealing should be a property of the artefact, not a column.** The current model marks a row
`Complete` and then keeps writing to the file for three more operations before hashing it. Nothing
enforces the ordering, nothing prevents a later write, and `UpdateRunState`'s `WHERE` clause admits
any transition including backwards out of a terminal state. In a rebuild, sealing is the act of
closing the write connection and computing the hash, in that order, in one place — and every
subsequent open of that path is read-only by construction, not by convention. The state column then
records *what* the seal concluded rather than *whether* it happened, and "is this run sealed" is
answered by the presence and validity of the hash rather than by a string. That also removes the
possibility of the two disagreeing, which is currently the branch's central defect.

**A degraded run should be sealed and marked degraded, not failed.** The type system already models
this correctly — `AnalysisHealth` is a separate axis, `RunState`'s remarks explain at length why
`Degraded` was removed from it as "never an alternative to `Sealed`" — and then
`DirectCaptureRunner:612` calls `FailRun` on exactly that condition and throws the distinction
away. The consequence is that a run whose capture succeeded completely and whose ninth derived
phase failed is unopenable: the user cannot see the eight phases that worked. Worse, the failure is
invisible in the moment, because `AuditRunResult.State` says `Sealed` and the dashboard prints
"Complete". The rebuild should persist the three axes it already designed, seal on capture success,
and let the gates read health rather than inferring it from a lifecycle value that was forced to
carry it.

**There should be one run-usability gate, and consumers should not be able to invent their own.**
Right now there are five independent rules — `OutputEligibilityEvaluator`, four `State == Sealed`
predicates across three view models, `PromoteToLibraryAsync`'s own inspection, and
`BaselineEligibility`, which forgot the state check entirely. The evidence that this shape fails is
in the code: `Kind.Compare` is a fully-implemented, fully-tested gate with no caller, because
compare's authors wrote their own check instead. A single `RunUsability.For(bundle, purpose)`
returning a reason-carrying result, with the purposes enumerated, would make "did compare go
through the gate" a question with an answer. The current arrangement makes it a question that
requires reading four files, and the answer is no.

**The library should not read four candidate paths for `audit.db`.** Three are labelled legacy,
decision 0001 says nothing predates the current build, and the standing product guidance is that no
older bundles will exist in the field. The cost is not the file probes; it is that
`ExtractMetadataAsync` is 200 lines of layered fallback in which no reader can tell which branch is
live, and the `manifest.json` branch — provably unreachable, since nothing writes the file — sits
inside it declaring runs `Sealed`. A rebuild should define one bundle layout, fail loudly on
anything else, and let the extractor be twenty lines.

**Two writers for one file is how `user_metadata.json` acquired a format it cannot read back.**
`RunMetadataService` writes a serialised record; `UpdateUserMetadataAsync` writes a hand-built
dictionary and parses the existing file through a `ValueKind` switch that mishandles both `long`
and array values, with a `catch { }` that discards everything on failure. Neither author appears to
have known the other existed until the comment at `Metadata.cs:170` was added. The rebuild's rule
is narrow and cheap: a file has one owning type, and every other component goes through it.

**This was right, keep it: the split of `ProfileId` from `CoverageId`, and the reasoning recorded in
both.** Two identities that could plausibly have been one, kept apart because they have different
recoverability — the profile is a pure function of the forest and can be re-derived when metadata
is missing; the coverage identity can only be read back from where it was written. The XML remarks
state the failure mode a combined type would produce: a half-populated instance at exactly the
sites that re-derive the profile, "which is how a wrong key comes to silently group runs that must
not be compared." Both types also state what they deliberately do *not* fold in, and why —
`CoverageId` hashes the declared set rather than the achieved one so a dead DC does not strand a
run on a private comparison island; `NormalizeExclusions` refuses to normalise internal whitespace
because the capture filter does not. This is the standard the rest of the branch should be held to,
and it is standard set inside the branch itself.

## Corrections to existing documents

These are recorded, not applied. No document listed here was edited.

| Document | Claim | Correction |
|---|---|---|
| `docs/DATA-MODEL.md:157` | "A degraded run is still `Sealed`; its health is carried on a separate axis." | True of the in-memory `AuditRunResult`, false of the persisted row. `DirectCaptureRunner.cs:602–613` calls `FailRun` whenever any derived or findings phase failed, so a degraded run's `run_state` is `Failed`. Every downstream gate reads the row, so a degraded run cannot be opened, exported or reported on. |
| `docs/DATA-MODEL.md:7`, `:15`, `:21` | "`audit.db` is signed at capture"; "rows the classifier derives … stay in `audit.db` under the signature"; "a signed snapshot". | The mechanism is an unkeyed SHA-256 of the file bytes stored in plaintext JSON beside it (`DatabaseIntegrityService.cs`). The sidecar rationale is sound — writes to `audit.db` genuinely would invalidate it — but "signed" overstates the guarantee, and `Verify`'s result blocks nothing. |
| `docs/map/E-findings.md`, E1 | "a bundle can be `derived_health=Complete` and `findings_health=Degraded` simultaneously." | Correct as metadata, but incomplete: either health being degraded also causes `FailRun`, so such a bundle is `run_state='Failed'` and is refused by F8 and F17. The two health keys can disagree; the run cannot survive either of them disagreeing with `Complete`. |
| `docs/map/E-findings.md`, E10 | "user edits to `audit.db` invalidate the capture signature, which is why suppressions live in a sidecar." | Verified from the signing side and correct. Worth adding that the coverage is *exactly one file* — `ComputeHash(dbPath)` streams `audit.db` only — so `user_metadata.json`, `invocation.json` and `suppressions.db` are all outside it, and the `.sig.cache` keyed on size and mtime can return `Verified` without rehashing. |
| `docs/review/01-infrastructure-storage.md`, the re-analysis torn-source decision (2026-08-07) | Re-analysis now refuses a source whose run row is not `Complete`, so no fresh signature is issued over evidence no build vouched for. | The equivalent hole on the **capture** path is still open. `SecurityModeCaptureService.cs:88–99` gates signing on `result.State is RunState.Sealed`, and `DirectCaptureRunner:676` sets that literal unconditionally — so a run persisted `Failed` is still signed. |
| `src/SecureAD.UI/ViewModels/HelpViewModel.Content.cs:818` | The bundle contains "manifest.json — artifact listing with SHA-256 hashes". | No production code writes `manifest.json`. It is read at two sites and written only by tests. The only SHA-256 in a bundle is the single-file hash in `audit.db.sig`. |
| `src/SecureAD.Core/RunLibrary/RunStorageLocation.cs` | `Session` is the "Default for Configuration Mode". | Residue of scoped capture, removed 2026-08-02. Nothing selects a storage tier by mode. |

## Coverage gaps in this pass

- **`docs/work/RUN-MODEL-DESIGN.md` (2,428 lines) was consulted only by targeted `git grep`**, not
  read through. It carries `F-01-NN` findings that overlap this branch and may already record some
  of what is above. Its finding numbering is unrelated to this file's `F1`–`F17` component ids; a
  future session should reconcile the two namespaces or rename one.
- **`docs/review/12-run-model-rework.md` (720 lines) — read the first 46 lines only**, enough to
  establish which eight files are new and what the slice claims. Its individual findings were not
  checked against the current tree.
- **`docs/review/01-infrastructure-storage.md` (3,069 lines) — read four excerpts** around lines
  80–92, 505–525, 565–590 and the `F-01-6` block. The `:1938` region named in the brief was not
  reached.
- **`RunLibraryViewModel.cs` was read in sections** (`:195–240`, `:263–265`, `:325–375`) plus a full
  structural grep of its commands and `CanExecute` predicates. `RunCard`, `ProfileGroup` and the
  compare-selection bodies at `:445–583` were not read line by line.
- **`RunCoverageReader.cs` (314), `DomainDeclaration.cs` (296), `RunCoverageResolver.cs` (115) and
  `AttestationVerifier.cs` were characterised from their call sites, their tests' assertions and
  `docs/review/12`'s summary**, not read in full. F9's boundary claim rests on who consumes
  `RunCoverageSnapshot`, which was verified by grep.
- **`ExistingCaptureAnalysisService.cs` (323) was read only around `:130–160` and `:200–290`.** Its
  interaction with F is the second `CompleteRun` caller and the second `Sign` caller; the
  re-analysis flow itself belongs to D20.
- **The `user_metadata.json` round-trip defect in F13 is verified structurally**, from the
  `ValueKind` switch and the `SavedRunRecord` property types, not by execution. Which of the two
  failure modes fires depends on the actual `AceCount` magnitude.
- **No tests were run.** Per the brief this pass is advisory and makes no code changes; the failure
  modes described are read from source and would need a test to demonstrate.
