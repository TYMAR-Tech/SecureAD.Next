# G — Compare

**Owns:** whether two sealed runs may be measured against each other, what the difference between them
is, and what the difference is permitted to claim. It begins where F17 hands over a chosen pair and
ends at a `CompareResult` rendered in one window and one home-screen card.

**Boundary note:** three edges were settled before this file was written and are honoured rather than
relitigated. F owns run identity, sealing and output eligibility, and F17 owns which runs are
*offered* as a pair — G describes what happens after a pair is chosen. C owns the storage and the read
surface; G owns only the comparison semantics layered over it. E14 records `RunDiffService` as a
complete, tested, unreachable G-component; G14 rules on it rather than rediscovering it.

Two further edges were arguable and are stated rather than chosen silently. **The four `Acl*` view
models are not G's:** `AclCompareViewModel` (513), `StoredAclCompareViewModel` (264),
`AclDeltasWindowViewModel` (89) and `AclDeltaRowViewModel` (35) all carry `LiveAclDelta` and
`ILiveDiagnosticsService`, never `AceDelta` or `CompareResult`. They compare live DACLs against live
or against stored, which is the freshness overlay the README's note on branch H reserves. They are
named here so they are not lost, and H should claim them. **`RunCoverageSnapshot` stays with F9:** G
consumes five of its predicates — `CoverageId`, `IsComplete`, `IsCoverageKnown`, `AreExclusionsKnown`
and `IsBaselineEligible` — and defines no coverage vocabulary of its own.

**Cross-branch position.** B creates the runs, C stores and reads them, D and E stamp health and
findings onto them, F decides whether either may be used at all and normalises the pair. G is the
last branch to consume that chain and the only one to consume two runs at once. Nothing downstream
consumes G: `git grep` for `CompareResult` and `ChangeReport` across `src/` returns the compare
window, the drift card and nothing else. No report generator, no exporter, no dashboard reads a
comparison. There is no G→I seam to draw.

## The flow

1. **A pair arrives.** Either `RunLibraryViewModel.RequestCompare` normalises two runs oldest-first
   and raises `CompareRequested` (F17), or `MainViewModel.Drift` picks the next-older sealed run in
   the same profile unprompted.
2. **`ToolWindowLauncher.LaunchCompareAsync`** (`:132`) or `LoadDriftAsync` (`:68`) calls
   `MainViewModel.CompareRunsAsync` (`:863`), which constructs a `SecurityCompareEngine` per call and
   passes two `audit.db` paths. There is no interface, no registration, no injection.
3. **`SecurityCompareEngine.CompareAsync`** immediately delegates the whole structural half to
   `StructuralCompareEngine.CompareAsync` (`:27`). This is verified, not assumed: objects, ACEs,
   coverage deltas, both `CompareRunInfo`s, the compatibility verdict and `NotAssessedCells` all come
   back from the structural engine and are copied through verbatim.
4. **`StructuralCompareEngine.LoadRunInfoAsync`** opens each database read-only, reads
   `dim_database_metadata` into a dictionary, counts `dim_object` and `fact_ace`, and calls
   `RunCoverageReader.Read(conn)` to recompute coverage rather than read a stored verdict. The
   capture timestamp falls back through `created_utc` → `completed_utc` →
   `SELECT started_utc FROM [run]`.
5. **`CompareCompatibilityValidator.Validate`** runs five rules in order: mode equality; schema
   version equality *compared numerically* so `"1"` and `"1.0"` match; the coverage matrix; the
   not-assessed cell count; tool major version. It returns one status and one warning string.
6. **The coverage matrix is three tests, deliberately ordered.** `IsBaselineEligible` on either side
   fails first and returns `DegradedCoverage` — placed ahead of the hash check because two runs that
   excluded *the same* populated domain have identical `CoverageId`s and would otherwise read as
   fully compatible. Then a `CoverageId` mismatch returns `IncompatibleCoverage` **only if**
   `ExclusionsAreDefensible` is false. Then a non-empty symmetric difference of covered cells returns
   `CoverageMismatch`.
7. **`CanCompare` is an allow-list** of four statuses: `Compatible`, `CoverageMismatch`,
   `DegradedCoverage`, `ToolVersionMismatch`. Anything else short-circuits `StructuralCompareEngine`
   into a result with metadata, a status and a warning, and **no delta collections at all**.
8. **Deltas are computed against the coverage intersection.** `ComparableCells` intersects the two
   `CoveredCells` sets at `(module, domain)` grain — not domain grain, because a run can complete
   `Objects` for a domain and fail `SecurityDescriptors` for it. The filter is applied only when
   *both* runs have `IsCoverageKnown`; otherwise every row passes.
9. **Objects, ACEs and coverage are diffed** by full in-memory load of both sides into dictionaries,
   then added/removed/modified passes, then a deterministic sort. Coverage deltas are the one family
   with no intersection filter — they *are* the coverage comparison.
10. **Control back in `SecurityCompareEngine`.** If the structural status is not comparable, it
    returns the structural result unchanged. Otherwise it computes finding deltas by full load of
    `fact_finding` from both files, keyed on `finding_key`, filtered by the same cell intersection
    re-implemented inline (`:74–87`) rather than reused.
11. **Graph deltas are gated separately and much harder.** `CanCompareGraphFindings` requires non-null
    `CoverageId` on both sides, case-insensitive equality, and `IsComplete` on both. If it fails,
    `ControlEdgeDeltas` is `[]` and `GraphFindingsWithheldReason` carries a sentence saying so — an
    empty list and a withheld list must not look alike.
12. **`CompareResultsViewModel`** copies five collections into `ObservableCollection`s, wraps findings
    and control edges in filtered `ICollectionView`s that hide unchanged rows by default, and lazily
    builds a `ChangeReport`.
13. **`ChangeReportBuilder.Build`** reduces the finding deltas to a verdict: any introduced finding
    means `Worsened`, regardless of how many were resolved. It reads nothing but `FindingDeltas`.
14. **`CompareResultsWindow.xaml`** renders four qualification notices above the tabs — chronological
    reversal, the compatibility warning, the not-assessed summary, the withheld-graph reason — each
    guarded by `CompareCoverageBindingGuardTests`.
15. **The drift card renders one line.** `DescribeDrift` produces a comma-joined count string. It
    reads no compatibility status, no not-assessed count and no withheld reason. Clicking through
    opens the same full window, which shows all four.

The shape of the branch is set by steps 6, 7 and 15. The compatibility rules are the most carefully
reasoned code in the repository, and the two surfaces that consume them disagree with them in
opposite directions.

## Components

### G1 — Compare run descriptor
- **Layer:** Core
- **Owns:** everything about one run that the other run's comparability is judged against.
- **Depends on:** F9, C2
- **Implemented by:** `Core/Compare/CompareRunInfo.cs` (26)
- **Non-obvious:** the `Coverage` parameter's own remarks record the design correction that defines
  the branch — it replaced a bare `CoverageModuleCount` int, which could say two runs differed in how
  many coverage rows they wrote but never *which*, and so could not distinguish "B added a domain"
  from "B lost one". Both shapes produce the same integer difference.

  `ScopeDescription` is carried, populated by `StructuralCompareEngine:148`, and asserted by
  `MetadataKeyContractTests:88` — and read by no compatibility rule. The validator's Rule 3 comment
  records why: the `ScopeDescription` comparison it replaced could never fire, because for a Security
  run the value is read from `dim_database_metadata`, which the capture path never writes it to, so
  both sides were always null and always equal. The field survived the rule it existed for, and now
  has a contract test guarding a value nothing decides on.

### G2 — Compatibility policy
- **Layer:** Core
- **Owns:** whether two runs may be compared at all, and what the user is told when they may not.
- **Depends on:** G1, F9, A (`ToolVersion`), D (`CoverageCell`)
- **Implemented by:** `Core/Compare/CompareCompatibilityValidator.cs` (288) — `Validate`,
  `ExclusionsAreDefensible`, `DegradedWarning`, `NotAssessedCells`, `CanCompare`,
  `SchemaVersionsMatch`; `Core/Compare/CompareCompatibility.cs` (58). Tested by
  `CompareCompatibilityValidatorTests.cs` (542) and `CompareSchemaVersionCompatibilityTests.cs` (55).
- **Non-obvious:** this is the most heavily reasoned file in the branch and possibly the repository —
  288 lines of which roughly half are remarks recording why each rule is shaped as it is, including
  the rules it replaced and why those were wrong. Three of those arguments are load-bearing and none
  is obvious from a call site.

  **The `DegradedCoverage` check is ordered ahead of the `CoverageId` check on purpose.** Two runs
  that excluded the same populated domain produce identical `CoverageId`s and would sail through as
  `Compatible`; putting the eligibility test first is the only thing preventing that.

  **`ExclusionsAreDefensible` requires the exclusion set to be *known*, and requires at least one side
  to have actually excluded something.** An unreadable declaration produces an empty exclusion set,
  which by inspection is indistinguishable from a whole-forest run — so treating unknown as defensible
  would relax the gate precisely on the bundles that can say least about themselves. And a coverage
  difference with no exclusion behind it is not a changed exclusion set at all.

  **`CanCompare` is an allow-list, and its remarks say why that is both correct and a maintenance
  hazard:** a newly added status is refused until someone considers it, which is the right default,
  but it means the list must be revisited every time the enum grows.

  **`DegradedWarning` distinguishes three cases that must not be stated as one another** — a conceded
  exclusion, a falsified `AttestedEmpty` claim, and a declaration set that could not be read. Its
  remarks name the failure it is avoiding: asserting a knowing exclusion at a user whose bundle was
  merely unreadable is a false statement about their forest.

  **The null-`CoverageId` hole.** `Validate` guards the mismatch test with
  `coverageIdA is not null && coverageIdB is not null` (`:73`). Two runs that both failed to record
  what they declared therefore *skip the test entirely* and fall through to Rules 4 and 5. F2's rule —
  null is not a match — is not enforced on this path. It is enforced on G3's path and on F17's UI
  path. The mitigation is indirect and partial: `IsBaselineEligible` is false when
  `AreExclusionsKnown` is false, so most unreadable bundles are caught one rule earlier as
  `DegradedCoverage`. But `RunCoverageSnapshot:93` records a case where `CoverageId` is null and
  `AreExclusionsKnown` is *true* — a re-analysis of a saved capture declares nothing at all — so two
  re-analysed bundles reach `Compatible` with no coverage statement having been proven about either.

### G3 — Graph-delta admissibility
- **Layer:** Core
- **Owns:** whether a delta computed over the whole captured graph, rather than per object, may be
  stated.
- **Depends on:** G1, F9
- **Implemented by:** `CanCompareGraphFindings` and `GraphFindingsRefusalReason` in
  `Core/Compare/CompareCompatibilityValidator.cs` (`:191–260`)
- **Non-obvious:** kept separate from G2 because it is a *different and much stricter* rule with a
  different justification, and because it is the only place in the branch where F2's null rule is
  honoured. Its remarks carry the argument: a control edge or escalation path is computed over the
  whole graph, so it cannot be filtered to an intersection the way an object or ACE delta can — an
  edge that appears to have vanished may simply run through a domain the other run never captured. It
  therefore demands proven identical `CoverageId` **and** `IsComplete` on both sides, and treats null
  as a failure explicitly, "because treating null as matching null would silently readmit the case
  this exists to refuse."

  **It refuses on behalf of a delta family that does not exist.** Every refusal sentence names
  "Control edge and escalation path deltas". `CompareResult` has no escalation path collection,
  `git ls-files` shows no `EscalationPathDelta`, and neither engine computes one. The gate is correct
  about escalation paths and the product never built them, so the user is told something was withheld
  that was never going to be offered.

### G4 — Delta vocabulary
- **Layer:** Core
- **Owns:** the shape of a single difference, per artefact family.
- **Depends on:** E15 (`Severity` strings), C1 (the column names these mirror)
- **Implemented by:** `Core/Compare/DeltaType.cs` (19), `ObjectDelta.cs` (20), `AceDelta.cs` (16),
  `ControlEdgeDelta.cs` (19), `CoverageDelta.cs` (24), `FindingDelta.cs` (42, including
  `FindingDeltaType`)
- **Non-obvious:** **two delta-type enums, and they are not parallel.** `DeltaType` has
  `Added / Removed / Modified / Unchanged`; `FindingDeltaType` has
  `Introduced / Resolved / Persisting`. The second exists because a finding is a risk statement rather
  than a row, and "introduced" carries a meaning "added" does not — a defensible split, undocumented
  anywhere the reader will find it.

  **`DeltaType.Unchanged` is never produced.** `git grep` finds it only in its own declaration and in
  two `CompareResultsViewModel` predicates that filter it out. Neither engine emits it:
  `ComputeControlEdgeDeltasAsync` writes only `Added` and `Removed`. The "Show unchanged rows"
  checkbox is therefore functional for the findings grid (`Persisting` is genuinely produced) and a
  permanent no-op for the control edge grid.

  `CoverageDelta.IsRegression` and `IsImprovement` compare `StateInA`/`StateInB` against the string
  literal `"Complete"`, not against D's `CoverageState` enum — so a rename of that enum member changes
  behaviour silently in a file that does not reference it.

### G5 — Compare result aggregate
- **Layer:** Core
- **Owns:** the whole answer to "what is different, and what could not be answered".
- **Depends on:** G1, G2, G4
- **Implemented by:** `Core/Compare/CompareResult.cs` (133)
- **Non-obvious:** the `NotAssessedCells` remarks are the clearest statement of the branch's purpose
  anywhere in the tree, and they are a warning to consumers rather than a description: "A consumer
  that renders the deltas and ignores this collection reproduces exactly the defect the axis exists to
  remove — an uncaptured domain reads as a forest full of remediated findings." One consumer heeds it
  (G12) and one does not (G13).

  `HasChanges` is `ObjectDeltas.Count > 0 || AceDeltas.Count > 0 || FindingDeltas.Count > 0 ||
  ControlEdgeDeltas.Count > 0`. **It cannot distinguish "nothing changed" from "the compare was
  refused",** because a refused compare returns a `CompareResult` with all four collections empty.
  G13 asks exactly this question and gets the wrong answer.

  `IsSecurityCompare` matches `RunA.AssessmentMode` against the string literal `"Security"`, with
  remarks noting the string is bundle metadata and unrelated to the surviving `AssessmentMode` enum.
  The counts are memoised with nullable-int backing fields for objects, findings and edges — but
  `AcesAdded`, `AcesRemoved`, `CoverageRegressions` and `CoverageImprovements` re-enumerate on every
  access. The inconsistency is invisible and probably harmless; it is noted because it makes the file
  read as though someone stopped halfway.

### G6 — Risk verdict
- **Layer:** Core
- **Owns:** the one-sentence answer to "did we get worse?", ahead of any detail.
- **Depends on:** G4, G5, E15 (`Severity`)
- **Implemented by:** `Core/Compare/ChangeReport.cs` (58, including `ChangeVerdict`),
  `Core/Compare/ChangeReportBuilder.cs` (92). Tested by `ChangeReportBuilderTests.cs` (108).
- **Non-obvious:** the verdict rule is deliberately unbalanced and says so: *any* introduced finding
  means `Worsened`, however many were resolved alongside it, because "fixing nine issues does not
  offset opening a new path to Tier 0, and a headline nobody can predict is a headline nobody trusts."
  That is the right call and the reasoning is recorded where the rule lives.

  `SeverityRank` parses the severity string tolerantly and ranks anything unrecognised at `-1`, so an
  odd stored value sorts last rather than throwing. `MaxListed = 50` caps each section with
  `IntroducedTruncated` / `ResolvedTruncated` flags so the cap is visible rather than silent.

  **The report reads only `FindingDeltas`.** It does not look at `Compatibility`, `NotAssessedCells`
  or `GraphFindingsWithheldReason`. A compare in which every graph delta was withheld and half the
  forest was not assessed can still headline "No material change — no findings introduced or
  resolved". The qualification exists, is computed correctly, and is carried past the one sentence the
  user is most likely to read.

### G7 — Structural delta engine
- **Layer:** Infrastructure
- **Owns:** loading two bundles and computing the object, ACE and coverage differences between them.
- **Depends on:** G1, G2, G4, G5, G8, C4 (`DatabaseConnectionFactory`), F9 (`RunCoverageReader`)
- **Implemented by:** `Infrastructure/Compare/StructuralCompareEngine.cs` (388). Tested by
  `StructuralCompareEngineTests.cs` (203), `CompareRunTimestampTests.cs` (108),
  `MetadataKeyContractTests.cs` (126).
- **Non-obvious:** **this is not config-mode residue and must not be read as such.** Its class summary
  states the ruling directly — "the base layer of security compare, not a standalone capability" — and
  `docs/review/00a-product-identity.md:57–61` records it as kept deliberately. The rename from
  `ConfigurationCompareEngine` on 2026-08-07 was the fix; the file is load-bearing.

  It is the only compare component that opens a database, and it opens each one **four separate
  times**: once in `LoadRunInfoAsync`, once in `LoadObjectsAsync`, once in `LoadAcesAsync`, once in
  `LoadCoverageAsync`. Each load is a full table read into a dictionary with no paging, so a compare of
  two large forests materialises both `dim_object` and both `fact_ace` tables in memory
  simultaneously. C's paging engine (C16) exists and is not used here.

  The timestamp fallback chain at `:135–137` carries its own archaeology: `CreatedUtc` is probed first
  and has no producer in `src/` today — it was written by the removed scoped-capture path — and
  looking only at it once left `CapturedUtc` permanently null. The `AssessmentMode` default is
  `"Security"` with the reasoning recorded: defaulting to the removed mode would label an unreadable
  bundle with a capability the product no longer has.

  `ReadRunStartedUtcAsync` catches `SqliteException` and returns null "because the run table is not
  present in every capture shape" — a claim that decision 0001 and the standing no-old-bundles
  guidance both contradict.

### G8 — Coverage intersection filter
- **Layer:** Infrastructure
- **Owns:** which `(module, domain)` cells a delta is allowed to be computed over.
- **Depends on:** F9, D (`CoverageCell`, `CoverageModules`)
- **Implemented by:** `ComparableCells` in `Infrastructure/Compare/StructuralCompareEngine.cs`
  (`:80–107`), and a second inline copy in `Infrastructure/Compare/SecurityCompareEngine.cs`
  (`:74–87`)
- **Non-obvious:** mapped as its own component because it is the single policy that makes every delta
  in the branch honest, and because **it is implemented twice.** `SecurityCompareEngine` builds its
  own `shared` set and its own `filter` boolean rather than accepting a `ComparableCells`, with a
  comment saying "As in `StructuralCompareEngine`" — an acknowledged copy. The two agree today.
  Nothing enforces that they continue to.

  Two decisions inside it are subtle and correct. **The grain is `(module, domain)`, not domain**,
  because a run can complete `Objects` for a domain and fail `SecurityDescriptors` for the same
  domain; filtering by domain alone would let every ACE of that domain read as removed. **The filter is
  disabled when either side's coverage is unknown**, because intersecting against an unrecorded set
  would discard every delta and report a confident "nothing changed" while `NotAssessedCells`, being
  the symmetric difference of two empty sets, simultaneously claimed nothing went unassessed.

  The two copies diverge in one respect that matters. The structural copy excludes a row with no
  domain — "the conservative direction". The security copy **includes** a finding with no resolvable
  target domain, on the stated ground that forest-wide rules genuinely have no single domain and
  dropping them would hide real findings. Both arguments are right for their subject; the shared name
  hides that they are different rules.

### G9 — Security delta engine
- **Layer:** Infrastructure
- **Owns:** the finding and control-edge differences layered on top of the structural ones.
- **Depends on:** G3, G7, G8, E7 (`fact_finding`), D (`fact_control_edge`), C4
- **Implemented by:** `Infrastructure/Compare/SecurityCompareEngine.cs` (260). Tested by
  `SecurityCompareEngineTests.cs` (271).
- **Non-obvious:** the delegation claimed in `.github/copilot-instructions.md` is real and total — it
  constructs a `StructuralCompareEngine` as a field, calls it first, re-checks `CanCompare` on the
  returned status, and copies `RunA`, `RunB`, `Compatibility`, `CompatibilityWarning`, `ObjectDeltas`,
  `AceDeltas`, `CoverageDeltas` and `NotAssessedCells` straight through. What it adds is exactly two
  delta families and one refusal reason.

  Both loaders wrap their query in `catch (SqliteException) { }` with the comment "may not exist if
  this is a Config Mode DB opened for comparison". Config mode capture was removed on 2026-08-02, and
  G7's own `AssessmentMode` default was changed for exactly that reason. **A missing `fact_finding`
  table therefore produces an empty dictionary, which produces zero finding deltas, which
  `HasChanges` reports as "no changes".** The one shape this silence was written for cannot occur, and
  the shape it now covers — a genuinely broken bundle — is one the user should be told about.

  `LoadControlEdgesAsync` filters `WHERE e.deny_cancelled = 0` and uses `TryAdd` on a three-part key,
  so a duplicate edge keeps the first row read, which is not deterministic without an `ORDER BY`. The
  ordering is applied to the deltas, not the load.

  The finding query is a fifth copy of the `fact_finding` join shape, and its comment says it "mirrors
  `v_export_findings`" — a view C2 owns and this code does not use. It joins `dim_principal` twice and
  `dim_object` once to recover a display name and a DN, duplicating what the view already computes.

  **It does not filter by `run_id`.** It reads every `fact_finding` row in each file, which is correct
  given one run per bundle, and which is precisely the assumption G14 does not make.

### G10 — Compare invocation
- **Layer:** UI
- **Owns:** turning a chosen pair into a running comparison.
- **Depends on:** G9, F17
- **Implemented by:** `UI/ViewModels/MainViewModel.cs:862–867` (`CompareRunsAsync`),
  `UI/Shell/ToolWindowLauncher.cs:132–147` (`LaunchCompareAsync`), `UI/RunLibraryWindow.xaml.cs:36`
  (`OnCompareRequested`). Tested by `CompareRequestTests.cs` (107), `CompareDirectionTests.cs` (63),
  `CompareToPreviousTests.cs` (142).
- **Non-obvious:** **every compare entry point does route through G2** — which is the opposite of what
  F17 found for sealing, and worth recording as a negative result. Both `LaunchCompareAsync` and
  `LoadDriftAsync` call `CompareRunsAsync`, which is the only construction site of
  `SecurityCompareEngine`, which always calls `StructuralCompareEngine`, which always calls
  `Validate`. There is no second compatibility rule and no bypass. The branch has one gate where F has
  five.

  What is *not* uniform is the layer above it. **Of the four ways to start a compare, one enforces
  `CoverageIneligibilityReason`.** `CanCompareWith` (`RunLibraryViewModel:466`) does;
  `CanCompareToBaseline` (`:371`) does not; `CanCompareToPrevious` (`:432`) does not; drift (G13) does
  not. So F17's carefully worded null-is-not-a-match refusal — the one place F2's rule reaches the
  user — guards a single command out of four.

  And the UI rule and the Core rule **disagree in both directions**. `CoverageIneligibilityReason`
  refuses *any* `CoverageId` mismatch outright, including the changed-exclusion-set case that G2's
  Rule 3 deliberately permits and documents at length. So the relaxation G2 was rewritten to allow is
  unreachable from the one command that checks, and reachable only from the three that do not check
  anything.

  `LaunchCompareAsync` is `async void` and swallows every exception into
  `vm.StatusText = $"Compare failed: {ex.Message}"`. The window is `Show()`n, not owned, so it
  outlives the library dialog by design.

### G11 — Compare results presentation
- **Layer:** UI
- **Owns:** rendering five delta families and one verdict without making the reader correlate across
  tabs.
- **Depends on:** G4, G5, G6
- **Implemented by:** `UI/ViewModels/CompareResultsViewModel.cs` (245), `UI/CompareResultsWindow.xaml`
  (313), `UI/CompareResultsWindow.xaml.cs` (36). Tested by `CompareResultsViewModelTests.cs` (66).
- **Non-obvious:** the drift-first default is the good decision here — `FindingDeltasView` and
  `ControlEdgeDeltasView` filter out unchanged rows unless `ShowUnchanged` is set, "so the grids show
  what actually changed rather than dumping every persisting finding". `HasVisibleFindingDeltas`
  recomputes rather than asking the `ICollectionView` for a count, which is why
  `OnShowUnchangedChanged` has to raise change notification for it by hand.

  `IsChronologicallyReversed` compares the two `CapturedUtc` values and drives a plain-language
  warning that "newly added items appear as removed". This is a genuine safety net rather than a
  duplicate of F17's ordering — `RequestCompare` normalises the pair, but `LaunchCompareAsync` accepts
  any two paths, so the invariant is not structural.

  `HasFindingDeltas` and `HasControlEdgeDeltas` drive tab visibility from collection counts. Combined
  with G3, **a withheld graph comparison hides the Control Edge tab entirely** — the refusal notice
  appears above the tabs, but the tab that would have carried the detail is gone, so the two states are
  distinguished by a banner and not by the surface the user is looking for.

### G12 — Refusal and qualification surface
- **Layer:** UI
- **Owns:** stating, before any delta is read, what this comparison is not entitled to claim.
- **Depends on:** G2, G3, G5, G11
- **Implemented by:** `NotAssessedSummary`, `HasNotAssessed`, `NotAssessedCount`,
  `GraphFindingsWithheld`, `GraphFindingsWithheldReason`, `WarningText`, `HasWarning`,
  `ReversedWarningText` in `UI/ViewModels/CompareResultsViewModel.cs` (`:170–245`);
  `UI/CompareResultsWindow.xaml:30–56`. Guarded by `CompareCoverageBindingGuardTests.cs` (112).
- **Non-obvious:** mapped separately from G11 because it is the branch's actual product, and because
  it is the only place in the map where a *binding* is defended by a test.
  `CompareCoverageBindingGuardTests`' remarks record why it exists: "Step 6 computed and tested the
  third bucket and then left it off screen, so a compare with an uncaptured domain still displayed a
  clean delta. The engine was correct and the user was still misled." It names four bindings
  explicitly rather than scanning every `{Binding}` in the file, with the reasoning that a blanket
  scan would report `DataGrid` row-item bindings as unresolvable and get weakened into something that
  verifies nothing.

  That is a compiler-invisible failure caught by a targeted test, and it is the strongest engineering
  artefact in the branch.

  `NotAssessedSummary` names the affected domains and de-duplicates them, degrading gracefully from
  one domain to a count-plus-list. All four notices render as static `TextBlock`s with no dismiss
  affordance, which honours `CompareCompatibility.DegradedCoverage`'s requirement that "the marker
  cannot be dismissed" — though nothing in the type system enforces that, and the requirement lives in
  the enum's remarks four projects away.

### G13 — Automatic drift
- **Layer:** UI
- **Owns:** answering "what changed since last time" without the user asking.
- **Depends on:** G5, G9, G10, F12 (`RunLibraryService`), F17
- **Implemented by:** `UI/ViewModels/MainViewModel.Drift.cs` (144), `UI/Views/HomeView.xaml:320–357`,
  `UI/Views/HomeView.xaml.cs:125–135`. `DescribeDrift` is untested;
  `tests/SecureAD.Core.Tests/Compare/DriftSummaryTests.cs` (62) asserts on `CompareResult` counts and
  never calls it.
- **Non-obvious:** the intent is right and stated well — "a drift tool should not require the user to
  go and ask what changed". The cancellation handling is careful: a `CancellationTokenSource` per
  load, cancelled and replaced on the next, with `OperationCanceledException` swallowed as "superseded
  by a newer load" and everything else logged as a warning rather than surfaced, since this runs
  unprompted.

  **It is the one consumer that ignores G5's explicit warning, and it does so in the worst available
  way.** `DescribeDrift` reads `result.HasChanges` and five counts. It reads no `Compatibility`, no
  `NotAssessedCells`, no `GraphFindingsWithheldReason`. A comparison refused as `IncompatibleCoverage`
  returns a result with every delta collection empty, `HasChanges` false — and the home screen prints
  **"No changes since the previous audit."** for a comparison the system declined to perform. The
  `HasDrift` flag is set to `true` on that path, so the card renders as a successful result.

  The same applies one level down: a compare that succeeded but withheld every graph delta, or left
  half the forest unassessed, produces a count string with no qualification attached. The full window
  one click away shows all four notices correctly. The summary that most users will read instead shows
  none.

  `FindPreviousRunAsync` constructs a fresh `RunLibraryService` and enumerates the entire library on
  every database load, then filters `State == RunLifecycleState.Sealed` — the fifth such predicate
  counting F17's four, and the one furthest from the others. It applies no `CoverageId` check at all,
  so drift is the only entry point that can reach G2's `DegradedCoverage` and `CoverageMismatch`
  relaxations, and the only one that renders neither.

### G14 — Same-database findings diff
- **Layer:** Infrastructure (service) / Core (contract, result)
- **Owns:** which findings are new, resolved, severity-changed or unchanged between two `run_id`s in
  one database.
- **Depends on:** E7, E15, C4
- **Implemented by:** `Infrastructure/Findings/RunDiffService.cs` (162),
  `Core/Findings/RunDiffResult.cs` (79), `Core/Services/IRunDiffService.cs` (18). Tested by
  `RunDiffServiceTests.cs`.
- **Non-obvious:** **the ruling: it is G's by subject, and genuinely dead.** E14's finding is
  re-verified — `git grep` across `src/` and `tests/` for `IRunDiffService`, `RunDiffService` and
  `RunDiffResult` returns the interface, the implementation, the result record, its own test file, and
  the map documents. No registration, no injection, no call site.

  It is dead for a structural reason E14 could not see without G: **it compares two `run_id`s inside
  one `SqliteConnection`, while every live compare compares two `audit.db` files.** One bundle holds
  one run, so the query it is built around — `fact_finding b INNER JOIN fact_finding c ON
  b.finding_key = c.finding_key AND c.run_id = $currentId` — returns nothing on any bundle the product
  produces. It is not merely unwired; it is written against a storage model this application does not
  have. Nothing would have made it reachable.

  **It is behaviourally different from the four other `fact_finding` readers, and the difference is
  not cosmetic.** It is the only one that selects `coverage_complete` and `coverage_reason` — the
  per-finding coverage qualification E4 stamps — so the dead implementation carries a qualification
  the live compare path (G9) drops entirely. It is also the only one that `Enum.Parse`s `severity`
  unguarded, where G6 ranks it tolerantly, and the only one that calls `reader.GetString` on
  `subject_sid`, `target_id` and `detail` without a null check, where G9 treats all three as nullable.
  As written it would throw on a finding the live path handles.

  **And it has one capability the live engines lack.** `RunDiffResult.SeverityChanges` reports
  findings present in both runs whose severity moved. `FindingDeltaType` has no equivalent — a finding
  that was Medium and is now Critical is `Persisting` in every live compare, invisible in the grids,
  invisible in the verdict, and counted in "N findings persist from the baseline run." That is a real
  gap, and the dead code is where the answer to it was written down.

## Naming & taxonomy

| Current | Proposed | Why it matters |
|---|---|---|
| `CompareCompatibilityValidator` | `CompareAdmissibility` — and split `Validate` from `CanCompareGraphFindings` into `ForRowDeltas` / `ForGraphDeltas` | One static class holds two gates with materially different strictness: one tolerates a null `CoverageId`, the other refuses it by name. The shared type name is why a reader checking "does compare enforce coverage identity" gets a yes and a no from the same file, and why the null hole in `Validate` survived alongside a remark two hundred lines below explaining exactly why null must not pass. |
| `CompareCompatibility.CoverageMismatch` vs `IncompatibleCoverage` vs `DegradedCoverage` | `PartialOverlap` / `DifferentDeclaredEvidence` / `KnownIncompleteEvidence` | Three coverage statuses whose names differ by adjective while their meanings differ by *kind* — a nameable shortfall, two runs that never looked at the same thing, and a missing positive that is invisible in any delta. `IncompatibleCoverage`'s own remarks have to open by disclaiming `CoverageMismatch`, and `DegradedCoverage`'s by disclaiming both. Documentation that exists to undo a name is the name's bill. |
| `StructuralCompareEngine` | `EvidenceCompareEngine` | The 2026-08-07 rename fixed the worse problem and left a residual one. "Structural" reads as *shape of the directory*, but the engine's subject is the captured evidence — objects, ACEs and the coverage of both. `SecurityCompareEngine` sits beside it named for a *product mode*, so the pair suggests two peers rather than a base layer and its extension. `EvidenceCompareEngine` + `SecurityCompareEngine` reads as layers. |
| `DeltaType.Unchanged` | delete | No producer. Its only effect is two UI predicates that filter for a value that never arrives, which makes the "Show unchanged rows" checkbox look functional for control edges when it is inert. |
| `DeltaType` vs `FindingDeltaType` | `RowChange` vs `RiskChange` | Two enums one letter apart in usage and entirely different in meaning. The distinction — a row appeared versus a risk was introduced — is real and worth keeping; the names conceal it and invite someone to unify them. |
| `ChangeReport` / `ChangeReportBuilder` | `RiskVerdict` / `RiskVerdictBuilder` | "Change report" promises a report of changes, which is what the delta tabs are. This type reports only the *risk direction* from findings and ignores objects, ACEs, edges and coverage. The name is why it is easy to miss that it also ignores every compatibility qualification. |
| `MainViewModel.Drift.DescribeDrift` | `DescribeUnqualifiedDeltaCounts` — or fix it | A name this general is what let a method that reads five integers and no qualification stand in for "what changed since the previous audit". |
| `DriftSummaryTests` | `CompareResultCountTests` | It never touches the drift summary. It constructs `CompareResult`s and asserts on `HasChanges` and the three finding counts. The name is why the drift string reads as covered when it has no test at all. |
| `RunDiffService` / `IRunDiffService` / `RunDiffResult` | `SameDatabaseFindingsDiff`, or delete with G14's `SeverityChanges` capability salvaged | E's proposed `FindingsDelta` is an improvement but understates the problem: the name gives no signal that this diffs two runs *within one file*, which is the reason it can never fire. |
| `CompareResult` (Core) vs `CompareResult` (private record in `StoredAclCompareViewModel.cs:133`) | rename the second to `StoredAclComparison` | Same name, same solution, unrelated concepts, and `StoredAclCompareViewModel` is in the very namespace most likely to be read alongside the compare branch. |
| `CompareRunInfo.ScopeDescription` | delete | Populated, contract-tested, and read by no decision. The rule it existed for was removed as unfireable; the field outlived it and now has a test guarding it. |
| `CompareResultsViewModel.WarningText` / `HasWarning` | `CompatibilityQualification` / `IsQualified` | It carries `IncompatibleCoverage` refusals and `DegradedCoverage` markers as well as version warnings. "Warning" is the mildest of the three things it renders. |

## Would-do-differently

**A refused comparison and an identical pair of runs must not be the same object.** This is the
branch's central defect and every other one is downstream of it. `StructuralCompareEngine` returns a
`CompareResult` with empty delta collections when compatibility fails, and the type offers
`HasChanges` as the natural question to ask of it. G13 asks that question and prints "No changes since
the previous audit" for a comparison the system declined to perform. In a rebuild, compatibility
resolves to a discriminated result before any engine runs — `Comparison.Refused(reason)` or
`Comparison.Completed(deltas, qualifications)` — so a consumer cannot reach a count without having
handled the refusal. The current shape makes the safe path the one requiring extra vigilance, and the
evidence that this fails is that the one consumer written in a hurry got it wrong and the one written
carefully got it right.

**Qualifications should travel with the verdict, not beside it.** `ChangeReport` is the sentence most
users will read, and it is built from `FindingDeltas` alone. `NotAssessedCells`,
`GraphFindingsWithheldReason` and `Compatibility` all sit on the same `CompareResult` the builder is
handed, and none is consulted. "No material change — no findings introduced or resolved" is a false
statement when half the cells were not assessed and every graph delta was withheld, and it is false in
the one place a false statement costs most. The rebuild makes the headline a function of the *whole*
result: a verdict that cannot be constructed without a qualification field, even when that field is
`None`. This costs one required property and removes an entire class of confidently-wrong headline.

**One compare rule, expressed once, consumed everywhere.** G2 is 288 lines of unusually good
reasoning, and the UI layer above it independently reimplements a stricter rule in
`CoverageIneligibilityReason`, applies it to one command out of three, and skips it for drift. The two
disagree in both directions: the UI refuses a defensible changed-exclusion-set compare that Core
deliberately permits, and Core permits a null-`CoverageId` pair that the UI refuses by name. So the
relaxation Core was rewritten to allow is reachable only from the paths that check nothing. This is
F17's five-gates shape recurring one branch later, and the fix is the same one F proposed: a single
`CompareAdmissibility.For(runA, runB)` returning a reason-carrying result, called by the enabling
predicate *and* by the engine, with no second opinion available.

**`ComparableCells` should be a value the engines are given, not a thing each engine builds.** It is
the policy that makes every delta in the branch honest, and there are two implementations of it
fourteen lines apart in intent. They already diverge on whether a row with no domain is comparable —
correctly, for their respective subjects — and the shared name hides that the divergence is
deliberate. In a rebuild the intersection is computed once at admissibility time, carried on the
result, and takes an explicit `MissingDomainPolicy` so the two answers are visibly two answers rather
than a copy that drifted.

**Do not gate a delta family that does not exist.** `GraphFindingsRefusalReason` tells the user that
"control edge and escalation path deltas were withheld", and no escalation path delta has ever been
computed. Either the family is built or the sentence stops naming it. The wider rule is that a refusal
message is a promise about a capability, and an unbuilt capability is the one thing a refusal must
never imply exists.

**The engines should read through C, not around it.** `StructuralCompareEngine` opens each bundle four
times and loads `dim_object` and `fact_ace` entirely into dictionaries, so a two-forest compare
materialises four full tables at once. C16's paging engine and C2's views both exist;
`SecurityCompareEngine`'s finding query even carries a comment saying it "mirrors `v_export_findings`"
while reimplementing the joins by hand. The rebuild has the compare engines consume the same read
surface everything else does, which removes the fifth copy of the `fact_finding` join, removes the
memory ceiling, and means a change to how a target DN is resolved reaches compare for free.

**Delete the `catch (SqliteException) { }` blocks, and the config-mode shapes they were written for.**
Three of them — two in `SecurityCompareEngine`, one in `StructuralCompareEngine.ReadRunStartedUtcAsync`
— silently substitute an empty result for a missing table, on the stated ground that a Config Mode
database or an alternative "capture shape" might be opened. Config mode capture was removed on
2026-08-02, decision 0001 says nothing predates the current build, and the standing guidance is that
no older bundles will exist. What survives is a `fact_finding` table that is missing for a *real*
reason producing zero finding deltas and a cheerful "no changes".

**Salvage severity change before deleting `RunDiffService`.** A finding that moved from Medium to
Critical is `Persisting` in every live compare — absent from the grids by default, absent from the
verdict, and counted in "N findings persist from the baseline run." The dead code is the only place in
the tree where somebody wrote that down as a distinct outcome, and it is the answer to a question a
drift tool exists to answer. `FindingDeltaType` gains `SeverityChanged`; the 162-line service goes.

**This was right, keep it: `CompareCompatibilityValidator`'s habit of recording the rule it replaced,
and why the old one was wrong.** Rule 3 does not merely state the coverage matrix; it names the
`ScopeDescription` comparison it replaced, explains that the rule could never fire because both sides
were always null, and notes that its warning "Diff limited to intersection" was a promise never kept.
Rule 4 records that it replaced a `fact_coverage` row-count comparison which could say two runs
differed but never which cells, and so could not tell "B added a domain" from "B lost one".
`CompareRunInfo` carries the same archaeology for `CoverageModuleCount`. This is the only place in the
codebase where the *failed* version of a rule is preserved next to the working one, and it is why this
branch's hardest decisions can be audited rather than guessed at. It should be the house style, not a
local one.

**Also right, keep it: `CompareCoverageBindingGuardTests`.** A correct engine, a correct view model,
and an unbound `TextBlock` produce a confidently clean delta over a half-captured forest, and no Core
or Infrastructure test can see it because WPF bindings are compiler-invisible. The guard names four
bindings deliberately rather than scanning the file, with the reasoning for that narrowness written
into the test. It is the right answer to a real gap and the pattern generalises to every refusal
surface in the app.

## Corrections to existing documents

*Corrections are recorded here and deliberately not applied to the documents named.*

| Document | Claim | Correction |
|---|---|---|
| `docs/map/E-findings.md`, E14 | `RunDiffService` "is a complete, tested G-branch (Compare) component with no G to attach to." | Correct that it is G's by subject and unreachable, but the reason is stronger than "no G reached it". It diffs two `run_id`s inside **one** `SqliteConnection`, while both live engines diff two `audit.db` **files**. One bundle holds one run, so its central `INNER JOIN ... AND c.run_id = $currentId` returns nothing on any bundle the product produces. No wiring would have made it work. |
| `docs/map/E-findings.md`, E14 | It "carries a fourth copy of the `fact_finding` row-reading SQL, independent of E6's `ReadFinding`." | Verified, and it is now a fifth: `SecurityCompareEngine.LoadFindingsAsync` (`:172`) is another. The copies also differ behaviourally. `RunDiffService` is the **only** one that reads `coverage_complete` and `coverage_reason`, so the dead code carries E4's per-finding coverage qualification that the live compare path drops. It is also the only one that `Enum.Parse`s severity unguarded and the only one that calls `GetString` on `subject_sid`/`target_id`/`detail` without null checks — it would throw on rows G9 handles. |
| `docs/map/F-run-model.md`, F17 | `RunLibraryViewModel.cs:492` phrases the `CoverageId`-mismatch refusal, "which is F2's null-is-not-a-match rule reaching the user in words." | Correct, and incomplete in two ways. It is reached from **one** of the three library compare commands: `CanCompareWith` calls `CoverageIneligibilityReason`; `CanCompareToBaseline` (`:371`) and `CanCompareToPrevious` (`:432`) check only `State == Sealed` and `DbPath is not null`. Drift (G13) checks neither. And the UI rule is *stricter* than Core's — it refuses any `CoverageId` mismatch, including the changed-exclusion-set case `CompareCompatibilityValidator` Rule 3 was rewritten to permit — so Core's relaxation is unreachable from the only command that checks. |
| `docs/map/F-run-model.md`, F17 | Four `State == Sealed` predicates in three files, "none of which consults `OutputEligibilityEvaluator`." | Verified. Adding `MainViewModel.Drift.FindPreviousRunAsync:112` — which F17 lists among its implementing files but does not count in the four — the drift path is a fifth independent sealing predicate, and the only one that additionally enumerates the whole run library on every database load. |
| `docs/map/F-run-model.md`, "Would-do-differently", one-gate item | "`Kind.Compare` is a fully-implemented, fully-tested gate with no caller, because compare's authors wrote their own check instead." | The premise is right and the diagnosis is partly wrong in G's favour. Compare's authors wrote a genuinely single Core gate: all four entry points reach `CompareCompatibilityValidator.Validate` through the one construction site of `SecurityCompareEngine`. What they added on top is not a competing *eligibility* rule but a competing *coverage* rule in the view model, which is a different failure. Worth recording, because G is the one branch that got the single-gate shape right at the Core layer. |
| `src/SecureAD.Core/Compare/CompareCompatibilityValidator.cs:207–260` and `SecurityCompareEngine.cs:37–47` | Refusal text and comments state that "control edge **and escalation path** deltas were withheld". | No escalation path delta exists. `git ls-files` shows no such type, `CompareResult` has no such collection, and neither engine computes one. The refusal names a capability the product never built. |
| `src/SecureAD.Infrastructure/Compare/SecurityCompareEngine.cs:201, :243` | `catch (SqliteException) { }` — "`fact_finding` may not exist if this is a Config Mode DB opened for comparison". | Config-mode capture was removed 2026-08-02, and `StructuralCompareEngine:142–145` was changed for exactly that reason ("Security is the only mode a run can be captured in"). The comment describes an impossible shape while the handler silently converts a genuinely broken bundle into "no changes". |
| `tests/SecureAD.Core.Tests/Compare/DriftSummaryTests.cs` | Named and summarised as testing the drift summary — "the summary must lead with risk … and must read correctly when nothing changed." | It never calls `DescribeDrift`, which lives in `SecureAD.UI` and is unreachable from `SecureAD.Core.Tests`. All three tests assert on `CompareResult.HasChanges` and the finding counts. The drift summary string has no test. |

## Coverage gaps in this pass

- **`CompareCompatibilityValidatorTests.cs` (542) was not read.** Its existence and size are recorded;
  individual assertions were sampled only via `git grep` for `ScopeDescription` and `CoverageId`. The
  null-`CoverageId` hole in `Validate` is derived from the source (`:73`), not from an absent test — a
  future pass should check whether a test asserts the current behaviour, which would make it
  intentional rather than an oversight.
- **`SecurityCompareEngineTests.cs` (271) and `StructuralCompareEngineTests.cs` (203) were not read.**
  Both engines were characterised entirely from source. Whether the `catch (SqliteException)` paths or
  `DeltaType.Unchanged` are asserted anywhere is unverified.
- **`StructuralCompareEngine.cs` lines 271–388 were not read** — `LoadObjectsAsync`, `LoadAcesAsync`,
  `LoadCoverageAsync` and `CountRowsAsync`. The four-open claim and the full-table-load claim rest on
  the call sites at `:54–56` and `:263–264` plus the method signatures, not on their bodies. The
  `ORDER BY`-less `TryAdd` determinism concern is stated for `LoadControlEdgesAsync`, which was read;
  the equivalent question for the object and ACE loaders is open.
- **`CompareResultsWindow.xaml` (313) was read only by targeted `git grep`** for the eight
  qualification and report bindings. The tab structure and the `DataGrid` column definitions were not
  inspected, so the claim that a withheld graph comparison hides the Control Edge tab rests on
  `HasControlEdgeDeltas` and the grep, not on reading the `TabItem` visibility markup.
- **`RunCoverageReader.cs` was not read.** F9 owns it and F's own coverage-gaps section records that
  it was characterised rather than read there too. G's statement that a re-analysis run yields a null
  `CoverageId` with `AreExclusionsKnown` true is taken from `RunCoverageSnapshot.cs:90–95`'s remarks,
  not traced through the reader.
- **`RunLibraryViewModel.cs` was read at `:365–525` only.** `RunCard`, `ProfileGroup` and
  `RequestCompare` itself (`:198–204`) were confirmed by grep and by F17's account rather than read
  line by line.
- **`AclCompareViewModel` (513) and `StoredAclCompareViewModel` (264) were read only at their heads**,
  enough to establish that both operate on `LiveAclDelta` / `ILiveDiagnosticsService` and therefore
  belong to H. Their internals are unmapped by any branch.
- **`docs/review/00a-product-identity.md` and `docs/review/01-infrastructure-storage.md` were consulted
  by targeted `git grep` only**, for the `StructuralCompareEngine` ruling and the compare-related
  sequencing items. `F-01-10`, `F-01-24` and the surrounding findings — referenced by name in
  `CompareCoverageBindingGuardTests` — were not read.
- **No tests were run and no code was changed.** Per the brief this pass is advisory; every failure
  mode described is read from source and would need a test to demonstrate. The drift "No changes since
  the previous audit" path in particular is derived structurally — from `CanCompare` returning false,
  the early return at `StructuralCompareEngine:40`, `HasChanges` over four empty collections, and
  `DescribeDrift:124` — and has not been executed.
