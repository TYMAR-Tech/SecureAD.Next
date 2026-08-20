# Rebuild map

## What this is

A component-level map of SecureAD, written so the app could be rebuilt from it — and so that
"what would we do differently" is recorded while the reasoning is still fresh.

It is organised by **functional stage**, following the data from the moment the app opens through to
what the user sees. The layering (`Core` → `Infrastructure` → `UI`) is an overlay on that, noted per
component, rather than a second tree.

## What this is not

**This is not a to-do list.** Every rename and restructure recorded here is a recommendation *for a
rebuild*, not a change to make in the current codebase. Renaming a type touches many files for zero
behaviour change; that trade is worth it when writing fresh code and usually is not worth it
otherwise.

Where something genuinely should change in the current codebase, that belongs in `docs/review/`,
which is where executable decisions live. This folder is deliberately advisory.

## Structure of each branch file

| Section | Purpose |
|---|---|
| **The flow** | What happens, in order, at runtime |
| **Components** | The map: a named responsibility, its layer, what it owns, and which files implement it |
| **Naming & taxonomy** | Names that mislead, with the proposed rename and the reason |
| **Would-do-differently** | Structural and design retrospective |

Naming and structure are kept apart on purpose. They are two backlogs at very different price
points: a rename is mechanical and low-risk, a restructure is neither. Merging them destroys that
signal, so a branch file must keep them as separate sections.

**Components is the most important section**, and the one to spend the most effort on: it *is* the
map. The other three are commentary on it. A branch file without a Components section answers "what
went wrong last time" but not "what would I rebuild", which is the question this folder exists for.

Each component carries these fields:

| Field | Content |
|---|---|
| **ID** | Branch letter plus number — `A1`, `B2` — so other components and branches can reference it |
| **Owns** | One sentence. The responsibility, not the implementation |
| **Layer** | Core, Infrastructure, or UI |
| **Depends on** | Other component IDs |
| **Implemented by** | File paths, with line counts for anything substantial |
| **Non-obvious** | Anything whose reason to exist is not apparent from its name. Omit when there is nothing to say |

## Depth

The map stops at **component** — a named responsibility with a stated boundary, usually one to eight
types. It does not describe individual classes.

That is a deliberate altitude. Class-level detail is the layer most likely to be wrong in a rebuild:
`KeysetQueryBuilder` might not exist next time, but "paginated reads over the derived store without
loading everything" certainly will. Component level captures the decision; class level captures only
this implementation of it.

Going deeper later is cheap because each component records its implementing files. Dropping to class
level becomes a fill-in rather than a re-derivation.

## Branches

| | Branch | Status |
|---|---|---|
| A | [Connect & Discover](A-connect-and-discover.md) | Written |
| B | [Capture](B-capture.md) | Written |
| C | [Storage — write path](C-storage.md) · [Storage — read path](C-storage-read.md) | Written (both halves) — see note below |
| D | [Derive & Analyse](D-derive-and-analyse.md) | Written |
| E | [Findings — the run](E-findings.md) · [Findings — the rules](E-rules.md) | Written (both halves) — see note below |
| F | [Run model & lifecycle](F-run-model.md) | Written |
| G | [Compare](G-compare.md) | Written |
| H | [Live verification](H-live-verification.md) | Written — see note below |
| I | [Output](I-output.md) | Written — see note below |
| J | [Presentation — shell & screens](J-presentation-shell.md) · [Presentation — grids & panels](J-presentation-grids.md) | Written (both halves) — see note below |
| K | [Cross-cutting](K-cross-cutting.md) | Written — see note below |

### Note on branch K

Cross-cutting is the only branch with **no folder and no namespace**. Its membership is a judgement
rather than a lookup, so [`K-cross-cutting.md`](K-cross-cutting.md) opens with the surface it
established — a folder-by-folder verdict over `src/SecureAD.Core/`'s 27 top-level entries plus
`Infrastructure/Configuration/`, `Infrastructure/Diagnostics/`, `DnHelper.cs` and the UI logging
quartet. Roughly 100 files and ~5,200 production lines in 27 components (K1–K27): the smallest
branch by line count and the largest by number of distinct subjects.

**K is a residue, not a branch, and the file says so rather than manufacturing coherence.** Its
components share exactly one property — more than one caller. The file's leading structural item
argues the residue is really *four* separable things: a directory-domain kernel (descriptors, ACEs,
DNs, GUIDs, rights), a run-observation layer (progress, cancellation, logging, performance), a
failure-reporting layer, and configuration, which is not cross-cutting at all but simply unowned.

**Its headline is that the product's entire structured error surface is unused.**
`src/SecureAD.Core/Errors/` is 20 files with 250 lines of tests, and `git grep "new AuditError"` over
`src/` returns nothing — every hit is in `tests/`. **Thirteen of the fourteen domain error-code enums
are referenced by exactly two files: their own declaration and `AuditErrorCodes`' formatter
overload.** The fourteenth, `DiscoveryErrorCode`, is genuinely produced and consumed — and bypasses
`AuditErrorCodes.Format` entirely, so the one working instance of the taxonomy does not use the
taxonomy's own contract. H21, I23 and J45 each found a symptom independently; K5 supplies the cause,
which is that no operation in the product returns an `AuditError`, so producing one was always
optional work with no compiler pressure behind it. That is why every failure a user sees is an
interpolated `ex.Message`, a swallowed exception, or a silent zero.

Three further closings. **J-b's `PermissionClassifier` question is answered and the count is worse
than asked:** there are **five** disagreeing answers to "is this right dangerous" — a bitmask
classifier that never uses its own `ControlAccess` constant, a per-GUID catalogue, J33's union of the
two, and *two* view-model implementations that string-match rendered display names, of which the live
one (H15) and the stored one (H16) disagree on `gpLink`, `userAccountControl`, `scriptPath` and both
unscoped cases. Two panels a user is meant to read as a pair apply different definitions, and H16 is
the narrower, so dropping live LDAP would silently shrink what the product calls dangerous.
**J-b's `UiPerfTrace` question is answered negatively:** nothing consumes it, though the design was
real — its warning threshold routes slow loads into `AppLog`'s dedicated warnings-only file, and the
product then offers no way to open the log folder. **Settings and `Configuration/` are
unconnected:** `AppSettings`, `StorageSettings`, `SettingsValidator` and `SettingsValidationResult`
have no consumer outside their own folder, and `SettingsViewModel` has no `Save` and references
neither them nor `UserPreferencesService`.

The dependency direction was checked rather than assumed and **holds**: `SecureAD.Core.csproj` has
one `PackageReference` and no `ProjectReference` at all. One subject-level leak, `DisplayFormatting`,
a Core type whose only four consumers are UI view models.

K also has the map's clearest "this was right, keep it": `SecurityDescriptorParser` /
`AceNormalizer` / `GenericRightsExpander` (K15), whose five consumers are exactly the five that
handle raw security descriptors and no others — the discipline every other shared component in K
failed, and the reason H's live-versus-stored comparison means anything at all.

Because K closed the map, it also ran a **whole-map coverage audit**: every `.cs` file under `src/`
(618) checked for whether its name appears anywhere in `docs/map/`. 574 named directly, 41 covered
collectively by an existing ruling or component, three genuine gaps — `MemoryMonitor.cs`, now K27;
`DiskSpaceCheckResult.cs`, recorded as a misfiling; and `LocalPrivilegedGroupCatalog.cs`, recorded as
an addition to `E-rules.md`'s three lookup catalogues, which are four. The method and its limits are
in K's coverage-gaps section.

### Note on branch J

Presentation is the third branch to split, and the largest surface the map has traced. The
`SecureAD.UI` project is 284 files and 47,779 lines; after subtracting everything G, H and I already
claimed, J's residue is 235 files and ~35,000 lines — roughly six times a single session, and three
times either branch that had already split.

[`J-presentation-shell.md`](J-presentation-shell.md) covers the **shell and the run-facing screens** —
bootstrap, the mode model, chrome, the tool-window launcher, `MainViewModel`, database bind, Home,
drift, Dashboard, capture progress, the audit wizard, the run library, Reports chrome, Help, Settings,
session restore, the offline tree, dialogs, theming, and the dead command surface (components J1–J20).
[`J-presentation-grids.md`](J-presentation-grids.md) covers the **evidence surfaces** —
`GridViewModelBase` and its 21 grids, the three grid multiplexers, the row types, the five grid pages,
the filter toolbar, the detail and preview panels, `AceAnalysisService`, acceptance authoring and
import, the policy wizard, and the single-live-read live panels (components J21–J46, 154 files,
~23,600 lines).

The seam between the two halves is `IScopedGrid` / `GridViewModelBase<TRow>`
(`ViewModels/GridViewModelBase.cs`, 514 lines). `IScopedGrid` is a two-method interface —
`EnsureBound()` and `ReloadIfScopeDirty()` — with four implementers: `GridViewModelBase<TRow>`, whose
21 subclasses are the grids, and three composite multiplexers (`ObjectsTabViewModel`,
`GroupsTabViewModel`, `AttackPathsTabViewModel`). The shell reaches every grid through exactly three things:
`GetGridForTabId` returning `IScopedGrid?` (`MainViewModel.Navigation.cs:93`), `EnsureBound()` (`:31`),
and `ScopeDn` propagation (`:121`). It also sits on C's already-settled boundary, since
`GridViewModelBase` is `KeysetQueryBuilder`'s only consumer. Component numbering is continuous across
both halves.

The shell half's central structural finding is that **there is no navigation model**. `ContentHost`
instantiates all nine pages simultaneously and toggles them with a visibility converter bound to
`ActiveMode`, so no page has a lifecycle, nothing is disposed on leaving a screen, and every page's
view model is alive from process start. Most of what is awkward in the branch follows from that.

Unlike E, F, G, H and I, **J has no dead subsystem**: all 71 `*ViewModel` types have a production
consumer. Its dead surface is finer-grained. A systematic sweep of all 138 `[RelayCommand]` methods
against all 64 XAML files found 95 bound, 43 unbound, and **28 with neither a XAML binding nor any C#
reference**. Nine of those are `DashboardViewModel`'s drill-downs, and `DashboardView.xaml` contains no
`Command=` binding of any kind — the dashboard was designed as a set of doorways into the evidence and
then wired entirely with `Click=` code-behind. That is I20's failure repeated in a second, more costly
place, and J20 records the one thing worth salvaging from it: the `DrillDownTarget` /
`NavigateWithDrillDown` contract, the only mechanism in the product that makes a summary number and the
rows behind it provably the same query.

The half also closes the provenance question. `SealedUtc` appears thirteen times in the UI project and
twelve are sort or comparison keys; the only rendered use is in a modal dialog about importing
acceptances. With H finding no live answer carries it and I finding no export does, that is three
branches agreeing, and it is recorded in J as a product-level conclusion rather than a branch finding.

The grid half revises two of those conclusions and sharpens a third. **J does have a dead subsystem**,
just a small one below the seam: `GroupMembershipViewModel` (110) is constructed on `MainViewModel` and
referenced by no XAML, and **six of the 21 grids are fully plumbed and unreachable** —
`TrustsGridViewModel`, `PasswordPolicyGridViewModel`, `BundleMatchGridViewModel`,
`SidHistoryGridViewModel`, `StaleDormantGridViewModel`, `HighValueTargetsGridViewModel`. Three are
registered in `GetGridForTabId` and have no view; the other three sit behind a `ViewMode` property no
XAML or code-behind ever sets. Trusts and password policies are directory-wide security facts the
product captures, derives and can never display. `LazyTabBehavior` (123) has no reference of any kind —
the seam's own deferred-binding purpose was solved twice, and the behaviour lost.

Its central finding is that **the product's one correct answer to "empty versus failed" is unbound**.
`GridViewModelBase.DataLoadState` is documented as ensuring "'failed to compute' is never confused with
'zero results'", and `TotalCountDisplay` renders three distinct states. No XAML anywhere binds
`TotalCountDisplay`, `IsCountFailed` or `CountLoadState`; all five grid pages bind the raw
`TotalResultCount` int, and `FilterBar.ResultCount` is typed `int` so they could not do otherwise. Only
`FindingsGridPage` has an empty state at all, and it asserts a cause — "The findings engine did not
produce results" — that is false whenever the failure was a query rather than a result. That is I20's
and J20's shape a third time, on the mechanism by which an audit tool says it does not know.

It also settles the findings-count question with a fourth data point. There are four answers to "how
many Critical findings": the grid (`v_grid_findings`, loaded run, suppressed excluded), the Dashboard
and Home tiles (`fact_finding`, latest run, suppression ignored entirely), the rule-family chip labels
inside the grid's own view model (suppression ignored), and a no-`dim_run` fallback that filters no run
at all. Home and the Dashboard turn out to share a source rather than disagree, which corrects J-a; the
grid is the genuine third answer, and the disagreement is directly clickable, since Home's severity
tile navigates to a grid that will show fewer rows. Accepted findings are filtered, never marked:
`FindingGridRow.IsSuppressed` is populated and bound in no grid column and no row style, and every
accept and revoke action in the product is a `Click=` handler.

### Note on branch I

[`I-output.md`](I-output.md) covers everything written *out* of a bundle to somewhere else: the CSV
export package, the three self-contained HTML narrative reports, the 46-entry SQL report
catalogue, and the UI that invokes them. 23 components (I1–I23), ~5,990 production lines, one
session.

It is the first branch the map has traced where the flagship subsystem turns out to be **fully
wired**. Every one of `ReportCatalog`'s 46 reports is reachable — 29 by default, the 17
`Diagnostics` entries behind advanced mode — and `ReportCatalogExecutionTests` executes every one
against a real `DerivedStore` so a report naming a column that does not exist fails in CI rather
than when a user clicks Run.

It is also the first branch that **distinguishes a report that could not be produced from one that
legitimately found nothing**, which G and H both failed. `VouchedCount` (I4) will not run a count
query at all unless every derived phase behind the number recorded success, because a view over an
unpopulated table returns an honest, false zero that no existence probe catches;
`CoverageWarningPresentation` (I3) carries two deliberately separate callouts, one for what the
capture reached and one for what the analysis did with it. That pattern is the branch's main
salvage into a rebuild.

Three dead or unreachable things, all traced. **Five `[RelayCommand]` export methods on
`MainViewModel` are bound in no XAML** (I20) — the shell reimplemented them as `Click=`
code-behind, which is why the coverage-confirmation prompt never fires for the three report
buttons and why single-tab CSV export cannot be reached at all. `ExportProgressEvent` /
`ExportState` (I22) have neither producer nor consumer, so the product's only long-running
operation has no progress reporting and the mechanism to give it one was built and left
unconnected. `ExportErrorCode` (I23) is produced by nothing; every export failure a user sees is
an interpolated `ex.Message`.

The branch's weakest point is provenance. `ExportManifest` (I9) records when the *export* ran, not
what it exported: no `run_id`, no `SealedUtc`, no structured coverage verdict, nothing about
suppressions. Neither `v_grid_findings` nor `v_export_findings_evidence` excludes suppressed
findings, and I10's headline severity counts do not filter them or say how many were included.
There are **three** independent CSV writers (I6, I15, I21) which disagree about RFC 4180 and about
formula-injection defence, so which safety properties an exported CSV has depends on which button
produced it.

### Note on branch H

Live access is **not** a top-level branch in the ideal structure. `docs/review/00a-product-identity.md`
decision 4 establishes that live verification has no meaning without stored evidence to verify
against, so it is a property of the audit workflow rather than a second way to use the tool.

[`H-live-verification.md`](H-live-verification.md) tested that decision against the code and found it
broadly upheld: `VerifyLiveAclAsync` really does open `audit.db` and compare against it, and it is the
only component in the branch that does. Three qualifications, all traced in the file. Its
`storedDbPath` is optional and defaults to `null`, so the audit case is a caller opt-in rather than
the method's contract. A `SqliteException` during the stored comparison is swallowed, so a comparison
that failed surfaces as "Live ACL matches snapshot." And the branch never reads `SealedUtc`, so no
live answer states the age of the evidence it was measured against.

**Sequencing item 4 has not been executed.** The Inspect view and `DirectoryTree` are still wired —
`ContentHost.xaml:58`, `MainViewModel.cs:499`, `ServiceFactory.cs:108`. H maps what is there rather
than what the note says will be there. It also records that `IDirectoryTreeService` and
`DirectoryTreeNode` still document themselves as serving capture scope selection, removed 2026-08-02,
which is the strongest evidence that the deletion is right: the component is already an orphan by its
own account. H20 argues that `MainViewModel.Inspect.cs` (32 lines) should be lifted out before the
deletion — it is the only live-to-stored identity bridge in the product, and it needs no LDAP to
survive.

The branch has 21 components (H1–H21), two of them dead. `IEffectiveAccessService` /
`EffectiveAccessService` (H10, 383 production lines against 433 test lines) has no production caller
at all — the fourth such subsystem the map has found, and again the best-designed of its rivals.
`LiveErrorCode` (H21) has neither producer nor consumer, and its formatter overload is unreachable.
The branch also holds **three** implementations of effective access — H7 live, H10 stored and dead,
H16 stored in a view model — which disagree with each other on non-canonical DACLs.

The file's leading would-do-differently item questions whether the branch should be rebuilt at all.
Every live operation in H takes a single DN; there is no forest-wide live operation anywhere in it. A
whole-forest audit tool cannot ask "which of these 4,000 findings are still true" through this
surface, only one object at a time. Re-capture and compare — branch G, already built and already
forest-wide — answers the same question at the scale the product operates at. That is a rebuild
question, not a decision; H is written to be useful either way.

### Note on branch C

Storage is the branch that had to be split, across two sessions and two files.
[`C-storage.md`](C-storage.md) covers the **write path** — schema definition, connection management,
the bundle layout on disk, and the writers (components C1–C15).
[`C-storage-read.md`](C-storage-read.md) covers the **read/query path** — the paging engine,
`ObjectQueryService`, the summary and dashboard query services, and the small projections
(components C16–C28).

The seam between the two halves is component C2, the view definitions: the write path authors them,
the read path consumes them, and nothing else crosses. C4 (`DatabaseConnectionFactory`) is mapped in
the write half but serves the read half, which references it rather than re-describing it.
Component numbering is continuous across both files, so a reference to `C7` or `C19` is unambiguous
without naming which half it lives in.

### Note on branch E

Findings is the second branch that had to be split, on the same grounds as C: roughly 11,300 lines
across 57 files. [`E-findings.md`](E-findings.md) covers **the findings run** — the pipeline phase,
`FindingsService` and its partials, the privileged-principal set, the coverage verdict, enrichment,
persistence, policy, suppression, acceptance, the action report and read-back (components E1–E15).
[`E-rules.md`](E-rules.md) covers **the rule catalogue** — the ten evaluators, `RuleEvaluatorHelpers`,
the SEC-* catalogue in `rules.yaml`, `BuiltInRules`, the evidence matrix and the three lookup
catalogues (components E16–E27).

The seam between the two halves is `IRuleEvaluator.Evaluate` (`Findings/IRuleEvaluator.cs`, 36
lines): the run half invokes it, the rules half implements it, and nothing else crosses. Component
numbering is continuous across both files.

The rules half made two grouping decisions that later sessions should treat as settled. **The ten
evaluators map to five components (E18–E22), grouped by evidence source** — control edges, object
attributes, membership shape, policy content, escalation paths — rather than one component per file,
because the ten group by subject matter and the evidence is what actually differs between them.
**`RuleEvaluatorHelpers` (1,154 lines) maps to five components (E23–E27)**, one of which is not a
helper at all: lines 774–946 are a shared rule engine that five SEC-* rules are entirely implemented
by. `RemediationHintCatalog` stays with E12 in the run half; the rules half references it.

### Boundary rulings

Where a branch's edge was genuinely arguable, the ruling is recorded here rather than left implicit
in whichever branch file happened to be written first. Later sessions should treat these as settled.

| Ruling | Decided during | Reason |
|---|---|---|
| **B stops at `merge_shards` plus capture coverage.** The later phases that `DirectCaptureRunner` invokes belong to D and E. | B | One type running the whole pipeline is a finding about that type, not a reason to let B annex two other branches. Recorded as a would-do-differently item in B. |
| **The `Direct*Writer` family is a component of B**, with a note that C owns the schema they write into. | B | They live in `Storage/` but run only during capture. Branch C should reference them, not re-describe them. |
| **SYSVOL and Group Policy capture folds into B** as a supplementary capture component. | B | Roughly 700 lines with its own file-reader seam and coverage story, but not enough to earn a branch of its own. |
| **The B/D line is *captured versus derived*, not *before versus after the merge*.** `DirectPrincipalWriter`, `DirectPasswordPolicyWriter` and `DirectObjectWriter.PopulateParentGuids` all run after `merge_shards` and are still B's. | B | The `Direct*Writer` ruling and the `merge_shards` ruling collide otherwise. These three write facts the directory stated — principal resolution only joins collected SIDs against `dim_object` and computes nothing new. `AssetTierWriter.Classify` and `DerivedAnalysisPipeline` stay with D because they produce facts the directory did not state. |
| **B owns capture progress *emission*; K owns the publisher transport and J owns the rendering.** | B | `ShardProgressEvent` and `ModuleProgressEvent` are emitted only by capture and describe capture's own units of work, so their shapes are B's. `IProgressPublisher` and its UI consumers serve every branch. |
| **Live access is not a top-level branch.** | A | See the note on branch H above. |
| **C is split into a write half and a read half.** The write half is `C-storage.md`; the read/query path is a second session. | C | 45 files and ~11k lines, and the two halves share only view names. Splitting is what this README already prescribes for an unusually large branch. |
| **C owns the run-control *tables* and the persistence mechanics; F owns the lifecycle *semantics*.** | C | `run`, `run_phase`, `run_checkpoint` and `run_coverage` are DDL in `audit.db` created by `DerivedStore.Open`, so C cannot skip them without leaving a fifth of its own schema unexplained. What `Sealed` means, eligibility, and library UX are F's. |
| **C owns the view DDL; D owns when views are created; the read half and J own what sits on top.** | C | The DDL text is a storage artefact authored at write time. Its creation is one phase of `DerivedAnalysisPipeline`, which is D's. |
| **`DatabaseConnectionFactory` is a component of C**, even though it serves the read path. | C | Per-connection composition — sidecar `ATTACH`, temp views — is a storage-shape decision, not a query decision. The read-half session should reference C4, not re-describe it. |
| **C owns the asset-tier *storage split*; D owns the classification.** | C | The evidence/policy division and the precedence temp view are storage design; `AssetTierWriter`'s tiering logic is derived analysis. |
| **`LowSignalOuRecommendationService` is mapped in C's read half**, despite running at capture time on the write connection. | C (read) | It is a read of the derived store and shares the read half's SQL idioms; its 100-line `SELECT` would be the only query in a branch about writers. Its *invocation* is B's, and the file records that. |
| **`InheritedAceResolver` is a component of C's read half**, though it lives in `Infrastructure/Security/`. | C (read) | It issues SQL at query time to reconstruct inherited ACEs, and is constructed at exactly one call site inside `ObjectQueryService`. Its sibling `AceAnalysisService` is excluded: it aggregates already-fetched rows and issues no SQL, so it belongs to J. |
| **`AuditObjectLocator` is mapped in C's read half**, though its input is a live-directory identity. | C (read) | The component is SQL against `dim_object`. The live identity that reaches it comes from H, which the file records as a cross-branch input. |
| **The paging seam with J is `KeysetQueryBuilder.Execute`.** | C (read) | `GridViewModelBase` is the builder's only consumer and owns page size, sort selection and load state. C stops at the builder; which sort is passed, and what a failed page looks like on screen, are J's. |
| **Run logs under `Logs/runs/` fold into C**, though they are outside the bundle. | C |
| **The D/E line is *derived fact versus evaluated rule*.** Control edges, group closure, asset tiers, escalation paths and chokepoints are D; `FindingsService` and the rule evaluators that read them are E. | D | Tested rather than assumed, and the code already draws it: `DerivedAnalysisPipeline` has two entry points with two health records, and `DirectCaptureRunner` interleaves derived coverage between them because findings must run after derived coverage is final. The type spanning both is mapped as D1 and recorded as a would-do-differently item. |
| **`BackfillFindingPrincipals` is E's, although its sibling `EnsureExpansionGroupsResolved` is D's (D6).** | D | Both write `dim_principal`, a B table. Each belongs with whatever produced the SID: expansion invented one set, findings the other. |
| **`CoverageEnforcementService` is not D's.** | D | `EscalationPathService` constructs it, but so do `FindingsService.Coverage` and `RuleEvaluatorHelpers`. It serves more than one branch; D17 references it rather than mapping it. E or K should claim it. |
| **`DerivedHealthReader` and `DerivedPhaseVerdicts` are D's (D2).** | D | The vocabulary is D's phase names and D writes every row they read. Their consumers are I and J, recorded as cross-branch outputs. |
| **`ExistingCaptureAnalysisService` is D's (D20).** | D | It is the second and only other entry point into the pipeline, and exists solely to run D over a copied bundle. What its run row means is F's. |
| **`AssetTierWriter` is mapped in both C6 and D11, deliberately.** | D | C6 owns the evidence/policy storage split; D11 owns the classification pass that fills it. The prior ruling already drew that line and D references it rather than restating it. |
| **`CoverageEnforcementService` is E's (E4).** | E | Its four call sites all reduce to one question — "is this conclusion safe to state?" — which is E's question, not a cross-cutting utility. `EscalationPathService` (D) constructing it no more makes it D's than D reading `dim_object` makes `dim_object` D's. It is stateless and constructed fresh at every site, so nothing is lost by placing it. This settles the open question D17 left. |
| **E owns suppression *semantics*; C5 keeps the sidecar as storage; F keeps whether a sealed run may accept new ones.** | E | C5 owns the file, the `ATTACH` and the `dim_suppression` DDL. E10 owns what `active`, `expires_utc` and `revoked_utc` *mean* — that revocation preserves the row rather than deleting it, and that `ImportAcceptance` differs from `Suppress` only by carrying `source_run_id`. |
| **The action report (`ActionGrouper`, `ActionPriorityCalculator`, `ActionReport`) is E's (E12), against the stated prior.** | E | Tested rather than assumed. Nothing it computes is persisted — `GenerateActionReport` runs on demand from one UI call site and the result is discarded — so by the "E ends at a persisted `fact_finding` row" prior it is I's. It is claimed for E because grouping findings by root cause and scoring them is a statement about what findings *mean*, and I owning a scoring policy would let two branches disagree about which finding matters most. E12 records the counter-argument. |
| **`FindingEvidenceMatrix` is E's, not J's**, despite its only production consumer being `HelpViewModel`. | E | It is a rule-catalogue statement about which evidence each SEC-* rule rests on, enforced by a parity test against `BuiltInRules`. J renders it; E defines it. Mapped in `E-rules.md`. |
| **`RunDiffService` is mapped in E (E14) with no G attachment.** | E | It has no production consumer at all — only the interface, the implementation, the result record and its own test. It is a Compare-branch component with no Compare branch reaching it; G should reference E14 rather than re-map it. |
| **`RunDiffService` is G's by subject, and dead for a structural reason (G14).** | G | G accepted E14's finding and ruled on it. It diffs two `run_id`s inside one `SqliteConnection` while both live engines diff two `audit.db` files; one bundle holds one run, so its central `INNER JOIN ... AND c.run_id = $currentId` returns nothing on any bundle the product produces. It was never wireable. G14 also records the one capability it has that the live engines lack — `SeverityChanges` — which should be salvaged into `FindingDeltaType` before the service is deleted. |
| **The four `Acl*` compare and delta view models are not G's.** | G | `AclCompareViewModel`, `StoredAclCompareViewModel`, `AclDeltasWindowViewModel` and `AclDeltaRowViewModel` (901 lines) all carry `LiveAclDelta` and `ILiveDiagnosticsService`, never `AceDelta` or `CompareResult`. They compare live DACLs against live or against stored, which is the freshness overlay this README's note on branch H reserves. G names them so they are not lost; H should claim them. |
| **G ends at `CompareResult`; there is no G→I seam.** | G | `git grep` for `CompareResult` and `ChangeReport` across `src/` returns the compare window and the drift card and nothing else. No report generator, exporter or dashboard consumes a comparison, so G has no downstream branch to hand off to. |
| **The H/J line is *subject*, not layer: H owns the live read engine and anything whose subject is live measured against stored; J owns panels that display a single live read with no stored counterpart.** The single named type that crosses is `LiveCheckService`. | H | H's true surface is ~8,900 lines across ~55 files once every `ILiveDiagnosticsService` consumer is counted — C-sized and E-sized, both of which split. A subject boundary keeps it to ~6,150 lines in one session and draws the line on a principle rather than on fatigue. `PreviewActionService` sits above `LiveCheckService` (7 call sites); `InheritanceViewModel`, `DelegationReportViewModel`, `GroupMembershipViewModel`, `ResolvePrincipalViewModel`, `PrincipalNameResolver`, `LdapInputHelper`, `ObjectDetailWindow` and `ObjectDetailPanelViewModel.Live*` each call `ILiveDiagnosticsService` for a single live read with nothing stored to compare against. All J's; H references them. |
| **`DirectoryTree` and the Inspect view are H's, against the rule above.** | H | Pure live browsing with no stored counterpart, so by the subject rule they are J's. Claimed for H anyway because sequencing item 4 names exactly those types and H is the branch that has to rule on them. The exception is recorded in H17–H20 rather than hidden. |
| **`EffectiveAccessService` / `IEffectiveAccessService` is H's (H10), though it reads only stored evidence.** | H | It is the offline twin of `EffectiveAccessEvaluator`, and the duplication question — do the live and stored evaluators agree about deny precedence — is only answerable with both in one file. It has no production caller, so no other branch is deprived by placing it here. |
| **`LiveSidResolutionService` is B's, not H's.** | H | Its only consumer is `SecurityModeCaptureService`. It resolves SIDs during capture, not during verification; the `Live` prefix is the only thing linking it to this branch. |
| **F owns whether a run may be *used*; I owns what is *produced* once it is eligible.** The single named type that crosses is `OutputEligibilityKind`. | I | F mapped `RunDatabaseInspector` and the eligibility semantics; I maps the six kinds' callers. I found `Open` to be a second caller-less kind alongside F's `Compare`, which is a finding F could not have made without tracing I's call sites. |
| **C owns the bundle layout on disk; I owns what is written *out* of a bundle.** | I | The two `manifest` artefacts are the test case: the bundle's `manifest.json` is C's and F's and has no producer, while `export_manifest.json` is I's and is written on every package export. Same noun, different branch, opposite fates. |
| **`DelegationReportViewModel` and `DelegationReportPanel` are not I's** (260 lines), despite the name. | I | They take `ILiveDiagnosticsService` and a single OU DN, and write no artefact. By the H/J subject rule they are a live panel with no stored counterpart. Only the name links them to `DelegationReportGenerator`, which writes a forest-wide HTML file from stored evidence. |
| **`HelpViewModel.ExportHtml` is not I's.** | I | It writes an HTML file, so it is mechanically an export, but its subject is the tool's own help text rather than audit evidence. J. |
| **`NoLapsGridViewModel.ExportCsv` *is* I's**, though it lives in a grid view model. | I | It is the third independent CSV writer over `audit.db`, and the disagreement between the three about RFC 4180 and formula injection is only visible with all three in one file. Mapped as I21. |
| **`ChangeReport` / `ChangeReportBuilder` are G's, not I's**, on the name alone. | I | `git grep` confirms neither appears anywhere under `Export/` or `Reports/`. The word "report" is the only thing connecting them to this branch. |
| **E12's ruling stands: the action report is E's, not I's.** | I | Re-tested as instructed rather than assumed. `GenerateActionReport`'s only production caller is `MainViewModel.Home.cs:117`, a J surface; nothing in I invokes it. I records that `finding_top_actions` (I14) and `DelegationReportGenerator.QueryActionPriorities` (I11) are two further independent prioritisations, which is a duplication finding rather than a reason to move E12. |
| **G's "no G→I seam" ruling stands, verified from I's side.** | I | `git grep -n "CompareResult\|ChangeReport"` over `Export/`, `Reports/` and `ExportCoordinator.cs` returns nothing. I records it as a gap in its own surface — a compare that cannot be exported is the missing half of the remediation story — not only as a fact about G. |
| **J is split into a shell half and a grids half.** The shell half is `J-presentation-shell.md`; the evidence surfaces are a second session. | J | 235 unclaimed files and ~35,000 lines once G's, H's and I's claims are subtracted — six times a single session. Splitting is what this README already prescribes for an unusually large branch, and J is the largest. |
| **The J seam is `IScopedGrid` / `GridViewModelBase<TRow>`.** | J | One named type, declared in one file, with 23 implementers on one side and the shell on the other. The shell touches it through exactly three members. It also inherits C's settled `KeysetQueryBuilder.Execute` boundary rather than straddling it. |
| **The four `Acl*` compare and delta view models are H's. Ruling 226 is resolved.** | J | Tested rather than assumed, as instructed. H did claim them: `H-live-verification.md`'s corrections table records "The ruling's placement of all four in H stands; its stated reason does not" — `AclCompareViewModel` is live-vs-live and `StoredAclCompareViewModel` is stored-vs-stored, neither live-vs-stored as G had supposed. J references H and does not re-map them. |
| **`DelegationReportViewModel` and `DelegationReportPanel` are J's. Ruling 234 is resolved.** | J | Ruling 228 already names the type among the single-live-read panels with no stored counterpart and assigns that whole set to J; H's coverage-gaps section lists it as "referenced rather than mapped". Mapped in J's grids half, since it is a panel rather than shell chrome. |
| **`MainViewModel.OfflineTree` and `DirectoryTreeNodeViewModel` are J's, not H's**, despite sharing a node type with H17–H20. | J | The subject rule decides it: H's tree browses live LDAP, this one reads `dim_object` through C's `OfflineTreeService` and drives grid scoping. It survives a greenfield that drops live access; H's does not. Mapped as J17. |
| **I20's count is superseded, not contradicted.** | J | I found five unbound export `[RelayCommand]`s while tracing exports. J's systematic sweep of all 138 commands against all 64 XAML files finds eight on `MainViewModel.Commands.cs` and 28 fully dead across the project. Recorded in J's corrections table; `I-output.md` is unchanged. |
| **J-b is a single file; the `DetailWindowViewModel` seam was tested and rejected.** | J | Tested rather than assumed, per the rule that a seam must be a single named type or call that crosses. `DetailWindowViewModel.BindGrid` (`:80`–`:126`) constructs **eleven of the same 21 `GridViewModelBase` subclasses**, so a split there would put J21's consumers on both sides rather than cross a boundary. The 21 near-identical grids and 21 row records collapse into two components, so ~23,600 lines map at J-a's depth in 26 components. |
| **`EffectiveAccessViewModel` and `StoredEffectiveAccessViewModel` are H's, already mapped as H15 and H16.** | J | Ruling 228 never named them among the single-live-read panels; the J-b brief did. `H-live-verification.md:401` and `:412` map both. J-b references them and does not re-map. H's count of three effective-access implementations stands. |
| **`AceAnalysisService` is J's (J33) and is not a fourth implementation of effective access.** | J | Confirms the earlier ruling that excluded it from C's read half, and answers the question J-a left open. `AggregateByTrustee` does no group expansion, so it answers "who has ACEs here" rather than "what can X do to this object". It is a third independent *access-mask decoder*, and its `RightsSummary` discards the allow/deny distinction its own detail rows carry. |
| **`StoredInheritanceViewModel` is J's (J42).** | J | Named by neither ruling 228 — which covers only the live `InheritanceViewModel` — nor H's coverage-gaps list, and unmapped by any branch until J-b. It is the stored counterpart to J43's live panel, survives a greenfield that drops live LDAP, and becomes the only implementation if one does. |
| **K's membership is the set of components with more than one consuming branch, established by sweep and stated in the file rather than inferred from a folder.** | K | K is the only branch with no folder and no namespace, so its edge cannot be read off the tree. The file opens with a folder-by-folder verdict table over `src/SecureAD.Core/`'s 27 entries so the judgement is auditable and arguable rather than implicit. |
| **`Assessment/` is F's, not K's**, except `PerfEvent.cs`. | K | 14 files whose subject is the run — `RunState`, `RunSummary`, `SavedRunRecord`, `AuditRunResult`, `ProfileId`, `CoverageId`, `SetBaselineResult`. That is F's vocabulary by subject and F already maps its consumers. `PerfEvent` is the exception: its subject is observation rather than the run model, and it pairs with K25 as the second of two unread performance-observation systems, which is only visible with both in one file. Mapped as K26; ruling 289's placement of `Logs/runs/` in C is honoured, so only the mechanism is mapped. |
| **Four of `Coverage/`'s thirteen files are E4's implementation, not K's.** | K | `CoverageDependencyGraph.cs` (197), `CoverageDependency.cs` (48), `CoverageGate.cs` (53) and `CoverageTaint.cs` (25) have exactly one consumer between them, `CoverageEnforcementService`. E4's ruling is not relitigated — it is *enlarged*: E4 is five files, not one. The remaining nine are genuinely cross-branch (`CoverageState` alone reaches nineteen files across B, D, E, G, I and J) and are K22. Recorded in K's corrections table against `D-derive-and-analyse.md`. |
| **`DnHelper` is K's (K17), though it lives in `Discovery/`.** | K | 34 consumers across all three projects; exactly one of them is discovery. It is the most widely consumed single file in the product, and attributing it to the branch whose folder it happens to sit in would misrepresent the codebase to anyone rebuilding from the map. A's ownership of the folder is unaffected. |
| **`Classification/` is mapped in K (K18) although it fails K's own membership test.** | K | Both classifiers have exactly one consumer each, and both are E's rule evaluators, so by the "more than one branch" rule they are E's. Mapped here because they sit in a Core folder no branch claimed and would otherwise be lost entirely, and because the fact worth recording about them is structural — they are the product's only two pure-function classifiers, against `AssetTierWriter.Classify` (D), which does the same kind of work against the database. The exception is recorded in K18 rather than hidden, and K18 recommends moving them to E. |
| **B's progress *emission* ruling (202) is upheld from K's side, and the split is confirmed correct.** | K | Tested rather than assumed. `ShardProgressEvent` and `ModuleProgressEvent` are published only by `DirectCaptureModule`; `RunProgressEvent` and `AnalysisProgressEvent` only by `DirectCaptureRunner`; `IProgressPublisher`, `IProgressObserver` and `SimpleProgressPublisher` serve all of them plus the dead export leg. K1 maps the transport, K2 the run/analysis event shapes and shared state enums, B keeps the shard and module shapes, and I22 keeps the export pair. |
| **`ErrorDisplayViewModel` and `ErrorDialog` are K's (K7), not J's**, despite being a window with a view model. | K | The J/K line for UI types is *whose failure is it*. This dialog has one caller, `App.xaml.cs:91`'s dispatcher-unhandled-exception handler, and its subject is the error model rather than any screen. It is also the only consumer of `UserFacingError`, which is why the observation that its structured-error constructor has no caller is only available with both in one file. J does not re-map it. |
| **`Infrastructure/Diagnostics/MemoryMonitor.cs` is K's (K27).** | K | Found by K's whole-map coverage audit, unmapped by any branch under any name. Its only consumers are three `LogMemory` calls in `EscalationPathService`, which would make it D's or E's by consumer — but its subject is observation, and placing it beside K25 and K26 is what makes it visible that the product has *four* unread observation channels and that this one is duplicated by a dispatcher timer in `MainViewModel` measuring something else. |

## The map is complete

Eleven branches, thirteen branch files, **256 components** (A10, B23, C28, D20, E27, F17, G14, H21,
I23, J46, K27), covering `src/SecureAD.Core`,
`src/SecureAD.Infrastructure` and `src/SecureAD.UI` end to end: A connects and discovers, B captures,
C stores and reads back, D derives, E evaluates rules and produces findings, F decides whether a run
may be used, G compares two runs, H verifies against live, I exports, J presents, K is underneath all
of them. Every claim in these files is traced against the code rather than inferred, and each file
ends with the sections of it that were not read.

### What recurred, across three or more branches independently

These are the findings that no single branch could have made, and every one of them was reached
separately before it was recognised as a pattern.

1. **A correct mechanism exists and nothing is obliged to use it.** The dominant failure in this
   codebase. `AuditError` and thirteen of fourteen error enums (K4, K5) — produced by nothing.
   `ExportProgressEvent` (I22) — a five-leg progress interface with one leg unconnected.
   `GridViewModelBase.DataLoadState` (J46) — the product's one correct answer to "empty versus
   failed", bound by no XAML. 28 `[RelayCommand]`s with no binding and no C# reference (J20), nine of
   them the Dashboard's drill-downs, reimplemented as `Click=` code-behind (I20). `CreateChildScope`
   (K3) — a six-level cancellation hierarchy with one instance. In each case the design is right and
   the boundary that would force its use was never drawn.
2. **The same question has three to six independent answers, and they disagree.** Three
   effective-access implementations (H7, H10, H16). Four counts of "how many Critical findings"
   (J46). Three CSV writers disagreeing about RFC 4180 and formula injection (I6, I15, I21). Three
   independent action prioritisations (E12, I11, I14). **Five** answers to "is this right dangerous"
   (K16), of which two are the live and stored halves of one panel. Two GUID catalogues (K13, K14).
   Two settings systems, one of them unreachable (K11, K12).
3. **Nothing states the age or provenance of the evidence it presents.** H found no live answer
   carries `SealedUtc`; I found no exported artefact does; J found twelve of thirteen uses in the UI
   are sort keys and the only rendered one is in a dialog about importing acceptances. K adds that
   `ToolVersion` (K19) is the one place the problem was recognised and fixed properly, and its
   reasoning — a hardcoded version made "a change in the rules indistinguishable from a change in the
   forest" — is the clearest statement of why provenance matters in this product.
4. **"Could not compute" and "found nothing" are not distinguished, except in three places.**
   `VouchedCount` (I4) and `CoverageWarningPresentation` (I3) get it right; `DataLoadState` (J46) gets
   it right and is unbound; `SettingsValidationResult`'s critical/non-critical split (K11) gets it
   right and is uncalled. Everywhere else a failure renders as a zero, an "engine did not produce
   results" message that is false whenever the failure was a query, or a swallowed `SqliteException`
   surfacing as "Live ACL matches snapshot."
5. **A well-built subsystem with no production caller.** `RunDiffService` (E14/G14),
   `EffectiveAccessService` (H10), `LiveErrorCode` (H21), `ExportErrorCode` (I23),
   `GroupMembershipViewModel` and six fully-plumbed unreachable grids (J46), `AppSettings` and
   `SettingsValidator` (K11). In several cases the dead one was the best-designed of its rivals, and
   each of G14, H10, I20, J20, J46 and K11 records the one capability worth salvaging even though the
   surface is not.
6. **Names describe an intention rather than the code.** `capture_scope_summary` for a capability
   removed in 2026-08-02. `TabExportService`, which is why two more CSV writers were written.
   `PermissionClassifier`, which is why four more danger classifiers were written.
   `SavedCredential.cs`, containing only an enum called something else. Every branch has a Naming
   section and none of them is short.

### What to read first, if you are starting a rebuild tomorrow

- **This README's "Depth" section**, so you know what altitude these files are written at and why.
- **[`C-storage.md`](C-storage.md) and [`C-storage-read.md`](C-storage-read.md).** The bundle and its
  schema are the product's spine; almost every other branch is a writer or a reader of it, and no
  rebuild decision can be made before that shape is settled.
- **[`F-run-model.md`](F-run-model.md).** What a run *is*, when it is sealed, and when it may be
  used. It is the smallest file that changes the most downstream decisions, and it owns `SealedUtc`,
  which recurring finding 3 says every branch needed and none of them read.
- **[`K-cross-cutting.md`](K-cross-cutting.md), Would-do-differently.** Not for the components, which
  are a residue, but because it is where recurring findings 1 and 2 are diagnosed rather than only
  observed, and where the directory-domain kernel a rebuild should extract first is described.
- **[`E-rules.md`](E-rules.md).** The rule catalogue is the product's actual value. Read it before
  deciding what a rebuild is *for*, and read [`I-output.md`](I-output.md) next, because I3, I4 and I9
  are the map's best worked examples of how to say something honest about incomplete evidence.
- **Then whichever branch you are about to touch**, plus this README's boundary rulings table, which
  is where every arguable edge was decided and should be treated as settled.

Two standing product-level questions the map raises and does not close. **Should live verification be
rebuilt at all** — H's leading item observes that every live operation takes a single DN and there is
no forest-wide live operation anywhere, so a whole-forest tool cannot ask "which of these 4,000
findings are still true" through that surface, while re-capture and compare (branch G) already
answers it at scale. J-b found ~2,400 lines of J's own surface would go with it, and K9 is the only K
component that does not survive. And **there is no G→I seam** — no report, export or dashboard
consumes a comparison, so a compare that cannot be exported is the missing half of the remediation
story.

## How to continue this work

**One branch per session.** Each branch needs deep, evidence-based tracing, which fills a session's
context quickly. A degraded context is where invented file paths and unverified claims appear — and
the whole value of these files is that they are traced rather than assumed. The written files are the
handoff: a fresh session that reads this README plus one completed branch file starts better informed
than a long session running low on room.

If a branch is unusually large — Storage is 45 files, Presentation is 128 view models — split it
across two sessions rather than compressing it.

Prompt to start a new session, replacing the bracketed parts:

```text
I'm building a component-level rebuild map of this app under docs/map/.
Read docs/map/README.md first — it defines the purpose, the four-section
template (The flow / Components / Naming & taxonomy /
Would-do-differently), and the depth we stop at. Then read
docs/map/A-connect-and-discover.md as the reference for tone, structure,
and level of detail.

This session covers branch [B — Capture].

Output shape — the conversation output must use the same section order
and structure as the file, so I am reviewing the document itself rather
than a summary of the research behind it:

  1. The flow — numbered, what happens at runtime, in order.
  2. Components — the map. For each: an ID (B1, B2...), a one-sentence
     "Owns", Layer (Core / Infrastructure / UI), "Depends on" (other
     component IDs), "Implemented by" (file paths with line counts),
     and "Non-obvious" wherever a reason to exist is not apparent from
     the name.
  3. Naming & taxonomy — names that mislead. Rename plus why it matters.
  4. Would-do-differently — structural and design retrospective.

Components is the most important section and deserves the most effort:
it IS the map. Findings are secondary. Without it there is no answer to
"what would I rebuild", only "what went wrong last time".

Do not merge sections 3 and 4. They are separate backlogs at very
different price points — a rename is mechanical and low-risk, a
restructure is neither — and merging them destroys that signal.

Rules carried over from previous sessions:

- Trace, don't assume. Every claim in these files is verified against the
  code. If you say something is unused, prove it with git grep. If you
  describe what a component does, read it. Prior sessions found several
  "this exists for X" assumptions that were wrong.
- Use git grep and git ls-files, not the built-in search tools. Per
  .github/copilot-instructions.md, those return misleading empty results
  in this workspace.
- Also read docs/review/00a-product-identity.md before drawing
  conclusions about whether something should exist. It already records
  product decisions, including deletions that are decided but not yet
  executed.
- This is advisory, not a to-do list. Renames and restructures are
  recommendations for a rebuild, not changes to make now. Make no code
  changes.
- Include at least one "this was right, keep it" item in
  Would-do-differently where one genuinely exists.
- Note cross-branch dependencies where a component's output feeds a later
  branch.
- Raise scope and boundary questions before presenting the document, not
  after. Where a branch's edge is genuinely arguable, propose a boundary
  and say why rather than choosing silently.
- If you find that an existing document in docs/ missed something,
  record it as an addition and say which document and which claim, so
  the correction is traceable. Do not silently contradict it.

Present the full document in conversation first, in the section order
above, so I can react before anything is written to disk. Then write
docs/map/[B-capture].md and update the branch table in
docs/map/README.md.
```

## Related documents

- `docs/review/00a-product-identity.md` — what the product is and is not; the deletion decisions
- `docs/decisions/` — architecture decision records
- `docs/ARCHITECTURE.md` — the current layering and run model
