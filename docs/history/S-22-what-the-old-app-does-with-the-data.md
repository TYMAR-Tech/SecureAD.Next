# S-22 — What the old application does with the data

**Type:** slice
**Reviewed at commit:** `a2e0627d`
**Size:** 42 files, 12,315 lines
**Date:** 2026-08-13

Branches D, E and G of the predecessor — derived analysis, rules and findings, and comparison. This
is the analytical half: everything that happens *after* capture and storage. Branches A, B and C were
read on 2026-08-12 and recorded at [`S-20`](S-20-what-a-bundle-stores.md), which listed the rules
engine, `EscalationPathService` and compare as explicitly **not read**. This session reads them.

**It changed no code and decided nothing.** Its output is this document.

## What it does

Takes a database full of objects, permissions and group memberships, and turns it into two kinds of
answer: **findings** — *this configuration is dangerous* — and **escalation paths** — *this account
can reach that administrative account, by this route*. On top of the paths it computes
**chokepoints**: the single permissions whose removal closes the most routes, which is the most
actionable thing the product produces. Comparison then tells a customer what changed between two
runs.

If this half vanished, the product would be a very thorough directory dump. Everything a customer
acts on is made here.

## Shape

- **`DerivedAnalysisPipeline`** — the orchestrator. Nine phases in a fixed order: `ANALYZE` → views →
  GUID map → delegation bundles → group expansion → control edges → asset tier → escalation paths →
  chokepoints. Findings run separately in `ExecuteFindingsAsync`.
- **`ControlEdgeService`** — turns access control entries into a graph. One edge per (entry ×
  control type), plus ownership edges, plus edges synthesised from `sIDHistory`.
- **`EscalationPathService`** (1,439 lines across two files) — the search. Loads the graph into an
  int-indexed `CompactGraph`, runs a reverse breadth-first search from every high-value target to
  find which principals can reach one at all, then reconstructs *representative* paths forward from
  those principals only.
- **Tier classifiers** — `StaticAssetTierClassifier` (well-known identifiers, object class, DN),
  wrapped by `DerivedAssetTierClassifier` (promotes to `Tier0Shadow`) and optionally by
  `PolicyAssetTierClassifier` (the customer's `tier-policy.json`). `Tier0ObjectTable` materialises the
  answer into a temporary table.
- **`FindingsService`** plus eleven evaluators under `Findings/Evaluators/` — the rules. Each issues
  SQL directly.
- **`StructuralCompareEngine`** and **`SecurityCompareEngine`** — comparison, the second delegating to
  the first.

## Dependencies

- **Depends on:** the captured layer (`dim_object`, `fact_ace`, `fact_group_membership_*`,
  `fact_coverage`), `SecureAD.Core` catalogues (GUIDs, well-known SIDs, Tier 0 relative identifiers),
  and one SQLite connection shared by every phase.
- **Depended on by:** the export report generators, and the UI grids and dashboard.
- **Layering violations:** none found in this reading. The one structural oddity is that
  `path_detail` — a JSON blob written for display — is re-parsed as the *input* to chokepoint
  aggregation, so two pipeline phases communicate through a rendering. That is `F-S22-6`.

## Verified-safe

Things checked and found correct. Recorded so they are not re-investigated.

- **Phase failure is recorded per phase and readable afterwards** — `DerivedPhaseVerdicts` at
  `DerivedPhaseVerdicts.cs:44-114`. `WhyUntrustworthy` returns *a sentence naming why a number cannot
  be trusted, or null*, so whether to print a number and what to say instead cannot drift apart. An
  unrecorded phase is treated as at least as serious as a failed one (`:16-25`). This is gate 4 done
  properly, in a codebase that predates the gate.
- **Comparison refuses graph deltas rather than degrading them** — `SecurityCompareEngine.cs:37-64`.
  The comment states the reasoning exactly: an edge that appears removed may pass through a domain the
  other run never captured, so *"refuse loudly rather than degrade — an empty list and a withheld list
  must not look alike."* `GraphFindingsWithheldReason` carries the reason out.
- **Findings coverage is post-processed rather than left to an optimistic default.**
  `FindingV2.CoverageComplete` defaults to `true` (`FindingV2.cs:58`) and most factories omit it, but
  `FindingsService.Coverage.StampCoverageOnFindings` (`:16-58`) resolves each finding's domain, checks
  the modules that rule actually needed, and stamps a reason. Path findings are skipped because they
  already carry per-row coverage. Checked specifically because the default looked wrong on its own.
- **The deny model is named in the bundle rather than assumed** —
  `control_edge_deny_model = BestEffortSameObjectTrusteeObjectTypeMaskWithSidHistory`
  (`DerivedAnalysisPipeline.cs:381`). The name is long and accurate, and it says *best effort*. A
  reader can tell what was modelled without reading the code. The gap it admits to is `F-S22-4`.
- **A path's identity deliberately excludes the row identifier that would churn** —
  `RuleEvaluatorHelpers.cs:530-539`. `path_id` is an autoincrement that changes every analysis, so the
  key uses a hash of the canonical signature instead. The comment records why, and the consequence
  for acceptances.
- **The control edge rebuild is atomic** — the `DELETE` and the rebuild share one transaction
  (`ControlEdgeService.cs:79-88`), so a failure mid-rebuild rolls back to the previous edge set rather
  than leaving a half-built graph.
- **Retention ordering is deterministic before any cutoff** —
  `EscalationPathRetentionPolicy.cs:44-54` sorts by target status, danger, length and then canonical
  signature as a final tiebreaker, so which paths survive the cap does not depend on enumeration
  order.
- **`Tier0ObjectTable` is rebuilt per phase rather than reused, and its empty result is deliberately
  unguarded** — `Tier0ObjectTable.cs:51-55` and `:33-40`. Both decisions are recorded with reasons,
  and the second is right: an absent `dim_object` throws rather than reading as "no Tier 0 objects".
- **The escalation grid discloses its own caps and pruning** —
  `EscalationPathsGridViewModel.cs:124-149` tells the customer the depth limit, that paths are
  representative, and how many candidates were pruned. It is honest wherever the phase succeeded;
  `F-S22-1` is what happens when it did not.

## Findings

### F-S22-1 — A crashed escalation phase renders as "no escalation paths"

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** `DerivedAnalysisPipeline.cs:134-198` catches every non-cancellation exception, records
  `FAILED: <message>` and continues. `RecordEscalationPathDiagnostics` (`:453`) therefore never runs,
  so no `escalation_*` metadata is written. `EscalationPathsGridViewModel.BuildRetentionWarning`
  (`:124-128`) reads exactly those keys and returns `null` when none are present, and
  `LoadEscalationMetadata` (`:156-180`) additionally swallows `SqliteException` and returns an empty
  map.
- **What happens to a user:** the escalation paths screen shows an empty list and no caveat. The
  customer reads *nobody can reach a Tier 0 account*. The truth is *the analysis crashed*. The run
  recorded `phase_escalation_paths = FAILED: …`, and nothing on that screen reads it.
- **Why it is this way:** the pipeline's fault tolerance is deliberate and its intent is good — a
  failed GUID map should not cost you the findings. The gap is that "continue anyway" was implemented
  and "say so at the point of display" was implemented only for the two export report generators.
- **Scope:** `WhyUntrustworthy` has exactly two production consumers, `DelegationReportGenerator` and
  `ForestReportGenerator` (`git grep -n "WhyUntrustworthy" -- src/`, measured at `a2e0627d`). The
  exported report says *unknown*; the screen the customer actually looks at says zero.
- **Options:** have the grids consult `DerivedPhaseVerdicts` as the reports already do; or make the
  pipeline's fault tolerance selective, so a phase whose failure invalidates a whole screen stops the
  analysis instead of degrading it silently.
- **Test cover:** `DerivedPhaseVerdictsTests` and `DerivedHealthReaderTests` cover the recording
  mechanism thoroughly. No test asserts that a screen reports a failed phase.
- **Status:** OPEN against the predecessor, which is frozen. Recorded as an obligation the rebuild's
  branch D and branch J rows must honour. Verified 2026-08-13.

### F-S22-2 — A skipped coverage module counts as complete coverage

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `ControlEdgeService.Persistence.cs:335` and
  `EscalationPathService.DataAccess.cs:595`, both reading
  `if (state is not CoverageState.Complete and not CoverageState.Skipped) return false;`.
  `CoverageState` (`CoverageState.cs:6-13`) declares `Complete`, `Partial`, `Denied`, `Failed` and
  `Skipped` as five distinct states.
- **What happens to a user:** a domain whose security descriptors were never read is reported as fully
  covered. Every control edge in it, and every escalation path through it, carries
  `coverage_complete = 1`. The customer is told the analysis was complete over data that was never
  collected — and `coverage_complete` is the field that exists precisely to stop that.
- **Why it is this way:** not recorded. The most likely reading is that `Skipped` was understood as
  *deliberately out of scope, therefore not a gap*. Even granting that intent, the flag it sets is
  consumed by callers asking *was this computed over everything* rather than *was anything
  unintentionally missed*.
- **What it contradicts:** [`0002`](../decisions/0002-absent-view-means-degraded-run.md) — missing
  output is a fact about the capture, never about the forest — and the
  [design document's](DESIGN-challenges-to-the-inherited-shape.md) own *what is not in question* list,
  which credits the predecessor with *"coverage is recorded positively and never inferred from
  absence"*. That credit is not fully earned.
- **Also gate 2:** the rule is written out twice, in two assemblies' worth of separate classes, with
  no shared owner. Changing one would not change the other.
- **Options:** treat `Skipped` as incomplete and let the reason string explain it was intentional; or
  keep the leniency but move the decision to one owned place so the two copies cannot diverge.
- **Test cover:** none found asserting behaviour for `Skipped` specifically.
- **Status:** OPEN. Verified 2026-08-13.

### F-S22-3 — The customer's own Tier 0 definition never reaches the escalation search

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** `DerivedAnalysisPipeline.ClassifyAssetTiers` (`:397-416`) builds
  `DerivedAssetTierClassifier` and, when a `tier-policy.json` exists beside the database, wraps it in
  `PolicyAssetTierClassifier`; that stack writes `dim_asset_tier`. Forty lines later
  `BuildEscalationPathsAsync` (`:427-429`) builds `EnrichedHighValueClassifier` on
  **`StaticAssetTierClassifier.Instance`** — no derived classifier, no policy. That classifier
  repopulates `temp.tier0_object` (`EnrichedHighValueClassifier.cs:44`, `Tier0ObjectTable.cs:56-96`)
  and is the only tier authority the path service is given.
  `PolicyAssetTierClassifier` can promote an object to full `AssetTier.Tier0` (`:8`, `:57`, `:92-97`).
- **What happens to a user:** an administrator writes a tier policy naming their certificate authority
  or their finance file server as Tier 0 — the single most important customisation this product
  offers. It appears correctly on the asset tier screen. The escalation path analysis does not target
  it, so the question *who can reach our certificate authority* returns nothing, and returns it
  confidently.
- **Why it is this way:** `EnrichedHighValueClassifier`'s own documentation (`:31-36`) argues that the
  tier answer is *"deliberately asked of a classifier rather than read from `dim_asset_tier`"* so that
  the two *"must not diverge"*. The reasoning is sound and the wiring defeats it: the pipeline hands
  the two phases different classifiers, so they diverge by construction. **This is precisely the
  failure pattern this session was commissioned to hunt** — a claim about not diverging, made in one
  component, never checked against the caller that decides whether it holds.
- **What it costs:** `DerivedAssetTierClassifier` promotes only to `Tier0Shadow`, which correctly does
  not enter `temp.tier0_object`, so that half is consistent. The loss is confined to customer policy —
  which is the half the customer controls and the half they will trust most.
- **Options:** build the escalation classifier from the same stack the tier phase used; or make the
  tier decision a single materialised input computed once before both phases, which is what challenge
  4 proposes.
- **Test cover:** classifier fixtures under `tests/…/EscalationPaths/Fixtures/` cover the classifiers
  individually. Nothing tests the pipeline's wiring of them.
- **Status:** OPEN. **Confirms design challenge 4 with evidence.** Verified 2026-08-13.

### F-S22-4 — Deny is matched only by exact trustee, while allow propagates through groups

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `IsDeniedByAce` (`ControlEdgeService.Persistence.cs:97-112`) keys the deny lookup on
  `(objectGuid, trusteeSid)`. There is no group expansion and no ordering. Allow entries, by contrast,
  become edges per trustee and are joined to group membership during path building
  (`EscalationPathService.DataAccess.cs`, and `ControlType.MemberOf` edges at
  `EscalationPathService.cs:713`). Group expansion runs one phase *before* control edges
  (`DerivedAnalysisPipeline.cs:73-74`), so `fact_group_membership_closure` is populated and available.
- **What happens to a user:** a `Deny` entry naming a group is invisible. If `Everyone` is denied
  `GenericAll` on an object and `Alice` is separately allowed it, Windows denies Alice and the product
  reports that Alice controls the object. That is a **false positive in a security tool** — the
  customer is sent to remediate access that does not exist, and the next false positive is trusted
  less.
- **Why it is this way:** two constraints, one real. Entry order was discarded at capture
  (`F-S20-7`), so canonical deny-before-allow evaluation was not available to this code. Group
  expansion was available and was not used.
- **Magnitude:** unmeasured, and it needs a forest. Deny entries are uncommon in Active Directory
  relative to allows, and group-scoped denies less common still — but they are used precisely where an
  administrator is being careful, which correlates with the objects that matter.
- **Options:** expand deny trustees through the same closure the allow side uses, which is the cheap
  half and removes the asymmetry; full correctness additionally needs entry order, inheritance flags
  and `SE_DACL_PROTECTED`, which is the work `F-S20-14`'s second option describes.
- **Test cover:** none found asserting a group-scoped deny cancels an allow.
- **Status:** OPEN. Verified 2026-08-13.

### F-S22-5 — Every object without a SID is a dead end in the search, which invalidates one of `F-S20-14`'s two proposed fixes

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `EscalationPathService.cs:190` — `if (targetSid is null) continue;`. The traversal
  only enqueues a successor when the target object carries a SID. Organisational units, containers,
  group policy objects and `AdminSDHolder` have none.
- **What happens to a user:** control over a container cannot be traversed *through*. This compounds
  `F-S20-14`, which established that containment produces no edges to a container's contents in the
  first place. The two together mean container-based delegation — the normal way delegation is
  performed in Active Directory — is invisible to path analysis from both directions.
- **Why this is more than a restatement of `F-S20-14`:** that finding offered two options, the second
  being *"keep explicit entries and add containment edges plus correct inheritance semantics"*. **That
  option would not work.** Containment edges terminating on a SID-less container are dropped at this
  line, so the added edges would change nothing until the traversal is also changed. The rebuild has
  taken the first option — store inherited entries — so this does not block it; but the record's stated
  alternative rests on an assumption about the traversal that the traversal does not satisfy, and
  nothing re-checked it. Recorded because `F-S20-14`'s options list is the kind of thing a later
  session reads as settled.
- **Options:** none proposed here; the rebuild's chosen direction avoids the issue. What is owed is
  that D13 does not inherit this line without deciding to.
- **Test cover:** none.
- **Status:** OPEN as a correction to `F-S20-14`'s options list. **No edit made to `S-20`.** Verified
  2026-08-13.

### F-S22-6 — Chokepoint aggregation re-parses a display blob, and silently drops steps it cannot recognise

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `EscalationChokepointService.cs:65` calls `ReadSteps(pathDetail)`, which
  `JsonDocument.Parse`s the `path_detail` column (`:138-156`). A path that yields zero steps increments
  `MalformedPaths` and is skipped (`:66-70`). A step whose `ctl` value does not parse to a known
  `ControlType` is skipped by `continue` at `:146-147` — **with no counter at all**.
- **What happens to a user:** chokepoints are the product's most actionable output — *"fix this one
  entry and four thousand routes close"*. They are computed by re-reading a string written for
  display. If a control type is ever renamed, steps of that type vanish from the aggregation and no
  diagnostic records it: the chokepoint list quietly gets shorter and still looks authoritative.
  Malformed paths at least produce a number in metadata; unrecognised control types produce nothing.
- **Why it is this way:** the path steps exist as structured objects in memory during path building
  and are serialised for storage. Rather than persisting them as rows, the next phase re-reads the
  serialised form. It works, and it is one table fewer.
- **What this establishes:** design challenge 3 is stated as *"Confidence: opinion. Formed from the
  schema, not from the findings engine."* The reading upgrades it. The blob is not merely a rendering
  shown to a customer; it is a **data interchange format between two phases of the same pipeline**,
  with a lossy parser and one unreported failure mode.
- **What partly refutes challenge 3:** findings are not evidence-free. `FindingV2` carries
  `SourceEdgeId` and `SourcePathId` (`:48-54`), which are real references back to the captured rows.
  The exception is delegation findings, whose factory is documented *"(no edge/path provenance)"*
  (`FindingsService.Persistence.cs:41`) and passes neither — and `dim_delegation` is queried 18 times,
  the second-largest rule family.
- **Options:** persist path steps as rows and have chokepoints aggregate those; at minimum, count and
  report unrecognised control types as `MalformedPaths` already are.
- **Test cover:** not established in this reading.
- **Status:** OPEN. **Confirms and strengthens design challenge 3.** Verified 2026-08-13.

### F-S22-7 — Comparison cannot tell a changed forest from a changed rule, tier definition or depth budget

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `SecurityCompareEngine` diffs `finding_key` sets (`:89-120`) and control edges.
  `finding_key` is `ruleId|subject|target` for hygiene findings
  (`FindingsService.Persistence.cs:24,52`; `RuleEvaluatorHelpers.cs:341`) and
  `ruleId|source|target|hash(signature)` for reachability findings (`RuleEvaluatorHelpers.cs:539`).
  Neither carries a rule version, a tier definition version or an analysis parameter. Compare reads
  none of them either:
  `git grep -n "rule_version\|RuleVersion\|max_depth\|AnalysisMode\|tier" -- src/SecureAD.Infrastructure/Compare/ src/SecureAD.Core/Compare/`
  returns nothing at `a2e0627d`, against a control grep for `RunA` in the same paths that returns six
  matches.
- **What happens to a user:** change the Tier 0 policy and re-run, and every reachability result
  shifts. The comparison reports them as findings **Introduced** and **Resolved** — the vocabulary of
  a forest that changed. A customer reads *forty-one new escalation paths appeared this month* when
  nothing in the directory moved. The same holds for a rule whose detection logic changed under a
  stable rule identifier, and for a change to `escalation_path_max_depth`, which silently resolves
  every path longer than the new limit.
- **Why it is this way:** `rule_version` is stored on `fact_finding` and `escalation_path_max_depth`
  in run metadata, so the inputs exist. They were never brought into comparison, and the comparison
  was built to answer a narrower question.
- **What this establishes:** design challenge 4's argument — *"two runs compared across a tiering edit
  would report churn that looks like change in the forest, which is the failure `0026` and `0027`
  exist to prevent, arriving through a door neither of them watches"* — is **correct, and the door is
  wider than the challenge says**. It is not only the Tier 0 set. Any analysis parameter has the same
  effect.
- **Options:** record the analysis inputs a run used and refuse or qualify a comparison across a
  change to them, in the same shape [`0026`](../decisions/0026-one-answer-to-whether-runs-may-be-compared.md)
  already uses for coverage. This is a product decision about *refuse* versus *qualify* and is listed
  below for the owner.
- **Test cover:** compare has tests for compatibility and coverage intersection; none for analysis
  parameter drift, which is unsurprising since it is not modelled.
- **Status:** OPEN. **Confirms and extends design challenge 4.** Verified 2026-08-13.

### F-S22-8 — `affected_path_count` is computed from a deliberately truncated sample

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `EscalationPathRetentionPolicy.cs:12-15` — `MaxPerSourceTarget = 5`,
  `MaxPerSource = 20` — plus `RepresentativePathGlobalCap = 250_000`
  (`EscalationPathService.cs:240`). `EscalationChokepointService` aggregates over the rows that
  survived (`:40-84`), and `AffectedPathCount` is one of the ranking keys (`:91`).
- **What happens to a user:** a chokepoint's headline number understates its true impact whenever any
  source principal had more than twenty retained paths, which is exactly the case for the heavily
  connected principals a chokepoint analysis is meant to surface. The ranking is by
  `AffectedTargetCount` first, so the *order* is less affected than the number; but the number is what
  a customer quotes when justifying the remediation.
- **Why it is this way:** the caps exist for a real reason — without them the table is unbounded — and
  the grid discloses that paths are representative. What is not disclosed is that a *derived count*
  inherits the truncation.
- **Compounding:** `F-S20-14` already established that `affected_path_count` understates impact
  because containment produces no edges. This is a second, independent reason for the same number to
  be low, and the two do not cancel.
- **Options:** compute chokepoint impact from the reachability computation rather than from retained
  representative rows — which is what design challenge 1 proposes and, in this specific respect, is
  right; or label the count as a lower bound.
- **Test cover:** not established in this reading.
- **Status:** OPEN. Verified 2026-08-13.

### F-S22-9 — Design challenge 1's arithmetic describes a shape the predecessor does not have

- **Severity:** maintainability — but filed because a decision is pending on it
- **Confidence:** verified
- **Evidence:** the challenge states *"Confidence: high. This one is arithmetic rather than taste"*,
  that `fact_escalation_path` is a transitive closure that *"grows combinatorially with the graph"*,
  and proposes reverse breadth-first search from Tier 0 targets over an in-memory edge set. The
  predecessor already does all of it:
  - multi-source reverse BFS seeded from every high-value target at once —
    `EscalationPathService.ComputeReverseDistanceIndex` (`:343-383`)
  - over an in-memory int-indexed graph — `CompactGraph` (`:242-341`)
  - used to skip principals that cannot reach a target — `PrincipalsSkippedByReverseBfs`
    (`:471`, `TraversalCounters` at `:237`)
  - storing representative paths only — `AnalysisMode = "Representative"` (`:829`)
  - under hard caps of five per source-target, twenty per source, 250,000 globally
- **Why this matters:** `fact_escalation_path` is bounded by *principals × 20*, which is linear, not
  combinatorial. The table is not the shape the challenge describes, so the argument that settles it —
  arithmetic about closure growth — does not apply to it.
- **What survives:** the challenge's *recommendation* is largely the predecessor's existing design,
  which strengthens rather than weakens it. Two genuinely open questions remain, and they are narrower
  than the challenge as written: whether the persisted representative-path table earns its place at
  all given that reachability and chokepoints could be materialised directly from the reverse search
  (`F-S22-8` argues they should be), and whether the *9M edges* benchmark note refers to control edges
  — which the challenge itself says should be stored — rather than to paths.
- **Why it is this way:** the challenge is explicit that challenges 3, 4 and 5 were formed from the
  schema rather than the code. Challenge 1 is not so labelled, and is marked high confidence; it was
  formed the same way. `S-20` recorded the same limitation about itself and corrected two conclusions
  because of it.
- **Options:** restate challenge 1 against what the code does, and carry the two narrower questions
  into D13 and D16.
- **Test cover:** not applicable.
- **Status:** OPEN as a correction to `DESIGN-challenges-to-the-inherited-shape.md`. The status line
  in that document has been updated to point here; **the challenge's text is left for the owner to
  revise or withdraw.** Verified 2026-08-13.

### F-S22-10 — `EscalationRunResult`'s two path counters are named the wrong way round

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `EscalationRunResult.PathsRetained` counts paths discovered *before* retention —
  `EscalationHealthCheck.cs:79` describes it as *"paths before retention"* and `:89` as
  *"discovered paths"*. `TotalPaths` is the count *after* retention —
  `EscalationPathService.cs:821`, `TotalPaths = retainedPaths.Count`.
- **What happens to a user:** nothing today. `DerivedAnalysisPipeline.cs:461-462` maps them to
  `escalation_paths_discovered` and `escalation_paths_retained` correctly, so the metadata and the grid
  warning are right. This is recorded because reading the two lines in isolation makes them look like
  a swapped-metadata bug — which is how this review first read them — and the next person to touch
  either will have to re-derive that they are fine.
- **Why it is this way:** not recorded. Most likely the retention step was added after the counter was
  named.
- **Options:** rename in the rebuild. Do not "fix" the mapping.
- **Test cover:** the mapping is not asserted anywhere found.
- **Status:** OPEN, gate 6 category — a name describing an intention rather than the code. Verified
  2026-08-13.

### F-S22-11 — `FindingV2.FindingKey` documents a key shape that nothing produces

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `FindingV2.cs:15` — *"Unique identity key (rule|subject|target|source)"*. Three shapes
  are actually produced: `ruleId|subjectSid|targetId` (`FindingsService.Persistence.cs:24,52`;
  `RuleEvaluatorHelpers.cs:341`), `ruleId|sourceSid|targetSid|hash(signature)`
  (`RuleEvaluatorHelpers.cs:539`), and a discriminator form at `RuleEvaluatorHelpers.cs:448`. None is
  `rule|subject|target|source`.
- **What happens to a user:** nothing directly. It matters because
  [`0023`](../decisions/0023-a-finding-has-a-stable-identity.md) makes finding identity load-bearing
  for acceptances surviving across runs, and this is the doc comment a reader consults to learn what
  identity is.
- **Options:** describe the two real shapes, and say which rules produce which.
- **Test cover:** none binding the comment to the code.
- **Status:** OPEN. Verified 2026-08-13.

## The six questions the brief asked

1. **Does the escalation search terminate correctly, and what bounds it?** Yes, and by five things:
   `maxDepth` (`EscalationPathService.cs:104`), per-path cycle prevention (`:195`), state dominance
   (`:205-212`), the 250,000 representative cap (`:240`), and the retention caps. **The premise of the
   question needs correcting:** `fact_expansion_status`'s `budget_exhausted` and `depth_reached`
   belong to *group membership expansion*, which has explicit node and time budgets
   (`DerivedAnalysisPipeline.cs:267-272`). The path search has **no time budget and no node budget**.
   On a graph large enough it does not give up; it runs. What a customer is told when a cap bites is
   good — the grid names the depth, the pruning and the counts — except when the phase failed
   outright, which is `F-S22-1`.

2. **What happens to a path when coverage is incomplete?** `coverage_complete` is genuinely computed
   and genuinely propagated: per object for edges, per path from the domains of its steps, then onto
   findings with a reason string. It is **not** defaulted, despite `FindingV2`'s optimistic initialiser,
   because of the post-processing pass. It reaches the screen only as a **grid column** — nothing
   renders a path differently because of it. The defect is at the base: `F-S22-2`.

3. **How is Tier 0 decided, and what happens when it is wrong?** On three dimensions — well-known
   relative identifier, object class, DN pattern — by `IAssetTierClassifier`, materialised into
   `temp.tier0_object`. When it is wrong the whole escalation analysis is wrong, and there is no
   record of which definition a result used. It is wrong today for every customer who writes a tier
   policy: `F-S22-3`.

4. **Do the rules query storage directly?** Yes, and more than the design note says. The note's three
   numbers reproduce exactly — 15 `fact_control_edge`, 18 `dim_delegation`, 3 `fact_ace` — but the
   full surface is **108 `FROM` clauses across 21 files against 15 distinct tables**, with
   `dim_object` at 20 the most-queried of all
   (`git grep -ho "FROM fact_[a-z_]*\|FROM dim_[a-z_]*" -- src/SecureAD.Infrastructure/Findings/`,
   measured at `a2e0627d`). Whether that is a problem in practice was not settled by this reading and
   is a branch E design question, per the note's own framing.

5. **What does compare actually compare, and can it distinguish a changed forest from a changed rule,
   tier definition or pipeline?** It compares finding keys, control edges, objects, entries and
   coverage. It can distinguish **none** of the three. `F-S22-7`.

6. **Is the deny model correct?** No, and it says so in its own name. `F-S22-4`.

## The challenges, ranked

**Criteria, in this order:** how much it changes what the product can *say* to a customer; how much
more expensive it is to fix later than now; and how confident this reading is. A challenge nobody can
act on is noise, so anything not actionable is left out.

| Rank | Challenge | Standing after this reading | Basis |
|---|---|---|---|
| 1 | **4 — the Tier 0 definition is a versioned input, recorded on every finding** | **Confirmed and widened.** Was opinion; is now evidence-backed twice over — the definition does not even reach the search (`F-S22-3`), and comparison cannot see a change to it or to any other analysis parameter (`F-S22-7`) | evidence-backed |
| 2 | **3 — a finding's evidence should be structural rather than a blob** | **Confirmed and strengthened, with one part refuted.** The blob is a pipeline interchange format with a silent failure mode (`F-S22-6`), which is worse than the challenge claimed; but findings *do* carry `SourceEdgeId`/`SourcePathId`, so the "evidence is only a rendering" framing is too strong except for delegation findings | evidence-backed |
| 3 | **2 — split the file into sealed evidence and disposable analysis** | **Untouched by this reading, and unblocked.** Confirmed only that the captured/derived boundary the split needs is real and already enumerated: `ReanalysisTables` lists exactly eight derived tables (`DerivedAnalysisPipeline.cs:200-210`) | evidence-backed, from `S-20` |
| 4 | **5 — hygiene and reachability findings are different things** | **Partly refuted, and the residue is sharper.** The acceptance risk the challenge names is already handled: reachability keys include a route hash, so accepting one route does not accept all. The real cost is the inverse, which the challenge's own table predicts — an acceptance lapses whenever any hop on the route changes | evidence-backed |
| 5 | **1 — do not materialise the escalation path closure** | **Premise refuted; recommendation largely already implemented.** `F-S22-9`. Two narrower questions survive and should be carried to D13 and D16 | evidence-backed |

**What would settle each:**

- **4** — an owner decision, then a rebuild row. The engineering is not in doubt; what is in doubt is
  whether a tier-definition change should **refuse** a comparison or **qualify** it, which is the
  question below.
- **3** — a design decision at D15 on whether path steps are persisted as rows. The evidence is
  gathered; nothing further needs reading.
- **2** — a decision, and it is cheapest taken before anything in the rebuild writes derived data.
  Nothing in this reading changes that.
- **5** — an owner decision on what accepting a reachability finding is supposed to *mean*. That is a
  product question about a customer's intent, not a technical one.
- **1** — a measurement, and `BenchmarkSuite1` is kept for it: how long a reverse search plus
  on-demand reconstruction takes against a real edge set, versus a lookup in a persisted table.

## Challenges that contradict an accepted decision

Named, with **no edit made**, per the brief.

- **`F-S22-2` contradicts [`0002`](../decisions/0002-absent-view-means-degraded-run.md)** in the
  predecessor's implementation. `0002` says missing output is a fact about the capture; treating
  `Skipped` as `Complete` makes a gap in the capture invisible. `0002` itself is not challenged — the
  predecessor fails to meet it. No new record is needed; a rebuild row is.
- **`F-S22-7` sits in a gap between [`0026`](../decisions/0026-one-answer-to-whether-runs-may-be-compared.md)
  and [`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md).**
  Both answer *may these runs be compared* in terms of coverage and forest shape. Neither has a
  member for *the analysis parameters differed*. `0026`'s closed set of outcomes has no door for this,
  which is the same sequencing error `0027` was written to correct — and it is the second time it has
  arisen. **A new record may be needed. The owner decides.**
- **`F-S22-9` challenges a proposed, not accepted, document.**
  `DESIGN-challenges-to-the-inherited-shape.md` carries *"Status: proposed. Nothing here is decided"*,
  so no accepted decision is contradicted. Its status line now points here; its text is untouched.

## Open questions for the owner

These need product judgement, not a technical answer.

1. **When the analysis definition changes, should a comparison be refused or qualified?** If a
   customer edits their Tier 0 policy and re-runs, the honest answers are *"we cannot compare these"*
   or *"here is the comparison, and note that the tier definition changed"*. Refusing is safer and
   more annoying; qualifying is more useful and relies on the customer reading the qualification.
   `0026` already chose *qualify* for a forest that gained a domain and *refuse* for a failed run, so
   there is precedent for both. This is `F-S22-7`.

2. **What does a customer mean when they accept a reachability finding?** *"This particular route is
   fine"*, or *"this account reaching that account is fine, however it happens"*? The predecessor
   implements the first. The consequence is that the acceptance lapses whenever any hop on the route
   changes, and the customer sees a finding they thought they had dealt with. The second
   interpretation is stabler and accepts more than the customer may realise. This is challenge 5's
   real content.

3. **Should a chokepoint's impact number be a truthful lower bound, or a complete count?** A complete
   count means not truncating the paths it is derived from, which costs storage. A lower bound is
   cheap and honest but weaker in a remediation argument — *"closes at least 20 routes"* persuades
   less than *"closes 4,000"*. This is `F-S22-8`.

4. **When a derived phase fails, should the screens that depend on it show nothing, or refuse to
   render?** The exported reports already say *unknown*. The screens show zero. Making them agree is
   engineering; deciding whether a customer should see a partial analysis at all is not. This is
   `F-S22-1`.

## Not reviewed

Deliberately skipped, so the gap is known rather than assumed covered.

- **The contents of the rule catalogue.** What the rules look for is a product question and a
  different exercise, per the brief. The eleven evaluators were read at survey depth for *shape* only,
  and sampled deeply only where a shape question was live.
- **`GroupExpansionService` and the closure algorithm itself.** Its budget mechanism was read because
  question 1 required it; the expansion logic was not. `fact_group_membership_closure` correctness is
  assumed, and every escalation path depends on it — this is the largest single gap in this reading.
- **`FindingsPolicyEvaluator`, `SuppressionService`, `AcceptanceImportService`, `ActionGrouper` and
  `ActionPriorityCalculator`.** Suppression and acceptance were touched only where finding identity
  required it.
- **`DerivedStoreSchema.Views.cs`** (1,011 lines). The grids read views; this reading went to the
  tables underneath them. A view that misrepresents its table would not have been caught.
- **`StructuralCompareEngine`'s internals.** Read at its interface to `SecurityCompareEngine` and for
  the coverage-intersection rule; the object and entry delta logic was not read line by line.
- **Branches I and J**, except where a screen's behaviour was the evidence for what the analysis was
  for — which is `F-S22-1` and the escalation grid's disclosure.
- **Anything requiring a forest.** The magnitude of `F-S22-4` and `F-S22-8` is unmeasured and is
  marked `needs-environment` rather than guessed at.
