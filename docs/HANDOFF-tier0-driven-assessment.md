# Handoff: Tier-0-driven discovery and detailed-assessment admission

## Start the new session here

The owner is frustrated by time spent reducing storage without removing unnecessary evaluation.
He requested this record and a plan so implementation can continue in a new session. The next task
is a pipeline/work-boundary change, NOT more S1 deduplication, transaction tuning or another feasibility debate.

**Updated 2026-09-10: the contract gate is CLOSED. Step 1 of the plan is complete.** Decision
[0116](../docs/decisions/0116-discovery-first-assessment-admission.md) is **Accepted** and settles
broad-principal treatment, Judgement schema 28, the scope wording and route retention.

**Updated later 2026-09-10: Steps 2, 3 and 4 are implemented, and fixture re-anchoring is complete.**
The vertical slice is wired into the real `JudgingRun` but still **behind an opt-in entry point**,
`JudgingRun.JudgeWithTier0Discovery`. The default path still assesses every object.

**The remaining blocker is not code.** Gate-caused test failures fell from 89 to 5, and those five are
artefacts of a temporary measurement switch rather than real - each calls the unscoped entry point by
design. What stands between here and flipping the default is **owner approval of the exact scope
wording and its placement on screen**. Until that is settled a gated run shows scoped counts without
the sentence saying they are scoped, which a customer would read as a forest-wide total. That is the
one thing this product must not do, so the flip waits on it rather than on engineering.

Decision [0117](../docs/decisions/0117-naming-context-roots-are-tier-0-assets.md) was accepted during
this work: naming-context roots are Tier-0 assets. It closed a real gap - a partition root holds no
SID, so no route could reach it, and replication rights are granted *on the root*, which on a domain
root is DCSync. Discovery-first as originally written would have reported every partition root as not
assessed automatically, in every forest, permanently.

Read plan section "Step 6" first: it records what was built, how fixtures were re-anchored and what
that cost, and the three outstanding items.

Do not re-ask the owner to approve the contract, redefine Tier 0, or re-explain why unrelated accounts
should not be deeply assessed. Do not rebuild the discovery service; it exists and its suites pass.

Read, in order:

1. `.github/copilot-instructions.md` — read the live file, not a historical copy.
2. `docs/decisions/0116-discovery-first-assessment-admission.md` — the accepted contract; start here.
3. `docs/WHAT-THE-PRODUCT-IS.md` — the owner-confirmed next-direction paragraphs explain what changed.
4. `docs/next/PLAN-tier-0-driven-assessment.md` — durable implementation plan, acceptance cases and gates.
5. `docs/layers/judgement/the-judgement-store.md` — current schema 27 and S1 paired-result/performance hold.
6. This handoff's artifact and preservation sections before building or running anything.

Suggested opening request:

> Continue the Tier-0-driven assessment plan. The discovery service, admission run and schema 28 are
> implemented behind the opt-in JudgeWithTier0Discovery entry point; do not rebuild them. Re-anchor
> the forest-wide control-count fixtures under new scope-aware identifiers so the gate can become the
> default, and do not weaken any existing test to obtain a green total. Confirm the exact scope
> wording with the owner before any Shell edit.

This record is not blanket approval for an unspecified API/UI change or additional measurements.
Follow the repository's contract-before-code approval rule for anything 0116 does not already settle.

## What Step 1 established (do not re-derive)

- **Three chains bind discovery to the store it must stop requiring.** `Tier0RelevanceRelation.FromControlEdge`
  throws unless `edge.Id > 0` with matching generations/catalogue; `ownership_target.target` references
  `control_object(target)`, and `OwnershipAuditStorage.Observe` is reached only from `ControlEdgeStorage.Write`;
  `ownership_relation.edge_id` references `control_edge(id)`. All three must be broken.
- **Seeding needs no control store.** `Tier0Classifier.ClassifyMany` takes any `Tier0Target` sequence and
  reads membership from `derivation.ReadMembershipInput()`; targets come from `OwnershipAuditRun.Target`,
  a pure function of the streamed object.
- **No rule consumes the control store.** All 17 `IRule` implementations read Evidence via `context.Permissions`.
- **`SelfMembershipScheduler` is the working precedent** for the discovery service's shape and coverage semantics.
- **Measured cost:** `EvaluatingObjects` 35,655 ms of a 50,637 ms run; `SelectingOwnershipScope` 1,500 ms;
  `AssessingOwnership` 3,564 ms. 112,093 control records and 23,751 full-control assessments across 8,407
  targets, to justify 51 selected targets and 210 ownership records.
- **Path to Tier 0 does not exist** and is not being built here. The backward walk produces an admission
  decision, not a route; 0116 retains the route so a later stage reads it rather than re-traversing.

## What the owner meant

- Owners and ACLs already exist in captured Evidence. No new capture or second raw-permission copy.
- An unrelated normal account such as jimmy.strand should not enter automatic detailed control,
  full-control or hypothetical takeover evaluation. Ordinary audit rules still apply independently.
- Starting at shared Tier-0 seeds, follow incoming possible controller and membership relationships
  using captured facts. Inspect newly reached accounts/groups and their controllers; avoid cycles and
  repeat assessment. A normal account reached by such a route becomes relevant to inspect.
- Do NOT select scope by first creating the entire detailed forest-wide control store. That dependency
  is why the current implementation still pays the cost before deciding what matters.
- Ownership is one possible control mechanism. Current owner, direct supported control and hypothetical
  ownership takeover are separate claims. Conditional candidates can drive discovery before takeover is
  proven; Unknown cannot disappear or become safe. WRITE_DAC does not need an ownership simulation to
  establish that particular step, and alternative source candidates must remain available.
- Build the minimal shared Tier-0 path-discovery mechanism and assessment gating in one vertical slice.
  Full path visualization/ranking/remediation/all-path enumeration are not prerequisites.
- Use ONE authoritative Tier-0 definition/classifier, not a separate ownership list or expected-admin
  filter. The current classifier is partial; unvisited is not proof of unimportant/safe/complete scope.

## Current code — the new direction IS implemented, behind an opt-in entry point

Schema **28** / control engine 9 / principal catalogue 3; Derivation schema 11. Latest accepted
decision observed: 0116. Recheck live numbering before creating another record.

New files this session, all in `next/src/SecureAD.Judgement`:

- `Tier0Discovery.cs` — budget, 15 typed reasons, limitations, coverage.
- `Tier0DiscoveryScheduler.cs` — the per-object scan; calls no evaluator.
- `Tier0AdmissionRun.cs` — classify, select, persist, then assess only admitted targets.

Changed: `Tier0RelevanceRelation` (capture-backed factory and witness), `OwnershipScopeSelector`
(comparer now separates capability and witness), `OwnershipAuditStorage` (re-anchored
`ownership_relation`, added `RecountCandidates`), `OwnershipAuditValidation` (verifies capture-backed
routes against the captured descriptor), `ControlEdgeStorage` (added `Assess`), `JudgingRun`,
`JudgementWriter`, `JudgementSchema`, `ControlEdge`, `FullControlStorage`.

Tests added: `Tier0DiscoveryEvidence.cs`, `Tier0DiscoveryAdmissionTests.cs` (28),
`Tier0CapturedRelevanceRelationTests.cs` (10), `Tier0GatedJudgingTests.cs` (9).

**`JudgingRun.Judge` still calls `ControlEdgeDeriver.Derive` for every streamed object.** That is the
default and it is deliberate until the count fixtures are re-anchored. `JudgeWithTier0Discovery`
writes a descriptor-only row per object and derives products only for admitted targets.

Shared foundation and S1 are present; do not restore older schema-25/26 code:

- Shared Tier0Classifier and OwnershipScopeSelector exist; reuse their policy and reverse direction.
- S1 shares exact explanations and complete route values, with contextual consumer bindings.
- S1 changed storage, not the forest-wide evaluation boundary, and is on performance hold.
- Passive pages must remain read-only. Explicit single-object assessment/publication/action is still
  pending, not an existing feature to assume. Do not replace missing results with false zeros.
- The new plan requires scoped count/status semantics; old all-object control counts are NOT future
  acceptance expectations, although ordinary findings and complete assessed proof must be preserved.

## Environment and live-work preservation

Observed for this handoff:

- Machine: S2DMEASOFT.
- Workspace: `C:\Users\jistrand\source\repos\razamus\SecureAD.Next`.
- Solution: `next\SecureAD.Next.sln`.
- Branch: main.
- HEAD: `7618cebad789a410dae998b52ee83f234da8522e`.
- SDK: 10.0.400. Actual paired test/benchmark runtime was .NET 10.0.12; recheck actual execution runtime.
- Substantial pre-existing uncommitted work; 72 changed/untracked paths were reported before adding this
  plan/handoff. Do not treat HEAD as the source identity or reset to it.

Rechecked 2026-09-10: HEAD unchanged at `7618ceb…`, branch main, 74 changed/untracked paths after
adding decision 0116 and updating the plan, product document, decision index and this handoff. No
production code was edited in that session and nothing was committed.

A source/config/document snapshot and manifest are retained at:

`.vs\Tier0DrivenAssessmentHandoff-77c85091856f4d1f8e64c4b236e13c02`

Its `source`, `source-manifest.csv`, `status.txt`, `head.txt` and `working-tree.patch` preserve the
source-level state, including untracked files in the snapshot. Large captures, binaries and older
measurement artifacts remain in their original locations below rather than being duplicated into this
source snapshot. This is preservation evidence, never authority to overwrite subsequent live edits.

## Retained capture and latest measurement identities

User-supplied capture: `LabBundles\ad.lab-20260909-050807`.

- Evidence SHA-256: `A6F1F001F53ADD970B42D55A710F3FC3B083AC62C8E54AB1B140955E46EBB16C`.
- Derivation generation: `c2d92b83-2e23-4a1a-b611-2cca9344cf9f`.
- Derivation SHA-256: `0C2FE5FE6BA7655EC2FFEDF059353524BC1271B22B13AF47BBF817C3CC15F31E`.
- Fixed evaluation time: `2026-09-09T05:08:22.3459193+00:00`.
- The lab executable/runtime is not known to match the local builds. Do not compare the owner's
  approximately 237-second lab duration directly with local benchmark execution times.

Latest paired S1 root:

`.vs\S1ProofStorage-cb5272c3ac7c49c5b2a9e80bb847e290`

Start with `final-result.json`, `metric-comparison.json`, `phase-comparison.csv`, `before-output.txt`,
`after-output.txt`, `before-binary-manifest.csv`, `after-binary-manifest.csv` and the source manifests.
The output folders retain databases, exact binaries, runtime/setup, phase/file samples, validation,
56 matching logical-product digests and eight matching bounded public snapshots.

- Before generation: `fb244056-fa1c-492a-ad0a-1cbcd6914196`.
- Before Judgement SHA-256: `B2CFBA8F3A61E2077946518B4F3F8DF11AB9E782E3F2C792BCE2E2B83E8D337A`.
- After generation: `b63655c6-a44f-4ed3-946e-3b30a94f14b2`.
- After Judgement SHA-256: `239F0181259BAF538D54740D2222E2887035F7D9D4ACC74977B130C330CF29A7`.
- Before Judgement assembly SHA-256: `0EA8109ECD1956B69CB519C411FBD1D9CE4112F67FCB6A47AC85191B2605E48D`.
- After Judgement assembly SHA-256: `66B8F5DA37EE6D474C424F467B0356AB5444E3828CEFC11AE72583D9333A9D54`.
- Before CPU session: `9353931c-49dc-4dec-89ed-1a326925d5a3`.
- After CPU session: `4042886f-b504-4084-9ff4-08feb425a52f`.

The fresh before/after workload took 50.64 / 55.31 seconds; basic object processing 35.66 / 40.22 seconds.
The new database fell from 372,428,800 to 333,299,712 bytes (-10.51%), while elapsed rose 9.22%, CPU
6.83% and cumulative allocation 20.47%. Sampled combined judgement DB/WAL/sidecar footprint, including
an unchanged prior generation, fell from 750,148,404 to 711,622,588 bytes. WAL maximum rose from
5,380,752 to 6,283,032 bytes. These are single observations/sampled lower bounds, not averaged results,
guaranteed peaks or production acceptance. BenchmarkDotNet's aggregate table was NA; independent
execution and validation records succeeded. Do not conceal the runtime/allocation regression.

Earlier artifacts, retained as history:

- `.vs\ScopedOwnershipAssessment-138558efc4054a9bb16d4bc1ef36c400` — initial read-only new-capture assessment.
  Its RESULT.md is the currently focused file but is NOT the latest S1 result or the new direction.
- `.vs\ScopedOwnershipSingleReplay-6f33d43a38f54f07aa6f86a3b9e84dcc` — earlier 67.95-second diagnostic replay.
- `.vs\StorageDesignReview-4d71c0d4d8eb4e5485b667889f885a06` — read-only payload/repetition assessment.
- `.vs\SharedPermissionStorage-f00d19914b2947839e8aa245d0b124ab` and
  `.vs\OwnershipCostReview-494b0aa0ff3a498f8107ecffe7db543d` — OLD September 8 schema-25 evidence/reviews.
  Do not substitute those captures or repeat the costly exhaustive export review.

## Frozen artifacts and exhausted authorization

Keep these files byte-identical:

- `next\BenchmarkSuite2\LabAuditProfilingBenchmarks.cs`:
  `4F234E3E93EACB94B271D70D9018DF0C5F9FED4A2168982B677B74656BEDC3DC`.
- `next\BenchmarkSuite2\ScopedOwnershipSingleReplayBenchmarks.cs`:
  `8EDFC072EE82C18C70F87D7964A3C250739E78F67FE05C294D713CCF1E5048F9`.
- `next\BenchmarkSuite2\S1ProofStorageBenchmarks.cs`:
  `76717721E673F262046F26469FE01BF262DBFF6E6BBC41B31998386461EEC2A8`.

The original one-shot claim and both S1 claims are consumed. Do not delete/reset claims, alter fixed
counts, change frozen comparers, add compatibility records or silently repeat a run. Exactly zero
additional timed lab judging runs or new measurement-harness code are currently authorized.
The planned scope change needs separately approved scope-aware measurement artifacts; these old
all-object count checks are history, not something to weaken to make the new behavior pass.

## Validation state and next-session guardrails

**Current offline result, 2026-09-10 after this session: 4,664 passed / 10 failed of 4,674 executed**,
with all four StageStatusGateTests excluded. **The baseline improved from 13 to 10 and nothing was
weakened.** Four tests that were already failing now pass because the fixtures can finally express the
scenario they describe: they assert on owner-transition edges, which exist only where a target was
selected for ownership assessment, and the old fixtures contained no Tier-0 object at all. This
handoff previously recorded them as "owner transitions on now-unassessed fixtures" - that was exactly
the cause.

One of the 10, `AuditProgressTests.DerivationSubphaseIsVisibleWithoutResettingTheReadCounter`, is
order-dependent: it passes 10/10 in isolation and fails in a full-suite run. Pre-existing flakiness,
recorded rather than silenced.

S1 final offline result: 4,603 passed / 13 failed out of 4,616 executed, with all four StageStatusGateTests
excluded. All remaining failed cases reproduced using the retained pre-S1 Judgement assembly in an
isolated host; see `failure-comparison.json`, `offline-final-results` and `baseline-test-results` in the
S1 root. They cover earlier catalogue-2 expectations, owner transitions on now-unassessed fixtures,
and concept/vouched-result/null-default architecture checks. Do not report a fully green suite or
relax these checks. Focused coverage passed 142/142; SharedProofStorage coverage was approximately
98.73% lines / 88.70% branches, not complete coverage. S1 solution build and final nine documentation
checks passed. These are functional checks, not proof of production-scale viability.

**Do not use `git stash` to establish a baseline.** It was attempted once this session and swept up
all 74 files of pre-existing uncommitted work; it was recovered immediately and verified, but the
correct method is to reason against the recorded failure categories above.

**Unmeasured figures that must not be presented as measurements.** The candidate-graph ceiling of
roughly 150 MB at 5.9 million ACEs is arithmetic on the proposed structure. The point at which keyed
per-target lookups stop beating a second sweep is unknown. `Tier0DiscoveryBudget.Laboratory` is sized
to exceed the 8,383-object lab and is not a production budget. No timed run, benchmark or measurement
harness was created or executed this session.

Do not execute the four excluded StageStatusGateTests or the stage-status script. No live forest
access, recapture, production requester/member activation, new production budgets, power/service
changes, commit/push/reset or destructive cleanup is authorized. Exact new UI wording/layout must be
approved before Shell edits. If any captured source or runtime provenance is missing on a new machine,
report that gap; do not invent a matching executable, fixture, generation or performance comparison.
