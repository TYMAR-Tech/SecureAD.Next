# Tier-0-driven assessment: implementation plan

**Status:** Owner-confirmed direction, recorded for implementation in a new session. No implementation
of this pipeline change has started. This planning session does not authorize new timed runs,
measurement harnesses, live work or unreviewed UI wording/layout.

Read [what the product is](../WHAT-THE-PRODUCT-IS.md) and the current repository instructions first.
Accepted decisions remain the authority for current behavior. The change below intentionally replaces
part of the all-object detailed-control contract under decisions
[0114](../decisions/0114-scoped-ownership-assessment-during-judging.md) and
[0115](../decisions/0115-share-judgement-explanations-and-membership-proof.md); do not rewrite those
historical decisions or claim this direction is already implemented.

## 1. Settled product boundary — do not reopen these questions

- Captured owners and permissions already exist in Evidence. No recapture, extra raw permission copy
  or new directory connection is proposed. Reuse those facts and their existing source identities.
- An unrelated ordinary account such as `jimmy.strand` does not need automatic detailed control,
  full-control or hypothetical owner-takeover assessment. Its captured facts remain readable and
  ordinary applicable audit rules still run, including existing ownership-finding rules where applicable.
- Detailed assessment becomes relevant when incoming controller/membership discovery from Tier-0 assets
  reaches the object, or through a separately approved explicit object investigation.
- Ownership is one possible control mechanism, not a separate reason to deeply assess every object.
  A current owner SID is a fact; an established control operation is a conclusion; changing ownership
  to obtain control is a further, potentially conditional conclusion. WRITE_OWNER is not proven takeover.
- Use the one authoritative Tier-0 definition and shared classifier. Controller relevance does not
  automatically relabel an object as confirmed Tier 0. Expected-administrator policy is not a scope filter.
- Build minimal shared path discovery and assessment admission together. Do not wait for a complete
  path UI, all-path enumeration, ranking or remediation product, and do not create a second ownership-only
  path/importance implementation.

## 2. The defect in the current ordering

`JudgingRun` currently calls `ControlEdgeDeriver.Derive` and writes control/full-control products for
all streamed objects. Only afterward does `OwnershipAuditRun.Assess` read those stored edges and select
where hypothetical ownership transitions run. Sharing the Tier-0 classifier did not remove that first
forest-wide detailed pass. Merely moving the existing selector call earlier cannot work: its current
input is the expensive store we need to stop requiring.

The latest code is schema 27/control engine 9/catalogue 3 with the S1 storage candidate retained.
S1's paired lab checks matched 56 logical products, but the new file was only 10.51% smaller while
elapsed time rose 9.22% and cumulative allocation rose 20.47%. Performance acceptance is on hold.
Do not resume string sharing, transaction tuning or evaluator micro-optimization as a substitute for
this work-boundary change. Do not automatically revert the existing candidate or other uncommitted work.

**Where the time actually goes, from the retained S1 `phase-comparison.csv` (before pass).**
`EvaluatingObjects` 35,655 ms of a 50,637 ms run; `SelectingOwnershipScope` 1,500 ms;
`AssessingOwnership` 3,564 ms. The unconditional per-object pass is roughly 70% of the run, while the
scope selection and ownership assessment it exists to serve are under 11% combined. The retained
`RESULT.md` records 112,093 basic control records and 23,751 full-control assessments across 8,407
observed targets, against 50 seeds, 840 relations, 51 selected targets and 210 ownership records.
These are single retained observations, not averaged results or production acceptance.

## 3. Target processing model

Keep the [application stage order](WORKFLOW.md) and the separation of Evidence, Derivation and Judgement.
Within judging, separate ordinary rule evaluation from control-product assessment admission:

1. Validate the pinned source generations and use the shared classifier's supported Tier-0 seeds.
2. Prepare reusable indexed identity/membership lookups from captured or already-derived inputs.
   A bounded data/index pass is allowed in the design; it must not invoke the full control evaluator
   for every object or silently materialize an expanded forest-wide permission model.
3. Queue the seeds. For each newly reached target, read its captured owner and ACL and identify
   supported potential incoming controllers. Resolve captured group membership and other supported
   dependencies using source-bound lookups. Queue newly relevant objects and retain the reason for inclusion.
4. Run detailed checks only for admitted targets and the operations required there. Existing detailed
   evaluators remain the semantic authority. Candidate discovery must not depend on their whole-forest
   output, and full-control aggregation must not be a prerequisite for discovering a possible controller.
5. Record supported conclusions and conditional/unsupported relationships distinctly. Publish the
   assessed scope, findings, relevant proof and incomplete coverage atomically, then read those results.

Use a visited set keyed by complete capture-local identity, not display names or unscoped builtin SIDs.
Retain alternative predecessor reasons without evaluating the same target repeatedly when it is reached
by several routes. Follow incoming control relationships, not an administrator's outgoing management
of ordinary objects. Do not repeatedly enqueue an entire subtree or enumerate all possible paths.

**Avoid a circular prerequisite:** a possible owner/WRITE_OWNER relationship may justify further
inspection before takeover is proven. Its eventual Unknown result must not erase the potential route
or turn incomplete discovery into a safety verdict. A supported WRITE_DAC relationship does not need
an ownership simulation to establish that particular control step; retain alternative candidate facts.

**Verified 2026-09-10 — the circular prerequisite is concrete, in three places.**
`Tier0RelevanceRelation.FromControlEdge` is the only `ControlCandidate` constructor and throws unless
`edge.Id > 0` with a matching judgement generation, derivation generation and catalogue version, so the
discovery vocabulary is defined in terms of the store this slice must stop requiring.
`ownership_target.target` references `control_object(target)`, and `OwnershipAuditStorage.Observe` is
reached only from `ControlEdgeStorage.Write`, so an ownership target can currently exist only where the
detailed pass already ran. `ownership_relation.edge_id` references `control_edge(id)`, so retained
routes cannot outlive the edges. A capture-backed candidate source is therefore required before
Step 4 can gate anything; moving the existing selector call earlier cannot work.

**Verified 2026-09-10 — seeding does not require the control store.** `Tier0Classifier.QualifyMany`
accepts any sequence of `Tier0Target` and takes membership from `derivation.ReadMembershipInput()` in
the Derivation store. The targets it is given are built by `OwnershipAuditRun.Target(subject,
namingContexts)`, a pure function of the streamed object. Seeds can be assembled during the object
stream without any detailed evaluation.

**Verified 2026-09-10 — no rule consumes the control store.** All 17 `IRule` implementations read
permissions from Evidence through `context.Permissions`; none read `control_edge`, `control_object` or
full-control products. Removing the unconditional pass does not alter ordinary findings. An earlier
check that appeared to confirm this searched a non-existent `Rules/` directory and returned no matches;
that result established nothing and was redone against the real files.

**`SelfMembershipScheduler` is the working precedent for Step 3.** It observes each streamed object's
captured ACEs, collects candidate pairs, reports typed limitation reasons (`BroadTrustee`,
`DescriptorIncomplete`, `ProductionBudgetNotConfigured`, budget-exceeded stops) and exposes `Requests()`
and `Coverage()`. Model the discovery service on it rather than inventing new coverage semantics.

**Do not promise a small scope:** broad control, Everyone/NULL DACL, deeply nested groups or genuinely
large controller sets can make much of the forest relevant. Represent broad/unresolved controller
sets explicitly rather than inventing individuals, silently clipping them or claiming closure after
skipping them. Define their treatment at the contract gate; do not choose an unmeasured production
budget or silently fall back to detailed evaluation of every object.

## 4. Shared responsibilities and contract gate

The recommended component is a shared, capture-backed relevance discovery service in Judgement,
separate from ownership-specific orchestration. It can use Judgement's existing capability vocabulary
without reversing the Derivation-to-Judgement assembly boundary. Keep the authoritative classifier in
Derivation. Future Tier-0 path presentation must consume the same discovery facts and inclusion reasons,
not recalculate importance using another policy. No new project, database engine or orchestrator is needed.

Before production edits, settle and record the following concrete contract changes under the repository's
approval process. Check current decision/schema numbering then; no new number is reserved by this plan.
Do not ask the owner to redefine Tier 0 or explain again why unrelated accounts should not be deeply assessed.

| Concern | Required contract |
|---|---|
| Candidate relation | Source/semantic versions; exact target/controller identity and resource scope; relation/operation kind; original ACE ordinal, owner or membership witness; reason and uncertainty. It is not an effective-authorization verdict. |
| Discovery coverage | Seed qualification, input completeness, supported relation kinds, processing completion, unresolved/broad sets and remaining work. The current classifier's unsupported asset/membership/control/dependency bases stay explicit. |
| Admission/work accounting | Separate raw records indexed, candidates inspected, objects reached, detailed control/full-control calls, ownership-transition calls and stored proof. Traversal completion is not complete security coverage. |
| Detailed-result coverage | Distinguish assessed, assessed-with-limitations, not assessed automatically, unavailable inputs and incomplete processing. An absent detail row is not a known empty permission set. |
| Reader/count contract | Ordinary object facts still come from Evidence. Control/holder counts cover the explicitly assessed scope, not a fictional complete forest. A captured but unassessed target is distinct from an absent or unreadable object. |
| Publication/integrity | Bind results and witnesses to the exact Evidence, Derivation, policy and assessment generation. Preserve cancellation, rollback, previous-generation selection and read-only page access. No compatibility records to keep obsolete counts passing. |

Candidate extraction must be conservative within its stated supported scope. Account for deny/order,
object-specific and callback ACEs, SELF, OWNER RIGHTS, NULL/unreadable DACLs, group type, primary groups,
SID history where supported, foreign/builtin scope and identity ambiguity. Reuse existing normalization
and semantic authorities; do not copy a permissive approximation of an evaluator and call it verified.
Unsupported cases retain source-linked uncertainty, not an empty success or blanket exclusion.

## 5. Bounded implementation sequence

### Step 1 — Verify the live baseline and finalize approval boundaries

**Complete, 2026-09-10.** Baseline verified on S2DMEASOFT, branch main, HEAD
`7618cebad789a410dae998b52ee83f234da8522e`, with substantial pre-existing uncommitted work preserved
and no snapshot restored. The three code findings and the phase timings recorded in sections 2 and 3
above were established in this step. The contract gate closed with owner-accepted decision
[0116](../decisions/0116-discovery-first-assessment-admission.md), which settles broad-principal
treatment, Judgement schema 28, the scope wording and route retention. S1's performance hold and the
exhausted measurement allowance remain in force. Do not reopen these questions.

Read the local handoff, current instructions, this plan and the linked S1 result. Check machine, branch,
source manifests and runtime before edits; never restore an old snapshot over later work. Record the
new admission, coverage and read/count contracts and the exact changed automatic behavior. Obtain
approval of those concrete contracts and any changed UI text/layout before their implementation.
Keep S1's performance hold and exhausted measurement allowance explicit.

### Step 2 — Specify the acceptance fixtures and baseline observations

Use bounded offline fixtures with a Tier-0 seed, unrelated ordinary users, direct controllers,
nested security membership, multiple routes, cycles, conditional ownership, denies, missing inputs,
ambiguous cross-domain identities and broad principals. Establish expected relevance independently
from captured facts and the policy, not by using the new selector to generate its own expected result.
Add a negative control proving the call-count test detects deliberate evaluation of an unrelated object.
Reuse retained lab diagnosis; no new timed run or harness is authorized by this plan.

### Step 3 — Build captured-fact adapters and shared reverse discovery

Inspect existing persisted indexes before adding anything. Provide targeted owner/ACL and membership
lookups and compact source references, not another copy of all permission proof. Build the shared
queue/visited/reason/coverage service without requiring completed control products. Qualify seeds through
the shared classifier, retain supported conditional candidates, and expose missing support honestly.
Keep per-target discovery separate from the expensive full-control/ownership routines.

### Step 4 — Gate detailed assessment in the real judging path

Wire discovery and admission into `JudgingRun` in the same vertical slice; a standalone unused selector
is not completion. Keep the forest-wide rule pass and its existing findings independent. Remove the
unconditional control/full-control evaluation and proof write for unrelated targets. Reuse the existing
assessment code for admitted objects without rewriting its permission semantics. Assess a target once
per generation; retain subsequent inclusion reasons without re-evaluating it.

The first correction may reuse the existing detailed evaluator for admitted targets to keep the
migration bounded. Avoiding unnecessary full-control aggregation within that admitted set is a
separately explicit refinement, never a reason to retain the unconditional forest-wide pass.

### Step 5 — Persist and present scoped results without misleading users

Version changed disposable storage/results as required; preserve old generations and frozen comparers.
Store a genuine assessed-scope manifest and enough source-bound candidate facts for replay/future paths,
not dummy per-object control records. Migrate every reader/count consumer of the old all-object contract,
including object, holder and any member-attribution views. Unsupported combinations must say so and
remain inactive, not synthesize missing detail. Show owner and raw permissions independently of detailed
assessment availability. Proposed meanings are "detailed control not assessed automatically" and
"results cover assessed targets only"; exact wording/layout still requires owner approval.

Do not invent an on-demand button or silently compute details in a getter. The explicit object runner
and immutable target-result publication are still pending; reuse this assessment boundary when that
separately approved feature is built. Passive pages remain read-only throughout this slice.

### Step 6 — Prove behavior, admission and failure boundaries

**Steps 2, 3 and 4 implemented 2026-09-10.** What exists now:

- `Tier0DiscoveryScheduler` observes each streamed object's captured owner and ACEs and collects
  candidates without invoking any evaluator, modelled on `SelfMembershipScheduler`. `Tier0Discovery.cs`
  carries its budget, typed reasons, limitations and coverage.
- `Tier0RelevanceRelation.FromCapturedPermission` and `Tier0CaptureWitness` break the first chain: a
  candidate no longer needs `edge.Id > 0`. `FromControlEdge` is unchanged for edge-sourced relations.
- `ownership_relation` is re-anchored — `edge_id` nullable beside witness columns, with a CHECK
  enforcing exactly one provenance. Judgement schema **28**, checkpoint added rather than replaced.
- `Tier0AdmissionRun` classifies seeds, feeds capture-backed candidates to the existing
  `OwnershipScopeSelector`, persists the decision, then derives products only for admitted targets.
- 47 new tests: 28 admission acceptance cases with a two-part negative control, 10 capture-backed
  relation cases, 9 integration cases driving the real `JudgingRun`.

**The third chain did not need breaking.** Because every streamed object keeps a descriptor-only
`control_object` row — owner-approved, so "captured but unassessed", "unreadable" and "absent" stay
distinct — `ownership_target.target REFERENCES control_object(target)` remains satisfiable and the
referential guarantee is kept rather than dropped.

**Three defects the fixtures caught, recorded because each would have measured nothing.**
`OwnershipScopeSelector.CompareRelations` omitted capability and relied on unique edge IDs to keep
relations distinct, so capture-backed candidates would have collapsed independent routes; the fix was
verified by disabling it and watching the test fail. Holder resolution used distinguished names only,
but a descriptor stores its owner as a SID, so every owner route would have been silently lost.
Coverage was order-dependent, under-reporting limitations to a caller who read it before the
candidates.

**Gating is opt-in, via `JudgingRun.JudgeWithTier0Discovery`.** Enabling it unconditionally failed 176
existing tests whose fixtures state expectations as forest-wide control counts. Those are exactly the
counts this decision calls history rather than oracles, but re-anchoring them under scope-aware
identifiers is a session of its own, and weakening them to obtain a green total is forbidden. Offline
result: 4,649 passed / 14 failed of 4,663, four StageStatusGateTests excluded. The 14 match the
handoff's known categories and none names a type introduced here.

**Outstanding before the default can flip:**

1. **Fixture re-anchoring is complete.** Measured with gating forced on, gate-caused failures fell from
   89 parameterised cases to **5**, and all five are artefacts of the temporary measurement switch
   rather than real: each explicitly calls the unscoped entry point by design, and the switch forced
   gating on every call so none could opt out. All five pass on the real path. Six Shell workflow
   suites and `OwnershipAuditIntegrationTests` were re-anchored; the switch has been removed.
2. Obtain owner approval for the exact scope-wording rendering and placement, then make the Shell edit.
   **This is the remaining blocker.** Until then a gated run's counts are scoped without the
   qualifying sentence on screen, which a reader would take for a forest-wide total.
3. Establish a production `Tier0DiscoveryBudget`. `Laboratory` is sized to exceed the 8,383-object lab
   and is explicitly not measured against the nine-domain shape.

When the default does flip, the tests deliberately kept unscoped need an explicit unscoped entry point
rather than relying on the default. They are marked in place with the reason: two assert the 0114
contract that 0116 removes and have scope-aware counterparts beside them
(`UnadmittedTargetIsNotAssessedAndSaysSoWithoutClaimingSafety`,
`AnUnadmittedOrdinaryTargetHasNoDetailedProductsAndSaysSo`); one needs 103 owned organizational units
to exercise reader paging, which discovery is right to decline.

**How fixtures were re-anchored, and what it cost.** `SelfMembershipDiscoveryTests.Bundle` gained an
opt-in `tier0Route`, writing a genuine Tier-0 group owned by each captured principal. Ownership was
chosen over a DACL grant because an owner sits on the descriptor rather than in the ACL, so it adds
no row to a *target*-view count. It is not free: it produces an existing-owner edge visible in
*holder*-view queries for the owning SID, so three suites that count holder rows needed their
assertions anchored to the capability they are about rather than to being the only row present. That
is recorded on the parameter rather than left as a surprise.

**A fixture that could not express its own scenario.** Re-anchoring fixed four tests that were already
failing before this work: three `ControlEdgeSizingTests` ownership-wording cases and
`FullControlDoesNotDischargeTheLiveOwnerChangeGate`. Each asserts on an owner-transition edge, which
exists only where a target was selected for ownership assessment. The old fixtures contained no Tier-0
object at all, so nothing was ever selected and the edge never existed. The handoff recorded these as
"owner transitions on now-unassessed fixtures"; that is exactly what they were. The offline baseline
is therefore **10 failures, improved from 13**, with none weakened.

`AuditProgressTests.DerivationSubphaseIsVisibleWithoutResettingTheReadCounter` is order-dependent -
it passes 10/10 in isolation and fails in a full-suite run. That is pre-existing flakiness, not a
regression from this work, and it is recorded rather than silenced.

**Dead surface removed after the slice settled.** `ControlEdgePage.DiscoveryCoverage` was declared and
never assigned, so it promised a reader something the product never supplied. Four
`Tier0DiscoveryReason` members - `NoQualifiedSeed`, `AmbiguousIdentity`, `MembershipNotCaptured` and
`MembershipCompletenessUnknown` - were never emitted by the scan, and their arms in the admission
mapping could never be taken; keeping them would have told a reader that discovery reports membership
incompleteness when this bounded scan does not read membership at all. `Tier0DiscoveryBudget.Laboratory`
is referenced only by tests and deliberately stays: `JudgeWithTier0Discovery` requires a
caller-supplied budget by design, and the constant exists so tests need not invent one.

**Naming-context roots, added 2026-09-10 under [0117](../decisions/0117-naming-context-roots-are-tier-0-assets.md).**
Re-anchoring `ReplicationWorkflowTests` exposed a real coverage gap rather than a fixture problem: a
partition root holds no SID, so no controller route can reach it, and replication rights are granted
*on the root*. On a domain root that combination is DCSync. Discovery-first as originally written
would have reported every partition root as not assessed automatically, in every forest, permanently.

Three changes closed it. `Tier0Basis.PartitionRoot` qualifies a captured naming-context head whose
object class agrees with the kind the capture recorded (`domainDNS`, `configuration`, `dMD`); a
mismatch is an unverified identity, not a seed. `Tier0Classifier`'s unique-identity precondition now
applies only to objects that actually carry a SID, since an object without one cannot have an
ambiguous one. `CapturedMembershipInput.Project` retains partition heads, which every earlier version
projected away as not principals - that is Derivation schema **12**, the tables unchanged and the
version carrying the difference, because a version 11 store does not contain the roots at all.

**Partition-aware consequence was already built and is retained.** `ReplicationControlDeriver` reads
the captured naming-context kind and records `ResourceContextUnverified` for any holder on a
non-domain partition under `P-90`, so a configuration or schema grant is reported as Unknown rather
than as established domain-secret exposure. Admitting these roots does not flatten that distinction.

**AD CS remains out of scope here.** The configuration partition holds `CN=Public Key Services`, and
enrolment ACLs are already captured, but the template settings that decide whether a template is
dangerous - `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag` and the application policies - are
not on the captured attribute catalogue. The owner has agreed to add them so the option stays open;
the rules that would read them are later work under `P-142` and `0099`.

**Unmeasured, and not to be presented otherwise.** The candidate-graph ceiling of roughly 150 MB at
5.9 million ACEs is arithmetic on the proposed structure, not a measurement. Keyed per-target lookups
beat a second sweep only while the admitted set stays a small fraction of the forest; where that
crossover sits is unknown and needs the nine-domain shape under separate authorization. No timed run,
benchmark or harness was created or executed in this session.

Run focused tests and the authorized offline suite with the four StageStatusGateTests excluded.
Maintain complete evidence comparisons for assessed objects and ordinary findings. Do not require the
old forest-wide control/full-control counts: reducing those products is now intentional, unlike S1's
storage-only change. Replace no frozen expectation in place; add separately identified scope-aware
acceptance tests and preserve the old measurements as history. Investigate new failures against the
retained baseline; do not weaken the known failing tests merely to obtain a green total.

### Step 7 — Measure only under a newly approved allowance

Before any new measurement artifact or timed judging run, obtain an explicit run count and fixed
workload. The previous single replay and S1 before/after claims are consumed and must not be reset.
Discovery tools must not mistake them for reusable compatible benchmarks. A new artifact must call the
real pipeline, separate rule work/indexing/discovery/detailed assessment/publication/readback, freeze
after its first successful run, and count the expensive calls that were actually avoided. No warmups
or averaging by default. Record exact builds/runtime/seals, final and overlapping DB/WAL/temp space,
CPU/elapsed time, allocation and memory, and scope/completeness. Old counts are not an acceptance oracle
for the intentionally changed scope. No production sizing promise follows from a lab ratio.

### Step 8 — Close the slice with a verifiable new-session record

Record changed behavior, remaining unsupported bases, proof/call-count tests, failures, exact measured
artifacts if authorized, and preserved originals. Completion requires the production path to avoid
unrelated detailed work and the GUI/API to disclose scope truthfully—not merely a smaller database.
Production-scale acceptance remains separate, using the recorded nine-domain shape and realistic
permission/membership complexity under explicit authorization.

## 6. Required acceptance cases

| Case | Required result |
|---|---|
| Unrelated `jimmy.strand` | Ordinary rule checks and captured facts available; zero automatic detailed control/full-control/owner-transition calls for that target and no detailed control proof written. |
| Jimmy reached through a supported possible Tier-0 route | Source-linked inclusion, relevant detailed assessment and inspection of incoming controllers; no automatic relabelling merely because of relevance. |
| Tier-0 administrator owns/manages an unrelated user | The outgoing relationship alone does not admit that user. |
| Conditional WRITE_OWNER / existing-owner route | Candidate retained and eligible for discovery; takeover certainty remains separate and Unknown where its gate is open. |
| Direct supported WRITE_DAC | That control step can be established without first proving an ownership transition; alternative source candidates survive. |
| Diamond routes / cycles | All necessary independent inclusion witnesses retained; one assessment per target and no endless or all-path traversal. |
| Scope/case/identity ambiguity | Preserve exact evidence and builtin domain scope; do not resolve an ambiguous SID to an arbitrary object. |
| Missing seed qualification, membership or permission evidence | Typed incomplete/unavailable coverage, not safe/not-important/empty-success and no silent forest-wide fallback. |
| Broad controller sets | Explicit, source-bound treatment and honest completeness; no unapproved explosion or silent truncation. |
| Unassessed object and holder pages | Raw facts still readable; no fabricated full-control result, false forest totals or hidden assessment writes. |
| Cancel/crash/corrupt or redirected witness | No partial published verdict; previous generation remains selected and invalid proof is refused. |
| S1/new shared storage | Captured facts, valid complete proof and immutable references remain intact; no resumed storage micro-tuning or hidden weakening of checks. |

## 7. Starting code and outstanding limits

Read these existing entry points, then change only those required by the approved contract:

- `next/src/SecureAD.Judgement/JudgingRun.cs`: unconditional detailed object work and the independent rule pass.
- `next/src/SecureAD.Judgement/OwnershipAuditRun.cs`: currently selects from already-written control edges.
- `next/src/SecureAD.Judgement/OwnershipScopeSelector.cs` and `next/src/SecureAD.Judgement/Tier0RelevanceRelation.cs`: existing reverse traversal/reason semantics; adapt/reuse rather than duplicate policy.
- `next/src/SecureAD.Derivation/Tier0Classifier.cs`: shared classification, currently partial.
- `next/src/SecureAD.Judgement/ControlEdgeDeriver.cs`, `next/src/SecureAD.Judgement/FullControlDeriver.cs`, `next/src/SecureAD.Judgement/OwnershipControlDeriver.cs`: expensive assessment admission points, not discovery prerequisites.
- `next/src/SecureAD.Judgement/JudgementReader.cs`, `next/src/SecureAD.Judgement/OwnershipAuditValidation.cs`, `next/src/SecureAD.Shell/Services/BundleAssetSource.cs`: coverage, validation and passive-reader consequences.

Current S1 verification was 4,603 passed / 13 failed offline, with those failed cases reproduced using
the retained pre-S1 assembly; focused coverage was 142/142. The four StageStatusGateTests remain
excluded. Full Tier-0 asset/dependency qualification, explicit object assessment, production budgets
and production-scale acceptance are not silently supplied by this plan. No live access, recapture,
service/power changes, new production activation, commit/push/reset, destructive snapshot restoration
or automatic deletion of old generations is authorized.
