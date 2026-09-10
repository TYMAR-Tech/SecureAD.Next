# The judgement store

**Code:** `next/src/SecureAD.Judgement/`
**Layer:** Judgement — where what the rules concluded is kept, and why it is not kept with the evidence.

[`what-a-finding-is.md`](what-a-finding-is.md) says what a rule makes of an object. This page is
where that answer goes: a second database in the bundle's own directory, written after capture has
finished and sealed separately from the evidence it judged.

**Current storage:** judgement schema **29**, control engine **9**, principal catalogue
**3**, with unchanged Evidence format and Derivation schema **12**. Shared explanation/route storage under
[0115](../../decisions/0115-share-judgement-explanations-and-membership-proof.md) is implemented locally
with paired lab proof parity verified, but performance acceptance is on hold because elapsed time
and cumulative allocation increased. This is not a production-acceptance claim. The
[scoped audit integration](#scoped-ownership-during-judging--schema-26) implements 0114. Full-control
catalogue-2/3 semantics remain supported within the current schema; older schema files require
re-judging under the existing schema policy and are not rewritten. The
[shared permission-proof storage boundary](#shared-permission-proof-storage--schema-25) records
the implementation, verified lab storage change and remaining acceptance limits; historical version records
below retain their original meaning.

**Schema 28 changes what stored counts mean.** Under
[0116](../../decisions/0116-discovery-first-assessment-admission.md) discovery decides which objects
receive detailed control assessment, so `ControlEdgePage`'s counts cover the assessed scope rather
than the captured forest. A schema 27 file and a schema 28 file are otherwise indistinguishable while
meaning different things, which is why the version rises although the tables do not change.
`ownership_relation` is re-anchored in the same release: `edge_id` is nullable beside witness columns
naming the captured owner or entry, because a route discovered before any control edge exists has no
edge to reference. Exactly one provenance per row is enforced by a check constraint.

**Schema 29 lets a reader tell which of those two meanings a file holds.** `control_product` carries
`discovery_scoped`, because a scoped product and a forest-wide one are otherwise the same rows with
the same columns. Without it the screen would either omit the scope caveat where it is needed or show
it where it is not, and the second understates real coverage as surely as the first overstates it.

**The shell judges through `JudgingRun.JudgeWithTier0Discovery`.** `JudgingRun.Judge` is retained for
callers that need the unscoped contract, including the tests that assert the pre-0116 state.

**Next-session priority:** the owner clarified that automatic detailed control work must follow
Tier-0 relevance, not precede its discovery. The
[Tier-0-driven assessment plan](../../next/PLAN-tier-0-driven-assessment.md) replaces the dependency on
an already-expanded forest-wide control store. It is not implemented yet and does not resume S1
micro-optimization or authorize another timed run. S1's code, results and performance hold remain retained.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `JudgementSchema` | Every table in a judgement store, and the indexes built once writing is done |
| `JudgingRun` | Judging a sealed bundle: read every object once, offer it to every rule, write what they concluded |
| `JudgingPhase` | Transient preparation, evaluation, writing, publication and readback progress; not a stored outcome |
| `JudgementWriter` | The one way a judgement store gets written |
| `JudgementReader` | Reads a store back, and refuses one that does not belong to the bundle it sits in |
| `JudgementDescription` | What one judging recorded about itself |
| `StoredJudgement` | Everything a judging concluded: what it found, and which rules were run to produce it |
| `StoredRuleExecution` | One rule's execution, read back |
| `StoredRuleExecutions` | Every scheduled rule's execution, beside the state of the judging that produced them |
| `RuleExecution` | Everything one rule did to one bundle, and the unit the store commits |
| `MissingInput` | One declared attribute that was not captured, and how many objects it cost |
| `JudgementRunState` | What became of a judging run as a whole |
| `RuleExecutionOutcome` | What became of one rule within that run |
| `FindingsQuery` | What a findings grid asks for: which findings, and where to carry on from |
| `FindingsPage` | One page of findings, and whether there is another |
| `FindingsPageMark` | Where a page of findings ended, so the next can start after it |
| `FindingsFilterValues` | What a findings grid's filters may offer, taken from the findings that exist |
| `ControlCapability` | The supported bounded control capabilities, not the complete stage-6 catalogue |
| `ControlEdge` | A stored capability attributed to its named trustee, with evidence and independent expectedness |
| `ControlEdgeClass` | Semantic categories, never severity or an ordered risk score |
| `ControlEdgePage` | A bounded page with generation, coverage and counts, including hidden expected edges |
| `Tier0RelevanceKind` | Qualified membership versus control/dependency candidates, not a Tier-0 label |
| `Tier0RelevanceRelation` | Immutable controller-to-affected relation referencing source membership or a stored permission |
| `Tier0CaptureWitness` | The captured owner or ACE behind a discovered candidate, so a route needs no stored control edge |
| `Tier0DiscoveryReason` | Why discovery cannot claim complete coverage, never a statement that unreached objects are safe |
| `Tier0DiscoveryBudget` | Explicit bounded scan limits; no production default has been measured |
| `Tier0DiscoveryLimitation` | One limitation bound to the captured target, entry ordinal and trustee that caused it |
| `Tier0DiscoveryCoverage` | What the scan inspected and what stopped it, which is work accounting rather than security coverage |
| `OwnershipScopeState` | Included, outside the computed scope, or undetermined |
| `OwnershipScopeProgress` | Distinct visited-target, examined-relation and included-target counters, not permission counts |
| `OwnershipScopeSelection` | Immutable source-bound scope decisions, retained inputs, coverage and cancellation, with selector version |
| `OwnershipScopeSelector` | Reverse traversal over shared classifications and captured relations, now consumed during judging |
| `OwnershipAssessmentOrigin` | Automatic audit versus explicit object request |
| `OwnershipAssessmentExecution` | Not assessed, completed, limited, cancelled or failed execution |
| `OwnershipAssessmentAvailability` | Contract availability, staleness, unsupported versions or invalid proof |
| `OwnershipScopeDecision` | Selection references and coverage shared by the selector and ownership result contracts |
| `OwnershipAssessmentBinding` | Source/target/audit identities, evaluation time, owner-rights context hash and semantic versions |
| `OwnershipCandidateAssessment` | A retained WRITE_OWNER source reference with the still-open assignment gate |
| `OwnershipAssessmentResult` | Versioned result/attempt contract with structural validation, not an assessment store or runner |
| `OwnershipAuditCoverage` | Validated stored automatic assessment status and scope limitations for target or holder-view presentation |
| `FullControlAssessment` | A full-control summary assessment with separate permission proof and support links |
| `FullControlRight` | One required right and its ordered alternative sources, with an explicit completeness voucher |
| `FullControlSource` | Captured descriptor, holder, scope and expectedness inputs used to replay a summary |
| `MemberAttribution` | One stored holder expansion with member identities, retained links, representative routes and explicit completeness |
| `MemberAttributionBudget` | Configured node, link, stored-record and processing-time limits; no production default |
| `MemberAttributionDetail` | Generation-bound member evidence and separately stored resource applicability |
| `MemberAttributionLink` | An explicit or primary membership link retaining its source DN, attribute and ordinal |
| `MemberAttributionMember` | A distinct resolved, unresolved or unconfirmed member, with captured identity evidence |
| `MemberAttributionRoute` | A representative chain grouped by initial membership and linked to its parent route |
| `MemberAttributionState` | Established, not established or unknown membership/applicability, never a concrete access check |
| `MemberAttributionStop` | Explicit not-run and node/link/storage/time stopping reasons |
| `MemberPermissionPage` | A bounded reverse page of source permissions with generation and completeness |
| `MemberPermissionReference` | A source group-held permission, not a newly counted member edge |
| `MemberResourceApplicability` | Stored group-route usability for one member in one resource context |
| `ControlEvaluationState` | Whether a capability is established, not established or unknown |
| `ControlExpectedness` | Whether control is expected, unexpected or not yet classified |
| `ControlExpectednessReason` | The stored reason for that separate classification |
| `ControlObjectEvaluation` | Per-object coverage, retained even when no edge can be identified |
| `ControlPrecondition` | A named condition with its own evaluation and evidence source |
| `ControlUncertainty` | Explicit unresolved inputs that limit a capability claim |
| `SelfMembershipRequest` | One explicit user, target group and add/remove own-account question |
| `SelfMembershipBudget` | Deterministic limits for a bounded requester batch |
| `SelfMembershipAssessment` | Stored authorization, own-account and readiness answers with their evidence |
| `SelfMembershipAssessmentSet` | Readback voucher distinguishing no scheduled request from no product |
| `SelfMembershipOperation` | Whether the explicit own-account request adds or removes membership |
| `SelfMembershipIssue` | A missing input or known readiness blocker that limits the answer |
| `SelfMembershipAceEvidence` | One original permission entry beside requester applicability and scope |
| `SelfMembershipDiscoveryBudget` | Explicit work limits for an automatic scan; no production default is chosen |
| `SelfMembershipDiscoveryMode` | Whether questions came from explicit requests or an automatic scan |
| `SelfMembershipDiscoveryReason` | Why coverage is limited, keeping missing evidence, unsupported routes and processing stops apart |
| `SelfMembershipDiscoveryLimitation` | One limitation bound to the captured target, permission, trustee or member it came from |
| `SelfMembershipDiscoveryCoverage` | What the scan examined and where it stopped, never a claim about the forest |
| `SelfMembershipSummary` | Generation-bound counts and coverage read without loading every assessment |
| `OwnershipCountLimit` | Why a stored ownership count is a placeholder rather than a measurement |
| `OwnershipAuditCount` | A stored ownership count that says whether it was measured, and if not what prevented it |

<!-- TYPES:END -->

---

## Shared Tier-0 relevance and ownership contracts — decision 0112

The [shared foundation](../derivation/what-stage-2a-derives.md#shared-tier-0-foundation--decision-0112)
supplies classifications and positive membership witnesses. `Tier0RelevanceRelation` belongs to
Judgement, outside ownership-specific evaluation. A checked effective-membership support becomes a
directed relation from the member to its core root. A persisted control edge becomes an operationally
unqualified candidate, preserving its source edge ID, audit/Derivation generations, catalogue version,
permission conclusion and uncertainty. Expectedness changes neither direction nor relevance. A proven
WRITE_OWNER/WRITE_DAC permission is not silently promoted to operational Tier-0 control.

The ownership contracts separate automatic scope, request origin, execution, candidate conclusions and
availability. `OwnershipAssessmentBinding` includes the complete shared input binding, target/resource
identity, audit generation and (for explicit requests) source audit seal, evaluation time and a hash of
the relevant owner-rights context. Automatic results do not embed their enclosing audit's own seal.
`CheckBinding` distinguishes stale identities from unsupported versions and malformed contracts.
`CanPublish` rejects failed/cancelled attempts, contradictory scope and invalid candidate contracts;
it performs no publication. All candidate owner transitions remain Unknown and must retain the open
`CanSetTakeoverOwnerSid` check. A completed request with no candidates is distinct from not assessed.

**Structural contract validation is not seal verification, permission replay or a complete relevance
selector.** A future writer/reader must still qualify selection routes to core anchors, verify all
referenced source files and replay permission proof. This slice adds no tables, automatic scope switch,
ownership evaluator integration, object runner, cache or Shell action. Current audits still produce
their existing owner transitions for all retained WRITE_OWNER assessments. Capture, rules, existing-owner
findings, full-control supports and counting are unchanged. The explicit metadata delta is catalogue
3 on newly generated control/full-control results; catalogue-2 proof retains its original recorded
version and remains replay-readable. Other full-control catalogue versions are still rejected.

The accepted [0112](../../decisions/0112-shared-tier-0-classification-and-ownership-contracts.md) and
[Stage 6 contract](../../next/SPEC-stage-6-control-edges.md#15-proposed-shared-tier-0-and-ownership-contracts)
govern the first slice and later boundaries. Final foundation validation passed the solution build,
133 focused tests and 281 additional ownership, permission, storage-integrity, architecture,
public-surface and documentation checks: **414 distinct targeted tests**, not the full suite. The
focused tests cover canonical policy identities, original-membership negative controls, independent
supports, direction, stale/malformed contracts and catalogue-2/3 stored full-control readback.

All 133 focused tests also passed under `dotnet-coverage` on test-host runtime **.NET 10.0.12**. The
collector reported these executable source-line hits for that focused run only:

| Source | Hit lines | Reported executable lines |
|---|---:|---:|
| PrincipalClassificationRegistry | 93 | 100 |
| Tier0Classification | 52 | 53 |
| Tier0Classifier | 160 | 166 |
| OwnershipAssessmentResult | 56 | 60 |
| Tier0RelevanceRelation | 48 | 48 |

These are neither complete branch coverage nor proof that every semantic case is tested. Test and
coverage artifacts are retained locally, not required by this document or clean-clone validation.
Read-only review found no concrete defect within the implemented boundary. The handoff source-manifest
comparison found all **1,004 existing files outside the 11 approved changed files byte-identical**;
the frozen benchmark source hash also matched. No snapshot was restored over live work.

This is offline functional validation, not production scale, an ownership lab-gate result or a cost
measurement. At that foundation checkpoint, automatic selection, target-specific publication/replay,
object execution and UI remained unimplemented. Frozen benchmarks and the four excluded stage-status tests remain untouched. Existing
full-suite progress-test intermittency and instrumentation-sensitive scanner limitations are not
closed by these targeted runs; no production acceptance or performance improvement is claimed.

## Offline ownership scope selector — decision 0113

**Implemented as a callable library, not connected to judging or the UI.** The owner approved this
bounded slice under [0113](../../decisions/0113-automatic-ownership-scope-follows-shared-relations.md).
`OwnershipScopeSelector.Select` consumes one shared input binding, one audit generation, existing
classifications, supplied captured relations and explicit source coverage. It creates no Tier-0 list
and performs no membership discovery. Established shared classifications are starting points; their
original proofs already identify core objects or supported effective members. Further selected
controllers retain their original classification rather than being relabelled Tier 0.

The selector follows **incoming** relations. It never includes an ordinary object simply because a
Tier-0 administrator manages it. Possible WRITE_OWNER/ownership relations remain eligible for relevance,
without establishing the operation or a completed path. A disproven source permission is retained in
the input inventory but does not propagate inclusion. Unresolved holders, placeholders and unverified
resource contexts cannot be guessed into controller identities. Unsupported dependency qualification
remains a coverage limitation, not a new implemented dependency capability.

Each selected target is visited once. All distinct incoming source relations at visited targets are
counted as examined, including those rejected for propagation; independent usable relations are kept
as inclusion reasons. Cycles terminate and shared controllers keep alternative reasons without
enumerating all paths. Input ordering does not change the completed decisions or control-relation
reason order. Conflicting GUID/DN/scoped-SID identities block propagation and disclose incomplete
scope. Different BUILTIN domain scopes are separate identities. Mixed capture/audit generations and
conflicting payloads for the same source-edge ID are rejected rather than merged.

Cancellation during input reading or traversal returns a `WasCancelled` snapshot with processing
incompleteness and any discovered inclusions/reasons. Cancellation is not swallowed as successful
completion; an unrelated callback failure still propagates. The result retains consumed original
classifications and relations, its source identities, and **SelectorVersion 1**, independent of the
principal classifier and ownership evaluator versions. Passive `For` lookup never restarts selection;
an unlisted target returns `Undetermined` with an input limitation.

Finishing traversal does not remove upstream limitations. Current shared classification producers are
partial, so their uncovered objects remain `Undetermined`, not definitively outside a complete forest
scope. Results satisfy the existing `OwnershipScopeDecision` structural contract, but are not sealed
stores or proof that an audit may publish after cancellation. This slice supplies no production budget
and does not use the existing membership-expansion defaults.

The 34 synthetic selector tests cover direction, chains, cycles, independent grants, disproven sources,
generation isolation, ambiguous identities, scoped BUILTIN principals, membership-witness reuse,
deterministic order and partial cancellation. A negative-control test caught an undercount of examined
disproven relations; it failed before the fix and passed afterwards, without changing inclusion
eligibility. Final validation passed the solution build and **448 targeted checks**, comprising these
34 tests plus the 414 foundation, permission, ownership, storage-integrity, architecture and documentation
checks. This is not a full-suite acceptance run.

The 34 selector tests also passed under `dotnet-coverage` on test-host runtime **.NET 10.0.12**. The
focused report recorded 209/217 executable source lines hit in `OwnershipScopeSelector` and 25/25 in
`OwnershipScopeSelection`; this is not complete branch coverage or proof of every semantic case.
Read-only review found no concrete defect within this slice's boundary. The fresh source-hash baseline
contained 1,023 files: all **1,017 files outside the six approved existing-file changes remained
byte-identical**. The frozen benchmark hash matched; no snapshot was restored. Test/coverage artifacts
are retained locally and are not prerequisites of this document or clean-clone validation.

At that selector-only checkpoint, audit integration and UI presentation were still pending and schema
25/engine 8 remained active. The subsequent schema-26 slice below implements audit integration and
status-only presentation. Explicit object execution and its separate target-specific publication
remain pending. No cost or production-acceptance claim follows from the selector tests.

## Scoped ownership during judging — schema 26

**Implemented under [0114](../../decisions/0114-scoped-ownership-assessment-during-judging.md).** New
judging runs use schema 26/control engine 9. They first retain basic permissions, existing-owner
control and full-control summaries while offering each captured object to each scheduled rule once.
Hypothetical owner transitions are deferred. The shared classifier's indexed `QualifyMany` path and
the existing reverse selector then determine the automatic scope; only selected targets receive
the detailed `OwnershipControlDeriver.Transition` evaluation. This changes which hypothetical
assessments run, not the underlying permission inventory, expectedness, existing-owner findings or
group-held counting. An unassessed WRITE_OWNER primitive remains an alternative candidate, not a
discarded relationship or a safety verdict.

The classifier builds one DN/scoped-SID/domain-root index for a batch and uses the same evaluator as
single-object classification. Supplied memberships remain source-linked; there is no new discovery
or production expansion budget. Missing Derivation records unavailable assessment inputs. An invalid
present membership-input product refuses judging rather than being silently treated as absent.
Unsupported assets, memberships, direct-control qualification and dependencies remain explicit scope
limitations. The current partial classifier does not establish a complete forest scope.

Four additional tables live in the private Judgement generation before publication:

| Table | Purpose |
|---|---|
| `ownership_audit` | Versioned source/evaluation bindings, owner-rights context hash, coverage, expected row counts and completion |
| `ownership_target` | Capture-local identity, scope decision, execution status, candidate count and assessed-transition count |
| `ownership_seed` | Retained membership witnesses and fingerprints of qualifying shared classifications |
| `ownership_relation` | Source-edge references for inclusion links, without duplicating permission proof |

Selected-target append reuses existing `permission_entry` values by complete target/generation-bound
identity. It does not replace primitive IDs, delete alternatives or rewrite full-control supports.
SELF normalization and NULL-DACL holder identity retain their original meanings. A selected target
with an unreadable descriptor and no identified candidates is completed with limitations, not a known
empty answer. All owner-change compounds remain Unknown and uncounted behind the existing laboratory
gate.

Readback verifies counts and bindings, replays stored seed witnesses against the selected verified
Derivation, validates retained inclusion links against complete captured ACE values, and checks that
the retained relation graph reaches exactly the recorded included targets. This is verification of
stored proof, not new discovery or assessment publication. Raw proof validation is separate from the
existing display projection, which omits trustee explanation fields. Opening and paging write no new
analysis. A new immutable generation gets its own validation; ordinary page reads retain generation
checks and stored target-specific coverage.

The approved status text appears beneath existing control coverage: assessed automatically, not
assessed automatically, or required derived inputs unavailable, with the explicit incomplete-scope
warning when applicable. The holder view directs users to target-specific status. The two new progress
labels are **Selecting ownership assessment scope** and **Assessing ownership takeover**. No on-demand
button or new top-level screen is implemented.

Cancellation is passed through writer finalization and immutable publication, including checks after
sealing and before manifest replacement. A cancellation test exposed the previous gap at the publishing
phase and passed after correction. The manifest replacement remains the commit point: no cancellation
check after it reports an already-published audit as unpublished. An in-progress SQLite operation or
file hash may finish before cancellation is observed; no instant-stop guarantee is made. The previous
published generation remains selected when cancellation is observed before replacement.

The new schema-26 layout checkpoint is `AF47D06ABD44412895EB9BBE5799BC48D065D5638D32959CECF497F88B6881A4`,
observed from this build, not an external historical anchor. All schema-15 through schema-25 checkpoints
and frozen benchmark sources remain unchanged. Integration tests cover selected/unselected targets,
missing inputs, primitive-row parity, exact proof reuse, OWNER RIGHTS, SELF, NULL DACLs, passive
readback, removed/resealed witnesses, approved labels and cancellation. Final validation passed the
solution build and **533 targeted checks**, not a full-suite acceptance run. The focused coverage run
passed **31 integration, batch-classifier and publication tests** on test-host runtime **.NET 10.0.12**.
Its reported executable source-line hits were:

| Source | Hit lines | Reported executable lines |
|---|---:|---:|
| Tier0Classifier | 170 | 193 |
| OwnershipAuditCoverage | 12 | 12 |
| OwnershipAuditRun | 90 | 90 |
| OwnershipAuditStorage | 188 | 194 |
| OwnershipAuditValidation | 82 | 90 |

These are focused line counts, not complete branch coverage or proof of all directory semantics.
The integration's source-hash baseline contained 1,027 files. All **1,002 files outside the 25 approved
existing-file changes remained byte-identical**, and the frozen benchmark hash matched. No snapshot
was restored over live edits. Local test/coverage artifacts are retained but are not dependencies of
this document or clean-clone tests. The four excluded stage-status tests and cost workloads were not
run, and no commit or push was performed.

Desktop/monitor checks, production-scale acceptance and the separate explicit object-request workflow
remain outstanding. The ownership-assignment laboratory gate remains open. No timing, storage-saving
or production-budget claim follows from these functional tests.

## Proposed bounded proof-storage redesign and validation plan

**Status: S1 and its two-pass lab validation approved under
[0115](../../decisions/0115-share-judgement-explanations-and-membership-proof.md); implemented and both passes completed, with performance acceptance on hold.**
The owner requested a production-scale design assessment before further code changes, then approved
this bounded first slice. Keep the sealed Evidence / reusable Derivation / immutable Judgement
architecture, SQLite and the existing product semantics. Follow-ons, UI changes and production
acceptance are not approved by this decision. The scope under [0114](../../decisions/0114-scoped-ownership-assessment-during-judging.md)
remains the authority for automatic ownership assessment.

### Evidence and limits

The supplied capture is `ad.lab-20260909-050807`, with 8,407 objects. A single successful local replay
of schema 26/control engine 9/catalogue 3 on S2DMEASOFT, .NET 10.0.12, took 67.95 seconds including
completion readback. Basic object processing took 57.71 seconds; ownership selection 2.20 seconds,
selected assessment 5.65 seconds, publication 0.78 seconds and completion readback 0.66 seconds.
These are retained stopwatch boundaries, not averaged benchmark results. BenchmarkDotNet's aggregate
result was NA; the execution and validation artifacts separately record success. The sampled CPU
trace identifies database writing and commits as major costs, with selected-target permission reload
also material. This is not an improvement comparison with the owner's approximately 237-second lab
run: the lab executable, source revision and runtime have not been established as identical.

Read-only aggregates over the completed replay found:

| Content | Observed logical payload | Relevant distinction |
|---|---:|---|
| Full-control assessment JSON | 79,365,759 bytes | Includes per-right decisions and source context; not all repetition |
| Membership-route JSON inside those assessments | 16,921,009 bytes | 11 distinct complete values totaling 19,733 bytes |
| Permission trustee explanation text (`meaning`) | 14,108,474 bytes | 169,254 non-null uses of 15 distinct texts totaling 1,071 bytes |
| Target strings in table `target` columns | 34,221,994 bytes | Repeated names, including reference keys |
| Strings in `generation` / `derivation_generation` columns | 17,318,448 bytes | Repeated source identities |

Component figures overlap their parent JSON; do not add them twice. The 372,428,800-byte final
Judgement file includes 40 indexes, record/page overhead and numeric fields. Text/BLOB table payload
totals 240,333,914 bytes; the remainder is not a measured index-only total. The largest sampled
Judgement DB/WAL/sidecar footprint was 377,719,440 bytes; samples can miss brief peaks and exclude
external temporary files, retained earlier generations, inputs and filesystem allocation/compression.
None of these figures is a promised saving or a production sizing rule.

### S1: share repeated immutable values, preserve every answer

**Approved first implementation slice:** share exact trustee explanation text and complete
membership-route values within one Judgement generation. Keep per-permission source identity and
per-target/holder conclusions independent. Do not combine this with transaction batching, evaluator
changes or a new reader-validation lifetime; otherwise a regression cannot be attributed to one change.

| Storage concern | Proposed representation | Consumers in S1 |
|---|---|---|
| Repeated trustee explanation | A generation-local, versioned text-value table with integer references | `permission_entry.meaning`; reconstruct the original `PermissionTrustee.Meaning` before existing proof checks |
| Repeated membership explanations | One versioned complete route value, plus explicit consumer bindings | Control-edge routes and `FullControlSource.MembershipRoutes` |
| Per-consumer integrity | A checked binding from consumer identity/context to the referenced value | Every affected control edge, full-control assessment and permission entry |

The route value preserves the whole ordered `MembershipRouteSummary`: incompleteness reasons,
membership and route order, catalogue roots, authorization/protection flags, every step's scoped
identity and distinguished name, and primary-group markers. A repeated step is not an interchangeable
route. Neither alternative routes nor steps may be removed to reduce counts. Existing finding-owned
route storage and Derivation storage remain unchanged in this first slice; the Judgement-specific
adapter must not alter the shared `MembershipRouteStorage` implementation compiled into Derivation.

Full-control persistence should use an internal storage representation with a required route-value
reference instead of embedding the same route JSON again. Reconstruct the existing public model before
validation/presentation. Do not serialize a fake empty/NotDerived route in place of a required value,
add compatibility copies, or treat a missing reference as an empty successful answer.

**Identity and integrity contract:**

- Preserve text exactly: case, whitespace, null versus empty and the stored UTF-8 value. Do not
  resolve descriptions from a newer live catalogue or replace captured names with current names.
- Scope sharing to the immutable Judgement generation and exact Evidence/Derivation and semantic
  version bindings. Consumer bindings retain target identity, holder SID/resource scope and applicable
  entry ordinal or assessment identity. Identical payload bytes do not merge consumer meanings.
- Use a versioned encoding and indexed digest lookup, followed by complete value equality. A hash
  match alone is not permission to merge values. Fingerprints must bind both the exact value and its
  required consumer/source context; a redirected reference with a valid new payload hash must fail.
- Retain existing complete ACE fingerprints, flags, masks, GUID strings, callback bytes, source order,
  full-control rights/supports, expectedness and uncertainty. Shared text must reconstruct those same
  values before the existing checks run. Do not move integrity responsibility out of the proof chain.
- Create shared values and consumer references transactionally. A failed object leaves no dangling
  references or reusable IDs from its rolled-back transaction. Preserve the current object rollback
  guarantee and previous-generation publication guarantee. Do not introduce an unbounded whole-forest
  value cache; use indexed persisted lookup and transaction-scoped reuse.
- Passive reads remain read-only. No new discovery, derivation, membership expansion or assessment
  is triggered by reading a shared value.

S1 is confined to Judgement storage helpers, schema, write/read adapters, their tests and governing
documentation. `SharedPermissionStorage`, `ControlEdgeStorage` and `FullControlStorage` are the primary
existing entry points. Leave rule/evaluator logic, the shared Tier-0 classifier/selector, public result
contracts, Evidence, Derivation, production host budgets and Shell presentation unchanged. A future
format change requires a new Judgement schema version; the live tree was checked and 0115 assigns
schema 27 to S1. Engine 9/catalogue 3 retain their unchanged semantics.
Older sealed generations and their original readers/checkpoints are preserved, not migrated or
relabelled; current-format reopening follows the existing re-judging policy.

**Local implementation, performance acceptance on hold:** `shared_proof_value` retains versioned, source-bound
exact values; its indexed lookup digest is followed by complete ordinal equality. `permission_entry.meaning`
now references a text value and carries a target/generation/ordinal-bound `meaning_binding`, including
for null meanings. The original complete ACE association fingerprints are unchanged in purpose.
`control_membership_route` binds each control edge to its complete route value. Full-control JSON
omits the repeated membership property and uses required `route_value_id` / `route_fingerprint`
columns; readback reconstructs the public source before the existing evaluator checks.

Route values use the existing relational membership encoding once per shared value, under a private
`proof-route:` subject. Its existing writer/reader validation is reused without editing the shared
Derivation implementation. The complete value payload is checked against that ordered reconstruction;
these are not per-consumer compatibility copies. Finding-owned rows keep their existing encoding.
Caches belong to the object transaction, and a completed/rolled-back transaction cannot return its
cached IDs. Object transactions, evaluator replays, public counts and reader lifetimes are unchanged.
The schema-27 layout checkpoint is `B7CA7DBFC045647A5211E35E833C92626A712383300D0AC2C14D84E49C1E5ADF`,
observed from this build; every schema-15 through schema-26 checkpoint is retained unchanged.

### Follow-on work is separate, not hidden in S1

| Follow-on | Why it remains necessary | Boundary |
|---|---|---|
| Writer/lookup costs | Per-object commits, repeated commands and the measured full-table `SharedPermissionStorage.Load` | Separately measured command reuse, bounded transactions and a target/generation lookup index; do not weaken durability or object rollback |
| Repeated evaluation and validation | Full-control write validation replays the assessment twice after initial calculation | Define reusable validated inputs/results before changing verification; never simply remove corruption checks |
| Page-read cost | Full-control validation precedes pagination; GUI requests open new readers | A separately reviewed immutable-generation validation lifetime and page-local work; no safety claim from a stale cache |
| Other repeated storage | Long identity keys, generation strings and per-right JSON | Measure compact typed/reference forms separately; S1 does not collapse the 308,775 stored right checks |
| Ownership graph memory | Input/edge materialization and multiple relation collections grow with the graph | Compact or disk-backed indexed inputs without changing shared Tier-0 policy, completeness or retained alternatives |

This order is not approval for all follow-ons. S1 alone is neither a complete speed solution nor
production acceptance. Do not narrow basic auditing further, switch database engines, enumerate all
paths, or enable requester/member expansion to work around the measured storage costs.

### Implementation sequence and validation gates

1. **Approval and preservation.** Obtain explicit approval of S1's representation/contract and the
   separately described measurement allowance. Record the live HEAD, uncommitted production-source
   manifest, actual loaded runtime, application/benchmark/SQLite assembly hashes and build configuration.
   Preserve originals, previous results, golden fixtures and all pre-existing changes. Do not build over
   the only copy of a measured executable; retain the before build independently.
2. **Fix the external reference before coding.** Pin the supplied input seals, evaluation time and
   schema-26 public answers below. Inventory complete baseline shared values and every consumer binding
   independently of the proposed writer. Specify required null/empty, context, ordering and corruption
   behavior. A candidate cannot generate its own expected values or pass by matching counts alone.
3. **Prepare and freeze the comparison artifacts.** Discover usable existing artifacts first. If new
   schema-aware artifacts are approved, exercise the real production writer, completion readback,
   object-first and holder-first pages, repeated pages and selected-target append. Freeze their setup,
   input and comparison logic after the first successful before run. Verify negative controls before
   relying on the comparison; retain all outputs rather than deleting fixtures.
4. **Implement only S1.** Add exact-value sharing and checked consumer reconstruction without changing
   conclusions, transaction boundaries, evaluator/replay behavior or UI. Run focused tests as each
   storage seam changes; do not stack unrelated performance changes on top of a failing gate.
5. **Prove functional preservation and failure behavior.** Build the solution and run the focused
   storage/integration/presentation tests, then the authorized offline suite with the four
   `StageStatusGateTests` cases explicitly excluded. Separate uninstrumented correctness results from
   coverage results; do not hide known flaky/profiler-sensitive failures by weakening tests.
6. **Measure the identical workload after S1.** Use the same approved comparison artifact, collection
   tool, source inputs, runtime/configuration and read selections as the before run. Compare final
   DB bytes, DB/WAL/temp/retained-generation disk overlap, phase elapsed/CPU, allocations, working/private
   memory and first/repeated-page costs. Separate observer/profiler overhead and sampled lower bounds
   from guaranteed peaks. A faster writer with materially slower reads or higher peak memory is a
   regression to explain, not an unqualified improvement.
7. **Close the bounded slice or stop.** Require exact public-value/binding preservation, expected
   primitive/finding/coverage counts, all corruption controls rejecting, unchanged publication safety,
   and a measured net physical storage reduction including reference/index overhead. Report every
   timing/memory trade-off without inventing an acceptance threshold. A single observation is diagnostic,
   not statistical confidence. Stop for unexpected proof changes, unexplained material regressions or
   inability to establish parity without additional authorized work. Production acceptance remains open.

The focused test set includes `SharedPermissionStorageTests`, `ControlEdgeCommandReuseTests`,
`FullControlStorageTests`, `FullControlEvaluatorTests`, `OwnershipAuditIntegrationTests`,
`FullControlPresentationTests` and `FullControlWorkflowTests`; retain Derivation's membership-route
tests as a no-change boundary. New S1 tests must cover:

| Gate | Required cases |
|---|---|
| Exact values | All trustee fields; null/empty/case/whitespace; masks/flags/GUIDs/callback bytes; exact ordered route/root/step values and limitations |
| No false sharing | Same SID in different resource domains; same text under different contexts; different flags, ordinals or route order; indexed lookup collisions with unequal complete values |
| Reference integrity | Missing/replaced shared values, redirected consumer references, wrong target/holder/generation/version and altered/resealed payloads; valid and nonempty controls beside each rejection |
| Complete public reconstruction | Object-first and holder-first reads, hidden counts, pagination and repeated references; no lazy write or fabricated empty value |
| Transaction/publication | Failure after shared-value insertion, rollback then another object, cancellation before publication, previous generation still readable and references never escaping rollback |
| Independent parity | Every distinct changed value and all consumer bindings compared to the schema-26 source; full public-model parity on bounded adversarial fixtures and representative lab reads |

Compare complete values once per shared node and stream consumer-binding comparisons rather than
re-exporting the entire public object model for every target. No expensive exhaustive exports are
authorized. If this cannot establish the required equivalence, record the gap and seek explicit
authorization; do not substitute a cardinality-only check or claim complete lab public-model parity
from representative reads. Expected physical route-row counts may change under S1; public routes,
their ordering and security conclusions may not. Existing frozen count/comparer expectations are
never relaxed, updated in place or satisfied using duplicate compatibility records.

### Pinned lab reference and one-execution constraint

The reference Evidence SHA-256 is
`A6F1F001F53ADD970B42D55A710F3FC3B083AC62C8E54AB1B140955E46EBB16C`.
Derivation generation is `c2d92b83-2e23-4a1a-b611-2cca9344cf9f`, SHA-256
`0C2FE5FE6BA7655EC2FFEDF059353524BC1271B22B13AF47BBF817C3CC15F31E`.
Keep evaluation time `2026-09-09T05:08:22.3459193+00:00`. The local replay Judgement generation is
`cfc4d72f-e839-4955-a09a-db1cf5c9dd71`, SHA-256
`9A379F512F244FBF4CD3E4985B1B07FDF1A81250592AAF134DEC232AF3A67073`;
it differs from the lab-produced generation, not from its input capture. The CPU session was
`03fced3f-2577-4756-8ee8-7d0c20a45a15`. Local trace/report availability is not a clean-clone test dependency.

Preserve 27 findings from 17 rules, 112,303 control records, 23,751 full-control assessments,
72,422 support links, 342,812 ACE associations and 208,900 full-control source references. All 8,407
targets remain recorded: 51 selected/completed-with-limitations with 210 Unknown/uncounted transitions,
8,356 undetermined/not-assessed, and 32,639 basic WRITE_OWNER records in total. SEC-031 and SEC-032 each
retain four unjudged objects. Coverage remains processing-complete but analysis/input-incomplete;
requester/member work stays unconfigured. None of these counts replaces complete proof comparison.

The owner requested one diagnostic execution, not warmups or averaged repetitions; that execution
has already happened. Preserve `LabAuditProfilingBenchmarks` byte-for-byte at SHA-256
`4F234E3E93EACB94B271D70D9018DF0C5F9FED4A2168982B677B74656BEDC3DC` and preserve the successful
`ScopedOwnershipSingleReplayBenchmarks` source, outputs and consumed execution claim. Do not reset its
claim, alter its fixed counts or silently rerun either artifact.

**Approved additional allowance under 0115:** a separate schema-aware comparison artifact and
exactly two additional lab judging executions: one before S1 and one after, with zero warmups and no
averaging. Each invocation includes the same pinned, bounded sequence of completion, object-first,
holder-first and repeated-page reads; do not add a judging run for each read direction. List those
selections before approval and freeze them for the pair. A separate consumed claim for each approved
before/after slot must prevent accidental extra judging invocations. The extra before execution is
needed only to establish the identical-artifact comparison:
the frozen one-shot runner cannot be repurposed. Retain the existing 67.95-second result as diagnostic
evidence rather than pretending a changed runner is the same baseline. The owner approved this two-pass
allowance and the pinned workload is recorded in 0115. Do not retry a completed or failed measured
execution automatically. Production-scale workloads are not part of this allowance. The additional
artifact is `S1ProofStorageBenchmarks`; its input/read sequence and logical comparer were frozen after
the successful before pass. Its before execution took 50.64 seconds including the pinned reads,
retained a 372,428,800-byte new judgement and sampled 750,148,404 bytes of combined judgement storage
including the previous 372,428,800-byte generation. Its count, complete-value/binding digest and
normalization-negative-control preparation passed. Both slots are now consumed; the after result
and its regression are recorded below. No third judging execution is authorized.

### S1 paired lab result — performance acceptance on hold

Both Release passes used the same frozen `S1ProofStorageBenchmarks` source (SHA-256
`76717721E673F262046F26469FE01BF262DBFF6E6BBC41B31998386461EEC2A8`), the pinned input and read sequence,
and actual runtime .NET 10.0.12 on S2DMEASOFT. Before/after source and binary manifests were retained;
the common Git HEAD alone does not identify either uncommitted implementation. Judgement assembly
SHA-256 before is `0EA8109ECD1956B69CB519C411FBD1D9CE4112F67FCB6A47AC85191B2605E48D`; after is
`66B8F5DA37EE6D474C424F467B0356AB5444E3828CEFC11AE72583D9333A9D54`.

The before generation is `fb244056-fa1c-492a-ad0a-1cbcd6914196`, database SHA-256
`B2CFBA8F3A61E2077946518B4F3F8DF11AB9E782E3F2C792BCE2E2B83E8D337A`; the after generation is
`b63655c6-a44f-4ed3-946e-3b30a94f14b2`, database SHA-256
`239F0181259BAF538D54740D2222E2887035F7D9D4ACC74977B130C330CF29A7`.
CPU trace sessions are `9353931c-49dc-4dec-89ed-1a326925d5a3` and
`4042886f-b504-4084-9ff4-08feb425a52f`. These are not the older diagnostic trace or the lab executable.

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| Judging plus the fixed completion/page reads | 50.640 s | 55.309 s | +4.670 s / +9.22% |
| Basic object-processing phase | 35.655 s | 40.221 s | +4.566 s |
| Ownership selection | 1.500 s | 1.526 s | +0.026 s |
| Selected ownership assessment | 3.564 s | 3.225 s | -0.339 s |
| Publication | 0.453 s | 0.416 s | -0.037 s |
| Completion readback | 0.485 s | 0.448 s | -0.037 s |
| Process CPU during the measured interval | 49.656 s | 53.047 s | +3.391 s / +6.83% |
| Cumulative managed allocation during that interval | 13,224,498,544 bytes | 15,931,714,368 bytes | +2,707,215,824 / +20.47% |
| Gen 0 / Gen 1 / Gen 2 collection deltas | 1,062 / 66 / 15 | 1,277 / 70 / 16 | +215 / +4 / +1 |
| Maximum boundary-sampled working set | 237,547,520 bytes | 233,840,640 bytes | -3,706,880 / -1.56% |
| Maximum boundary-sampled private memory | 186,998,784 bytes | 183,046,144 bytes | -3,952,640 / -2.11% |
| Final newly selected Judgement database | 372,428,800 bytes | 333,299,712 bytes | -39,129,088 / -10.51% |
| Maximum sampled combined Judgement DB bytes | 744,857,600 bytes | 705,728,512 bytes | -39,129,088 / -5.25% |
| Maximum sampled WAL bytes | 5,380,752 bytes | 6,283,032 bytes | +902,280 / +16.77% |
| Maximum sampled DB/WAL/sidecar total | 750,148,404 bytes | 711,622,588 bytes | -38,525,816 / -5.14% |
| Prior Judgement retained in each pass | 372,428,800 bytes | 372,428,800 bytes | unchanged |

Allocation is bytes allocated over time, not required live RAM. Boundary memory samples and 100 ms
file samples are observed lower bounds, not guaranteed peaks; external temporary files and filesystem
allocation/compression are not measured. The common retained prior generation explains why overlap
savings are smaller than the new-file percentage. BenchmarkDotNet reported NA for its aggregate table;
the independent execution stopwatches and validation records succeeded. This is one observation per
build, with profiler/observer/snapshot overhead, not averages or statistical significance.

All 56 logical product digests matched, including complete permission values, consumer associations,
complete control-route sequences, full-control stored proof and unchanged products. Every ACE/source
association fingerprint was independently checked before normalizing only validated Judgement IDs and
run timestamps. The same eight bounded public snapshots matched; no exhaustive public export was run.
All pinned findings, primitive/support counts, selected/unselected states, Unknown owner transitions,
and inactive requester/member products were preserved.

The after store has 15 explanation values totaling 1,071 payload bytes and 12 complete route values
totaling 22,360 payload bytes. There are 112,303 control consumer bindings. The shared relational route
representation has 34 routes and 81 steps; reconstructing each consumer still produces the original
87,340 logical routes and 174,764 logical steps. The earlier 11-value observation covered full-control
route JSON only, whereas S1 also shares control-edge route values. Full-control JSON payload fell from
79,365,759 to 61,969,730 bytes. These payload figures are not additive physical savings.

**Functional verification:** the new sharing/corruption tests passed; focused coverage passed 142/142.
The new shared-proof helper had approximately 98.73% reported line coverage and 88.70% branch coverage,
not full coverage. The final uninstrumented offline suite ran 4,616 tests: 4,603 passed and 13 failed;
zero excluded stage-status cases ran. Every remaining failed case reproduced using the retained
pre-S1 Judgement assembly in an isolated host. They concern earlier catalogue-2 expectations,
unselected ownership transitions and pre-existing concept/vouched-result/null-default architecture
checks. Existing failing tests and their expectations were not weakened. The new optional-null
collaborator and missing decision-index entry found during validation were corrected. The solution
build succeeds; the offline suite is not reported as fully green.

**Stop point:** storage and logical parity gates passed, but the measured workload is slower and
allocates more. The after CPU trace remains dominated by storage work and shows the added shared-value
serialization/binding/read work; it does not establish allocation attribution for every extra byte.
No performance acceptance, production acceptance or speed improvement is claimed. Production changes
and benchmark executions stopped after this result; the candidate is retained for review, not silently
optimized further or reset over existing work. Investigating the new writer serialization/binding
overhead is the bounded next recommendation and requires a new explicit measurement allowance before
another timed judging run. Transaction batching, evaluator weakening and reader-lifetime changes have
not been smuggled into this slice.

### Production-scale validation is a separate gate

Use the [recorded production shape](../../WHAT-THE-PRODUCT-IS.md#the-forest-this-is-built-for): nine
domains, approximately 347,000 objects and 5.9 million ACEs, deep names averaging about 97 characters,
and historically about nine million predecessor control edges. The predecessor edge figure is workload
context, not a predicted Next output count. The existing synthetic volume harness's mostly read-property
filler and discovery-on pairing is not representative evidence for this design.

Before claiming readiness, separately authorize retained offline scale fixtures or available sealed
production evidence. Cover increasing object/ACE volume and increasing holders, deny/object-specific
ACE density, conditional entries, identity ambiguity, membership depth/alternative routes, and both
high and low value reuse. Include small and broad ownership scope with honest incomplete coverage,
first/repeated holder and object pages, and re-judging while the prior generation remains retained.
Record measured output/reference counts, actual runtime/build, elapsed phases, peak memory and full
disk overlap, including available temporary-file measurements; do not extrapolate a lab ratio into
a production promise or choose new production budgets. Establish an explicit acceptable completion,
memory and disk envelope for the operator's hardware before acceptance, not after observing a result.
Scale fixtures remain synthetic evidence, not customer acceptance. No live access, recapture, service
or power changes, UI changes, production requester/member activation, deletion of old evidence,
commit/push/reset or execution of the four excluded stage-status tests is included.

## A bundle gains two files, and loses none

A captured bundle holds `evidence.db` and its seal. A judged one also holds `judgement.db` and
`judgement.db.seal`. Nothing opens the evidence for writing at any point, which is what lets the
same bundle be judged repeatedly while still proving what the directory said once.

`BundleLayout` owns all five names, as it owns every other name in a bundle, so no caller composes
one by concatenation.

**The store is disposable and that is a feature.** If an index is wrong, or a rule is improved,
the file is deleted and the bundle judged again. Nothing is lost, because the evidence was never
part of it.

---

## `judgement.db.partial`, then a rename

Judging writes to `judgement.db.partial`. The seal is written and the file renamed only once every
scheduled rule has finished. A reader asks for `judgement.db` and nothing else.

So a judging killed halfway leaves no file by the name a reader wants. This matters more here than
it does for capture: a half-judged bundle presenting the findings it managed to write looks exactly
like a forest with fewer problems than it has.

---

## The store names the capture it judged

`judgement.evidence_seal` holds the SHA-256 the evidence seal carries, and a reader refuses a store
whose value does not match the bundle it was opened beside.

This exists because the store is an ordinary file that can be copied. Two captures of one forest a
week apart produce directories with identical names holding mostly the same objects, so a judgement
moved into the wrong bundle would resolve nearly all of its findings and be wrong about every one of
them. The evidence seal is a permanent fingerprint of exactly one capture — taken once at the end of
capture and never reissued — which makes it the one value that can settle the question.

Copying a store between bundles is possible and unsupported. The check is what makes the attempt
fail loudly rather than silently.

---

## What ran is recorded, not inferred

`rule_execution` carries one row per scheduled rule, whatever became of it.

**This is what makes an empty `finding` table readable.** No findings and no execution rows means
nobody judged this bundle. No findings beside execution rows means every rule ran and nothing
matched. A screen with only the findings to go on would print both as a clean forest.

A rule that was scheduled and never executed gets a row too, with `RuleExecutionOutcome.DidNotRun`,
because an absent row cannot tell *never scheduled* from *scheduled and skipped*.

`objects_judged`, `objects_not_applicable` and `objects_not_judged` are three different answers and
none is derived from the others.

**Not applicable is not a gap.** A rule declares the classes it is about, and an organisational unit
offered to a delegation rule is not an object the rule failed to read — it has no
`userAccountControl` because it is not an account. Judged against a real forest on 2026-08-26 the
delegation rules called 6,279 of 8,361 objects unreadable on exactly that account, three in four,
which would have reported every judging as degraded for ever and taught an operator to ignore the
one signal that says the findings are incomplete.

**`objects_not_judged` is the real gap**: an object the rule *is* about, missing something the rule
declared it reads. That still degrades the run, and still should.

`rule_execution_missing_input` says which declared attributes were absent and on how many objects.
That turns *SEC-010 could not judge 4,000 objects* into *`primaryGroupID` was not captured*, which
is the difference between a mystery and an instruction.

---

## Two state machines, because a run and a rule fail differently

<!-- STATES:BEGIN -->

| `JudgementRunState` | What it means |
|---|---|
| `Running` | One or more scheduled rules has no terminal execution record, which includes the process being killed mid-run |
| `Completed` | Every scheduled rule reached a terminal, non-degraded result |
| `CompletedDegraded` | Every scheduled rule reached a terminal result, but one or more was indeterminate, errored or did not run |
| `Failed` | The coordinator itself failed — scheduling, sealing or recording the result |

| `RuleExecutionOutcome` | What it means |
|---|---|
| `Succeeded` | The rule ran and reached a verdict on every object it was offered |
| `Indeterminate` | The rule ran and could not reach a verdict on one or more objects, because a declared input was not captured |
| `Error` | The rule threw. Other rules continue; this one has no verdict |
| `DidNotRun` | The rule was scheduled and never executed |

<!-- STATES:END -->

`Failed` and an interrupted `Running` are not the same thing. One is a defect in this product; the
other is a claim about a customer's directory, and a store that could not tell them apart would
present a coordinator that never started as a judging that found nothing.

`CompletedDegraded` is not a lesser kind of success. A judging where a rule could not read its
declared inputs has not established that the forest is clean of what that rule looks for.

---

## Writing is atomic per rule, not per run

Each rule's findings commit in one transaction together with its own execution record.

The two alternatives both lose something. One transaction for the whole run throws away every
completed rule when the last one fails. No transaction boundary at all leaves findings written with
nothing saying which rule produced them. Committing per rule means a killed process loses only the
rule that was running, and no finding can exist without the record of what produced it.

---

## Derived evidence is bound to its generation

`judgement.derivation_generation_id` identifies the derivation used by a judging that requires one.
Schema 14 also persists SEC-021's grouped membership evidence and completeness using the same
`MembershipRouteStorage` encoding as Derivation. The finding carries its protection catalogue version
and any direct catalogue basis. Opening or paging it therefore does not reconstruct routes from a
newer derivation or silently lose longer alternatives.

An incomplete verdict may retain established findings beside its unresolved inputs. A rule that
throws still loses its entire output. This distinction was exercised end to end with a known
protected account and an unresolved membership elsewhere in the captured graph.

### Initial control-edge product — schema 15

**Historical baseline; current schema 21 also includes the later membership, requester,
password-reset, key-credential write and replication products described below.**

`JudgingRun` now calls `ControlEdgeDeriver` for each streamed object and persists its result through
`JudgementWriter`. `ControlEdgeStorage` records product completion, per-object descriptor coverage,
edges, supporting ACEs and preconditions. Membership evidence is stored with each edge rather than
reconstructed from a later derivation.

The supported primitives are `CanWriteDacl` and `CanSetOwner`. The supporting
`CanBecomeOwnerAndRewriteDacl` compound remains `Unknown`, research-blocked and uncounted; a proved
owner-setting right does not prove a takeover. Expectedness and capability evaluation are separate.
`JudgementReader.ReadControlEdges` supplies object-first and named-holder-first pages from the same
stored product. The object screen defaults to hiding expected edges, states their count, shows
coverage and evidence, and refuses to mix generations while paging.

This was a started slice, not completed stage 6. Ownership-derived control, membership changes,
credentials, replication, full-control aggregation and effective member expansion were not derived
by that initial slice.
Reachability remains unbuilt. The end-to-end witness is
`JudgingEndToEndTests.SealedDescriptorProducesStoredControlEdgesThroughTheRealCoordinator`;
automated tests do not discharge the stage's claim-specific laboratory gates or P-145.

### Bounded group-membership control — schema 16

**Implemented, not laboratory-accepted.** `ControlEdgeDeriver` now asks two separate questions
on captured group objects. Neither category nor target class says that the group is privileged.
Known non-group objects are excluded; a missing target class is an explicit coverage gap.

| Capability | What is established from permissions | What is not claimed |
|---|---|---|
| `CanModifyGroupMembership` | WRITE_PROPERTY (`0x20`) reaches `member`, without the own-account restriction | That every proposed membership value would pass AD's group-scope, value or other directory constraints; that the group is Tier 0 |
| `CanAddSelfToGroup` | A separate Self-Membership validated-write (`0x08`) candidate, with `HoldsSelfMembershipValidatedWrite` recording the permission answer | That a concrete requester can perform the operation. `AddedMemberSid == RequesterSid` stays `Unknown`; only the caller's own account may be added or removed |

**Why even a directly named self-membership candidate stays unknown in this bounded slice:**
the analysis does not identify and evaluate a concrete acting requester. A named trustee, including
a group or a broad identity, is not itself proof of that requester. The stored permission answer
can be established while the constrained operation stays unknown. This is an implementation limit,
not a new AD rule or acceptance of the stage-6 proposal's direct-requester claims. Group-held
self-membership expansion remains gated under `0110`; no member capabilities are generated.
An unknown self-membership candidate does not weaken an independent general membership write.

**The external anchor is Microsoft's distinction, not agreement between tests and code.**
[Control Access Rights](https://learn.microsoft.com/windows/win32/ad/control-access-rights)
defines WRITE_PROPERTY as 32 and validated SELF as 8, and explicitly limits Self-Membership to
the caller's account. [Self-Membership](https://learn.microsoft.com/windows/win32/adschema/r-self-membership)
gives its GUID and group target. The existing Microsoft-anchored `SchemaGuidCatalog` supplies
GUIDs rather than duplicating literals. `member` and Self-Membership share a GUID but not a right.

**Attribute and property-set entries are evaluated together, in stored order.** A temporary
projection selects only the entries reaching the one membership operation, then calls the existing
`EffectiveAccessCalculator`. Evaluating property sets separately and unioning answers would let a
property-set allow escape an attribute deny. A property set reaches `member` only when the captured
catalogue says it contains that attribute; no shipped membership list is assumed. Unknown property
scope, incomplete descriptors, unsupported/callback ACEs and relevant cross-trustee denies retain
unknown candidates. Inherit-only entries grant nothing on this object. NULL, empty and unread
descriptors remain distinct. Generic rights arrive mapped through the existing parser/normalizer.

**Stored evidence is not the projection.** Original ACE ordinals, trustees (including an original
SELF placeholder), masks, GUID flags, inheritance and callback bytes are retained, together with
the captured property-set explanation, requester constraint, descriptor outcome, generation and
existing membership routes. Both capabilities use `MembershipEscalation` under `0110`. Expectedness
still uses catalogue 2 and accepted authority scopes, including the P-150 correction; ownership
acceptance, protection and target privilege are not substitutes. The two existing views read these
same stored rows and expose the distinct wording, uncertainty and constraints.

**Counting is still named-holder counting, not member counting.** Each capability candidate is
counted once per target and scoped trustee; unknown candidates are included, explicitly labeled,
and keep object coverage incomplete. Expectedness counts are not counts of established operations.
The owner-to-DACL compound remains unknown and uncounted. Effective member expansion, ownership-
derived control, credential and replication capabilities, full-control aggregation and reachability
remain outside this work.

**Schema 16 and control engine 2 are semantic changes, not evidence or table-layout changes.**
Schema-15 judgements are refused and must be re-judged; an engine-1 product cannot claim membership
coverage. The schema-15 independent layout checkpoint remains untouched, and schema 16 explicitly
shares that layout. Semantic tests therefore accompany the layout check. No re-capture or
re-derivation is required. Principal catalogue version remains 2.

**Automated witnesses:** `GroupMembershipControlTests`,
`ControlEdgeStorageTests.MembershipKindsConstraintsAndOriginalAcesSurviveBothQueries`,
`JudgingEndToEndTests.SealedGroupDescriptorProducesSeparateMembershipCapabilities` and
`ControlEdgePresentationTests.BothViewsKeepGeneralAndSelfMembershipSeparateAndShowTheirLimits`.
The coordinator tests use newly created isolated synthetic bundles, including generic-write and
generic-all descriptors. The initial targeted run passed all 64 tests across membership analysis,
storage, layout, coordinator and presentation. The final full run passed **3,390 tests**, with none
failed or skipped, compared with the checkpoint's 3,356. The solution build succeeded.

**Observed negative control:** temporarily replacing the self-membership mask `0x08` with `0x20`
made both `SameGuidDoesNotMergeDifferentRights` cases fail. The WRITE_PROPERTY case reported
`Assert.Single` with two rows; the SELF case reported an empty collection. Neither case passed.
The correct mask was restored before the green full run. Existing layout mutation tests still
reject added columns and missing indexes; the old-schema tests refuse both 14 and 15, and the
engine-version negative control refuses engine 1 under the new scope.

**Validation findings, closed:** the older whole-object test fixture omitted its target class;
making its intended OU class explicit preserved its original assertions while the missing-class
test still proves the unknown boundary (test-fixture severity: low). The new engine-refusal fixture
initially opened a legacy filename instead of the generation product; it now mutates only its own
synthetic partial store before publication (test-fixture severity: low). Final review also corrected
SYSTEM self-membership expectedness to `UnknownCapabilityScope`, rather than claiming an incomplete
descriptor when the unresolved input is the requester operation (presentation severity: medium).
`SystemRequesterUncertaintyIsNotMislabelledAsAnUnreadDescriptor` guards that distinction.
`DuplicateGrantsDoNotMultiplyTheNamedHolderOrInvokeMemberExpansion` verifies the bounded count and
fails if the analysis calls member expansion.

**The implementation test run above did not claim a laboratory measurement.** The separate
schema-16 offline comparison below now records one, without discharging live requester gates.
The schema-15 corrected baseline remains 65,084
counted primitives: 53,265 expected, 11,805 unexpected and 14 of unknown expectedness. It does not
include these new membership candidates. No sealed laboratory evidence or `next/artifacts/` was
modified or reused for writes. P-145 and the remaining stage-6 laboratory gates remain open;
completed permission/Tier 0 session briefs are historical and the stage-6 specification remains
a proposal except where accepted decisions govern it.

### Isolated live Self-Membership measurement — 2026-09-06

**Historical AD behavior measurement: requester analysis and member expansion were unimplemented
at this schema-16 checkpoint.** The later schema-17 requester implementation and schema-18
integration do not turn this measurement into acceptance of that later code. Member expansion
remains unimplemented.
`next/tools/Test-LabSelfMembership.ps1` created fresh non-privileged objects under
`OU=SecureAD-SelfMembership-saSM6d575afc,DC=ba,DC=ad,DC=lab` on `BADC.ba.ad.lab`.
The two target groups have protected DACLs: Domain Admins and SYSTEM retain administrative access,
Authenticated Users has read access, and the test trustee has only object-specific SELF (`0x08`)
for the Self-Membership GUID. There is no general membership-write grant for either test trustee.
The direct trustee is one temporary user; the other trustee is a temporary global security group
containing a different temporary user. Neither target nor grant-holding group is privileged.

Each measured modify used a fresh, explicitly authenticated LDAP connection with signing and
sealing as the temporary caller, not the administrator. Binding errors cannot count as refused
modifies. Membership was read before and after each request; deletion tests started with the
member present. Administrator setup also demonstrated that the other account was a legal member
value. Twelve assertions passed:

| Grant | Caller adds/removes itself | Caller adds/removes another account |
|---|---|---|
| Direct Self-Membership | Both succeeded, LDAP 0; membership changed exactly as requested | Both refused, LDAP 50; membership unchanged |
| Self-Membership through one global security group | Both succeeded, LDAP 0; membership changed exactly as requested | Both refused, LDAP 50; membership unchanged |
| No-grant control, tested with both callers | All four operations refused, LDAP 50; membership unchanged | Not measured on this control |

**Fresh evidence and readback.** The CLI captured all three domains into
`ad.lab-20260906-053214`, containing 8,407 objects, including the eight objects in the successful
test OU and sixteen retained objects from incomplete setup attempts. Evidence SHA-256:
`137FF0CE603D5CC6463C76D1FA0432245A57C2FC1FF48481BDDDA9C6A8B8DA41`.
Derivation generation: `9059ced8-4300-431f-a5ce-e959d3e4d15a`; judgement generation:
`b3ba397d-3a48-43dc-bec5-2b48302be4dc`. Judging remains `CompletedDegraded`: 27 findings,
with SEC-031 and SEC-032 each indeterminate on four objects. This is not a complete all-rule pass.

The read-only comparison under `next/artifacts/self-membership-live-20260906-0527/` verifies
the successful run's object GUIDs, disabled users, grant-group membership and two exact SELF-only
grants. Raw captured ACE ordinals, trustees, masks and GUIDs match their stored supporting entries.
The live recorder uses `ActiveDirectorySecurity`, which normalizes entry order; the same
representation of captured bytes matches that live DACL. Raw ordering is checked separately with
`RawSecurityDescriptor`, not silently compared with the normalized display.

Both named holders have exactly one membership candidate on their respective targets:
`CanAddSelfToGroup`, permission precondition `Established`, operation `Unknown`, and
`AddedMemberSid == RequesterSid: Unknown`. Neither has general membership control. Both actual
object-first and holder-first reader/presentation paths return identical evidence and retain the
own-account/requester limitation. The grant group's member has no expanded edge, and the view
states that it is not a member expansion. No-grant candidates are absent. Altered-mask and
missing-representative negative controls were detected. **These are programmatic checks of the
real presentation classes, not a visual GUI inspection.**

**Retention and cleanup.** The owner chose to retain the objects. All nine temporary users across
the three attempts were disabled; passwords were never persisted. Each attempt has its own
`live-results.json` manifest, with GUIDs and directory names:

| Artifact subfolder | Retained OU under `DC=ba,DC=ad,DC=lab` | Outcome |
|---|---|---|
| `live` | `SecureAD-SelfMembership-saSMf2f33e85` | Incomplete: ADSI property adapter intercepted `Options`; corrected with `psbase` before retry |
| `live-retry` | `SecureAD-SelfMembership-saSM2f44e696` | Incomplete: built-in `measure` alias intercepted the helper; renamed before retry |
| `live-final` | `SecureAD-SelfMembership-saSM6d575afc` | All twelve live assertions passed |

Each OU contains users named with its `saSM` tag and suffixes `-D`, `-G`, `-O`, plus groups with
suffixes `-DirectTarget`, `-GroupTarget`, `-GrantHolders`, `-NoGrant`. The two setup findings are
closed harness defects, not failed authorization measurements. Their artifacts remain separate.
To preview cleanup, run `next/tools/Remove-LabSelfMembership.ps1` with `-ManifestPath` pointing to
one attempt's manifest and `-WhatIf`. Omit `-WhatIf` only when ready to confirm deletion. The
helper verifies GUIDs, names, ownership markers and the entire OU inventory, refuses extra objects,
and never recursively deletes or removes evidence files. Cleanup was not executed.

**Final verification:** solution build succeeded; all 3,390 tests passed, with none failed or
skipped. Nineteen script checks passed, including cleanup previews for all three OUs and refusals
for wrong scope, an unrecorded child, duplicate identity and reuse of an existing result directory.
All 238 pre-existing artifact file fingerprints were unchanged (transient SQLite WAL/SHM files
excluded); the fresh Evidence hash also remained unchanged. Read-only inventory confirmed all
24 retained objects and all nine users disabled. `validation.json` beside the inspection records
the checks; no credentials are included.

This measurement supports the own-account-only AD behavior in these two isolated grant shapes.
It does not implement concrete requester evaluation, accept arbitrary nested/token scenarios,
classify any target as Tier 0, or close P-145 and the remaining stage-6 acceptance gates.

### Bounded concrete requester assessment — schema 17

**Implemented from captured evidence; not a new live acceptance result.** Decision `0111` adds an
explicit requester/target/add-or-remove assessment beneath the existing named-holder product. The
first supported authorization routes are a direct captured user grant and one explicit same-domain
global security-group membership. The permission list is evaluated once for the concrete requester,
so an applicable deny through another identity is not missed. Stored order is retained.

Authorization, the own-account restriction and operation readiness are three separate answers. A
disabled account can therefore have established permission evidence without being described as able
to authenticate. An absent captured `member` value remains unknown rather than proving absence.
Nested, primary-group, SID-history, foreign, cross-domain, domain-local, universal and unresolved
routes remain unknown where they could change the permission answer. The assessment describes an
ordinary authenticated directory user; it is not a reconstruction of a live access token or a
prediction that an LDAP operation will succeed.

Judging accepts an explicit, deterministic request batch and refuses a batch beyond its configured
budget rather than silently dropping requests. Schema 17 stores the evidence seal and generation,
request identities, operation, three answers, original permission entries, requester applicability,
typed limits and links to the existing holder edges. Requester assessments are uncounted detail:
the named holder count required by `0097` is unchanged. Empty readback states whether no request was
scheduled or the requester product was not derived. The object-first and requester-first Shell views
read the same stored rows and perform no authorization calculation.

The 2026-09-06 artifacts remain historical evidence of two live grant shapes. They were not changed
or used to promote their schema-16 Unknown rows. Schema-16 judgements must be re-judged to obtain the
new product; evidence and derivation do not need to be rewritten. P-145 remains open.

**Earlier implementation-session validation (recorded, not rerun by the reviewer):**
`SelfMembershipRequesterTests` covers direct and one-global-group grants,
an applicable deny through another requester identity, stored order, missing membership,
distribution groups, another requested member, disabled accounts, incomplete descriptors and the
0x08/0x20 distinction. `JudgingEndToEndTests.ExplicitRequesterSurvivesTheRealCoordinatorWithoutMultiplyingTheHolderEdge`
writes and seals a real synthetic bundle, schedules one request, and reads its original permission
and holder-edge link back. Storage and presentation tests compare both directions. Schema-17 layout
mutations detect an added requester column and a removed identity index. The solution build and all
3,403 tests passed. The 238 historical artifact hashes, two lab-script hashes and fresh Evidence hash
were rechecked unchanged; no directory operation or cleanup ran.

#### Authorization correction and remaining review findings

The bounded authorization evaluator now retains possible earlier allow and deny outcomes instead
of discarding uncertainty when a later matching entry is reached. An uncertain deny before a known
allow, or an uncertain allow before a known deny, yields Unknown. Uncertainty that cannot change
the outcome does not erase a justified answer: a possible deny followed by a known deny remains
NotEstablished, and a possible allow followed by a known allow remains Established. A definite
decision stops evaluation; a later deny does not overturn an earlier grant. An undecided path at
the end of the DACL is implicitly denied, so a possible deny alone cannot grant the requested right.
These expectations follow Microsoft's
[ordered access check](https://learn.microsoft.com/windows/win32/secauthz/how-dacls-control-access-to-an-object),
not a rule that denies always win. Incomplete descriptors cannot justify either definite answer
because the evidence does not locate or constrain the missing entries. Callback conditions are
not evaluated; their possible allow/deny effects are retained. Unrecognized ACE kinds remain
uncertain in both directions.

SELF now resolves the captured holder and SID together to the target object. A real SELF trustee
has no DN; the requester explanation nevertheless identifies the captured target group and its
explicit same-domain global-security membership. The original entry still names `S-1-5-10` (SELF).
Missing target SID/GUID yields IdentityMissing; missing membership stays MembershipNotEstablished,
not non-membership. This does not expand the supported membership routes or equate SELF with the
requester. Add and Remove share authorization for the validated write (`0x08`, not `0x20`), while
own-account and readiness remain separate, including disabled accounts and already-present members.

**Correction validation:** the unchanged focused test selection, `SelfMembershipRequesterTests`
and `JudgingEndToEndTests`, ran 69 cases against the unfixed production code: 39 passed and 30 failed.
After the fix, all 69 passed with none failed or skipped. The full solution build succeeded.
Visual Studio Test Explorer then ran the entire `SecureAD.Next.Tests` project: **3,444 passed,
zero failed and zero skipped**. The focused runs used those two fully qualified TypeName filters;
the full run used the Project filter. These are new executions, not historical test statuses.
The regressions cover both unsafe answer directions, same-outcome and later uncertainty,
incomplete descriptors with relevant entries, callback/unsupported entries, unknown scope/trustees,
bounded unsupported routes and both Add/Remove paths. Four synthetic sealed-bundle cases exercise
the real permission reader and coordinator with null-DN SELF, explicit/absent membership, and
missing target SID or GUID. Historical expected values and retained laboratory Evidence are not
inputs to these new synthetic tests and were not rewritten.

The session-start SHA-256 comparison covered 1,268 tracked/nonignored files: only the two production
files, two test files and two documentation files changed; none were added or removed. All 330
artifact/lab/script files in that comparison, including both retained Self-Membership scripts,
were unchanged. The ignored fresh `evidence.db` was checked separately against the supplied baseline
and still hashes to `137FF0CE603D5CC6463C76D1FA0432245A57C2FC1FF48481BDDDA9C6A8B8DA41`.
This comparison is not a rerun of the historical 238-file fingerprint procedure. The session-only
diff was inspected and `git diff --check` passed. No AD contact, directory operation, cleanup,
application launch, historical fixture change or commit occurred. The pre-existing modification
to `.github/copilot-instructions.md` was left untouched.

**R5 persistence correction:** requester readback now refuses malformed stored answers even when
the judgement seal correctly describes those bytes. Local `System.Text.Json` options require every
non-optional constructor field and respect non-nullable fields. Microsoft's
[required-property guidance](https://learn.microsoft.com/dotnet/standard/serialization/system-text-json/required-properties)
and [nullable-annotation limits](https://learn.microsoft.com/dotnet/standard/serialization/system-text-json/nullable-annotations#limitations)
distinguish missing fields from explicit nulls and explain why root arrays and collection elements
also need explicit checks. This is local to requester persistence, not a global serializer change.

- JSON null, malformed JSON, wrong collection shapes, null elements, missing nested constructor
  fields, null required nested values and null `ApplicationData` are rejected, not replaced by empty
  collections. Enum values must be defined. Original ACE type text is retained, including unknown
  ACE kinds; readback does not turn unsupported captured evidence into a new authorization answer.
- Required scalar text must be nonblank; typed GUIDs and timestamps must parse. SQLite account
  values must be integers and `member_present` must be exactly 0, 1 or null. Assessment and holder
  IDs must be positive, ACE ordinals nonnegative and unique, and holder IDs unique. Assessment
  generation, consumed Derivation generation and Evidence seal must agree with the judgement.
- A missing requester product beside assessment rows is invalid even when the query selects no
  row. An incomplete or unsupported requester product is refused. An absent product with no rows
  still means NotDerived; an empty completed product remains a different, valid answer.
- Each referenced holder edge must exist beneath a completed, supported control product and match
  target DN (case-insensitively), target GUID when known, `CanAddSelfToGroup`, both generations and
  counted state. Its holder SID and resource scope must match at least one stored requester route
  not marked DoesNotMatch; Unknown routes remain possible references, not grants. SELF keeps its
  original `S-1-5-10` explanation and resolves to the assessment target SID for matching. BUILTIN
  identities require the target domain's scope; unscoped identities cannot acquire an extra scope.
- Empty holder lists remain valid without a control product. Explicit nullable identity evidence
  remains nullable. No permissions, readiness or membership answers are recomputed during readback.
  A malformed selected row aborts the whole read rather than exposing the preceding valid rows.
  Data errors become `InvalidDataException` with assessment/field context (and edge ID for a bad
  reference); the Shell adapter returns `Shell.SelfMembershipAssessmentsUnreadable`, not an empty
  success or an unhandled parsing exception.

**R5 validation:** the interrupted tests compiled, but their first run (195 cases: 10 passed,
185 failed) could not open the new synthetic stores because their Derivation generation was
fabricated. That is fixture failure, not persistence evidence. Creating a real sealed synthetic
Derivation reached readback: 195 cases, 15 passed and 180 failed against unchanged production.
The expanded pre-fix selection ran 231 cases: 17 passed and 214 failed. Those raw totals also include
two test defects later corrected: an error-code expectation missing the established `Shell.` prefix,
and a target-mismatch mutation blocked by a foreign key. They are not 214 independently demonstrated
production defects. The latter fixture now creates the alternate control object before redirecting
the edge, without disabling foreign-key enforcement. No frozen historical expected value changed.

After the production correction and these test repairs, `SelfMembershipStorageTests` plus
`ControlEdgeStorageTests` ran **231/231 passed**, covering both directions and the real Shell
adapter. `MalformedSealedRowIsRejectedInBothDirections`,
`ShellReportsMalformedSealedRowsAsReadFailures`,
`HolderReferencesRequireMatchingCompletedControlProduct` and
`BuiltinReferencesRequireTheTargetResourceScope` exercise the refusals; direct/SELF Add and Remove,
explicit missing evidence and empty/unscheduled products supply positive controls. The existing
real-edge round trip in `ControlEdgeStorageTests` was preserved. The R1/R3 selection,
`SelfMembershipRequesterTests` plus `JudgingEndToEndTests`, ran **69/69 passed**. A fresh full
`SecureAD.Next.Tests` run passed **3,665/3,665**, with none skipped, and the full solution build
succeeded. Focused runs used fully qualified TypeName filters; the full run used the Project filter.

The R5 baseline contains 1,269 tracked/nonignored files; a separate read-only hash manifest covers
389 retained artifact/lab files including ignored files. Retained files remained unchanged, including
fresh Evidence SHA-256 `137FF0CE603D5CC6463C76D1FA0432245A57C2FC1FF48481BDDDA9C6A8B8DA41`.
This is not a rerun of the historical fingerprint procedure. No AD contact, application launch,
directory operation, cleanup or commit was performed. Existing instructions and earlier feature
work were preserved. Schema 17, evaluator version 1 and control engine version 2 are unchanged.

| Review finding | Current status |
|---|---|
| R1 — ordered uncertainty | Corrected and regression-tested; definite answers require agreement of the possible ordered outcomes. |
| R2 — no production requester scheduling | Shared automatic discovery, coverage persistence and minimum host notices are implemented in schema 18. Production enablement remains open: Shell/CLI pass no discovery budget pending approval of a numerical recommendation. Completed synthetic measurements are recorded below; they do not enable the feature. |
| R3 — SELF holder resolution | Corrected and regression-tested through the real permission reader/coordinator; original SELF evidence is retained. |
| R4 — stale/mixed-generation Shell rows | Corrected and regression-tested: old rows clear on failed reads/selection changes; differing judgement generations withhold both products. See the [Shell readback contract](../shell/the-assets-screen.md#requester-and-control-readback-safety--r4). |
| R5 — supporting JSON and holder-edge validation | Corrected and regression-tested; malformed records and mismatched references fail the read, including through the Shell adapter. Persistence safety only, not feature acceptance. |
| R6 — requester grid sizing | Corrected and regression-tested after owner approval of the synthetic preview. Real-product laptop/monitor/forest checks remain outstanding; not fully visually accepted. See the [Shell sizing contract](../shell/the-assets-screen.md#requester-sizing--r6). |
| R7 — incomplete requester presentation | Approved and implemented in the bounded Shell slice: separate plain-language answers and expandable selected requester evidence. 137 focused checks and the full 3,837-test suite passed; solution build succeeded. Real-product verification remains open; see the [Shell presentation record](../shell/the-assets-screen.md#r7-requester-presentation). |
| R8 — contradictory product overview | Current-state reconciliation completed for the delivered scope across the product overview, roadmap, judgement and Shell specifications and P-145. Offline workflow verification is recorded below. This closes the documentation contradiction, not R2 enablement, real-product verification or requester/Stage 6 acceptance. |

The R1/R3 authorization correction, R5 persistence safety and R4 Shell readback safety are complete.
R4's unchanged focused selection passed 47/47 after 18 passed and 29 failed against the unfixed
Shell; its additional regression selection passed 348/348, the full test project passed 3,703/3,703
with none skipped, and the solution build succeeded. The linked Shell document owns the behavior
and test details. No persistence or authorization code changed for R4.

R6 sizing is now corrected without changing authorization, persistence, schema 17 or scheduling.
The unchanged 12-case layout selection passed 12/12 after 6 passed and 6 failed against the unfixed
layout; the broader selection passed 133/133, the full test project passed 3,715/3,715 with none
skipped, and the solution build succeeded. The linked Shell document owns the measurements and
the distinction between the approved synthetic preview and outstanding real-product validation.

This does not accept the whole requester feature, close P-145, or provide a live LDAP-success claim.
**The R6 handoff called for R2, then R7 and R8 in bounded slices.** The owner clarified that laptop/monitor
checks will happen during normal verification, not in a separate session blocking this work.
They remain unperformed, not implicitly accepted. At the end of the R6 session, ordinary Shell/CLI
re-judging scheduled no requester batch and R2 had not been implemented. The later schema-18
integration described below supplies automatic discovery but leaves it inactive in both hosts
without an approved budget. R7 is implemented and the R8 current-state reconciliation below is
complete. R2 enablement, real-product verification and final feature acceptance remain open;
the historical R6 validation does not accept those later changes.

#### R8 current-state reconciliation

The owner authorized this bounded slice with "ok do r8" after the approved R7 implementation was
committed and pushed as `a92d592`. R8 reconciles what is delivered, what is inactive and what has not
been verified. It changes no production source, UI wording/layout, evaluator, storage schema,
processing budget or host composition, and includes no new commit or push.

| Question | Verified current state | What it does not establish |
|---|---|---|
| Is concrete requester analysis implemented? | Yes. The schema-17 assessment and schema-18 discovery coverage are retained in current schema 21; authorization, own-account restriction and readiness are separately stored. | A complete access token, general membership-write evaluation or live operation success. |
| Does normal judging automatically produce requester answers? | Not with the shipping configuration. `App.xaml.cs` and CLI `Main` pass a null discovery budget; both hosts reach shared judging and report that no scan was scheduled. | That nobody is authorized, that discovery is unimplemented, or that a numerical budget has been approved. |
| Does configured automatic discovery reach the hosts? | Synthetic test budgets reach the real Shell post-capture and both CLI judging paths, as covered by `SelfMembershipDiscoveryTests`. | Production enablement or a recommended budget; test limits are fixtures only. |
| Can stored answers reach the actual object screen? | Yes. `BundleAssetSource` and `AssetsViewModel` read the same persisted answers in target-first and requester-first views, including selected proof. | A visible-window or physical laptop/monitor acceptance result. |
| Do requester answers change holder counts? | No. Re-judging synthetic evidence with and without discovery preserves the actual screen's holder counts. | Expanded group-member capabilities or completed paths toward Tier 0. |
| What happens on re-judging or unreadable data? | Reloading clears prior selection; new-generation empty results and corrupted synthetic coverage cannot leave old proof visible. Valid control rows can remain after a requester-only failure. | Background refresh of an idle screen or acceptance of results from a failed attempt. |
| Where are discovery coverage and individual answers presented? | Shell completion and CLI summary report scan status and limitation counts. The object section reports selected-request availability and individual limits/proof. | A new object-screen browser of every capture-wide discovery limitation; R8 adds no presentation. |

**Offline workflow witness:** `SelfMembershipWorkflowTests` adds 12 cases over newly generated
synthetic sealed bundles. They use real Derivation, Judgement, generation publication, readers and
the Assets object-screen path, rather than inserting constructed answers into the screen. Direct,
same-domain global-group and SELF routes retain the original trustee and resolved explanation;
own-account Add and Remove keep their different readiness answers. Holder counts and synthetic
Evidence fingerprints remain unchanged. Re-judging with a null budget removes old selected proof;
deliberately replacing a synthetic coverage record with JSON null and resealing that disposable
test generation produces a visible requester-read failure without hiding valid holder edges.
Only capture is substituted for the Shell post-capture checks; the CLI offline path has a capture
callback that throws if invoked. Null budgets are passed through unchanged, separately from
injected finished/stopped scan cases. The actual production null-budget call sites were reviewed,
not changed. The new cases passed **12/12**; the broader requester, discovery, storage, readback and
presentation selection passed **454/454**, none skipped.

**Final offline validation:** the full `SecureAD.Next.Tests` project passed **3,849/3,849**, none
skipped, and the solution build succeeded. The 12 new workflow cases also passed under
`dotnet-coverage`; the new report is
`next/.vs/R8-cbda14f1a62c40f9ac80281fa11e711f/coverage.cobertura.xml`. Existing R7 tests, production
source, host budgets, schemas and measured performance artifacts are unchanged. This is a
workflow/regression result, not another performance comparison or a numerical budget recommendation.
No visible application window, live-directory operation, protected-artifact access, commit or push
was part of R8.

**Documentation findings corrected:** the roadmap still said concrete requester analysis was
unimplemented; the overview mixed current schema-18/R7 behavior with schema-17-era statements;
older approval and measurement handoffs read like current next steps. These medium-severity status
contradictions are corrected or explicitly marked historical. P-145 was reviewed and remains open;
its recorded offline comparison and acceptance conditions did not need changing. Frozen measurements
and fixtures were not edited, no protected artifact was accessed, and no prose-shape test was added
as a substitute for review. The existing R6/R7 real-template tests remain the offline layout witnesses.

**R8 documentation correction is complete; final feature acceptance is not.** The remaining gates
are explicit: a justified and owner-approved numerical discovery budget before R2 enablement;
real-product and laptop/monitor verification; claim-specific requester laboratory acceptance;
and P-145's remaining capabilities, Tier 0-target review and Stage 6 gates. The historical live
Self-Membership experiment did not evaluate the later requester implementation. Stage 6 remains
bounded permission-derived control, not ownership findings or completed chained-path analysis.
Further tuning stays paused. A later enablement or acceptance decision must update these statuses
when supported; it must not be inferred from this reconciliation.

#### R2 production scheduling boundary

**Contract and integration approved, 2026-09-07.** Implementation was outstanding at approval and
was subsequently delivered in schema 18 below; the numerical budget is still unapproved.
After an explanation tied to the actual production paths below, the owner answered
"i approve proceed". This approves the shared permission-first scheduler, both own-account Add and
Remove per concrete pair, schema-18 persisted discovery summary and typed limitation records,
generation-bound summary/selection readback, and minimum Shell/CLI notices. Authorization and
explicit-batch refusal do not change. No numerical automatic-discovery default is approved; measure
and obtain approval before enabling a new production limit. This later answer supersedes the
earlier coverage-contract approval boundary below, not the outstanding production enablement and acceptance gates.

##### Delivered in schema 18 — 2026-09-07

**Automatic discovery is implemented and reached by both hosts; it performs no work until a
processing limit is configured, and says so.** `SelfMembershipScheduler` runs inside the existing
single pass over captured objects, without adding a second whole-catalogue stream. Requester and
holder lookups still add work, measured separately below. For each captured
group it examines Self-Membership entries that apply to the object itself, resolves the direct user
or the explicit same-domain global-security-group members, resolves `SELF` through the target, and
schedules **both Add and Remove for the requester's own account** on every concrete pair. Missing
membership never selects the operation. `SelfMembershipEvaluator` decides every answer unchanged, so
decision 0111's authorization rules, the own-account constraint and holder counts are untouched.

**Discovery does not restrict itself to established allows.** Denies and uncertain entries are
discovered, because a scan that kept only the safe cases would produce a screen listing exactly what
an administrator does not need. Broad runtime trustees and NULL DACLs are recorded as limitations
rather than expanded into a requester per captured account: expanding them would manufacture
concrete claims the evidence does not support.

`SelfMembershipDiscoveryCoverage` is persisted with the assessments and validated on read. It
records the mode, whether the captured-input scan finished, the configured budget, the work
consumed, the pairs discovered and typed `SelfMembershipDiscoveryLimitation` records. The four
states remain distinct and separately reportable: **missing captured evidence**
(`DescriptorUnavailable`, `MembershipNotCaptured`, `GroupTypeMissing`, `MissingIdentity`),
**unsupported analysis** (`UnsupportedRoute`, `BroadTrustee`, `UnresolvedTrustee`), **processing
stops** (the four budget reasons) and a failed or cancelled attempt, which publishes nothing and
leaves the previous generation current. A finished scan claims only that the captured permissions
this run could read were examined; it is not a claim about the forest or about attribute
completeness. `JudgementReader.ReadSelfMembershipSummary` reads counts and coverage without
materialising every assessment, and the selection read carries the same coverage.
`SelfMembershipCoverageStorage` refuses a missing, malformed, contradictory or orphaned record,
including through the Shell adapter, rather than returning an empty-looking result.

**Both production hosts now report it.** `JudgingLauncher` reads the summary back from the store and
`NewAuditViewModel` states it on the completion screen; `SecureAD.Cli.Program.Summarise` prints the
equivalent line for an unattended run. Each host words its own sentence, following the existing
`UnresolvedWording` precedent, but both read the same stored fields so the facts cannot drift.
**When no budget is configured — the current shipping state — both say the questions were not
scheduled and that this is not a result saying nobody can add themselves to a group.**

Validated offline against synthetic sealed bundles only. `SelfMembershipDiscoveryTests` proves
discovered requests reach judging and persist readable answers through the Shell post-capture path,
CLI `--judge` and CLI post-capture, each observed failing first with zero stored answers.
`SelfMembershipDiscoveryCoverageTests` covers denies, uncaptured permissions, NULL DACLs, broad
trustees, missing group type, unsupported scope, both operations per pair, a deterministic
processing stop that retains what it found, and a cancelled judging leaving the earlier generation
current. `SelfMembershipCoverageTests` mutates the sealed store in twelve ways and requires a
controlled read failure in both directions. `SelfMembershipNoticeTests` checks the host wording.
No AD contact, no application launch, no retained artifact or lab write.

**Still open.** The completed synthetic before/after measurements below do not justify an approved
numerical automatic-discovery budget, so normal judging still schedules no requester questions.
Further tuning is paused under the owner's recorded priority. Nested, primary-group,
SID-history, foreign-principal and cross-domain routes remain unsupported and are recorded as such.
R7 presentation is implemented and R8 current-state reconciliation is complete. Real-product
verification and final acceptance remain outstanding; P-145 and R2 enablement remain open.

##### What discovery costs — measured 2026-09-07, no budget set

**Measured with `next/tools/SecureAD.Measure`, offline against synthetic captures only.** Each shape
is judged twice, once with the scan configured and once with no budget, so the difference is the
cost of discovery and nothing else. Figures are from one machine — Xeon 8171M, 8 cores, 32 GB — and
**are not a published safe threshold for any forest**.

| Capture shape | Pairs | Scan cost | Per pair | Stored per pair |
|---|---|---|---|---|
| 1,000 objects | 500 | 0.5 s | 1.06 ms | ~3.1 KB |
| 5,000 objects | 2,500 | 3.7 s | 1.49 ms | ~3.1 KB |
| 10,000 objects | 5,000 | 12.6 s | 2.52 ms | ~3.1 KB |
| 20,000 objects | 10,000 | 54.2 s | 5.42 ms | ~3.1 KB |
| 10,000 objects | 25,000 | 180.9 s | 7.24 ms | ~3.1 KB |

**Storage is stable and predictable at about 3.1 KB per account/group pair.** Elapsed time is not:
the cost per pair climbs as the work grows.

**Two defects were found and fixed, and the answers did not change.** Each question about a group
re-read that group's permissions and re-queried its stored control edges; questions are now ordered
by target so each is read once. And every answer was its own committed transaction — the
control-edge writer already batched, while the requester writer passed no transaction — so 50,000
answers meant 50,000 commits; they now commit in batches of 1,000, rolled back if a run fails part
way. Together these took the largest shape from 211.7 s to 180.9 s and the smallest from 1.1 s to
0.5 s.

**Correction from the laptop measurement: the earlier object-count comparison was invalid.**
Judging's `scan-ms`, `read-ms`, `assess-ms` and `write-ms` remain useful observations, including the
13.4-second scan and 2.7-second request loop. However, the old generator always wrote every member,
holder and target plus the domain root, even when this exceeded the requested object count.
Both the nominal 3,000-object and 9,000-object runs with 750 groups and ten members therefore held
**9,001 objects**. Their similar elapsed times did **not** rule out a table-size or collation cost.
The nominal 10,000-object / 25,000-pair shape in the historical table actually held **27,001 objects**.
The table preserves the recorded figures, not an endorsement of its original shape labels.

**The requested batched read is implemented without narrowing the attributes returned.**
`ObjectAttributesReader.Read` still reads the object row, then reads every multi-valued table in
one `UNION ALL` query with separate text and byte columns. Ordinal order is restored within each
attribute. Empty attributes remain present; `Find` returning null cannot mean unfetched. The
complete-input and independently named regression checks are described in
[what an object holds](../evidence/what-an-object-holds.md).

**A Release baseline was collected before the reader edit on this laptop**, through
`SecureAD.Measurements.ObjectReadBenchmarks.ReadObjectAttributes`. It uses 1,000 generated objects,
100 real by-name reads per invocation, and separate empty/populated cases. Setup and capture
generation are outside the measured method. The same benchmark was used unchanged afterwards.

| Input | Before mean | After mean | Change | Before / after standard deviation |
|---|---|---|---|---|
| Empty attributes | 174.5 µs | 167.4 µs | -4.1% | 16.79 / 9.70 µs |
| Populated attributes | 129.3 µs | 130.5 µs | +0.9% | 4.15 / 4.09 µs |

**No meaningful speedup is established.** These are short-run measurements with substantial
uncertainty, not evidence for a processing budget. An initial union-wide database sort regressed
the populated case to 170.1 µs; that version was replaced with per-attribute ordinal sorting before
the after measurement above. The baseline CPU trace attributed 7.09% total samples to SQLite's
parameterless `ExecuteReader`, including calls from both object and value reads. Later sampled
symbol attribution was inconsistent, so no new dominant-cause claim is made from those names.

**The harness now verifies what is stored, not what was requested.** Impossible shapes are refused;
object, domain and physical ACE counts are read independently from the generated database before
judging. Each configured scan must finish, discover exactly the generated number of pairs and store
two assessments per pair; the scan-off run must store none. The name-lookup query plan on the new
synthetic captures reports `SCAN captured_object USING COVERING INDEX ix_captured_object_dn`, not
an indexed name seek. This is a remaining measured investigation, not permission to change sealed
storage, collation semantics or the host budget.

**Completed volume run on this laptop: Intel Core i7-1370P, 14 cores / 20 logical processors,
about 32 GB RAM, .NET 10.0.11, Release.** The 0.1-scale capture was independently verified as
34,700 objects, 590,000 physical ACEs and nine domains, with mean DN length 92.4 characters.
Generation took 20.6 seconds; the sealed capture occupied 231 MB. All three scan-on runs completed
with 750 discovered pairs and 1,500 assessments; every scan-off run stored none.

| Repeat | Scan off | Scan on | Difference | Scan-on allocated bytes | Added judgement bytes |
|---|---|---|---|---|---|
| 1 | 72,601.7 ms | 64,448.7 ms | -8,153.0 ms | 4,910,620,072 | 3,768,320 |
| 2 | 51,852.5 ms | 66,492.6 ms | 14,640.1 ms | 4,909,675,968 | 3,768,320 |
| 3 | 78,729.0 ms | 86,858.2 ms | 8,129.3 ms | 4,909,654,888 | 3,768,320 |

The median paired difference is 8,129.3 ms, but the spread and negative first difference prevent
interpreting that as a reliable isolated discovery cost. Allocated bytes are cumulative allocation,
not peak memory. Judgement storage was 12,836,864 bytes with scanning versus 9,068,544 without.
The final run's phase log recorded scan 6,214 ms, read 354 ms, assess 578 ms and write 111 ms.
The raw CSV remains in the system temporary directory under
`SecureAD-measure-20260907-071634-0786180ac66b46f7b253a973ac03e6a3/measurements.csv`;
the generated capture was deleted after the repetitions. A small nine-domain validation run also
verified 1,000 objects / 17,000 ACEs / 90 pairs, and the old impossible
`1 3000 750 10` command was observed failing before generation.

**Full-volume run completed successfully on 2026-09-07; one observation, not a budget acceptance.**
`1 --production 1` generated and independently verified **347,000 stored objects / 5,900,000
physical ACEs / nine domains**, with mean DN length 93.4 characters. Generation took 197.7 seconds
and the sealed capture occupied 2,341 MB. The harness exited with code 0. Scanning completed with
exactly **7,500 discovered pairs and 15,000 stored assessments**; the scan-off run stored none.

| Full-volume metric | Observed value |
|---|---|
| Judging with discovery off | 4,713,081.4 ms — 78 min 33 sec |
| Judging with discovery on | 5,002,759.3 ms — 83 min 23 sec |
| Paired elapsed difference, as recorded in CSV | 289,678.0 ms — 4 min 50 sec |
| Scan-on cumulative allocated bytes | 49,104,321,136 |
| Judgement bytes with discovery off | 89,944,064 |
| Judgement bytes with discovery on | 127,713,280 |
| Additional judgement bytes | 37,769,216 |
| Scan completed / pairs / assessments | True / 7,500 / 15,000 |

The final phase log recorded `scan-ms=338507`, `read-ms=18704`, `assess-ms=30886` and
`write-ms=806`. Those phase times are measurements inside the scan-on run, not components that
must sum to the difference between two separate whole runs. The allocation figure is cumulative
managed allocation, **not peak memory or a required RAM capacity**. The CSV is retained beneath
the system temporary directory at
`SecureAD-measure-20260907-072851-5bd6899deaab4779986b8f83f2a80016/measurements.csv`.

**The next investigation is the scan-off judging pipeline.** It already took nearly 79 minutes,
with no requester discovery and with the harness scheduling **zero rules**. That time must not be
attributed to the product's 17 rules, nor assumed to be explained by requester name lookups. Profile
the real scan-off path on bounded, independently verified synthetic shapes, separating evidence
streaming and permission reads, control-edge derivation, store writes and sealing. Vary object and
ACE counts separately to identify which work grows, then change only a measured bottleneck and
repeat the same measurement. The name-predicate index scan remains a lead, not a proven explanation
of this baseline. No new full-volume run or production-code change is implied by recording this plan.

**Bounded scan-off CPU profile completed, 2026-09-07.** The new
`next/BenchmarkSuite1/ScanOffJudgingBenchmarks.cs` calls the actual `JudgingRun.Judge` with zero
rules and a null discovery budget. Its four shapes vary objects and physical ACEs independently,
retain nine domains and 18 target/holder group pairs with five members each, and use the same
distinct synthetic read-property trustees as the volume harness. Capture generation and stored-count
verification are outside the measured method. Independent SQL counts are checked against requested
objects, domains and ACEs; three deliberately wrong expected counts are observed being rejected.
Each measured judgement must complete; readback checks zero requester pairs and assessments.
The fixture is deleted afterwards. The existing object-read benchmark and production code were not
changed. The new benchmark is frozen after its successful run.

Release BenchmarkDotNet monitoring job: one launch, one warmup, three measured iterations, one
invocation per iteration. CPU trace session: `de9f9690-2482-4f91-8976-add999cd4b56`.

| Objects | Physical ACEs | Mean | Reported error | Standard deviation |
|---|---|---|---|---|
| 1,000 | 17,000 | 329.6 ms | 1,011.7 ms | 55.46 ms |
| 1,000 | 51,000 | 528.8 ms | 1,602.2 ms | 87.82 ms |
| 3,000 | 17,000 | 707.2 ms | 2,037.4 ms | 111.68 ms |
| 3,000 | 51,000 | 929.0 ms | 2,071.1 ms | 113.52 ms |

Both object count and ACE count affect the observed means, but the short-run uncertainty is large.
These timings neither establish a scaling law nor explain the 79-minute full-volume baseline.
They are new workload measurements, not before/after optimization results.

| Reported sampled function | Self CPU | Total CPU |
|---|---|---|
| `PrincipalClassificationRegistry.For` | 0.06% | 29.64% |
| `SqliteCommand.ExecuteReader(CommandBehavior)` | 13.10% | 13.11% |
| `ObjectPermissionsReader.DescriptorOf` | 0.04% | 3.92% |
| `ObjectPermissionsReader.ObjectOf` | 0.00% | 3.05% |
| `ObjectPermissionsReader.Lookup` | 0.03% | 1.79% |

**Attribution limits matter.** These are sampled CPU percentages, not elapsed phase timings, and
the trace also includes fixture setup and readback. Its call tree contains implausible getter/runner
ancestry, while the reported classification hotspot has no line-level samples. Treat that
classification attribution as provisional; do not change authority classifications or claim that
classification explains 29.64% of the full-volume elapsed time.

The more concrete source-mapped observations are in `ObjectPermissions.cs`: line 381, the by-name
object query's `ExecuteReader`, carries 204 samples (2.96% of trace samples); line 644, the trustee
lookup's `ExecuteReader`, carries 94 (1.36%). The object query uses
`WHERE distinguished_name = $dn COLLATE NOCASE LIMIT 1`. Source inspection confirms that
`JudgingRun.cs` line 394 calls `ReadPermissions(subject.DistinguishedName)` inside the whole-object
loop even with discovery off and no rules. This places the previously observed name-predicate scan
on the scan-off path too; it still does not quantify its full-volume share.

**Permission-name query isolated, 2026-09-07: the repeated scan is now reproduced directly.**
This follows the earlier repeated-read finding rather than reopening it. The batched attribute
read was implemented, but it did not remove the separate permission reader's object-name lookup.
The existing CPU trace was reused; no duplicate pipeline benchmark or full-volume run was started.

The check loaded the product's Release SQLite provider (SQLite **3.53.3**) and called the actual
`BundleSchema.CreateTables` and `BundleSchema.CreateDeferredIndexes` in disposable in-memory
databases. Only synthetic `captured_object` rows were inserted, with verified inserted counts.
Foreign keys were disabled for this isolated table fixture: it is **not a sealed capture or an
end-to-end judging measurement**. No evidence file, production schema, host or protected artifact
was changed. The SQL tested was the exact `ObjectPermissionsReader.ObjectOf` query:

```sql
SELECT object_id, distinguished_name FROM captured_object
WHERE distinguished_name = $dn COLLATE NOCASE LIMIT 1
```

`PRAGMA index_xinfo(ix_captured_object_dn)` reports **BINARY** collation on `distinguished_name`.
`EXPLAIN QUERY PLAN` reports:

| Query | Observed plan |
|---|---|
| Actual permission-name query, `COLLATE NOCASE` | `SCAN captured_object USING COVERING INDEX ix_captured_object_dn` |
| Case-sensitive diagnostic control | `SEARCH captured_object USING COVERING INDEX ix_captured_object_dn (distinguished_name=?)` |
| Integer object-ID diagnostic control | `SEARCH captured_object USING INTEGER PRIMARY KEY (rowid=?)` |

The index exists, but its name comparison does not match the query's case-insensitive comparison.
This makes the actual query scan the index rather than seek to a name. **Removing `NOCASE` is not
a fix:** the diagnostic control returned no object for the deliberately case-varied name, while
the real query returned the correct object. First, middle, last, case-varied and absent probes
were all checked for their expected returned object ID or absence.

Native `sqlite3_stmt_status` counters measured work rather than laptop-dependent timings:
`SQLITE_STMTSTATUS_FULLSCAN_STEP` (1) counts forward scan steps; `SQLITE_STMTSTATUS_VM_STEP` (4)
counts executed SQLite virtual-machine instructions. The numbers below are observed counters,
not elapsed-time estimates and not ambiguous profiler symbol attribution.

| Rows | Last-name scan steps | Last-name VM steps | Absent-name scan steps | Absent-name VM steps |
|---|---|---|---|---|
| 1,000 | 999 | 3,011 | 999 | 3,008 |
| 3,000 | 2,999 | 9,011 | 2,999 | 9,008 |
| 10,000 | 9,999 | 30,011 | 9,999 | 30,008 |

Case-varied last-name probes had exactly the same work as the last-name probes. The first-name
probe used zero scan steps and 14 VM steps at all sizes, demonstrating why early-object probes
alone miss the growth. The case-sensitive control used zero scan steps and 14 VM steps for each
existing exact-case name at all sizes; absent and case-varied probes used 10 VM steps and returned
nothing. That control isolates the collation mismatch but intentionally does **not** preserve the
production behavior, so it is not an optimization candidate as written.

The exact production query was then executed once for **every** name in each synthetic table;
each result was checked against its expected object ID. A prepared statement was reused, so these
counts exclude repeated statement preparation and do not time the complete permission reader.

| Rows / successful lookups | Observed total scan steps | Observed total VM steps |
|---|---|---|
| 1,000 | 499,500 | 1,512,500 |
| 3,000 | 4,498,500 | 13,537,500 |
| 10,000 | 49,995,000 | 150,125,000 |

The total scan work matches `N * (N - 1) / 2`: ten times as many objects produced about one hundred
times as many scan steps in this isolated all-object lookup. **This establishes a concrete
quadratic lookup mechanism on the scan-off path, not the fraction of the 79-minute run it caused.**

**The bounded permission-read fix is implemented and remeasured, 2026-09-07.** The Evidence reader
retains the most recently streamed object's internal row ID and exact name. An exact-name permission
read uses that ID directly, passing through the unchanged descriptor parsing, trustee resolution
and uncertainty logic. No public method signature, object-attribute contract or sealed schema changed.

**Ambiguity is checked, not assumed away.** Once per reader, before the fast route is used, SQLite
groups stored names under its own `NOCASE` comparison and checks for duplicates. That adds one
name-index scan/sort, not one name scan per object. If any names are ambiguous, the entire reader
keeps the original lookup. Case-varied and non-current names likewise retain the original lookup.
This is one retained identity and one boolean, not a managed dictionary of the forest. The internal
row ID avoids treating null or repeated GUIDs as interchangeable objects. The owning description is
[what an object's permissions hold](../evidence/what-an-objects-permissions-hold.md).

Five new regression cases passed against the old reader before the change and the same 40
permission tests passed afterwards. They exercise null and shared GUIDs, duplicate names with exact
or different case, non-ASCII case distinctions, escaped commas, earlier/missing objects, absent
descriptors and disposal. Duplicate-name reads are compared with a separate, non-streaming reader
using the original lookup, so bypassing the ambiguity guard would select a different descriptor and
fail the comparison. No frozen fixture or existing benchmark was changed.

The **same** `ScanOffJudgingBenchmarks.JudgeWithoutDiscovery` CPU collection and four parameter
combinations were rerun unchanged. Before session: `de9f9690-2482-4f91-8976-add999cd4b56`;
final after session: `d56c86d9-c201-493d-9fb3-ebc721aef546`. The pre-change figures below are the previously
recorded baseline, not another newly generated estimate.

| Objects | ACEs | Before mean | After mean | Mean change | Before / after error | Before / after standard deviation |
|---|---|---|---|---|---|---|
| 1,000 | 17,000 | 329.6 ms | 431.4 ms | +30.9% | 1,011.7 / 2,980.5 ms | 55.46 / 163.37 ms |
| 1,000 | 51,000 | 528.8 ms | 511.0 ms | -3.4% | 1,602.2 / 1,701.3 ms | 87.82 / 93.25 ms |
| 3,000 | 17,000 | 707.2 ms | 556.9 ms | -21.3% | 2,037.4 / 1,795.0 ms | 111.68 / 98.39 ms |
| 3,000 | 51,000 | 929.0 ms | 741.4 ms | -20.2% | 2,071.1 / 1,858.6 ms | 113.52 / 101.88 ms |

The larger bounded shapes have lower observed means; **the smallest regressed by 30.9% in the final
run**, with high variance. The first after run (`d98f4649-bdca-43f8-a6e0-f1e487e3034a`) recorded means
335.3 / 523.6 / 545.2 / 770.6 ms in the same row order. The full test suite then caught an optional
null callback default; the callback was made an explicit required collaborator, without changing
the gate, and the complete benchmark was rerun on that final code. Both observations are retained
rather than selecting the more favorable small-case number. **The wide short-run uncertainty
prevents calling these percentages established speedups or dismissing the regression.** The new
traces contain the `ReadAt` route; the initial after trace also identifies the once-per-reader
uniqueness check. Sampling metadata and call attribution vary, so CPU percentage changes are not
used as an improvement metric or as proof of the remaining bottleneck. The deterministic change is removal
of repeated name scans for the ordinary unique-name streamed path; ambiguous and arbitrary by-name
reads intentionally retain their old cost.

At completion of the bounded benchmark, no full-volume rerun had been launched. The recorded
78/83-minute observations above remain the **pre-fix baseline**; the subsequent intermediate and
full-volume comparisons are recorded below. No processing budget is approved.

**Intermediate-scale remeasurement completed, 2026-09-07.** The unchanged Release harness was run
with `3 --production 0.1`, the same settings as the earlier intermediate baseline. It regenerated
and independently verified **34,700 objects, 590,000 physical ACEs and nine domains**, with 75
target/holder group pairs, ten members per holder and mean DN length 92.4 characters. This uses
the same synthetic generator and shape, not the earlier deleted capture file. Generation took
23.5 seconds (previously 20.6); the sealed capture again occupied 231 MB.

All three scan-on runs completed with exactly **750 pairs and 1,500 assessments**, and the scan-off
runs stored none. The process exited with code 0 and deleted its generated capture. No production
code or measurement setup changed during this remeasurement.

| Repeat | Scan off | Scan on | Paired difference | Scan-on allocated bytes | Added judgement bytes |
|---|---|---|---|---|---|
| 1 | 14,972.3 ms | 18,796.8 ms | 3,824.5 ms | 4,866,962,096 | 3,768,320 |
| 2 | 11,861.9 ms | 19,131.7 ms | 7,269.9 ms | 4,865,886,552 | 3,768,320 |
| 3 | 12,475.0 ms | 20,630.4 ms | 8,155.4 ms | 4,865,886,872 | 3,768,320 |

**Comparison with the recorded pre-fix intermediate baseline**, using the median of each metric's
three observations. Elapsed differences are medians of paired differences, not the difference of
the two elapsed medians. CSV values retain their own rounding.

| Metric | Before median | After median | Change |
|---|---|---|---|
| Scan-off judging | 72,601.7 ms | 12,475.0 ms | -60,126.7 ms; **-82.82%** |
| Scan-on judging | 66,492.6 ms | 19,131.7 ms | -47,360.9 ms; **-71.23%** |
| Paired scan-on minus scan-off | 8,129.3 ms | 7,269.9 ms | -859.4 ms; -10.57% |
| Scan-on cumulative allocated bytes | 4,909,675,968 | 4,865,886,872 | -43,789,096; -0.89% |
| Judgement bytes with scanning | 12,836,864 | 12,836,864 | unchanged |
| Judgement bytes without scanning | 9,068,544 | 9,068,544 | unchanged |
| Added judgement bytes | 3,768,320 | 3,768,320 | unchanged |
| Scan-on pairs / assessments | 750 / 1,500 | 750 / 1,500 | unchanged |

Every new scan-off time is below every old scan-off time; the same holds for scan-on times. This
is clear observed improvement **at this verified intermediate shape**, unlike the noisy small
benchmark comparison. It does not erase the recorded smallest-case regression or establish a
general speedup for arbitrary by-name/ambiguous reads. Added storage and result counts are equal;
those facts alone are not a comparison of every judgement field across regenerated captures.

The final phase log recorded `scan-ms=5881`, `read-ms=450`, `assess-ms=751`, `write-ms=284`
(the preceding repetition: 5782 / 335 / 540 / 114 ms). Discovery still has separate work; its paired
elapsed differences remain variable and must not be treated as a safe budget. Allocation is
cumulative, not peak memory. The raw after CSV remains under the system temporary directory at
`SecureAD-measure-20260907-163634-064bd62b59c449cabb31ff5b2175c13c/measurements.csv`;
the before CSV is the previously recorded `SecureAD-measure-20260907-071634-0786180ac66b46f7b253a973ac03e6a3` run.

**Post-fix full-volume measurement completed successfully, 2026-09-07.** The owner requested the
run after reviewing the intermediate improvement. The unchanged Release harness ran
`1 --production 1`, regenerating and independently verifying **347,000 stored objects, 5,900,000
physical ACEs and nine domains**, with mean DN length 93.4 characters. It exited with code 0.
The scan completed with exactly **7,500 pairs / 15,000 assessments**; the scan-off run stored none.
The before and after CSVs agree on objects, groups, members per group, domains, ACEs, repetition
count, scan completion and requester counts. These are matching synthetic shapes, not the same
sealed capture file: each run generated its own input and deleted it afterwards.

| Full-volume metric | Before fix | After fix | Change |
|---|---|---|---|
| Judging with discovery off | 4,713,081.4 ms (78 min 33 sec) | 111,315.8 ms (1 min 51 sec) | -4,601,765.6 ms; **-97.64%** |
| Judging with discovery on | 5,002,759.3 ms (83 min 23 sec) | 491,347.0 ms (8 min 11 sec) | -4,511,412.3 ms; **-90.18%** |
| Paired discovery-on minus discovery-off | 289,678.0 ms (4 min 50 sec) | 380,031.2 ms (6 min 20 sec) | **+90,353.2 ms; +31.19%** |
| Scan-on cumulative allocated bytes | 49,104,321,136 | 48,666,289,792 | -438,031,344; -0.89% |
| Judgement bytes with discovery on | 127,713,280 | 127,713,280 | unchanged |
| Judgement bytes with discovery off | 89,944,064 | 89,944,064 | unchanged |
| Additional judgement bytes | 37,769,216 | 37,769,216 | unchanged |
| Scan-on completed / pairs / assessments | True / 7,500 / 15,000 | True / 7,500 / 15,000 | unchanged |
| Capture generation, outside judging | 197.7 sec | 217.8 sec | +20.1 sec |
| Sealed capture size, as reported | 2,341 MB | 2,341 MB | unchanged |

The final scan-on phase log is retained separately from whole-run subtraction:

| Phase log field | Before | After | Change |
|---|---|---|---|
| `scan-ms` | 338,507 | 355,766 | +17,259 ms |
| `read-ms` | 18,704 | 20,078 | +1,374 ms |
| `assess-ms` | 30,886 | 32,900 | +2,014 ms |
| `write-ms` | 806 | 832 | +26 ms |

**The common judging pipeline is substantially faster in this observed full-volume comparison;
the discovery work is not.** Its paired elapsed difference increased by 90.4 seconds and all four
recorded discovery-phase values increased. These regressions remain visible alongside the overall
improvement. A phase measurement within one run is not a component guaranteed to sum to the
difference between two whole runs. The remaining discovery cost is separate from the permission
identity-reuse fix and must not be hidden by its benefit.

Allocation is cumulative managed allocation, **not peak memory or a RAM requirement**. Equal
counts and file sizes do not compare every judgement field across independently regenerated
captures; the separate regression suite supplies the identity/case/absence correctness checks.
Neither the earlier smallest-case regression nor uncertainty is erased by this full-volume result.

Raw CSVs remain beneath the system temporary directory:
- Before: `SecureAD-measure-20260907-072851-5bd6899deaab4779986b8f83f2a80016/measurements.csv`.
- After: `SecureAD-measure-20260907-164746-70cc99867d12454192f04e6e0742634d/measurements.csv`.

Both hosts still pass no budget; recording this comparison changes no production code, storage/schema
or authority decision. SID-classification attribution remains provisional.

**Owner-approved handoff: pause further discovery tuning and return to product work.** Preserve
the validated permission-read fix, regression tests and existing measurement artifacts. The remaining
discovery cost stays open under P-152; pausing tuning does not approve a budget or enable either host.
Remeasure when subsequent work changes data access, candidate counts or processing volume, and before
approving production limits, rather than after presentation-only changes. The owner subsequently
requested a documentation checkpoint, commit and push before moving to a new session; that commit
and push were explicitly authorized for that checkpoint. The next bounded preparation was the
[R7 presentation](../shell/the-assets-screen.md#r7-requester-presentation), subsequently explicitly
approved, implemented and offline-validated in the continuation session. No further commit or push
is authorized by that historical checkpoint. R8's later documentation correction does not close
R2 enablement or final feature acceptance; laptop/monitor checks remain normal outstanding product verification.

Each full-volume measurement had one repetition, always scan-off before scan-on, supplying neither a variability estimate nor a
stable isolated discovery cost. This completes the observed full-volume before/after comparison, **not**
performance acceptance, a stable scaling curve or a processing-budget proposal. Both hosts remain
unchanged with no discovery budget, and storage/schema and authorization changes remain unapproved.

The solution build and all 3,754 tests passed with zero skipped after the reader, regression-test,
harness and governing-document changes. This is correctness validation, not performance acceptance.

After the bounded permission-read fix and required-callback correction, the full suite passed
**3,759/3,759, zero skipped**. The five new cases account for the increase. The benchmark remained
unchanged and its final after run completed successfully; correctness validation does not close
the outstanding performance acceptance or justify a budget.

**The historical figures are not a bound.** Their requested shapes stopped at 20,000 objects
against a production forest of roughly 347,000 with 5.9 million access control entries — see
[the forest this is built for](../../WHAT-THE-PRODUCT-IS.md#the-forest-this-is-built-for). A budget
argued from them alone would be argued from a capture two orders of magnitude too small.

**To re-run the measurement**, from the repository root:

```powershell
dotnet run --project next/tools/SecureAD.Measure -c Release -- 3
dotnet run --project next/tools/SecureAD.Measure -c Release -- 3 9001 750 10
dotnet run --project next/tools/SecureAD.Measure -c Release -- 3 --production 0.1
dotnet run --project next/tools/SecureAD.Measure -c Release -- 3 --production 1
```

The first argument is how many times each shape is repeated; the next three — objects, groups,
members per group — select a single shape. Two optional following arguments specify domains and
ACEs. `--production` scales 347,000 objects and 5.9 million physical ACEs while retaining nine
domains; the synthetic workload uses 750 target groups with ten members per holder at full scale.
This is volume evidence, **not a reconstruction of production membership density, delegation,
control-edge counts or chained paths**. Additional ACEs are ordinary read-property entries and
have distinct synthetic trustees. Long DNs model naming depth, not a complete OU hierarchy.
**Build in Release or the numbers mean nothing.** Each capture is generated once, reused for all
scan-on/off repetitions, then deleted. Only one capture is needed at a time. `measurements.csv`
remains beneath the printed temporary directory. Scan-on minus scan-off can be negative due to
warmup and noise; never interpret that as a saving or a safe threshold. It contacts no directory
and reads nothing from a real forest. Both production hosts still pass no discovery budget.

##### Historical R2 prerequisite review — before schema-18 approval

The following paragraphs record the earlier schema-17 proposal and prerequisite validation, not
the current integration status. The schema-18 delivery, R7 implementation and R8 reconciliation
above supersede their then-open implementation/presentation statements; their approval history,
test counts and evidence provenance remain historical.

The then-current production
Shell path is `NewAuditViewModel.JudgeAsync` through `IJudgingLauncher.RunAsync` and
`JudgingLauncher` to `JudgingRun.Judge`. Its only current launcher caller follows capture; an
interactive offline requester action is not already present. CLI `Program.RunAsync` reaches
`Program.Judge` both for offline `--judge` and after capture/derivation. Both hosts call the overload
that supplies an empty requester list. The CLI does judge; the missing integration is explicit
requester scheduling, not judging as a whole.

The existing request contract carries requester DN, target DN, Add or Remove, and an optional
member DN; null means the requester's own account. The default budget permits **100 submitted
requests** and **10,000 relevant permission entries per assessment**. The coordinator checks the
submitted count before deduplication, refuses an oversized batch rather than taking its first
100 entries, then deduplicates and orders requests deterministically. The permission-entry limit
instead records `PermissionBudgetExceeded` with Unknown authorization. It is not a global bound
on the ordinary rules or control-edge pass. Unknown requester answers are not reflected in the
coordinator's overall completion state, which depends on capture scope and rule outcomes; a host
must read and report requester outcomes separately rather than imply that completion means every
requested question was answered definitively.

Each successful judging publishes a new complete judgement generation, including its entire
requester set. Requests are not automatically carried forward: an empty batch publishes an empty
completed requester product. Failure before publication leaves the previous generation current;
it must not be presented as results of the failed attempt. Evidence and Derivation are not rewritten.
`ExplicitRequesterSurvivesTheRealCoordinatorWithoutMultiplyingTheHolderEdge` exercises the library
coordinator, not either production host. Closing R2 requires host-to-store regression checks that
prove automatically discovered requests reach judging after capture and through offline CLI judging,
then read the persisted answers, including refusal and replacement behavior. Scheduling does not
authorize changing the evaluator, public contracts or storage semantics without prior approval.

**Owner requirement and specification-backed direction:** the owner clarified on 2026-09-06 that
this "should always run on new captures". The existing-capture-first scope and same-Evidence-only
request-file proposal were not approved and are withdrawn. The judgement specification's
[permission/group-first approach](../specs/JUDGEMENT-HALF.md#authorization-membership-is-cached-by-context-capability-evaluation-remains-target-specific)
starts with a captured permission's trustee, resolves relevant captured members and validates scope.
Decision 0111 requires concrete bounded questions, not an administrator-maintained selection list.
Normal Shell and unattended CLI judging must discover them from each capture's own evidence,
including the first capture, within the supported direct-user and single explicit same-domain
global-security-group routes. SELF resolves to the captured target identity and membership, not the
machine's current user. This assesses own-account changes; it never performs membership changes,
uses live lookups or constructs a forest-wide requester/target cross-product.

**Remaining approval boundary:** define and persist truthful discovery coverage and budget stops,
separately from individual authorization answers and overall rule completion. Schema 17's requester
product stores only evaluator version and completion; its public assessment set carries rows,
product availability and generation, not discovery coverage. Unknown assessments require concrete
requests and cannot stand in for an unidentified requester or an unvisited part of the capture.
Decision 0102 requires retained partial expansion with an explicit stop reason; it does not change
the existing submitted-batch refusal into "take the first 100". A new discovery coverage contract,
its storage/readback and the minimum host notices needed to avoid a complete-looking partial result
require approval before implementation. Authorization and holder counts remain unchanged; broad
R7 presentation and R8 reconciliation were deferred at this checkpoint.

**Recommended bounded production slice; not yet approved:** integrate one permission-first scheduler
into normal judging, reached by both hosts. For each relevant captured Self-Membership entry, use
its direct user or explicit group members; resolve SELF through the target. Do not restrict seeds
to established allows: relevant denies and uncertain entries must not disappear from discovery.
Schedule both Add and Remove for each concrete pair, with null member DN, independently of whether
the captured target lists the requester. Missing membership is not proof of absence. Evaluate with
the existing ordered authorization code and retain links to stored holder edges without adding
counted edges. Do not traverse nested/primary-group/SID-history/foreign or cross-domain routes;
record unresolved and unsupported discovery evidence rather than manufacturing requester identities.
Broad runtime trustees and null/unreadable descriptors cannot justify a fabricated complete empty
requester set; record the coverage limitation without expanding every user against those targets.

Use a separate automatic-discovery budget and persisted coverage product, not silent truncation of
submitted batches. **The initial 100-record/50-pair discovery recommendation is withdrawn.** After
the revised recommendation to establish a measured processing budget rather than a blanket 50-pair
cutoff, the owner answered "ok i apporove your proposal". This approves the budget direction, not a
new numerical threshold or the entire proposed storage/readback extension. The explicit library
batch limit is not evidence of an appropriate automatic-discovery limit. The next bounded task is
offline measurement with synthetic inputs: account for discovery work, assessment processing,
memory and stored-result size before recommending numerical limits. Do not bypass the existing
submitted-batch refusal to perform that measurement or contact AD; retained Evidence and laboratory
artifacts remain read-only.

**Budget-direction documentation validation:** the fresh external baseline is
`%TEMP%\SecureAD-R2-budget-baseline-20260906-230510`. The full test project passed 3,715/3,715,
none skipped, and the solution build passed after recording this direction. Only this document
and the product overview were edited; no production code or tests changed. These are preservation
checks, not processing measurements or acceptance of automatic scheduling. No numerical budget
has been established by these test results.

The proposed coverage behavior retains unresolved nodes already encountered and records which
target/holder was reached and the stop reason; an unknown remainder is not a known total. Missing
captured evidence, unsupported analysis and a processing stop are different reasons, not a single
claim of incomplete capture. The 10,000-entry per-assessment authorization limit and explicit
submitted-batch refusal remain unchanged. Ordinary rules and counted holder edges continue
independently. A completed generation may contain a truthfully partial requester product; failure
or cancellation before publication still leaves the previous generation current, never relabelled
as the new attempt's results.

This recommendation needs a versioned judgement-storage/readback extension for discovery scope,
configured limits, unresolved inputs and stop reasons (not changes to Evidence or Derivation), plus
minimum Shell/CLI coverage notices. Historical schema-17 results must not acquire an invented
automatic-discovery coverage claim. Full requester presentation was assigned to R7. The proposed integration verification
must exercise the real Shell post-capture path and both CLI judging paths using synthetic sealed
bundles, with no directory contact, and prove persisted results and generation replacement rather
than merely inspecting calls or supplying a hard-coded library batch.

**Prerequisite correction validation, 2026-09-06:** the fresh external baseline is
`%TEMP%\SecureAD-R2-baseline-20260906-201531`, at HEAD
`0e4762baf1c713f9bc86538da3e7ab1cde33ed52` on `main`: 30 modified tracked files, 338 untracked,
nothing staged. Only this document and the product overview changed in this prerequisite slice;
no production code or tests changed. Fresh Test Explorer runs passed 526/526 focused requester,
storage, readback, sizing and host regressions and 3,715/3,715 full-project tests, none skipped;
the full solution build passed. These are preservation checks, not R2 before/after defect evidence
or host-to-store acceptance of automatic discovery, which was unimplemented pending approval at that checkpoint.
The session-only diff was inspected and `git diff --check` passed. All 389 retained artifact/lab
files, including ignored files, matched the fresh hash manifest; fresh Evidence remains SHA-256
`137FF0CE603D5CC6463C76D1FA0432245A57C2FC1FF48481BDDDA9C6A8B8DA41`.
Instructions, the gallery, historical fixtures and earlier fixes were preserved. No visual/live
verification, application launch, directory operation, cleanup or commit occurred. R2, R7, R8 and
P-145 were open at that checkpoint; current status is in the review register above.

### Captured-lab validation of the initial slice — 2026-09-06

**The catalogue-1 baseline, not stage-6 acceptance.** A fresh evidence-only copy of
`ad.lab-20260905-212426` was derived and judged before the P-150 correction below. This is the newer capture
used by the interrupted session, not the older `03:54` capture named in its brief. All three domains
and 8,383 captured objects were represented. The source, preserved previous copy and new copy retain
Evidence SHA-256 `2DEF9F8AD4DE01877970B7F97F845716C1FFC1B093B01F388004610526E76BE4`.
No directory connection or modification was made.

| Initial-slice measurement | Result |
|---|---:|
| Counted WRITE_DAC primitives | 32,544 |
| Counted WRITE_OWNER primitives | 32,540 |
| Expected primitives | 43,447 |
| Unexpected primitives | 11,805 |
| Expectedness unknown | 9,832 |
| Supporting owner-to-DACL compounds, unknown and uncounted | 32,540 |
| Objects with unanswered supported primitives | 0 |

All 65,084 primitives have evaluation `Established`. **That is separate from whether a right is
expected**, and neither this table nor zero unanswered supported primitives means all stage-6
capabilities were evaluated. Judging produced 27 findings; SEC-031 and SEC-032 each retained their
four unresolved objects, so the overall run remains `CompletedDegraded`.

**The byte-level check did not call SecureAD's parser or access evaluator.** The .NET
`RawSecurityDescriptor` reader parsed the 390 distinct captured descriptors. Its entry ordinals,
types, SIDs, masks, GUID presence, inheritance flags and opaque data matched the 1,547 distinct
supporting signatures representing all 433,561 stored control-ACE records. Generic mapping and
inherit-only interpretation follow [MS-ADTS 6.1.3](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a).
Every counted primitive had an applicable raw allow, and independently enumerating uncomplicated
direct grants found the same 65,084 identities with none omitted. Altering a compared ACE and
removing an edge in memory each made the corresponding check detect the mismatch. These checks
establish provenance and direct-grant coverage, not token-wide effective access.

The previous and fresh generations have identical edge answers and object coverage after excluding
generation identifiers. The planted `SecureADTakeoverOuter` group retains two unexpected primitives
on `OU=SecureADTakeoverTarget,OU=BA Lab,DC=ba,DC=ad,DC=lab` and one unknown, uncounted compound.
Object-first and holder-first reader calls return the same edge identities. The target has 15 stored
rows, seven default-visible rows and six hidden expected primitives; supporting rows are not added
to those primitive counts. An absent target is not presented as a complete empty result.

**The baseline exposed P-150, since corrected below.** All 9,818 `UnknownAuthorityScope`
primitives belong to `BUILTIN\Administrators`: 460 scoped to `ad.lab`, 8,834 to `ba.ad.lab` and 524
to `ph.ad.lab`. The three scoped group objects are captured. `ObjectPermissions` deliberately gives
well-known SID labels no domain; the original `ControlEdgeDeriver` recorded a scoped holder but passed the
unscoped label's domain into its direct expectedness check. Decision `0099` accepts Administrators
within its own domain. The missing scope handoff was the defect, not the accepted catalogue.
Do not resolve a shared BUILTIN SID
by taking the first matching directory row, or remove the uncertainty required for non-domain
resource contexts under P-90.

**Unexpected volume has two large concentrations.** Account Operators contributes 8,426 primitives
(4,260 on groups, 4,120 on users, 24 on foreign security principals, 16 on computers and six on group
managed service accounts). Forest-root Domain Admins contributes 3,210 outside its accepted authority
scope. A large count does not by itself justify widening the catalogue. SYSTEM contributes 16,732
expected primitives; ADDC, BADC and PHDC each contribute six unexpected primitives. Server Operators,
Print Operators, Backup Operators and Replicator have no named-trustee primitives in this slice;
that is not a claim that they have no other capabilities. Enterprise Domain Controllers accounts for
the remaining 14 unknown expectedness answers, with `UnknownCapabilityScope`.

Artifacts, including the two executable checks, raw diagnostic outputs and binary fingerprints,
remain under `next/artifacts/stage6-control-recovery-validation/`. Judgement generation:
`4cfa848c-83c2-42b5-8eb9-c65014d07c72`; derivation generation:
`709c602a-19ad-428d-91bd-5d10efb507a6`. **P-145 remains open:** the remaining capabilities,
member expansion, Tier 0-target analysis and the claim-specific live laboratory gates are not
discharged by this offline check. No application behavior or policy was changed in the baseline pass.

### P-150 corrected — catalogue 2, 2026-09-06

`ControlEdgeDeriver.Expected` now obtains direct BUILTIN domain authority from the target's domain
only when the target is in that domain naming context and its captured domain root supplies a SID.
The well-known label remains domainless. Configuration, schema, application-partition and missing-
scope cases remain unknown; a membership route retains its root's own recorded scope. No first-match
SID lookup or new expected principal was introduced.

`PrincipalClassificationRegistry.Version` is now 2. The storage layout remains judgement schema 15:
new edges carry the changed semantic version, and old generations are read as recorded, not relabeled.
**Re-judge existing evidence to obtain the correction; re-capture and re-derivation are not required.**

The regression uses a real two-domain bundle containing both Administrators groups and real
descriptors, in both capture orders. It verifies that the reader's label is still domainless,
object-first and holder-first identities agree, scopes stay separate, expected primitives are hidden
with their count stated, and the supporting ownership compound remains unknown and uncounted.
Both cases failed before the fix with *expected 2 expected primitives, actual 0*. Two direct-scope
positive cases also failed; the negative scope and cross-domain membership-root cases passed.
After correction and versioning, all 60 targeted tests passed.

A separate copy of the same evidence and sealed derivation was judged into generation
`a0eef917-5c1b-493b-98bf-8b21bbcf63b4`. The preserved baseline was not overwritten.

| Counted primitive classification | Catalogue 1 | Catalogue 2 |
|---|---:|---:|
| Expected | 43,447 | 53,265 |
| Unexpected | 11,805 | 11,805 |
| Unknown | 9,832 | 14 |

Exactly 9,818 counted primitives changed from `UnknownAuthorityScope` to
`ExpectedSameDomainControlPlane`, all scoped BUILTIN Administrators. Another 4,909 supporting
compounds changed only their expectedness: their capability evaluation remains unknown and they are
still uncounted. Each domain already had two expected Administrators primitives; the corrected
holder totals are therefore 462 in `ad.lab`, 8,836 in `ba.ad.lab`, and 526 in `ph.ad.lab`, not merely
the reclassification deltas. The remaining 14 unknown answers still have `UnknownCapabilityScope`
for Enterprise Domain Controllers.

The executable comparison in `next/artifacts/stage6-p150-scope-correction/compare-p150.ps1` checks
both directions: all other stored edge fields (apart from the new generation and catalogue version),
8,383 object-coverage rows, 433,561 control ACEs, 97,620 preconditions, membership-route tables, 27
finding rows and all 17 rule-execution rows match the baseline. The evidence fingerprint is unchanged.
The real reader shows eight hidden expected primitives and four visible rows on the planted target;
the two unexpected takeover-group primitives remain visible. Opening the historical generation
still returns its version-1 answers. **P-150 is closed; P-145 and stage-6 acceptance remain open.**

### Schema-16 membership slice — offline lab comparison, 2026-09-06

**Checkpoint `491fbff`, not stage-6 acceptance.** The bounded membership slice was committed,
then the corrected schema-15 evidence and derivation were copied into a new, separate workspace
directory. The original `next/artifacts/` files were not used as writable working files. All twelve
files in the source bundle, including its existing SQLite sidecars, retain their original hashes;
all six database seals in the comparison baseline and final working copy verify.

The final judging used the baseline's exact evaluation time,
`2026-09-06T03:28:21.4277714+00:00`, so time-dependent rule inputs did not change. It completed in
108.95 seconds as generation `3fd5276e-66b3-4f1b-925f-0f3720672fff`, with judgement schema 16,
control engine 2 and principal catalogue 2. Derivation remains
`709c602a-19ad-428d-91bd-5d10efb507a6`; Evidence SHA-256 remains
`2DEF9F8AD4DE01877970B7F97F845716C1FFC1B093B01F388004610526E76BE4`.

**Existing answers did not change.** Comparing by target, scoped holder and capability, rather
than generation-local row numbers, found identical values for all 97,624 old edge rows, 433,561
supporting ACE rows, 97,620 preconditions and the existing membership-route evidence. The 8,383
descriptor-coverage records are unchanged apart from the explicitly broader completeness question
below. All 27 findings, their detail tables and all 17 rule-execution rows match. The judging outcome
remains `CompletedDegraded`. The 32,540 owner-to-DACL compounds remain unknown and uncounted.

| Counted slice | Expected | Unexpected | Expectedness unknown | Total | Capability evaluation |
|---|---:|---:|---:|---:|---|
| Existing WRITE_DAC/WRITE_OWNER | 53,265 | 11,805 | 14 | 65,084 | Established |
| General membership writes | 8,635 | 2,141 | 0 | 10,776 | Established |
| Own-account-only Self-Membership candidates | 6,457 | 2,141 | 2,163 | 10,761 | Unknown |
| All counted rows in these slices | 68,357 | 16,087 | 2,177 | 86,621 | Mixed; not a total of proven operations |

Both new capabilities occur across **2,163 captured groups**. Those groups now have incomplete
supported-capability coverage because their concrete self-membership requester operations are
unanswered, **not because descriptors were lost**. General membership-write answers remain
established independently. An expected self-membership candidate is still unknown as an operation;
the expectedness column does not establish the requester constraint.

**The unexpected membership volume is attributable, not unexplained.** Account Operators contributes
2,130 general writes and 2,130 self-membership candidates: 2,054 of each in `ba.ad.lab`, 40 in
`ph.ad.lab` and 36 in `ad.lab`. The principal named `ba.laps.new`
(`S-1-5-21-1834058357-2590327168-2246012571-1607`) contributes the other eleven of each, against
groups under `OU=Groups,OU=BA Lab`, including the LAPS-related groups. No wider authority was granted
to either holder by changing the catalogue. SYSTEM contributes 2,163 expected general writes and
2,163 self-membership candidates with unknown expectedness (`UnknownCapabilityScope`). The other
four excluded operator groups and the domain-controller computer accounts have no named-holder
membership candidates in this capture; that is not a claim about their other rights or expanded
membership. The renamed RID-500 account `jimmystrand` has fifteen additional general membership
writes, each supported by an object-specific READ_PROPERTY/WRITE_PROPERTY ACE on `member`, without
a corresponding Self-Membership candidate.

**Independent byte-level and coverage checks passed.** The .NET `RawSecurityDescriptor` reader,
not SecureAD's descriptor parser or effective-access calculator, verified 122 distinct ACE
signatures representing all 21,537 new stored membership ACE rows. Checks covered ordinal, type,
SID, mapped mask, GUID-presence flags, GUIDs, inheritance and opaque bytes. Independently enumerating
uncomplicated direct grants from the captured groups found the same 21,537 candidate identities,
with no omissions or additions, across all 2,163 groups. Changing a compared mask and omitting a
candidate in memory were both detected; the stable-store comparison also detected omitted old
edges and altered old ACE masks through read-only query mutations. No evidence file was mutated.

**Both reader directions agree.** Twenty-five representative rows cover every observed scoped
holder/capability combination. Object-first and named-holder-first calls returned identical full
edge evidence and generation identities. Toggling the object filter retained its expected count;
expected rows were hidden by default without changing their stored classifications. These are real reader checks, not a claim
that a person manually exercised the graphical interface.

**What this capture cannot validate:** all self-membership candidates also have a general-write
candidate for the same target and holder. There are **zero self-membership-only cases**, no relevant
denies, callbacks or inherit-only grants, and no property-set-based membership grants in this
measurement. The fifteen scoped grants reach `member` directly. Automated tests cover the absent
scope/deny/callback cases; this captured-evidence pass does not replace controlled live tests of
own-account versus other-account modification, especially through a trustee group. It also does
not establish token-wide effective authorization, member expansion, full Tier 0-target review,
remediation or the acceptability of the default result volume. **P-145 and the claim-specific
laboratory gates remain open.**

Local artifacts are deliberately untracked under `next/lab-validation-membership-491fbff/`:
`run-judging.ps1`, `compare-membership.ps1`, `inspect-membership.ps1`, `verify-integrity.ps1`, their
logs, JSON reports, source/binary manifests, a preserved baseline and isolated working copies.
The first diagnostic generation `f16f74a8-ce95-4af3-b252-3abb842227ea` is retained separately but
excluded from the comparison: PowerShell's automatic JSON date conversion discarded fractional
seconds. The final harness preserves date strings and refuses a reference time that does not
round-trip exactly. A catalogue-namespace typo stopped an earlier harness attempt before judging;
a later file-count alarm was JSON-array handling, with all twelve original files independently
confirmed unchanged. These were corrected harness defects, not product or evidence changes.

---

## Password-reset control — bounded implementation preparation

**Requirement already documented; bounded implementation and wording approved.** The owner selected
"Approve the capability-first implementation and wording" after reviewing the recommendation below.
The owner's "begin" follows his clarification that the Stage 6 documentation is for this build.
`CanResetPassword` is in the [current-build capability catalogue](../../next/SPEC-stage-6-control-edges.md#5-the-edge-catalogue-for-stage-6)
and the [judgement-half capability contract](../specs/JUDGEMENT-HALF.md#capability-is-the-unit-everything-above-this-layer-consumes).
The approved implementation maps that existing requirement to code; it does not reopen the requirement or
claim that the predecessor SEC-003 implementation is this build's design. Accepted decisions
0097–0101 and 0110 govern counting, expectedness and the `CredentialExposure` category.

### Implemented path

| Code | Delivered behavior |
|---|---|
| `SchemaGuidCatalog` and `BundleReader.ReadPermissions` | The Reset Password GUID is already known, and the real reader already expands generic rights. No new password attribute, capture pass or directory access is needed. |
| `EffectiveAccessCalculator.Over` | Reuses its ordered named-trustee calculation after projecting the relevant reset operation. It is not a full requester-token evaluator. |
| `ControlEdgeDeriver` | Evaluates password reset alongside descriptor/membership operations. `AddScopedEdges` reuses the ordered operation projection while `OperationScope` distinguishes extended rights from membership/property scopes. Original ACEs, target identity, coverage and uncertainty are retained. |
| `JudgingRun.Judge` | Its unchanged shared object stream calls the extended control derivation during ordinary Shell/CLI judging, independently of the inactive Self-Membership discovery budget. |
| `ControlCapability`, `ControlEdge.EdgeClass`, `ControlEdgeStorage` | Store `CanResetPassword` as `CredentialExposure` in the existing tables and read it in both directions. `PasswordResetScopeNotEvaluated` identifies unresolved reset scope. |
| `ControlEdgesSectionViewModel` | Uses the approved resource-backed wording and caveat in the unchanged control table. Filters, counts, generation checks, evidence expansion and R6/R7 sizing are retained. |

### Approved and implemented bounded semantics

- Evaluate the **Reset Password** control-access right, `0x100` scoped to
  `00299570-246d-11d0-a768-00aa006e0529`, including unscoped All Extended Rights and expanded
  Generic All. A Change Password grant, Write Property or Generic Write alone is not this right.
  A property-set membership must not turn a different extended right into Reset Password.
- Match the captured account class chain: user, computer, inetOrgPerson and managed-service-account
  classes covered by the documented right. Do not restrict the feature to ordinary user accounts
  merely because the first fixture is a user. Missing class evidence retains uncertainty; known
  non-account objects do not acquire password-reset capabilities. Managed-account operation rules
  are not converted into a promise that a password reset or subsequent logon would succeed.
- Combine applicable broad and reset-specific entries in captured order for the same requested
  operation. A broad allow cannot escape a specific deny by being evaluated separately. Ignore
  inherit-only entries for the current target; retain the original entries as proof.
- Keep the existing bounded named-holder model. Unresolved cross-trustee deny applicability,
  conditional/unsupported entries, missing scope or incomplete descriptor evidence must not become
  an established grant or a clean absence. Preserve NULL-DACL, empty-DACL and unread-DACL distinctions.
- Count one holder/target/capability, never one per group member or supporting ACE. No general member
  expansion is introduced. Reuse current authority/capability-scope policy, including 0100's
  directly evidenced SYSTEM grants; do not copy SEC-003's predecessor administrator exclusions.
  Expectedness, target Tier 0 classification and operation success remain separate questions.

Microsoft's [Reset Password right](https://learn.microsoft.com/windows/win32/adschema/r-user-force-change-password)
supplies the fixed right identity and applicable account classes. Its
[password operation description](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/change-windows-active-directory-user-password)
distinguishes an administrative reset from a change using the old password. These are sources for
offline analysis, not authorization to perform either operation.

### Storage, presentation and validation

**Versioning:** judgement schema **19** and control engine **3**, without changing the Evidence
or Derivation schema. The new version records the larger evaluated capability set, even though the
existing tables can store the additional capability. Re-judge existing sealed evidence; do not
relabel historical generations, reinterpret an older missing capability as an evaluated negative,
or modify frozen results. Schema-18 stores are refused rather than presented as having evaluated
password reset. An unsupported control engine yields a not-derived control product; category
contradictions produce a read failure. Both cases clear previously selected screen evidence.

**Presentation:** keep the existing table, columns, sizing and evidence expander. Use the neutral
capability label **"Password-reset permission"**, with the existing Established/Unknown evaluation
column carrying the answer. The supporting evidence states: **"Permission evidence only.
A password reset and subsequent sign-in have not been tested."** Update the partial-capability
scope notice to include password reset while still naming key-credential control, replication,
ownership-derived control, full-control aggregation and member expansion as unfinished. New wording
is resource-backed in `SecureAD.Shell/Resources/ControlEdgePresentation.resx` and
`SecureAD.Judgement/Resources/ControlEdgeScope.resx`. `ControlEdgePage.SupportedScope` is now a
resource-backed static property instead of a literal constant; its sole production consumer remains
the Shell section. Explicit owner approval preceded the edits; no XAML layout or reset action changed.

**Verification coverage:** focused positive and negative cases cover direct/group/SELF holders, applicable
account classes, broad versus specific scope, both deny orders, generic-right expansion through the
real permission reader, unrelated Change Password/property rights, unknown/malformed scope,
conditional entries, cross-trustee uncertainty and NULL/empty/unread descriptors. Preserve current
counting/expectedness regressions, including SYSTEM and domain-scoped BUILTIN identities. The tests exercise
the real shared judging pass, sealed persistence, both object-screen directions, category readback,
version refusal and old-result clearing. Existing descriptor/membership regressions remain in the
selection. The synthetic requester fixture gained an optional user-descriptor argument, leaving
all existing defaults unchanged; configured requester discovery still stores two own-account answers
while the reset holder count stays unchanged. This is not a byte-for-byte comparison of every old
generation. Frozen fixtures remain unchanged, and no production performance budget is claimed.

**Scope boundary:** this slice supplies the documented capability and its evidence, not the
SEC-003-style finding, a severity decision, new Tier 0 classification, requester-token expansion,
full-control aggregation or Stage 7 paths. The corresponding finding is a separate consumer of the
capability under current target/expectedness rules. Further discovery tuning remains paused. No
live-directory operation, protected-artifact access, commit or push is included. P-145 and final
Stage 6 acceptance remain open.

**Historical preparation validation:** before production edits, the full offline suite passed
**3,849/3,849**, none skipped, and the solution build succeeded. Only the preparation and
product-overview clarification had changed then. Those were preservation checks, not capability
validation. The subsequent implementation checks are separate below.

**Implementation evidence:** `DirectResetGrantProducesTheDocumentedCredentialCapability` failed
against the preceding implementation with an empty edge collection, then passed unchanged after
the new capability was added. `PasswordResetControlTests` supplies **43** operation cases;
`PasswordResetWorkflowTests` supplies **9** real reader/store/screen cases; three new no-window
`ControlEdgeSizingTests` cases bind the new wording at 900-by-430, 1,300-by-650 and 1,600-by-900.
The combined reset, existing descriptor/membership and layout selection passed **132/132**.
Low-severity test-setup errors were corrected: missing namespace imports and an inherit-only fixture
using `0x02` instead of the captured raw `0x08` flag. These were not product reproductions and
required no production workaround.

**Final validation:** the full offline project passed **3,904/3,904**, none skipped, and the solution
build succeeded. The first full run passed 3,896/3,904; all eight failures were the layout guard's
missing schema-19 checkpoint. The observed layout hash was identical to schema 18, as expected
for this capability-semantic change. A new schema-19 entry was added without replacing any
historical hash; the layout check and all seven deliberate layout mutations then passed, followed
by the successful full run. This corrected test-integration omission did not change the schema
layout or weaken its guard.

The reset operation/workflow, real-template sizing, layout guard and synthetic-host selection also
passed **85/85** under code-coverage collection. Its report is
`next/.vs/PasswordReset-252cbdc67eba41fabfdcb08a89689d83/coverage.cobertura.xml`.
No visible window, live-directory operation, protected-artifact access, performance experiment,
commit or push was performed. The extra capability adds judging and storage work; prior P-151/P-152
measurements remain observations of their recorded product version, not a measured budget for
this enlarged product. Real-product visual verification, the separate security finding and final
Stage 6/P-145 acceptance remain outstanding.

---

## Key-credential write permission — bounded implementation

**Requirement documented; bounded implementation and wording explicitly approved.** The owner
selected **"Approve the bounded implementation and wording"** after reviewing the recommendation
against Stage 6 and decisions 0097–0101/0110. This adds `CanWriteKeyCredentialLink` as
`CredentialExposure`; it does not approve the rest of the Stage 6 proposal or create a finding.
The preceding password-reset validation is historical and is not a pass for this enlarged product.

### Implemented scope

- Write Property (`0x20`) reaches `msDS-KeyCredentialLink`, whose published attribute GUID is
  `5b47d60f-6090-40b2-9f37-2a4de88f3063`. The captured catalogue takes precedence over shipped names.
  Direct attribute, captured property-set, applicable class-root and unscoped property grants are
  evaluated as one ordered operation. The real reader expands Generic Write and Generic All.
  Read Property, extended rights, validated writes, WRITE_DAC/WRITE_OWNER and writes to other
  attributes do not independently establish this capability.
- Supported targets follow the captured user/account class chain, including computers,
  inetOrgPerson and both managed-service-account classes. A captured user ancestor also covers
  an extended account class. Known non-account targets do not receive this capability; missing
  target class or relevant scope evidence stays Unknown. This is not a new general schema-hierarchy
  reconstruction or a promise that a server will accept a particular modification.
- `AddScopedEdges` now carries the operation identity separately from the access-mask bit;
  Write Property no longer invariably means `member`. Broad, attribute and property-set entries
  retain captured order, so one scope cannot escape a deny evaluated in another scope.
  Inherit-only entries grant nothing on the current target. Already-materialized inherited entries,
  original class/attribute scope, ordinal, mask, flags, trustee and application data remain evidence;
  this slice does not replay parent-to-child inheritance from an OU.
- SELF resolves to the target account while original SELF evidence survives. Microsoft's separate
  computer validated-write route has SELF/value restrictions; those are not imposed on general
  Write Property and validated-write-only access is explicitly not derived here. No key-credential
  value parsing, key generation, modification or authentication is performed.
- Cross-trustee deny applicability, unsupported/conditional entries, unresolved holders and
  incomplete descriptors remain unknown. NULL DACL, empty DACL and unread/unparsed DACL retain
  their distinct outcomes. Per-object coverage survives when no holder edge can be identified.

The external anchors are Microsoft's [user class](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/719c0035-2aa4-4ca6-b763-41a758bd2410),
[computer inheritance](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/142185a8-2e23-4628-b002-cf31d57bb37a),
[object-specific access procedure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3da5080d-de25-4ac8-9f2b-982709253dfb),
[domain-update grants](https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/domain-wide-updates)
and [validated-write constraints](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f70afbcc-780e-4d91-850c-cfadce5bb15c).
These anchor permission semantics, not a claim that an attack or sign-in was tested.

### Captured property-set evidence and findings

`SchemaGuidCatalog.AttributeBelongsToPropertySet` answers true/false only from a positive captured
assignment of the requested attribute to one set. A missing, malformed or contradictory assignment
returns unknown. Observing unrelated members is not proof that a set's list is complete. The existing
reader cannot distinguish an unassigned attribute from an unread assignment, so both remain unknown
at this boundary; no shipped property-set list substitutes for forest evidence. Existing catalogue
APIs, capture format and principal catalogue version 2 are unchanged.

| Finding | Severity/status | Evidence and correction |
|---|---|---|
| KCL-1: partial member list treated as proof of exclusion | High — corrected | With the old member-list inference temporarily restored, `PartialPropertySetDenyCannotLeaveAnEstablishedAttributeGrant` expected Unknown but observed Established. It passed unchanged after restoring the positive-assignment safeguard. The sibling general-member-write operation uses the same safeguard; its former empty-list fixture now correctly asserts Unknown, and a separate positive different-set fixture proves exclusion. No frozen fixture was changed. |
| KCL-2: capability-only judging ignored captured schema | Medium — corrected | Real workflow tests found property-set grants Unknown even though `BundleReader.ReadSchemaGuids` recovered the assignment. `JudgingRun` had populated schema only in the rules-request-derived-facts branch. The control context now reads it independently, reusing the existing instance when available. The same workflow assertions then passed. |
| KCL-3: expectedness fixture lacked required context | Low — corrected test setup | Key Admin fixtures first scheduled no derived-fact consumer, then still omitted the captured nTDSService object. The existing membership product correctly remained incomplete. The fixture now requests the existing membership context and includes the service object with unset dSHeuristics; production expectedness was not relaxed. Both Key Admin cases pass as visible Unexpected edges. |

### Storage, presentation and preserved boundaries

Judgement **schema 20 / control engine 4** records the enlarged evaluated set and property-scope
correction. Existing control tables store holder, target, scope, original ACEs, preconditions,
expectedness/reason, catalogue version, generations and coverage. No table layout or Evidence/
Derivation schema changes were needed. Schema 19 is refused rather than read as having evaluated
the new capability; unsupported engines are not derived and contradictory categories/missing proof
fail readback. A new schema-20 layout checkpoint matches schema 19's unchanged layout; every
historical hash is preserved, and the layout test plus seven deliberate mutations passed **8/8**.

Counts remain one named holder/target/capability, not one per ACE or group member. Expectedness
remains separately scoped under the accepted catalogue: broad principals stay visible, Key Admins
and Enterprise Key Admins receive no exemption, directly evidenced SYSTEM rights use 0100, and
BUILTIN domain scope retains P-150's correction. Missing membership context is still Unknown,
not a guessed Unexpected or Expected answer. No general member expansion was added.

The existing table uses the approved **"Key-credential write permission"** label, with its ordinary
evaluation/expectedness columns. Resource-backed evidence says **"Attribute: msDS-KeyCredentialLink."**,
**"Category: CredentialExposure; this does not classify the target as Tier 0."** and
**"Permission evidence only. A key-credential write and subsequent sign-in have not been tested.
This does not establish account takeover or a completed path to Tier 0."** The partial-scope notice
names validated-write-only key-credential access and the other unfinished products. Password-reset
wording is preserved. No XAML/layout, requester scheduling, count/filter or generation/failure
safeguard changed. Re-judge sealed evidence to obtain the new product.

### Verification

The initial `DirectPropertyWriteProducesTheDocumentedCredentialCapability` test failed with no
edge before implementation, then passed unchanged. The focused operation/catalogue/reset/membership
selection passed **156/156**. The new real-reader/store/screen workflow passed **31/31** after the
corrections above. No-window sizing passed **25/25**, including three new key-credential cases
and the existing reset/requester/broken-layout controls.

**Final validation:** the full offline project passed **4,025/4,025**, none skipped, and the complete
solution build succeeded. The first full run passed 4,023/4,025; both failures were the schema
documentation guard naming the new public `AttributeBelongsToPropertySet` member. Its component
member table and absent-input contract were added without weakening either guard. This was a
low-severity documentation-integration omission, corrected before the final full run.

The combined key-credential, public schema-query, membership, password-reset, real-template sizing,
layout-guard, readback-safety and synthetic-host selection passed **270/270** under `dotnet-coverage`.
The new report is
`next/.vs/KeyCredentialLink-76360e855a064de79a7623b717ffd323/coverage.cobertura.xml`;
previous reports were not replaced. The report was parsed to verify actual executable-line hits:
ControlEdgeDeriver **215/233**, ControlEdgeStorage **163/163**, SchemaGuidCatalog **196/197**, and
ControlEdgesSectionViewModel **180/202**. These are coverage observations for this selection, not
complete branch coverage or proof of live authorization semantics. The CLI coverage build resolved
SDK 10.0.400 under the unchanged `latestFeature` policy and reported 216 compiler/analyzer warnings;
it succeeded, but no warning-free-build claim is made. No warning suppression was added.

No live directory, protected capture, historical measurement artifact or performance experiment is
part of this work. P-151/P-152 measurements remain tied to their recorded product version and do not
establish a cost or budget for this larger capability set. Discovery tuning remains paused; both
hosts still pass no discovery budget. Ordinary laptop/monitor verification, separate security
findings (including password reset), Tier 0-target review and final Stage 6/P-145 acceptance remain
outstanding. Implementation and validation were performed without committing or pushing. The owner
subsequently requested documentation review and publication of the completed slice; that request
authorizes this commit/push only and does not broaden the implementation or verification boundary.

**Historical next-session boundary:** prepare `CanReplicateSecretDomainData` and `CanReplicateFilteredAttributes`
together from the Stage 6 catalogue, judgement-half authorization requirements and accepted decisions
0097–0101, 0104, 0105 and 0110. Verify operation-specific right combinations, naming-context-root
targets, missing evidence, deny ordering, scoped expectedness and domain-controller presentation.
Reuse existing products where appropriate, retain permission-only claims, and present the bounded
implementation and wording recommendation for explicit approval before editing. Discovery tuning,
production budgets, ownership transitions, separate security findings and Stage 7 paths are not
folded into that preparation.

---

## Replication permissions — bounded implementation

**Explicit approval:** after reviewing the preparation recommendation, the owner said "i approve",
asked whether this feeds a rule, and subsequently requested "implement it". This builds stored
permission conclusions for later rules, not a new finding, severity, live operation or Stage 7 path.
The approved labels are **Secret-data replication permission** and **Filtered-attribute replication
permission**, with visible non-collapsing holder/naming-context grouping in both existing directions.

### Evaluation and target boundary

`ReplicationControlDeriver` shares `ControlEdgeDeriver.OperationScope` and
`EffectiveAccessCalculator` for each ordered Control Access (`0x100`) check. Broad and GUID-scoped
entries are evaluated together in original order. Rights for different holders, roots or generations
are never joined. The real permission reader expands Generic All; Generic Write, property writes,
validated writes, WRITE_DAC and WRITE_OWNER do not independently establish replication.

- `CanReplicateSecretDomainData`: Get-Changes AND Get-Changes-All.
- `CanReplicateFilteredAttributes`: Get-Changes AND (Get-Changes-All OR Get-Changes-In-Filtered-Set).
- Both alternatives survive as component checks and original proof when both exist. A proven
  alternative does not inherit uncertainty from an unnecessary alternative. An unresolved required
  component remains Unknown. Known denial wins a conjunction; a known grant wins a disjunction.
- Applicable denies, unsupported/conditional entries and unknown scope before a terminal entry
  remain limitations. Later entries cannot reverse a completed single-right check. Cross-trustee
  denial stays unknown when applicable membership is not established; this is not a complete token
  model. NULL, empty and unread/unparsed DACLs remain distinct. Original SELF entries are retained
  while evaluation uses the target identity, as in the earlier slices.
- `BundleReader.ReadNamingContexts` supplies exact roots and kinds from `partition_coverage`.
  A root-looking name or class on a child is insufficient. Root class/identity gaps remain unknown.
  Captured roots absent from the object stream receive explicit unanswered-object coverage, so a
  named-holder query cannot report complete silence for a missing root.
- Domain, Configuration and Schema identities remain separate. Non-domain servicing/token
  contexts remain unverified under P-90 for ordinary holders; descriptor-native SYSTEM and a NULL
  DACL's Everyone result retain their bounded meanings. No application/DNS partition capture or
  constrained `EXOP_REPL_SECRETS` route is added. Uncaptured partitions are not established coverage.

The external authorization anchor is [MS-DRSR §5.101](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/15bbda52-7742-4ce3-9327-018647b0fc26),
read during preparation. Every component check is against `ncRoot`. The right GUIDs are
`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`, `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` and
`89e95b76-444d-4c62-991a-0facbeda640c`, respectively. Microsoft's
[filtered-set description](https://learn.microsoft.com/windows/win32/ad/rodc-and-active-directory-schema)
supports potential credential-like application data, not an assertion that every filtered attribute
is a high-impact secret. Section 5.3's contradictory exclusive-right sentence is corrected to AC-77.

### Persistence, expectedness and presentation

Judgement **schema 21 / control engine 5** identifies the enlarged evaluated set. Principal catalogue
**2**, Evidence/Derivation schemas and existing control table layout remain unchanged. The new
schema-21 layout checkpoint retains the schema-20 hash; no historical checkpoint was replaced.
Re-judge existing evidence; older schema/engine results are not treated as having evaluated replication.

The two capabilities are `ReplicationControl`, with one counted holder/root/capability each.
Supporting ACEs, duplicate grants, group members and alternative qualifying rights do not multiply
counts. Three rights establishing both capabilities therefore produce two counted edges. The existing
proof table stores each component outcome/GUID, root DN/kind and presentation-only holder DC evidence.
The latter is an observation, not an authorization prerequisite. `ControlEdge.ReplicationNamingContextKind`
and `ControlEdge.HolderDomainControllerAsset` expose those separately in readback. Root, required proof,
category and generation contradictions fail readback. Stored component checks are replayed against
the retained ordered ACEs; changing a granting mask to Read Property cannot leave an Established row.

Expectedness remains independent: broad principals stay visible; SYSTEM requires effective direct
evidence; missing membership still means Unknown. Replication no longer inherits Schema Admins'
schema-administration expectation merely from target location: restricted scope remains unknown
without independent proof, while a separate unrestricted authority route can still establish expectation.
No catalogue entry is widened. Domain controller accounts receive no expectedness exception.

The screen uses existing columns, sizing, filters, page IDs and selected evidence. Replication groups
are visible, non-collapsing and page-local; other capability categories are kept outside those groups.
The notice explicitly permits continuation on another page. The DC asset badge requires a captured
computer identity with readable UAC/primary-group values and agreeing existing DC signals. Missing,
malformed or conflicting signals stay unconfirmed; existing rules' DC interpretation is not changed.
The caveat states **Permission evidence only. No replication operation or credential extraction was
performed. This does not establish account takeover or a completed path to Tier 0.**

### Findings and verification

| Finding | Severity/status | Evidence and correction |
|---|---|---|
| REP-1: §5.3 excluded the Get-Changes-All filtered-set alternative | High — corrected documentation | The sentence contradicted both AC-77 and MS-DRSR §5.101. The corrected wording retains separate capabilities and both alternatives. |
| REP-2: template-level grouped source produced an empty table | High — corrected before completion | 19 real-template sizing cases failed, including existing labels. Moving the source to the instantiated section resources restored the rows without weakening their assertions. |
| REP-3: missing captured root could disappear from holder coverage | Medium — corrected during review | The object stream cannot visit an absent root. Remaining captured roots now produce unanswered-object rows; the real-reader regression verifies incomplete coverage. |
| REP-4: stored component labels could outlive their granting masks | High — corrected during review | Readback now replays component checks against original ordered entries. The synthetic mask-to-Read-Property mutation fails through the real screen adapter. |
| REP-5: test integration errors | Low — corrected | One fixture incorrectly expected a later All grant to survive an earlier unscoped deny; one workflow import was missing. The no-scroll mutation retains resources so it fails for geometry, not XAML parsing. The root-conflict fixture now uses a second synthetic controller so the writer's duplicate-pass guard does not prevent testing the reader. New test analyzer warnings were corrected without suppression. |
| REP-6: root-reader contract and concept-name guards | Medium — corrected | The first full run passed 4,108/4,110. Architecture guards required an explicit `Result<T>` for root reads and an operation-specific name instead of the reserved `Evaluate` name. `ReadNamingContexts` now reports structured failures, checked before opening the judgement writer; `CheckRight` names the actual operation. Neither guard was weakened. |
| REP-7: BUILTIN replication missed the verified-domain safeguard | High — corrected | Final sibling review added missing/contradictory/verified target-domain cases. The first two reproduced false Established results while the positive control passed. Reusing `ControlEdgeDeriver.IsDomainTarget` keeps those candidates Unknown with `ResourceContextUnverified`; all three then passed unchanged, including proof validation. Catalogue 2 is unchanged. |

Final focused cases: **49** synthetic operation cases, **35** sealed-bundle workflow cases,
**32** real-template sizing/grouping cases and **8** layout/version-mutation checks passed.
The workflow includes both viewing directions, generic mappings, duplicate/member counts, alternatives,
Configuration/Schema scope, proven/conflicting DC identities, old schema/engine refusal, damaged proof,
missing roots and a 103-edge page-boundary fixture. These are synthetic/offline results, not a live
authorization or performance measurement. Historical key-credential results above are not a pass
for this enlarged product.

**Final validation:** the full offline suite passed **4,116/4,116**, none skipped, and the solution
build succeeded after the BUILTIN correction. Before that correction, the full suite passed 4,113/4,113;
the added three-case regression is what exposed the scope gap rather than an existing test failure.

**Earlier coverage checkpoint:** the completed selection below passed **650/650** before REP-7.
Its report is `next/.vs/Replication-b51bb1b3e32a4d2ea54a3195e9a8e5bf/coverage.cobertura.xml`, beside
`replication.trx` and `coverage-run.log`. Parsed executable-line hits were ReplicationControlDeriver
**144/148**, ControlEdgeDeriver **235/240**, ControlEdgeStorage **165/165**, BundleReader **172/356**
and ControlEdgesSectionViewModel **207/215**. These are observations of that selection/version,
not complete branch coverage or proof of the later guard. The SDK was **10.0.400** under the unchanged
`latestFeature` policy. That incremental coverage build recorded **155 compiler/analyzer warning
occurrences**, including repeated project emissions; no warning-free-build claim is made. An earlier
completed attempt recorded 340 occurrences before the new test warnings were corrected; incremental
build scopes differ, so those counts are not a measured warning-reduction claim. Both reports survive.

The subsequent coverage rerun including REP-7 was **cancelled by the user and not automatically restarted**. Its directory,
`next/.vs/Replication-9345845ac735443caae9d29c0896f6ec`, contains an incomplete coverage output and build
log but no test-result file. It is not a passing coverage result and does not establish coverage of
the final guard. A report-reading attempt initially used the wrong relative directory; its failed
reads and 0/0 output were discarded and replaced by absolute-path reads requiring executable lines.
The full-suite and solution-build results above remained valid independently of that coverage gap.

**Coverage gap closed at the session checkpoint.** The owner requested completion of the remaining
work before moving to a new session. The solution build succeeded again, and the Release test binary
was checked against the changed source/resource inputs before coverage ran with `--no-build --no-restore`.
Output was streamed while also being retained in a new log, rather than hidden until completion.
The final selection passed **653/653**, none skipped, in **40.1 seconds** for the coverage command
(the preceding build is not included in that time). All three
`BuiltinReplicationRequiresVerifiedTargetDomainContext` cases passed, and the report confirms hits
on both the guard and its `ResourceContextUnverified` assignment at lines 95–96.

The new report is
`next/.vs/Replication-Final-63b2903202cd4d149e113f3fea66381d/coverage.cobertura.xml`, beside
`replication.trx`, `coverage-run.log` and `run-summary.json`. The summary records exit code 0,
elapsed time and the test assembly SHA-256. Parsed executable-line hits are ReplicationControlDeriver
**146/150**, ControlEdgeDeriver **236/240**, ControlEdgeStorage **165/165**, BundleReader **172/356**
and ControlEdgesSectionViewModel **207/215**. These are selection-specific executable-line observations,
not complete branch coverage or live authorization verification. Skipping a redundant build does not
resolve the earlier analyzer warnings or justify a warning-free-build claim. All earlier and cancelled
reports remain preserved. No production code changed during this final coverage closeout.

**Historical next-session starting point at the replication checkpoint:** bounded ownership-control preparation, not another replication
implementation pass. Start from Stage 6 §5.1 and the accepted ownership/control decisions, distinguish
existing ownership findings from existing-owner and owner-transition capabilities, and present the
concrete implementation and laboratory-verification recommendation for explicit approval. No live
directory work or new capability implementation is authorized by this handoff. The working tree
contains the completed, uncommitted replication slice and the owner's instruction-file edit; preserve
both. The Git checkpoint remains `main` / `1d94b39`; no commit or push was requested.

Discovery tuning remains paused and both hosts still pass no production discovery budget. P-151/P-152
measurements remain tied to their recorded product version. Separate findings (including password
reset), ownership gates, effective member expansion, Tier 0-target review, laptop/monitor verification
and final Stage 6/P-145 acceptance remain outstanding. No live directory or protected artifact was
accessed; no frozen measurement was changed; no commit or push is authorized by this implementation.

---

## Ownership control — bounded implementation

**Approval:** the owner selected "Approve the bounded implementation and wording; offline only",
then requested "implement it". This implements the bounded recommendation against Stage 6 §5.1
and Accepted decisions 0095–0098, 0103, 0107 and 0109; it does not accept the whole proposal.

### Claims and scope

`IsOwnerAndCanRewriteDacl` records existing-owner permission control as `DirectoryControl`.
`ObjectOwnershipReading.Eligibility` supplies the existing accepted-owner policy independently of
rights qualification. Accepted owners and proven-deleted owners produce no ownership edge. Unknown
identity, absent owner-acceptance facts and incomplete membership do not prove a non-administrative
acting owner. An established existing-owner capability is counted once at that owner; group members
are not expanded into additional edges. Blocked and unknown assessments are stored but uncounted;
unknown assessments still make object coverage incomplete, including in named-holder queries.

`CanSetOwner` retains its independent permission conclusion. The supporting
`CanBecomeOwnerAndRewriteDacl` now has evaluated owner-right prerequisites but remains **Unknown and
uncounted**, because 0103's `CanSetTakeoverOwnerSid` laboratory gate has not been discharged.
Neither a proven owner-right branch nor an existing ownership finding discharges that gate.

`OwnerRightsReading` is shared with SEC-031/032 and SEC-060. Independent WRITE_DAC, OWNER RIGHTS
and implicit rights remain separate proof branches. Grants and denies keep their stored order;
inherit-only entries do not govern the current object, scoped/unsupported entries retain uncertainty,
and a completed right check does not inherit uncertainty from irrelevant later entries. An earlier
OWNER RIGHTS deny cannot be bypassed by calling a later ordinary allow an independent grant.
NULL, empty and unread/incomplete descriptors remain different inputs; no implicit grant is
represented by an invented ACE.

The named modification is `AddWholeObjectWriteDaclAllowForOwner`: add a whole-object WRITE_DAC
allow for the named owner, removing no existing entries. This is evaluated evidence, not an executed
change or arbitrary permission-rewrite claim. The implicit branch checks the captured class ancestry,
character 29 (including malformed → 1), and the specific DA/EA exemption independently of expectedness.
The production evidence/context has **no serving-DC owner-right behavior baseline**. A heuristic alone
does not select one. Affected implicit computer-owner questions remain Unknown; unrelated non-computer
and independently established explicit routes are not automatically made Unknown. Synthetic evaluator
cases name classic updated behavior explicitly; they are not production observations. The newer
modification-specific branch remains unsupported for this template, separately from missing evidence.
Privilege-based takeover and arbitrary modification templates remain outside this slice.

The external anchors are [MS-ADTS 6.1.3.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/fb7c101d-ec8b-4fbf-bca8-7d7c2d747d0c),
[dSHeuristics](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5),
[MS-DTYP 2.5.3.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/4f1bbcbb-814a-4c70-a11e-2a5b8779a6f9)
and [Owner of a New Object](https://learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object),
read during the approved preparation. No claim is anchored solely to code/test/document agreement.

### Persistence and presentation

Judgement **schema 22 / control engine 6** identifies the changed semantics. Principal catalogue **2**,
Evidence/Derivation schemas and table layout are unchanged. A new layout checkpoint preserves every
historical hash. Re-judge on an isolated copy to obtain the product; schema 21/engine 5 is not silently
treated as ownership coverage. Optional ownership derivation inputs pass the existing evidence and
generation checks even when no finding rule asks for them; absent inputs produce unanswered ownership,
not a requirement to enable requester discovery.

The existing proof table holds a typed `OwnerSource` snapshot (owner, target identity/class ancestry,
descriptor state/completeness, heuristic and eligibility/context inputs) and named checks. Original
ordered ACEs remain alongside it. Both write and read paths replay the rights evaluation and reject
missing/contradictory source, changed outcomes/counting, inconsistent target/owner identity or altered
granting masks. Existing generation/category checks remain in force. This detects inconsistent proof;
the bundle seal is corruption detection, not a claim of cryptographic authenticity.

Both existing directions use **Existing-owner permission control** and **Owner-change permission
control — not verified; not counted**. The caveat is **Ownership and permission evidence only. No owner
or permission change was performed. This does not establish account takeover or a completed path to
Tier 0.** No layout or replication grouping changes were made. Expectedness remains separate from
authorization; no catalogue entry or domain-controller exception was added.

SEC-031/032 retain their identities and Low/Medium severities at version **3**; SEC-060 retains its
identity and High severity at version **2**. Related shared-check corrections do not create a new
finding or revise the historical stored findings. Proven-deleted owners remain ownership findings.

### Findings and verification

| Finding | Severity/status | Evidence and correction |
|---|---|---|
| OWN-1: coarse ownership helpers were not §5.1 authorization evidence | High — corrected | Both helpers treated any OWNER RIGHTS entry as suppression and inspected only the last class name. The shared ordered check and public-rule inheritance/derived-class controls replace those shortcuts. |
| OWN-2: a heuristic stood in for a serving-DC behavior baseline | High — corrected within the bounded slice | Production supplies no such baseline. Affected implicit computer-owner cases are Unknown, with unread heuristic and unrecorded behavior distinguished; direct grants remain independently answerable. |
| OWN-3: older rule fixtures omitted the owner's acceptance fact | Medium — corrected test inputs | The first focused run passed 257/268. Subject-only fixtures now supply the separate owner fact; an explicit missing-owner-fact negative control still refuses the claim. Tests no longer call computer-owner coverage complete from the heuristic alone. |
| OWN-4: irrelevant later unsupported OWNER RIGHTS entry affected a completed grant | Medium — corrected | Presence is established by a known applicable entry. Paired before/after controls retain uncertainty before a terminal grant and exclude irrelevant uncertainty after it. |
| OWN-5: integration type mismatches | Low — corrected | New tests used a nonexistent completeness enum value, and proof reconstruction initially used the wrong constructor argument/import. Compilation checks exposed these; corrected without suppression. |
| OWN-6: full-suite integration expectations and operator wording | Medium — corrected | The first full run passed 4,178/4,181. Ownership gaps now have their own operator explanations instead of protection-specific wording; the membership fixture supplies an owner when asserting whole-product completeness; the generation test asserts the Derivation now consumed by ownership even without a finding rule. |
| OWN-7: agreement between a cached heuristic and its label was insufficient | High — corrected | Readback validates the raw character and documented numeric fallback. A mutation changing both the stored value and its prerequisite label is rejected rather than accepted because they agree. |
| OWN-8: malformed Markdown tables in the modified-document scope | Low — corrected formatting | Stage 6 §7.1's sIDHistory row lacked its Source cell, and two predecessor finding-key examples contained unescaped pipes. Column/escape repairs preserve the stated treatment and rendered historical keys. The check's deliberately broken row fails and its escaped-pipe control passes. |

Focused verification passed **276/276**: ownership evaluator, public ownership rules, sealed-bundle
readback, stored proof, both screen directions, real-template sizing, and replication regressions.
New cases cover zero/non-WD/allow/deny OWNER RIGHTS, both orders, inherit-only/unsupported entries,
missing owner/acceptance/behavior, orphan and accepted owners, group counts, original ACE-free owner
evidence, old schema/engine refusal, proof mutation and a 103-target holder query across the page boundary.
This focused result alone does not accept the entire product.

**Final offline checkpoint:** the full suite passed **4,182/4,182**, none skipped, and the solution
build succeeded. The targeted coverage selection passed **623/623**, none skipped, in **21.5 seconds**
for the coverage command, excluding the preceding build. It used SDK **10.0.400** under the unchanged
`latestFeature` policy and the current Release test binary with `--no-build --no-restore` after checking
source/resource timestamps. These are synthetic/offline results, not live authorization or production
performance measurements. A successful build is not a claim that existing analyzer warnings were resolved.

The report is `next/.vs/Ownership-562f252ff37742fba28529ec6f76f55a/coverage.cobertura.xml`, beside
`ownership.trx`, `coverage-run.log` and `run-summary.json`. The test assembly SHA-256 is
`5A2EC387D12C95532FA2FC7CD16520E155AD29E894F5C305FB958A00C05173E2`.
Executable-line hits, grouped by source file, are OwnerRightsReading **87/88**,
OwnershipControlDeriver **117/123**, ObjectOwnershipReading **80/83**,
BroadPrincipalCanTakeOverObject **133/146**, ControlEdgeDeriver **217/230**,
ControlEdgeStorage **167/167** and ControlEdgesSectionViewModel **212/218**.
These are selection-specific line observations, not complete branch coverage. Coverage had completed
before the interrupted handoff; closeout confirmed the saved counters, assembly hash and input timestamps
rather than overwriting or needlessly rerunning that report. All earlier replication reports remain intact.

The stage-status check and its negative controls pass. The bounded modified-document table check
also passes with explicit broken-row and escaped-pipe controls; it scans the actual changed documents,
not only the old areas directory. `git diff --check` is clean.

**Publication and next-session boundary:** this bounded implementation is complete, with judgement
schema **22**, control engine **6** and principal catalogue **2**. The owner subsequently requested
documentation review, commit/push and a new-session handoff. That request authorizes publication of
the completed replication and ownership slices, including the preserved instruction-file edit; it is
not standing authorization for future commits or pushes. `main` / `1d94b39` is the pre-publication
baseline; Git history and the publication handoff identify the resulting commit. Coverage reports
under `next/.vs/` remain local and ignored, not missing files a new session should regenerate blindly.
Preserve all historical evidence, measurements and earlier completed/cancelled coverage reports.

**Historical next-session boundary: bounded `HasFullControl` preparation.** Read Stage 6 §5 and §7, the
accepted control/expectedness/counting decisions, and this checkpoint before inspecting the code.
Propose a full-control summary only when the complete effective generic-all mapping is established,
including rights assembled from several grants. Keep the underlying primitives, source facts and
independent routes; do not count both an established summary and the primitives it summarizes.
A deny that breaks full control must leave surviving rights visible. Present the concrete implementation,
counting/readback behavior, exact screen wording and synthetic verification recommendation for explicit
approval before editing. Preparation does not accept the whole Stage 6 proposal or authorize a new
capability implementation, live operation, discovery budget, member expansion or Stage 7 path work.

**Remaining gates:** no live directory access or owner/permission changes were performed. Stage 6
§13.1's WRITE_OWNER-only tests (self, unrelated account, member group), eight resulting-owner cases
at heuristic 0 and 1, and the separate AdminSDHolder owner-only restoration observation still require
separate authorization and recorded serving-DC behavior. Those would verify only their own claims.
Laptop/external-monitor checks, effective member expansion, constrained routes, new findings, Tier 0
review and final P-145/Stage 6 acceptance remain outstanding. Discovery stays inactive in both hosts;
no production budget is authorized. Only publication of the completed slices is authorized above.

## Full-control aggregation — bounded implementation

**Approval and baseline:** after the bounded recommendation covering implementation, counting,
wording and synthetic verification, the owner requested "implement it", then "continue".
Work started from clean `main` / `8e0865d`, judgement schema 22, control engine 6, principal catalogue 2.
This authorizes the bounded implementation below, not the whole Stage 6 proposal, live operations,
discovery enablement, member expansion, commit or push.

### What the summary establishes

`HasFullControl` is represented by `FullControlAssessment`, not a new primitive `ControlCapability`.
`FullControlEvaluator.AssessFullControl` requires all thirteen specific rights in the AD
`GENERIC_ALL_MAPPING` (`0x000F01FF`) for the same named holder, resource context and target.
One grant or several may supply them. Original primitive conclusions remain unchanged.

The external anchors remain MS-ADTS 6.1.3 for the mapping and MS-DTYP 2.4.3 for stored generic bits,
already recorded in the permission model. **Captured raw generic bits are not expanded into
authorization.** Stored order is retained: a deny before a grant can prevent it; a later deny does
not undo an earlier completed grant. A grant after a deny is not credited as an independent way
around that deny. Inherit-only entries do not grant rights on the current object.

The whole-object mask alone is insufficient because that question excludes scoped entries.
Separate checks retain scoped denies. Known named-operation scopes can break full control;
unresolved property-set, object-type, target-class or authorization applicability remains Unknown.
Scoped grants are not unioned into whole-object authority. Raw-mask full-control candidates, including
several potential contributing grants, receive an assessment; ordinary partial-right-only holders
retain their existing primitive records rather than gaining a redundant full-control row.
Unread descriptors still retain object-level unanswered coverage even when no holder can be identified.

`FullControlRight` carries an explicit completeness voucher beside its source lists. Each required
right retains alternative granting ordinals and denying or unresolved ordinals. The conjunction of
these checks preserves alternative source combinations without enumerating every possible grant set.
A stored witness can establish two source-disjoint complete routes; absence of that witness is not
a claim that no alternatives exist. A complete NULL DACL establishes Everyone through descriptor
evidence without an invented ACE. Empty, unread and incomplete descriptors remain different inputs.

This is named-holder permission analysis, not a user-token expansion or an executed AD operation.
Existing SELF resolution remains bounded to the captured target; group memberships do not combine
different holders' grants. Implicit ownership is not used to fill a missing full-control right.
Existing-owner assessments remain independent. `CanBecomeOwnerAndRewriteDacl` stays Unknown and
uncounted, including when full-control permissions are established.

### Stored evidence, counts and both views

Judgement **schema 23 / control engine 7** identifies the new product. Principal catalogue **2**
and Evidence/Derivation schemas are unchanged. Re-judge on an isolated copy to obtain it; schema 22
and engine 6 do not silently become full-control coverage. No new finding or rule version is added.

The existing primitive and coverage-table layouts are retained. Four additional tables hold:

| Table | Purpose |
|---|---|
| `full_control_manifest` | The expected assessment count for each evaluated object, including zero |
| `full_control_source` | One original ordered ACE snapshot per object with candidates, shared by its assessments |
| `full_control_assessment` | Typed source/check proof, holder/context, generations, state and independent expectedness |
| `full_control_support` | Explicit links to established primitive capabilities included in the summary count |

Writes are atomic with the object's primitive records. Readback replays rights and expectedness from
captured forest, issuing-domain and current membership-route inputs, rather than trusting the stored
label. It checks source identity/masks, support links, generation, category and manifest consistency.
A missing whole assessment and a contradictory stored "complete" flag are refused, not rendered as
smaller or complete counts. Matching summaries outside the visible page are validated before counts
are returned. This is consistency/corruption detection, not cryptographic authenticity.

The headline counts established summaries plus previously count-eligible primitives not linked to
an established summary. **Primitive `IsCounted` remains its original eligibility flag; the readback
projection and displayed count status express inclusion in a summary.** Summary IDs and primitive
IDs remain distinct, with one combined paging cursor and one generation in both directions.
Counts describe the entire selection, not only the visible page.

Only established WRITE_DAC/WRITE_OWNER, applicable general-membership, password-reset,
key-credential and replication capabilities can be supports. They keep their own evidence,
expectedness and categories. Both replication capabilities remain distinct and visibly grouped by
holder and exact naming-context root; neither subsumes the other. Unknown summary assessments add
no count and suppress nothing. Other unknown candidates retain the existing counting policy.
Existing-owner control retains its independent count; owner-change and requester assessments retain
their separate uncounted boundaries. No member counts are manufactured.

Broad principals remain unexpected. SYSTEM requires applicable complete descriptor proof and does
not transfer its expectedness. Restricted schema/DC capability scopes do not become unrestricted
through aggregation, and a summary cannot hide a supporting classification that is not expected.
No principal-catalogue change or DC expectedness exception is introduced.

Both screens use **Full-control permissions**, **Counted once**, and
**Included in full-control count — not counted again**. Broken/unknown summaries state that available
permissions remain visible and, where eligible, counted separately. Their evidence heading is
**Supporting permissions and alternative grant routes**. A proved independent-route witness says
**Removing one complete grant route alone leaves another route to full-control permissions.**
The caveat is **Permission evidence only. No directory operation was performed. This does not
establish operation success, account takeover or a completed path to Tier 0.**

Original target identity, ACE ordinals, masks and inheritance flags identify evidence within this
capture. They are not represented as cross-run `RemediationActionId` values. Inheritance origins
are not guessed, and this slice builds no repair executor, action-cut analysis or Tier 0 path.

### Findings and verification — 2026-09-08

| Finding | Severity/status | Evidence and correction |
|---|---|---|
| FC-1: summary expectedness replay trusted its label | High — corrected | Captured classification inputs now drive replay; changing both the stored label and its proof label is rejected. |
| FC-2: adding a manifest column changed an existing table contract | Medium — corrected | The unchanged Self-Membership corruption fixture exposed the six-column contract. The manifest moved to its own table; the existing test was preserved. |
| FC-3: new proof collections needed a completeness voucher and public registration | Medium — corrected | Added the consumed per-right voucher and registered all three public proof types. The voucher inventory retains its 57 baseline plus the named addition; a capability-specific method name respects the concept registry. |
| FC-4: a stored complete flag could contradict an Unknown summary | High — corrected | A new corruption control failed before the fix, then passed when readback began refusing the contradiction. |
| FC-5: new storage fixtures used a legacy path and hit an earlier foreign-key guard | Low — corrected | Tests now read the selected immutable generation; the malformed-file fixture explicitly bypasses foreign keys only to exercise readback refusal. Production constraints were not weakened. |
| FC-6: summary readback cost has no customer-scale acceptance | Medium — open | Proof validation precedes counts, including off-page summaries. Synthetic correctness/coverage does not establish cost for the 347,000-object, 5.9-million-ACE forest. No budget, limit or performance acceptance is inferred. |

The **full offline suite passed 4,305/4,305**, none skipped, and the solution build succeeded.
This preserves the earlier 4,182-test checkpoint and adds synthetic coverage; it does not revise its
recorded outputs. The final targeted coverage selection passed **796/796**, none skipped, with
exit code 0 in **52.0 seconds** for the coverage command, excluding the preceding build.
SDK **10.0.400** was used under the unchanged `latestFeature` policy. Coverage used the current
Release `net10.0-windows/win-x64` test assembly with `--no-build --no-restore` after source/resource
timestamp checks. A successful build does not claim that existing analyzer warnings were resolved.

The report is `next/.vs/FullControl-1c3b6e2ccd6746f2a3ca86a1c7e06da9/coverage.cobertura.xml`, beside
`full-control.trx`, `coverage-run.log` and `run-summary.json`. Its test assembly SHA-256 is
`AA4B8600E96EF897A40347849664BB3264C4DA2D1ED841DEAA9864DB52E010AC`.
Executable-line hits grouped by source file are FullControlAssessment **38/38**,
FullControlDeriver **36/41**, FullControlEvaluator **120/130**, FullControlStorage **105/106**,
ControlEdgeDeriver **230/234**, ControlEdgeStorage **208/208**, and
ControlEdgesSectionViewModel **238/244**. These are selection-specific line observations, not
complete branch coverage or a performance benchmark. The earlier 795-test coverage report in
`next/.vs/FullControl-bcc394c2412b4952972ad8d100dfdf6f/` is preserved and predates FC-4's correction.
No ownership/replication report was overwritten or regenerated.

The new schema-23 layout checkpoint is
`049DB54C430BFFEC233CF89D36E888DABDF4858E281FA94C758E7377FBF177D7`, recorded from this build rather
than an external historical store. Its provisional in-session value changed when FC-2 moved the
manifest; every published schema-15 through schema-22 hash remains unchanged. Negative controls
cover missing source/support/whole assessments, changed grant masks, labels, generations and coverage,
off-page proof corruption, layout drift and an unbound count-status cell. A 103-object holder query
checks combined paging and counts. Sealed-bundle judging verifies split full-control grants and the
independent existing-owner count. Real-template sizing passes at 900×430, 1300×650 and 1600×900.

The stage-status check and its self-test were requested during documentation closeout, but the
terminal command was cancelled by the user. No result from that invocation is claimed and it was
not retried; it remains an unverified documentation check, separate from the completed build/tests.

**Implementation boundary before publication:** no live directory access, discovery enablement, commit or push occurred.
The serving-DC behavior evidence, WRITE_OWNER-only and resulting-owner tests, AdminSDHolder owner-only
restoration observation, effective member expansion, constrained routes, Tier 0 review and final
P-145/Stage 6 acceptance remain outstanding. Laptop/external-monitor checks are normal product
verification and remain unperformed, not accepted by template sizing. New live work, capabilities,
discovery budgets or publication require separate authorization.

**Publication authorization:** the owner subsequently requested "commit and push then state next step".
This authorizes publication of this completed full-control slice and its documentation to `origin/main`,
not standing authorization for later commits, pushes or additional implementation. Git history identifies
the resulting publication commit. The local ignored coverage reports remain outside the commit.

**Historical next-session boundary at full-control publication: effective-member expansion preparation, not implementation.**
Start from schema 23/control engine 7/principal catalogue 2, Stage 6 §7.1 and accepted decisions
0097/0102, with the existing scope, expectedness and requester boundaries. Recommend how captured
membership evidence attributes group-held permissions to members without multiplying the counted
group edge; preserve independent routes, scope and incomplete-input distinctions. Present the concrete
storage/counting behavior, exact screen wording and synthetic verification for approval before editing.
Choose no production budget without measurements against the documented forest shape. The cancelled
stage-status check and normal laptop/monitor verification remain outstanding; publication does not
discharge them or the live ownership, serving-DC evidence, customer-scale readback and final Stage 6 gates.

## Bounded effective-member attribution

The owner accepted the bounded proposal, exact presentation and 0102 timing clarification, then
requested implementation and continuation. That implementation request did not authorize a production
budget, live verification, discovery enablement, commit or push. Subsequent publication authorization
is recorded below and does not change the other boundaries.

**Versions and inputs:** Derivation schema **11**, judgement schema **24**, control engine **8**;
principal catalogue **2** and Evidence are unchanged. Re-derive and re-judge an isolated copy to obtain
the product. Historical generations are not migrated, reclassified or substituted after a failed
current generation. `JudgingRun.JudgeWithMemberAttribution` requires an explicit budget and current
source-linked inputs; existing host entry points supply no member budget. Requester discovery remains
inactive independently.

**What is stored:** one expansion per scoped permission holder, shared across targets/capabilities;
source-linked members and unresolved DN/SID endpoints; graph links and representative chains grouped
by initial membership; shared resource-context answers; and references to original permissions and
full-control assessments. Unknown or ambiguous holders retain unanswered coverage rather than being
omitted from reverse completeness. Original current identities, primary-group links and foreign
references remain distinguishable. Security-enabled nesting participates; distribution-only routes
do not become current authorization. Cycles terminate without counting a group as its own member.
Disabled accounts retain membership evidence, not authentication readiness. Application partitions
and tombstone capture are not added: the current Evidence format has Domain/Configuration/Schema
contexts and no `isDeleted` attribute. Missing identities are not declared deleted. Explicit deletion
record semantics are tested separately from what current capture can establish.

**Scope and counting:** membership remains target-independent. Resource applicability follows the
captured naming context and retained group routes, not an inferred domain from an arbitrary DN.
Missing servicing context for non-domain partitions, unsupported nesting and foreign authorization
remain Unknown. This is not a complete requester token/access check. Full-control summaries retain
supporting permissions and alternative grants; Unknown/broken summaries suppress nothing. Existing-owner
control retains its independent count. Owner-change control stays Unknown/uncounted. Member identities,
paths and reverse references never add counted holder edges, and expectedness is not transferred.

**Budgets:** visited nodes, traversed links, logical stored expansion records and elapsed processing
are explicit batch limits. A stored-record unit is a member, retained graph link, representative route
or member/resource-context answer; context slots are reserved before discovering the member. Fixed
coverage manifests, existing source-permission references and database indexes are not member
multiplication and remain separately measurable storage costs. Input indexing is a separate linear
preparation cost, not an all-groups transitive closure. Stop reasons retain the discovered prefix and
processing position; work order is deterministic, while timed fresh executions may retain different
prefix lengths under the accepted 0102 clarification. The screen reads persisted results, never starts
another membership walk. Cancellation does not publish a partially written generation.

**Readback and presentation:** manifests, proof hashes, generation, scoped identities, context links,
member indexes and original permission linkage are checked. Missing/corrupt evidence is refused rather
than rendered empty; independently valid holder counts survive a member-detail refusal. Both directions
show **Members of the permission-holding group**, separate resolved/unresolved/unconfirmed counts and
the approved partial-result warning. **Permissions through group membership** is a separate paged
source-permission view, not a broadened named-holder query. Expected source counts describe the stored
selection and remain stated when hidden. Source permission references are deduplicated before paging;
resource uncertainty outside the current page still affects selection completeness.

Reverse rows also retain the **source permission's** evaluation and count status. Established
membership or group usability never promotes an Unknown permission. The reverse presentation reuses
the existing capability labels, including the unverified/uncounted owner-change label, and keeps
**Included in full-control count — not counted again** on supporting permissions. Separate regression
tests cover Unknown owner-change control, Unknown full-control presentation and retained support labels.

**Final synthetic/offline verification:** the solution build succeeded. The source-verified Release
regression selection passed **4,355/4,355**, none skipped within the selection; the four
`StageStatusGateTests` tests were explicitly excluded as an additional precaution, so this is not a
claim that the cancelled stage-status check or its self-test passed. Final targeted coverage passed
**799/799**, none skipped, with exit code 0. Both TRX reports record `Completed` and zero aborted or
not-executed tests. SDK **10.0.400** was used under the unchanged SDK policy; tests and coverage ran
with `--no-build --no-restore` after the Release assembly was checked against 38 changed source/resource
inputs. The coverage command took **53.7 seconds**, excluding the preceding build. These are synthetic
verification timings, not customer-scale performance evidence, and build success does not claim that
all analyzer warnings were resolved.

Final artifacts are in
`next/.vs/MemberAttribution-Final-fcecad10067a499a9091cbd45d44cc85/`: `offline.trx`, `offline.log`,
`offline-summary.json`, `targeted.trx`, `coverage-run.log`, `coverage-summary.json` and
`coverage.cobertura.xml`. The test assembly SHA-256 is
`4C4356CC0D061CBDBBC24E8ADB60E60EBD10C728FFEBB934C820BD9F85A63D82`.
Selection-specific executable-line hits are CapturedMembershipInput **19/19**, MembershipInputStorage
**56/61**, MemberAttribution **34/34**, MemberAttributionDeriver **123/124**, MemberAttributionScope
**79/81**, MemberAttributionStorage **214/217**, and MemberAttributionPanelViewModel **77/82**. These
line observations are not complete branch coverage.

Earlier in this implementation, the focused membership/scope/safety/presentation and historical control
sizing selection passed **93/93**. The pre-reverse-label-correction 4,352-test regression and 796-test
coverage artifacts remain preserved in `next/.vs/MemberAttribution-ec12b694eae84902a7212d4018ce155d/`,
including the stopped initial CLI build log, which produced no test verdict. The final results above
supersede those intermediate results without overwriting them. The background terminal wrapper marked
completed commands as cancelled; the saved exit-code-0 summaries and completed TRX counters were checked
directly before recording success. No successful test selection was inferred from that wrapper label.

New layout checkpoints, observed from
this build rather than a historical forest, are Derivation 11
`15DBD34B6918826C2408E64610E6F1B0E8F4B04675C7F7BD88E1B7D3740BA143` and judgement 24
`1C01DAC6A8A39F345A696C0B7C39119F6ED0F13C95786DF5BD642CBEB606ACFF`. Every published earlier checkpoint
is unchanged. Historical sizing checks retain their assertions but select the original named tables
and scroll to the relevant evidence rather than assuming it is the last section. New member-template
checks cover 900×430, 1300×650 and 1600×900 and reject an unbound member cell.

**Outstanding:** customer-shaped synthetic measurement and customer-scale readback acceptance, any
production budget, normal laptop/external-monitor checks, serving-DC evidence, live ownership/SDProp
gates, Tier 0 review and final Stage 6 acceptance. Small fixtures and coverage are not performance
acceptance for approximately 347,000 objects, 5.9 million ACEs and nine domains. Measure input indexing,
expansion, contextualization, writes, cold/warm forward/reverse validation and paging separately;
vary fan-out, nesting depth, shared routes, cycles and unresolved identities and retain dataset seeds,
machine/build identity, budgets, allocation/memory, I/O, storage and repeated timings. No limit is
selected here. The cancelled stage-status script/self-test remains unverified and is not retried.
Historical tests, frozen hashes and all earlier ignored measurement artifacts are preserved.

**Pre-publication handoff:** the instruction-file change present at implementation start was left
untouched, and all implementation changes were uncommitted at that handoff. The owner subsequently
requested documentation closeout, commit and push of the completed slice. This authorizes publication
to `origin/main`, including the related source, tests, documentation and already-present instruction
update; it is not standing authorization for later publication. Git history identifies the resulting
commit. Ignored coverage and measurement artifacts remain local and outside the commit.

Publication closeout passed **53/53** documentation, workflow, record, link, type-ownership and encoding
checks, and the solution build succeeded. The Release test assembly still matches the final verified
SHA-256 above; no code changed during this documentation closeout. The four stage-status tests and the
cancelled script/self-test were not run. The fetched remote and local `main` matched before staging.

**New-session boundary:** begin from the published member-attribution checkpoint: judgement 24,
control engine 8, Derivation 11, principal catalogue 2, and the final artifact directory above. Read
the repository instructions, product document, roadmap's remaining Stage 6 list, Stage 6 §7/§7.1 and
this implementation record before proposing work. The next proposed bounded task is customer-shaped
synthetic/offline measurement of member attribution and full-control readback. First inspect the
existing measurement infrastructure and propose explicit scenarios, execution scope and new artifact
locations for approval before generating/running large fixtures or changing measurement code. Use the
approximately 347,000-object, 5.9-million-ACE, nine-domain shape; no numerical production budget comes
from a small fixture. Preserve all stored-proof/counting/requester boundaries and historical artifacts.
No new capability, production activation, live-directory access, commit or push is authorized by this
handoff. The cancelled stage-status script/self-test remains unverified; physical display checks remain
normal verification, not a separate prerequisite session. Publication closes none of the scope,
serving-DC, live ownership/SDProp, customer-scale, Tier 0 or final Stage 6 acceptance gates.

## Opening checks three different ways of being wrong

`JudgementReader.Open` refuses before it returns anything:

| Check | What it establishes | Refused as |
|---|---|---|
| The judgement seal | These bytes are the bytes that were written | `JudgementSealAbsent`, `JudgementSealUnreadable`, `JudgementSealMismatch` |
| The schema version | This build understands these tables | `JudgementUnreadable` |
| The evidence fingerprint | This judgement is about *this* capture | `JudgementIsNotForThisEvidence` |

The third is the one no care by the writer can establish, because a store is an ordinary file that
can be moved. A bundle with no readable evidence seal is refused on the same footing as a mismatched
one: unverifiable is not the same as verified, and passing it would make the check optional in
exactly the case where the bundle is already odd.

`BundleSealing.VerifyJudgement` does the seal half, sharing one implementation with the evidence
seal so there is one set of four states rather than two copies of it. `BundleSealing.ReadSeal` is
how a judgement gets the fingerprint to record.

---

## Findings never leave the reader on their own

`Read` returns a `StoredJudgement` carrying the findings **and** the rules that ran. There is no way
to ask for one without the other.

That is a type-system decision rather than a documentation one. A caller holding a bare list of
findings can render an empty one as a clean forest without ever asking whether a rule ran, and no
amount of warning in a comment prevents it. `StoredJudgement.DidNotRun` and
`StoredJudgement.EveryRuleReachedEveryVerdict` are the two questions a screen has to answer before
it shows a count.

---

## One pass over the bundle, not one per rule

`JudgingRun.Judge` opens the sealed bundle, streams every object once, and offers each to every
scheduled rule while it is in hand. Judging forty rules costs the same read as judging one, so
adding a rule costs comparisons rather than another walk of the forest.

**How long judging takes is not known, and the numbers measured here do not answer it.** Streaming a
synthetic bundle on the development machine reached 43,409 objects a second on 2026-08-26, but that
is the read alone with no rule running; with the two delegation rules it fell to roughly 4,689. Both
figures come from invented objects carrying a handful of attributes, and the owner's judgement is
that a synthetic bundle is not complex enough to stand in for a forest. **The number that should be
trusted instead is the predecessor's: four to five hours over the owner's production forest.**
Judging is built for that duration rather than for the lab's 0.72 seconds.

**So a judging reports progress and can be stopped.** `Judge` takes an `IProgress<JudgingProgress>`
and a `CancellationToken`, both required rather than defaulted — gate 1 records that progress,
cancellation and the performance log all became quietly unused in the predecessor by being optional,
and a caller with no operator to tell says so by passing `JudgingRun.NobodyIsWatching`.

Progress counts objects rather than a percentage, because nothing counts a bundle before streaming
it and a percentage wrong by a little would stall at 99 in front of someone watching for hours. It
is reported every 1,000 objects, and the final report is unconditional so that a run ending between
two batches does not leave a total short of what was read.

**Cancelling costs the operator nothing but the time it ran.** The partial file is never renamed
over the finished one, so the earlier judgement survives — the same protection a crash gets, by the
same mechanism. A cancel that destroyed the previous answer would teach an operator never to press
it.

**A rule that throws loses only itself.** It is recorded as `Error`, offered no further objects, and
the rules beside it carry on. Its findings are discarded, because a rule that failed part way
through has no verdict and its partial output would read as a complete one.

**Nothing in the coordinator decides what a run means.** Each rule's outcome follows from what it
did, and the run's state follows from those outcomes inside the writer. A coordinator that could
name the state would be able to call a judging complete while a rule had read nothing.

---

## Findings are read a page at a time

A grid cannot hold a forest, so `JudgementReader.ReadPage` hands back one page and where to carry on
from. The approach is the predecessor's, read on 2026-08-26 and taken because it is better than the
obvious alternative.

**A page starts where the last one ended, not at a row number.** `LIMIT` with an `OFFSET` makes the
database walk and discard every row before the page, so the hundredth page costs a hundred pages of
work. `FindingsPageMark` carries the sort values of the last row shown and the next page is the rows
after it, which costs one seek at any depth.

**The sort ends in the distinguished name, and that is load-bearing.** Findings sharing a severity
and a rule have no order between them otherwise, so a page boundary landing inside such a group
shows some of them twice and loses others — silently, and differently each run. A distinguished name
is unique within a forest, so no two findings can tie on all three.

**Ordered by rank rather than by the word.** The stored severity is the enum's name, so ordering on
it is alphabetical — Critical, High, Low, Medium — which puts Low above Medium on a security screen
and looks entirely normal.

**One row more than the page is fetched and not returned.** Its existence is how a page knows another
follows, without a second query counting rows nobody asked to see. There is deliberately no total:
*page 3 of 400* costs the 400 on every page.

**A judging where no rule ran is refused rather than paged as empty.** `Read` hands findings out
beside the rules that ran because an empty list means nothing on its own; a page cannot carry every
rule execution, so it refuses instead, and `FindingsPage.DidNotRun` keeps the distinction reachable
for a screen holding a page.

**Wildcards in a container's own name are escaped before they reach the query.** `%` and `_` are
legal in a distinguished name and mean something to a `LIKE`, so selecting `OU=Test_1` would
otherwise quietly also show findings from `OU=Test01`.

---

## What a filter may offer comes from the findings that exist

`ReadFilterValues` hands back the severities and rules some finding actually has, and a screen
builds its filter lists from those rather than from the enum.

**A filter that cannot be set to nothing.** A list written into a screen offers Critical whether or
not anything is critical, and an operator who picks it and gets an empty grid has learned only to
distrust the control. Taking the values from the data means every choice narrows to something.

**Severities come back worst first, by rank.** The same alphabetical trap as the grid: ordering on
the stored word puts Low above Medium, which on a filter list reads as a mistake rather than as a
sort.

**Empty lists carry the count of rules that ran.** Two unlike things wear the same empty list — a
judged bundle whose rules found nothing, and a bundle nobody judged — so `FindingsFilterValues`
carries `RulesRan` and `DidNotRun` tells them apart rather than leaving a screen to guess.

**Filtering is a question, not a position.** The values narrow what `ReadPage` is asked for, and
because the resulting list is a different list, a `FindingsPageMark` taken from the old one does not
carry over: it points at rows the new list may not contain.

---

## What every rule did is readable without the findings

`ReadRuleExecutions` hands back one `StoredRuleExecution` per scheduled rule and no findings at all.
It is the other half of the question `ReadPage` answers: a page of findings says what was wrong, and
this says what was checked — including the rules that checked and found nothing, which no list of
findings can contain.

**The count of findings comes from a grouped query, not from the rows.** `SELECT rule_id, COUNT(*)
FROM finding GROUP BY rule_id` is one small read; carrying the findings themselves to count them
would make a screen of eleven rules pay for every finding in the forest.

**`FindingsProduced` sits beside the outcome rather than being inferred from an empty grid.** A rule
recorded as `Succeeded` with zero findings judged everything it was about and established something.
One recorded as `Indeterminate` established nothing about the objects it could not reach. Both write
zero findings, and only the pair of values keeps them apart.

**The list comes back vouched, not bare.** `StoredRuleExecutions` carries the run's state and
`DidNotRun`, because an empty list of executions means either a bundle nobody judged or a judging
that stopped before it recorded anything. Until this read existed the executions were reachable only
through `StoredJudgement`, which says the same thing; handing them back on their own would have taken
that statement away from the one caller whose whole subject is what was and was not checked. Gate 4
caught the omission.

---

## What is built

The schema, the two state machines, the writer, the reader and the `JudgingRun` coordinator are built.
Judging runs the scheduled rules over sealed evidence and also writes the bounded control-edge
products described above. These slices are not completion of stage 6 or its acceptance gates.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain a judging still in progress cannot be opened | `JudgementWritingTests.AJudgementInProgressHasNoNameAReaderAsksFor` |  |
| have a finished judgement named and sealed | `JudgementWritingTests.CompletingNamesTheStoreAndSealsIt` | 2026-08-26 |
| keep the previous answer when a re-judging dies part way | `JudgementWritingTests.AJudgingThatDidNotFinishLeavesTheEarlierOneIntact` |  |
| be certain a judging whose coordinator failed offers nothing to read | `JudgementWritingTests.AnAbandonedJudgingIsNotGivenAReadableName` |  |
| tell a judging where every rule reached a verdict from one where a rule did not | `JudgementWritingTests.EveryRuleReachingEveryVerdictIsCompleted` |  |
| be certain one unreadable input degrades the whole judging | `JudgementWritingTests.OneRuleThatCouldNotReadItsInputsDegradesTheJudging` |  |
| keep the rules around one that threw | `JudgementWritingTests.ARuleThatThrewDoesNotCostTheRulesAroundIt` |  |
| see which capture a judgement was made against | `JudgementWritingTests.TheStoreRecordsTheEvidenceItJudged` |  |
| be certain a rule cannot claim every verdict and also have missed objects | `JudgementWritingTests.ARuleThatReachedEveryVerdictCannotAlsoHaveMissedObjects` |  |
| be certain an unreached verdict says what was missing | `JudgementWritingTests.ARuleThatCouldNotReachAVerdictMustSayWhatWasMissing` |  |
| see what was missing named rather than counted | `JudgementWritingTests.WhatWasMissingIsRecordedByName` |  |
| be certain a finding is not filed under a rule that did not make it | `JudgementWritingTests.AFindingCannotBeFiledUnderAnotherRule` |  |
| be certain a rule that threw does not leave half a verdict behind | `JudgementWritingTests.ARuleThatThrewCannotAlsoCarryFindings` |  |
| be certain one rule is recorded once | `JudgementWritingTests.OneRuleCannotBeRecordedTwice` |  |
| be certain nothing is added to a sealed judgement | `JudgementWritingTests.NothingCanBeAddedAfterTheJudgementIsSealed` |  |
| tell a rule that was skipped from one that was never scheduled | `JudgementWritingTests.ARuleThatDidNotRunIsStillRecorded` |  |
| have a finding survive into a sealed judgement and come back out | `JudgementReadingTests.AFindingComesBackFromASealedJudgement` |  |
| see the evidence a finding rests on come back with it | `JudgementReadingTests.TheEvidenceAFindingRestsOnComesBackWithIt` |  |
| be certain the domain-controller signals are rebuilt rather than trusted | `JudgementReadingTests.TheDomainControllerSignalsAreRebuiltFromWhatWasStored` |  |
| see which version of a rule produced a finding | `JudgementReadingTests.AFindingCarriesTheVersionOfTheRuleThatMadeIt` |  |
| tell a bundle nobody judged from one where every rule ran and nothing matched | `JudgementReadingTests.ABundleNoRuleWasRunOverSaysSoRatherThanLookingClean` |  |
| be certain that distinction is not made by a reader that says it of everything | `JudgementReadingTests.ABundleWhereRulesRanAndNothingMatchedIsNotTheSameThing` |  |
| see what a rule could not read, by name | `JudgementReadingTests.WhatARuleCouldNotReadComesBackNamed` |  |
| see which capture a judgement was made against | `JudgementReadingTests.TheJudgementNamesTheCaptureItWasMadeAgainst` |  |
| be certain a judgement from another capture is refused rather than believed | `JudgementReadingTests.AJudgementMadeAgainstAnotherCaptureIsRefused` |  |
| be certain a judgement that cannot be checked is refused too | `JudgementReadingTests.AJudgementWithNoEvidenceSealToCheckAgainstIsRefused` |  |
| be certain a judging that never finished cannot be opened | `JudgementReadingTests.AJudgingThatNeverFinishedCannotBeOpened` |  |
| be certain a judgement edited after sealing is refused | `JudgementReadingTests.AJudgementThatWasEditedAfterSealingIsRefused` |  |
| be certain the same finding from two judgings keeps one identity | `JudgementIdentityTests.TheSameFindingFromTwoRunsKeepsOneIdentity` |  |
| keep a finding attached to an object that was renamed and moved | `JudgementIdentityTests.AnObjectThatWasRenamedAndMovedIsStillTheSameFinding` |  |
| be certain tightening a rule does not orphan the findings made under it | `JudgementIdentityTests.TighteningARuleDoesNotChangeTheIdentityOfItsFindings` |  |
| see two rules about one object as two findings | `JudgementIdentityTests.TwoRulesAboutOneObjectAreTwoFindings` |  |
| see one rule against two objects as two findings | `JudgementIdentityTests.OneRuleAgainstTwoObjectsIsTwoFindings` |  |
| be certain one finding cannot be stored twice and shown twice | `JudgementIdentityTests.TheSameFindingCannotBeStoredTwiceInOneJudgement` |  |
| be certain evidence that may be missing confidential values does not come back complete | `JudgementIdentityTests.AFindingWhoseEvidenceMayBeIncompleteDoesNotComeBackComplete` |  |
| be certain that is not said of everything | `JudgementIdentityTests.AFindingWhoseEvidenceWasCompleteComesBackComplete` |  |
| be certain evidence with no table is refused rather than quietly dropped | `JudgementIdentityTests.AnEvidenceKindWithNoTableIsRefusedRatherThanDropped` |  |
| see an account trusted for delegation found in a sealed bundle | `JudgingEndToEndTests.AnAccountTrustedForDelegationIsFoundInASealedBundle` | 2026-08-26 |
| be certain a domain controller is not reported for a setting it requires | `JudgingEndToEndTests.ADomainControllerIsNotReported` | 2026-08-26 |
| be certain every scheduled rule is recorded whether it found anything or not | `JudgingEndToEndTests.EveryScheduledRuleIsRecordedWhetherItFoundAnythingOrNot` | 2026-08-26 |
| see which attribute was missing when a rule could not reach a verdict | `JudgingEndToEndTests.AnObjectMissingADeclaredInputDegradesTheJudgingAndNamesTheAttribute` |  |
| be certain a judgement is bound to the bundle it judged | `JudgingEndToEndTests.TheJudgementIsBoundToTheBundleItJudged` | 2026-08-26 |
| judge a bundle again without the earlier judgement being added to | `JudgingEndToEndTests.JudgingTwiceReplacesTheEarlierJudgement` |  |
| be certain an object a rule is not about does not make the judging look degraded | `JudgingEndToEndTests.AnObjectTheRuleIsNotAboutDoesNotDegradeTheJudging` | 2026-08-26 |
| be certain an account genuinely missing an input still degrades it | `JudgingEndToEndTests.AnAccountMissingADeclaredInputStillDegradesTheJudging` |  |
| see how far a judging has got | `JudgingEndToEndTests.AJudgingReportsHowFarItHasGot` |  |
| be certain the last count reported is everything that was read | `JudgingEndToEndTests.TheLastProgressReportedIsEverythingThatWasRead` |  |
| stop a judging that is running | `JudgingEndToEndTests.AJudgingStopsWhenItIsAskedTo` |  |
| keep the earlier judgement after cancelling a re-judging | `JudgingEndToEndTests.CancellingARejudgingLeavesTheEarlierJudgementIntact` |  |
| read one page of findings and be told there is more | `FindingsPagingTests.APageHoldsWhatItWasAskedForAndSaysThereIsMore` |  |
| be certain the last page says there is nothing after it | `FindingsPagingTests.TheLastPageSaysThereIsNothingAfterIt` |  |
| be certain a page that exactly empties the findings offers no empty page after it | `FindingsPagingTests.APageThatExactlyEmptiesTheFindingsHasNothingAfterIt` |  |
| be certain reading every page shows every finding exactly once | `FindingsPagingTests.ReadingEveryPageShowsEveryFindingExactlyOnce` |  |
| see the worst findings first | `FindingsPagingTests.TheWorstFindingsAreOnTheFirstPage` |  |
| narrow a grid to one severity | `FindingsPagingTests.AskingForOneSeverityReturnsOnlyThatSeverity` |  |
| narrow a grid to one rule | `FindingsPagingTests.AskingForOneRuleReturnsOnlyThatRulesFindings` |  |
| narrow a grid to one container | `FindingsPagingTests.AskingForOneContainerReturnsWhatIsBeneathIt` |  |
| be certain a container whose name holds a wildcard does not widen the grid | `FindingsPagingTests.AContainerHoldingAWildcardDoesNotWidenTheGrid` |  |
| be certain a bundle nobody judged is refused rather than shown as a clean grid | `FindingsPagingTests.AJudgingWhereNoRuleRanIsRefusedRatherThanPagedAsEmpty` |  |
| tell that apart from a judging that ran and matched nothing | `FindingsPagingTests.AJudgingThatMatchedNothingGivesAnEmptyPage` |  |
| be certain severity orders by seriousness rather than alphabetically | `JudgementReadingTests.SeverityIsStoredSoThatTheWorstSortsFirst` |  |
| offer a filter only the values some finding actually has | `FindingsPagingTests.TheFilterValuesAreOnlyWhatTheFindingsHave` |  |
| read a filter's severities worst first rather than alphabetically | `FindingsPagingTests.TheFilterSeveritiesComeBackWorstFirst` |  |
| be certain empty filters from a bundle nobody judged say so | `FindingsPagingTests.FilterValuesFromABundleNobodyJudgedSaySoRatherThanLookingEmpty` |  |
| tell that apart from a judging that ran and matched nothing | `FindingsPagingTests.FilterValuesFromAJudgingThatMatchedNothingSayTheRulesRan` |  |
| narrow the findings grid by severity or rule from the screen | `AssetsViewModelTests.ChoosingASeverityNarrowsWhatIsAskedFor`, `AssetsViewModelTests.ChoosingARuleNarrowsWhatIsAskedFor` |  |
| stop narrowing without asking for a rule called "Any" | `AssetsViewModelTests.ClearingTheFiltersStopsNarrowing` |  |
| be certain changing a filter does not open the grid part way down a list that no longer exists | `AssetsViewModelTests.ChangingAFilterStartsTheGridAgainAtItsFirstPage` |  |
| be certain an empty filtered grid does not claim the container is clean | `AssetsViewModelTests.AnEmptyFilteredGridDoesNotSayTheContainerIsClean` |  |

**Confirmed in lab** is the date the owner saw this working against a real forest.

**On 2026-08-26 a finding this product computed reached a screen for the first time.** The owner ran
an audit in the application, pressed *View results*, and read it. Everything above it — capture,
seal, stream, judge, store, page, show — ran in one gesture with nobody at a command line. The run
before that one crashed on a resource key that never existed, which is why
`ViewResourceGateTests` was written.

**Dates are not filled in from that run beyond what it actually exercised.** A run producing a
handful of findings does not confirm a second page, an empty page, or a wildcard in a container
name, and a date against those rows would say the owner had seen something he had not.

**2026-08-26 is the first lab confirmation this product has recorded.** A bundle captured from
`ph.ad.lab` — 8,361 objects — was judged in 0.72 seconds. Both rules reported `Succeeded`, judging
2,082 accounts and passing over 6,279 objects they are not about. One finding: an account planted
for the purpose, `CN=lab.unconstrained`.

**The domain-controller exclusion was confirmed separately, and the first draft of this paragraph
claimed it without grounds.** No controller appeared in the findings, and that had three
explanations — the exclusion worked, the controller does not carry `TRUSTED_FOR_DELEGATION`, or it
was never judged. An absence cannot choose between them, so `judge-bundle.ps1 -Explain` was built to
ask the bundle directly. Against `CN=PHDC,OU=Domain Controllers,DC=ph,DC=ad,DC=lab` it reported
`userAccountControl` 532480 — `SERVER_TRUST_ACCOUNT` and `TRUSTED_FOR_DELEGATION` together — all
three controller signals agreeing, and SEC-011 reaching a verdict of nothing to report. That is the
second explanation eliminated and the third with it: SEC-011 is the computer rule, PHDC is a
computer the rule is about, and the coordinator offers every object in the bundle to every
scheduled rule, so the object the rule judged here is the object it judged in the run. What stood
between a real controller and a finding was the exclusion, and nothing else.

**The same was then observed in every other domain.** The forest carries three controllers, one per
domain, and all three read alike: `CN=baDC,OU=Domain Controllers,DC=ba,DC=ad,DC=lab` and
`CN=adDC,OU=Domain Controllers,DC=ad,DC=lab` each gave `userAccountControl` 532480, all three
signals agreeing, SEC-011 judging them and reporting nothing. So the exclusion holds across a
naming-context boundary, and at the forest root as well as in a child domain — the two places the
organisational-unit signal reads a differently shaped distinguished name.

**A guess about that boundary was wrong and is recorded because it was wrong.** The expectation was
that a controller in another domain is where the three signals part company — the primary-group
check looks for RID 516 or 521, which is domain-relative, and the organisational-unit check reads a
distinguished name in a different partition. Neither faltered. `SignalsDisagree` therefore still has
no lab exercise, and now demonstrably cannot get one here: every controller this forest has been
asked about, and all three agree with themselves. The disagreement path remains proven by test
alone, and the reason it has not been seen is that a healthy forest does not appear to contain such
an object.

The other blank rows were not exercised: nothing threw, no rule was skipped, and no account was
missing a declared input, so the refusals and degraded paths remain proven by test alone.

## Shared permission-proof storage — schema 25

**Approval and status:** the owner approved target-bound shared storage for ownership/control ACE
associations and full-control source lists, then separately approved an isolated offline comparison
helper. The bounded sealed-lab storage slice is implemented and validated: complete cross-schema
public-read-model comparison passed and a net lab storage saving is established. This is not
production-scale or final Stage 6 acceptance. There is no authorization for
publication, live directory access, recapture, UI changes or production expansion budgets.

`SharedPermissionStorage` stores each distinct complete permission entry once per target and
judgement generation, within the existing per-object transaction. `permission_entry` retains the
original ordinal, ACE type, every trustee field, mask, GUID strings and explicit presence flags,
inheritance/propagation flags and callback bytes in structured columns. Equality checks the complete
case-sensitive value representation, not a hash alone. Different physical ordinals and different
metadata remain distinct; null and empty values are not interchanged. There is no mask expansion,
SELF reinterpretation, compression, forest-wide cache, command-reuse change or transaction batching.

`control_ace` retains every original edge/ordinal association and refers to the shared entry.
`full_control_source_entry` retains each source-list position and original ordinal, referring to the
same entry only when all values match. Each association carries an integrity fingerprint bound to
its target, generation, ordinal and complete values. The full-control source also retains its count
and an ordered-list fingerprint. These detect changed values, misdirected references and reordered
lists; they are not a claim of cryptographic authenticity or permission to merge conflicting proof.

Readers join these records to reconstruct the existing public models. Full-control sources retain
the richer trustee metadata; control-edge evidence still returns null for trustee `UnresolvedReason`
and `Meaning`, as it did before. Existing proof-consistency checks, including validation beyond the
visible page where it protects counts, remain in place. No new permission derivation or membership
expansion is performed for display. Assessment explanations, alternative grants, ownership
preconditions, membership routes and support links remain separate and unchanged.

Named-holder counts remain independent of members and routes. Existing-owner control remains
independent, and `CanBecomeOwnerAndRewriteDacl` stays Unknown and uncounted. Concrete requester
assessments, partial results, unresolved nodes and budget stop reasons retain their existing
limitations. Empty, null, unreadable and incomplete descriptors do not become interchangeable empty
lists. Failed object writes roll back their new shared rows as well as their associations; cancellation
after substantial writes still leaves the previous published generation intact.

Only the disposable Judgement schema advances, from **24 to 25**. Control engine **8**, principal
catalogue **2**, and Derivation schema **11** are unchanged. The reader refuses schema 24; re-judge
unchanged sealed inputs in a new isolated copy rather than migrating the old database. The new
schema-25 layout checkpoint records this build's observed layout, not a historical forest anchor.
Every previous checkpoint and the frozen lab benchmark and same-schema comparer are preserved.

### Verification and limits

The current focused run passes **167 tests**. Sharing checks cover every stored field, distinct
ordinals, callback arrays, richer metadata, SELF/applicability and unsupported inputs. Corruption
checks include wrong target/generation, missing values/references, same-target metadata substitution,
case-only changes, reordered valid sources, and failures outside the displayed page. Existing
ownership/replication, late-proof rollback and cancellation-after-1,000-written-objects checks pass.

Fresh outputs from the sealed **ad.lab-20260908-145954** input retain 8,407 objects in three domains,
17 rules, 27 findings and CompletedDegraded, with requester discovery and member attribution inactive.
The schema-24 database is **686,673,920 bytes**; the schema-25 candidate is **543,715,328 bytes**:
**142,958,592 bytes (136.336 MiB; 20.8%) less**, including indexes and reference overhead. Index count
changes from 37 to 38, both have zero freelist pages, and the candidate's published WAL is empty.
There are **209,032 distinct complete stored entries**, with no duplicate complete-value rows or
unreferenced entries. All **208,900 full-control source references** reuse entries also referenced
by control edges. Target/generation/ordinal bindings, foreign keys and the frozen rule-uncertainty
fixture checks pass.

Complete object-first public models match for all **8,407 targets**, **144,732 control edges**,
**1,327,169 ACE associations**, **23,751 full-control assessments** and **72,422 support links**.
Every permission field, precondition, route, support, expectedness and uncertainty value is retained.
The complete findings/rule and inactive requester models are compared too; member attribution stays
unconfigured. Only independently validated judgement generation IDs and run timestamps are normalized.
The four disjoint export partitions cover every target once, preserve all public-reader validation,
and have identical normalized model hashes across schemas. Other query directions and filters retain
their focused test coverage. A case-only change from `AccessAllowed` to `accessallowed`, with counts
unchanged and the export hash refreshed, is refused by the comparator at the changed record. Wrong
generation and unexpected timestamp normalization attempts are also refused.

An uninstrumented offline run passed **4,422/4,422**, with only the four stage-status tests excluded,
and the solution builds successfully. The final repeat passed **4,421/4,422**: the existing
`AuditProgressTests.DerivationSubphaseIsVisibleWithoutResettingTheReadCounter` timed out again, with
no C# changes between the two runs. It uses controlled progress substitutes, not the shared storage
writer. **Medium — unresolved outside this storage slice:** the intermittent progress-wait failure
is retained, not hidden by relaxing the test or repeating until green. The coverage run records
**4,420/4,422**, not a full pass: that progress wait and the literal-instruction scanner's negative
control failed under instrumentation. The scanner's positive/negative cases and full uninstrumented
run pass; neither gate was weakened. Shared storage has full observed line and branch coverage.
Preservation checks found no unexpected changes in 1,001 original files outside the bounded edit list;
the frozen benchmark fingerprint still matches its preserved value.

Publication/readback and memory observations are diagnostic, not a controlled speed comparison.
The candidate's publication checkpoint records about 102.1 seconds and a 149.3 MiB process peak
including setup; cumulative allocation is not a RAM requirement. Peak WAL/temp growth is unmeasured.
The initial exhaustive export reached its helper's 15-minute cutoff after 3,500 objects. Its complete
publication and partial output are retained; revised export-only workers use fresh copies, preserve
all reader validation, and require complete disjoint target/association coverage before comparison.
Baseline export workers recorded 20.82–21.49 minutes each; candidate workers recorded 15.78–15.83
minutes each. These include exhaustive validation, serialization, output writing and hashing under
different concurrent load, not ordinary screen-opening latency or proof of a runtime speedup.
Baseline worker peaks were 94.3–104.8 MiB and candidate peaks 101.1–104.2 MiB, including setup; an
aggregate concurrent-worker peak was not measured. **Cumulative allocation increased** from
7.52–7.59 GiB to 10.77–10.87 GiB per export worker. That is an observed trade-off, not a RAM
requirement or a memory-improvement claim. Local input, source, binary, log, coverage and comparison
artifacts are retained, not required clean-clone documentation inputs. No runtime improvement is claimed.

Production-shaped validation remains outstanding. The existing volume harness couples its
discovery-disabled baseline with a discovery-enabled pass and deletes generated captures afterward;
most of its volume ACEs are read-property fillers, not the repeated ownership/full-control proof
addressed here. It is not a substitute for this retained, discovery-disabled storage comparison. No new scale harness
or production budget is authorized. Synthetic results alone cannot establish production acceptance.
The four stage-status checks remain unverified, and the previously reported clean-clone prose-path
citation issue remains separate. Earlier local progress changes and all prior artifacts are preserved.
