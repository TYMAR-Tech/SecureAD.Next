# Review 07 — Repository synthesis and correction roadmap

**Reviewed:** 2026-08-28  
**Reviewer/model:** GitHub Copilot  
**Production baseline:** `review-baseline-2026-08-28` (`d36ddb4`)  
**Review branch through:** `9ee2866`  
**Status:** Review complete; corrections not yet implemented

## Executive conclusion

SecureAD.Next's core architecture is sound and should be retained:

```text
Kernel -> Evidence -> Derivation -> Judgement -> Shell / CLI
```

Permanent sealed Evidence is separated from disposable analysis, missing input is intended to remain
visible, post-capture stages do not contact a domain controller, and the codebase already contains
strong typed states, primary-source anchors, schema refusal and real-forest feedback loops.

The repository is not yet ready for broad customer trust as a complete audit product. Its principal
problem is composition: components are often correct and well tested in isolation while their outputs
are not persisted, not consumed, or not carried to the operator. The review found 50 focused findings
plus 11 AdminSDHolder findings. They collapse into twelve root causes rather than sixty-one unrelated
repairs.

The safe response is not a rewrite and not a sequence of ad hoc patches. Build the missing production-
path test harness first, correct the lowest semantic and capture contracts, batch Evidence schema
changes to avoid repeated recapture, persist corrected Derivation products, connect them to Judgement
through typed uncertainty, and only then unify Shell/CLI and implement reviewed rules.

## What remains sound

1. **Layer direction.** Kernel remains independent; Evidence describes capture; Derivation computes
   reusable facts; Judgement owns executable rules; hosts present results.
2. **Permanent vs disposable artefacts.** Evidence remains immutable and sealed. Derivation and
   Judgement remain replaceable files bound to one Evidence capture.
3. **Fail-visible principle.** Missing, unread, malformed, disputed and incomplete inputs should never
   become empty or clean answers.
4. **Specification-first rule work.** Current and future rules require reviewed first-party-cited
   specifications before implementation.
5. **No live-directory analysis after capture.** Re-analysis remains offline and reproducible.
6. **No migration obligation for disposable stores.** Derivation/Judgement schema changes rebuild from
   Evidence. Evidence schema changes require recapture and should therefore be batched.
7. **Real-forest confirmation.** Lab runs remain necessary where models cannot prove LDAP/DC behavior.

## Consolidated root causes

### R-01 — Missing production-proof test tier

**Member findings:** T-01, T-02, T-03, T-04, T-05, T-06, T-07; E-C01/E-C02 false greens; D-01/D-02; H-10.  
**Owner:** Tests plus production composition seams.  
**Impact:** Components can be green while disconnected or incompatible.

Required response: Review 03's six-tier standard, adapter contract tests, post-mutation fault injection,
subsystem composition, one full offline product journey and real-environment confirmation.

### R-02 — Capture attempt and scope integrity are incomplete

**Member findings:** E-C01, E-C02, E-C03; K-07; inherited Review 00 completeness concerns.  
**Owner:** Audit + Evidence.  
**Impact:** Retry cannot roll back, newly mentioned partitions are not reconciled, exclusions are not
validated as exact identity pairs, and some crossRefs can be mislabeled.

Required response: atomic capture attempts, exact plan/exclusion matching, reachable/persisted
continuation reconciliation and typed external/application/domain partition classification.

### R-03 — Shared semantic parsers can overclaim

**Member findings:** K-01, K-02, K-03, K-04, K-06, K-08.  
**Owner:** Kernel, with consumer changes in Evidence/Derivation/Shell.  
**Impact:** ACL boundaries, generic rights, malformed heuristics, DNs, timestamps and absent policy
links can become confident wrong answers.

Required response: correct parsing/typing before rules depend on these values; preserve raw and
interpreted forms separately.

### R-04 — Interpretation provenance and compatibility are incomplete

**Member findings:** K-05, K-09; Review 00 catalogue provenance; D-03/Judgement comparison as positive
example.  
**Owner:** Kernel + Evidence + Derivation.  
**Impact:** Stores cannot state which attribute/GUID/parser semantics produced their projections.

Required response: version and persist catalogue/parser/semantic provenance; define compatibility and
refusal policy.

### R-05 — Analysis artefact identity and replacement are inconsistent

**Member findings:** D-03, D-06, D-07, J-06, J-07, E-C04; E-C05/H-09 need reproduction.  
**Owner:** Evidence/Derivation/Judgement shared artefact infrastructure.  
**Impact:** Derivation can be copied to wrong Evidence, two-file replacement can destroy the last good
analysis, and malformed/inaccessible stores can escape typed refusal.

Required response: one shared bound-artefact reader/writer protocol with recoverable generation
promotion and precise typed failures.

### R-06 — AdminSDHolder semantics are modeled as one flat question

**Member findings:** Review 00 F-ADH-001 through F-ADH-010; Decision 0089.  
**Owner:** Derivation semantic model.  
**Impact:** Principal protection, group-object protection and member propagation are conflated; mask
and RID/source uncertainty cannot be represented soundly.

Required response: implement accepted Decision 0089 before persisting or consuming protected facts.
The implementation draft remains noncanonical until revised and accepted.

### R-07 — Advertised Derivation products are not persisted

**Member findings:** D-01, D-04; T-03.  
**Owner:** Derivation.  
**Impact:** Authorization closure, protected-principal evaluations and latent paths disappear at method
return; reopened stores cannot support derived rules.

Required response: schema and reader APIs for corrected products, their bases/provenance and localized
uncertainty.

### R-08 — Completeness and uncertainty are fragmented

**Member findings:** D-04, D-05, J-01, J-02, H-02/H-07/H-08; Review 00 uncertainty findings.  
**Owner:** Evidence -> Derivation -> Judgement -> hosts.  
**Impact:** persisted completeness, run state, rule verdict and operator wording can disagree; global
booleans cannot qualify localized paths.

Required response: one cross-layer assessment vocabulary with typed causes and one authoritative stage
state derived from it.

### R-09 — Judgement's derived-input contract is unfinished

**Member findings:** D-02, J-01, J-02, J-03, H-04.  
**Owner:** Judgement.  
**Impact:** no derived fact affects findings; rules self-read attributes and declarations can drift;
host decides whether rules run after missing Derivation.

Required response: Judgement-owned declared input packages resolved centrally from validated Evidence
and Derivation; per-rule scheduling/outcomes based on typed inputs.

### R-10 — Existing executable rules lack current specifications and have an evasion

**Member findings:** J-04, J-05.  
**Owner:** Judgement rule specifications and rules.  
**Impact:** spoofable DC-like signals suppress unconstrained-delegation findings; SEC-011 severity is
unresolved; predecessor cards are not current authority.

Required response: current first-party-cited SEC-010/011 specifications, owner decision on severity,
and explicit treatment of disagreeing DC signals.

### R-11 — Hosts own divergent workflow policy

**Member findings:** J-10, H-01, H-03, H-04, H-05, H-06.  
**Owner:** shared application workflow + Shell/CLI adapters.  
**Impact:** Shell produces findings while CLI does not; exit codes and failure wording disagree; stage
policy is duplicated.

Required response: one host-neutral workflow and persisted typed stage summary; host-specific rendering
only.

### R-12 — Durable operator truth is incomplete

**Member findings:** J-08, J-09, H-07, H-08; H-09 needs reproduction.  
**Owner:** Judgement reader + Shell run/results views.  
**Impact:** paging can lose tied findings; run list and findings views omit durable degradation detail.

Required response: total finding order and persistent coverage/stage/rule-gap summaries on every results
surface.

## Finding status classification

### Confirmed blockers

- Capture: E-C01 through E-C04.
- Derivation: D-01, D-03 through D-07.
- Test architecture: T-01 through T-07.
- Judgement: J-01 through J-04, J-06 through J-08, J-10.
- Kernel: K-01 through K-05, K-07 through K-09.
- Hosts: H-01 through H-08 and H-10.
- AdminSDHolder: semantic defects accepted/corrected by Decision 0089 as described in Review 00.

### Needs reproduction

- **E-C05:** whether `RunCompletionReader` plain read-only open creates/requires SQLite sidecars.
- **H-09:** same-path external replacement behavior while `BundleAssetSource` holds an immutable reader.

### Needs first-party evidence

- **K-06:** whether `lastLogonTimestamp = long.MaxValue` is a documented no-logon sentinel.
- AdminSDHolder RID/source conflicts identified by Review 00 and the implementation-draft review remain
  unresolved until exact source excerpts are pinned.

### Product decisions required

1. SEC-011 severity and current SEC-010/011 specifications.
2. Policy for an established unplanned partition: fail capture or seal explicitly degraded Evidence.
3. Whether Evidence-only rules run when Derivation is missing/degraded (recommended: yes, per declared
   inputs, while whole-audit state remains degraded).
4. Exact persisted representation and scale budget for derived paths/roots.
5. Remaining AdminSDHolder source conflicts under Decision 0089.

### Safe deferred cleanup

- T-08 structural-gate limitation documentation.
- K-10 dead GPO CSE helper/stale comments, unless filtering is proposed.
- Review 00 test/lab wording cleanup that does not alter semantics.
- Actionability enhancements may follow correctness, except where current wording is false.

## Schema and compatibility impact

### Evidence

Likely one batched schema increment from version 8 to version 9 for:

- captured attribute catalogue version;
- shipped schema GUID/parser semantic versions;
- continuation reconciliation and partition classification outcome;
- any additional capture basis needed by completeness;
- optionally an artefact/run manifest if Evidence owns it.

Existing Evidence v8 remains readable only if the accepted policy can represent missing provenance as
Unknown. If new columns are required to avoid false claims, recapture is required under the existing
no-migration policy. Batch all Evidence-shape corrections before asking for new lab captures.

### Derivation

Schema 3 must change for corrected persisted products, localized uncertainty, catalogue/provenance,
effective roots and Evidence binding validation. The exact next version is decided by the accepted
implementation specification. Existing derivations are deleted and rebuilt.

### Judgement

Schema 3 must change for typed input/outcome reasons, Derivation generation/evidence binding, assessment
scope and durable rule-gap summaries. Existing judgements are deleted and rebuilt.

### Public/internal contracts

Expected compile-time changes:

- capture sink attempt lifecycle;
- typed partition/reconciliation result;
- parser/raw-vs-normalized permission types;
- Derivation product reader APIs;
- unified completeness/uncertainty types;
- Judgement rule input and verdict contracts;
- shared application workflow and host outcome types.

Compile failures during these changes are desirable because they force every consumer to acknowledge
new uncertainty.

## Correction waves

## Wave 0 — Build proof before repair

**Goal:** Make known defects fail through production-shaped paths.

Implement:

- `ICapturedObjectSink`/attempt contract tests against recording and production sinks;
- retry failure after persisted objects/ranged reads;
- cross-bundle Derivation mismatch test;
- state/completeness agreement tests;
- ACL-size and raw generic-right semantic tests;
- judgement-scope and undeclared-input tests;
- Shell launcher/store and process-level CLI tests;
- one offline capture -> derive -> judge -> read/display journey scaffold.

**Acceptance gate:** each critical/high repair has a red test at the lowest tier capable of observing
its real failure. Existing 2,643+ suite remains green except intentional new failures on the repair
branch.

## Wave 1 — Correct Kernel semantic safety

**Goal:** Stop shared parsers/classifiers from producing wrong facts.

Implement K-01, K-02, K-03; resolve K-06; design provenance needed for K-05/K-09. Address K-04 if the
new workflow accepts arbitrary DNs now; otherwise retain as an explicit blocked input boundary.

**Acceptance gate:** independent Microsoft/Open Specification fixtures, malformed boundaries, raw-vs-
comparison mask tests, no golden update without explicit reviewed rationale.

## Wave 2 — Capture attempt and scope integrity; batch Evidence schema

**Goal:** Ensure a sealed Evidence bundle says exactly what was attempted/read/omitted.

Implement atomic attempt rollback/staging, continuation reconciliation, exact exclusion pairing,
crossRef three-way classification, seal I/O normalization and Evidence provenance fields. Decide
unplanned-partition policy before coding.

**Acceptance gate:** failure after persisted state either retries cleanly or seals nothing; every
partition/exclusion/reconciliation outcome round-trips; real multi-domain capture; one Evidence schema
increment/recapture cycle.

## Wave 3 — Shared bound-artefact lifecycle

**Goal:** Make Evidence, Derivation and Judgement stores reliably bound, replaceable and readable.

Implement Derivation evidence-seal comparison, recoverable database+seal generation promotion, typed
malformed/inaccessible refusal, and reproduce E-C05/H-09. Reuse one infrastructure pattern without
inverting layer dependencies.

**Acceptance gate:** fault injection at every promotion point always leaves old or new generation
openable; copied analysis is refused; malformed stores return typed errors.

## Wave 4 — Unified completeness and typed uncertainty

**Goal:** One authoritative vocabulary and state calculation from capture to operator.

Define typed causes, locality/basis, assessment state, and stage summary. Resolve unknown group type,
missing scope, malformed heuristic, unplanned partitions and missing products without global booleans
hiding local facts.

**Acceptance gate:** persisted state, returned state, logs, Shell and CLI agree for every degraded
scenario; no Unknown can serialize/render as clean.

## Wave 5 — Correct AdminSDHolder model and persist Derivation products

**Goal:** Implement Decision 0089 and make reusable facts real artefacts.

Revise/accept the implementation specification, separate principal protection/group-object protection/
member propagation, resolve source disputes, persist authorization/protection/latent products and
localized bases, and expose reader APIs.

**Acceptance gate:** algorithm -> store -> reader round trips; real-forest verification; product
surface/gates updated; production rules can consume facts without recomputation.

## Wave 6 — Judgement input contract and current rules

**Goal:** Make rules consume validated typed inputs and preserve uncertainty.

Implement centrally resolved declared input packages, per-rule scheduling, typed verdict reasons,
whole-audit scope state, current SEC-010/011 specifications and DC-signal disagreement handling. Then
implement SEC-030 only from accepted persisted facts.

**Acceptance gate:** Evidence-only and derived rules coexist; missing/stale/degraded Derivation affects
only dependent rules while whole audit is degraded; rule declarations cannot drift from acquisition;
all rule specs have first-party anchors.

## Wave 7 — One host workflow and durable operator truth

**Goal:** Shell and CLI become presentations over one workflow.

Implement shared stage orchestration, machine-readable outcomes/exit codes, truthful cancellation/fault
messages, durable run stage summaries, rule-gap display, total findings paging, and host parity.

**Acceptance gate:** same offline input produces equivalent artefacts/status in Shell and CLI; full
Tier 5 journey passes; no transient-only degradation.

## Wave 8 — Real-environment confirmation and rule rollout

**Goal:** Prove the corrected system against behavior models cannot establish.

Run disposable-forest scenarios for LDAP paging/retry, referrals/partitions, security descriptors,
`dSHeuristics`, multi-domain BUILTIN identities, exclusions, SYSVOL permissions and full rule output.
Add production-shaped scale measurements before raising storage/path budgets.

**Acceptance gate:** archived bundle/log/commands and expected outcomes; all focused and full tests
green; remaining limitations stated in the product and review register.

## Dependency order

```text
Wave 0 tests
  -> Wave 1 semantics
  -> Wave 2 capture/Evidence
  -> Wave 3 artefact lifecycle
  -> Wave 4 uncertainty
  -> Wave 5 Derivation products/AdminSDHolder
  -> Wave 6 Judgement/rules
  -> Wave 7 hosts
  -> Wave 8 lab/scale validation
```

Wave 3 design can proceed in parallel with Wave 1, but implementation that changes schemas should be
coordinated with Wave 2. Rule feature work remains paused through Wave 5.

## Branch and commit strategy

1. Keep `review/repository-audit-2026-08-28` as the durable review record.
2. Keep `judgement-half` as the last known green implementation baseline.
3. Create one correction branch per wave from the chosen green integration branch.
4. Commit red reproductions separately from fixes where practical.
5. Merge accepted decisions/specifications before or with the implementation they govern.
6. Do not merge the current noncanonical AdminSDHolder implementation draft as accepted design until
   revised and explicitly accepted.

## Final confidence assessment

| Area | Assessment |
|---|---|
| Layered architecture | Sound |
| Evidence immutability/separation | Sound, with capture/lifecycle corrections required |
| Kernel design | Strong, with several semantic boundary defects |
| Derivation concept | Sound but operationally incomplete |
| Judgement concept | Sound for Evidence-only rules; derived-input contract unfinished |
| Shell preflight/consent | Strong |
| Host workflow parity | Unsound/incomplete |
| Test volume/quality | Strong local coverage; missing production composition tier |
| Current broad customer readiness | Not ready |
| Worth repairing rather than rewriting | Yes |

## Definition of repository-level done

The foundational repair is done only when:

- every confirmed Critical/High root-cause finding is fixed or explicitly accepted with rationale;
- every needs-reproduction/source item is resolved and recorded;
- Evidence/Derivation/Judgement identities and stage states agree;
- one full production workflow is shared by Shell and CLI;
- the Tier 5 offline journey and required Tier 6 lab scenarios pass;
- current executable rules have accepted specifications;
- no rule reports clean where required Evidence or Derivation is Unknown;
- the full suite builds and passes without accepted false-green gaps.
