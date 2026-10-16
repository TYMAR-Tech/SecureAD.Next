# Enterprise responsiveness: execution punch list

## Mandate and authority

**Owner-requested 2026-10-15. This is the single execution queue for this programme.**
The job is to make the complete capture-to-browsing experience usable at enterprise scale,
not to collect isolated improvements or reopen an architecture review before each click.

This queue governs scope, sequencing and completion for launch, Home, capture, derivation,
judgement, publication, results opening, every results tab and requested details.
The older ARCH/PERF queues, reviews and performance gates are historical evidence and reference,
not competing schedules or automatic reasons to stop this work.
Use current code, observed costs and the requirements below when choosing the engineering solution;
an older architecture preference is not a veto on a necessary replacement.
Preserve original measurements and failed comparisons without relabelling them.

This is an execution plan, not permission to change findings, weaken evidence, hide missing data
or perform every listed activity immediately.
New measurement campaigns/tools, native formats/public contracts and concrete UI changes need
their bounded scope confirmed before implementation.
Group those confirmations by the batches below, not by individual screen or click.
Do not ask the owner again to choose the priority, require compatibility or design the internals.

The general [punch list](PUNCH-LIST.md) holds unrelated backlog and historical records.
[Product orientation](WHAT-THE-PRODUCT-IS.md) records product purpose and owner direction, not a
second copy of this programme's live status.
Record programme findings against the relevant RESP item here; do not create parallel queues.

## The outcome

The operator can:

```text
Launch -> Home -> start an audit -> capture -> derive -> judge -> publish ->
View results -> Dashboard/Rules/Assets ->
Objects/Findings/Groups/Tier 0/LAPS/Delegations ->
search/filter/page -> object window -> attributes/permissions/classifications/routes ->
return -> another object -> Home -> reopen
```

The audit may perform substantial offline computation, but browsing must read prepared answers
instead of inheriting the audit's whole-forest workload.
An ordinary view must not open unrelated large proof products.
A selected detail must not reconstruct unrelated objects or complete collections behind a paging API.
Some genuinely wide queries and huge requested values may take longer, but they must remain
cancellable, explicit about progress/unavailability and bounded in memory without truncation.

**Functional correctness, performance verification and enterprise acceptance are separate states.**
A passing test count, a fast service method, a small synthetic or completion of a foundation
does not establish the whole operator journey is responsive.
RESP-01 must establish numerical response budgets from the approved workload before optimisation;
RESP-12 must demonstrate those budgets rather than substitute an isolated proxy.
Do not invent production thresholds or limits from small fixtures.

## Starting point: dated inventory, not a second implementation specification

- Branch: `perf02/responsive-browsing`, base HEAD `65dbb144430325ace9c30d63cf75193743068427`.
- Preserve the pending Groups/Tier 0 serving implementation, earlier navigation/publication work,
  owner changes and all frozen evidence; do not reset or recommit them merely to start this queue.
- Current native formats are capture root 3, Navigation 2, overview 1, Evidence 17,
  Derivation 16 and Judgement 75, with 32 registered rules.
- Existing foundations include small Dashboard/Findings/Groups/Tier 0 serving, saved completion
  aggregates, selected navigation/identity, ordered directory continuation, requested tree nodes,
  selected attribute fields and the existing original-membership value pager.
- These foundations are offline behaviour-verified, not current production-shaped responsiveness.
- Source-confirmed remaining paths include synchronous library refresh before the first window
  and on Home return, different new/existing-run results landing, LAPS inventory opening the
  classification-heavy Facts product, and Delegations opening Evidence and optionally Derivation.
- Requested original attributes, permissions, classifications and path/control proof still have
  coarse first-verification units, repeated content assembly/checks and some whole-value cards.
- Capture, derivation, judging, completion and viewing have separate protection lifetimes;
  the viewer already shares verified files internally, so do not sell that existing reuse as new work.
- Exact substring searches and authoritative full-scope counts can still scan saved data.
- The pre-existing null-default gate reports `Read.selected`, `ReadCore.selected` and
  `TreeNodeViewModel.observe`; track its repair in RESP-12 without diverting the programme into it.

The permitted production workload is approximately 540,483 objects, 405,982 derived principals,
2,593,737 nesting relationships, 132,043 distinct descriptors, 70,216,555 positions across those
descriptors and 653,688 requester questions in nine domains/11 partitions.
These descriptor positions are not the separately counted permission occurrences across objects.
The three-domain lab and a synthetic with nine domain names do not reproduce the accumulated
complexity of that forest.

Historical timing context is diagnostic evidence, not a current-build baseline:

| Record | What it establishes |
|---|---|
| October 10 production log/summary, Release `1c38fd6` | Capture about 2 h 32 m, derivation 4 m 10 s, judgement 4 h 38 m; combined path-processing segments about 175 minutes of judgement |
| Later supplied browsing log, executable `a0ab4c8` | First Dashboard plus Findings 273.4 s, including 246.2 s opening/checking large files; separate inventory, tree and warm-page query costs also existed |
| Current pending implementation | Different native layout/rule state; historical timings are not its measured result |

## Engineering contract for the whole programme

1. **Prepare answers once.** Capture builds captured navigation/inventory information,
   derivation saves reusable relationships, and judging saves classifications, findings,
   qualifications, exact counts and indexed browsing data while producing them.
2. **Separate the read workload from proof bulk.** Normal rows, filters and summaries use compact
   authoritative data; original permission/value occurrences and detailed proof stay available
   without being copied wholesale into every display product.
3. **Own trust at a run/generation lifetime.** Reuse verification while exact files remain
   continuously protected, including safe producer/completion/viewer handoffs where possible,
   but never carry a verdict across an unprotected gap, replacement or another generation.
4. **Distinguish kinds of checking.** File integrity, content consistency and current-request
   validity are different; expensive consistency work should not repeat per click without a reason,
   while cheap checks preventing stale/wrong-run answers remain.
5. **Bound the actual backend request.** Read the selected object/family/page, preserve every
   occurrence and oversized value, keep whole-question counts independent of loaded rows,
   and never label partial loading as incomplete capture or a complete object.
6. **Keep the UI's work bounded too.** Create visible rows/requested branches, cancel superseded
   work and keep disk/CPU/large allocations off the interaction path; a background task alone
   does not protect the UI from process-wide memory pressure.
7. **Keep the answers honest.** Preserve evidence/source/resource/generation binding, schema support,
   reasons, applicability/inheritance, ordering, duplicates, unavailable/unsupported/unassessed states,
   capture-only behaviour and prior-completed-root failure/cancellation protection.
8. **Preserve distinct security claims.** Group-held permission counts, membership counts, routes,
   concrete requester authorisation, ownership, successful operations and completed Tier 0 paths
   must not be substituted for one another; reuse the existing Tier 0 definition.
9. **Do not choose a mechanism first.** A custom SQLite block-verifying adapter is not selected
   or approved; choose the simplest native read/integrity contract that satisfies the whole journey,
   retaining full-file verification as a distinct operation and not creating a file per object.
10. **Count all preparation honestly.** Added display/index/proof preparation, validation, sealing
    and handoff time stays inside the reported audit cost, not hidden after a misleading finish.
    Slight judging overhead is acceptable for fast UI; substantial unexplained cost still needs investigation.

## Execution batches

Implementation sessions stay bounded, but the programme is not redefined after each session.
Finish and validate a coherent batch; continue the same queue with the next ready item.

| Batch | Items | Delivered outcome |
|---|---|---|
| 0: baseline and scope lock | RESP-00/01 | One current end-to-end cost map, response budgets and fixed verification/measurement protocol, not another architecture review |
| 1: run lifetime and all ordinary entry points | RESP-02/03/04 | Prompt shell/Home, consistent results entry, continuous trust reuse and lightweight normal data for every ordinary view, including LAPS and Delegations |
| 2: complete requested-detail journey | RESP-05/06/07 | Original attributes/permissions, saved classifications and route/control detail served at the requested boundary, with matching query, paging and UI lifecycle behaviour |
| 3: audit throughput and resource contention | RESP-08/09/10, RESP-11 if demonstrated necessary | Corrections to measured dominant judging/capture costs without weakening coverage, plus derivation/worker changes only where evidence warrants them |
| 4: enterprise proof and delivery | RESP-12/13 | Whole-journey performance evidence, ordinary display checks, accurate unresolved limitations and a self-contained correct-source handoff |

UI responsiveness is the first delivery objective.
RESP-08/09/10 depend technically on the measured baseline, but are scheduled after the integrated
viewer correction so expensive analysis work does not displace completing the viewer.
Do not turn that scheduling choice into an old ARCH-06 prohibition or a reason to leave those
stages out of this programme.

## Punch list

Statuses: `done` means the stated deliverable is evidenced; `next` identifies the next scope to
confirm; `open` is scheduled work; `conditional` requires the stated measured cause.
Report implementation/behaviour verification and performance verification separately in each
handoff, and do not call an implementation performance-accepted until its relevant budgets are met.
Dependencies below are prerequisites, not an invitation to invent new milestones.

### RESP-00 - Capture the complete journey and preserve the baseline

**Status:** done - current source trace captured; no new performance campaign. **Dependencies:** none.

Preserve the pending checkout and frozen records, identify current source/build provenance, and capture launch, all three producing stages, completion, every tab and selected-detail dependencies.
The starting-point inventory, engineering contract and journey matrix in this queue contain the resulting scope, including the newly identified ordinary LAPS/Home/handoff paths.
This closes the read-only scope inventory, not implementation, timing or enterprise acceptance.

### RESP-01 - Establish the current whole-journey cost map and response budgets

**Status:** open - approved RESP-01 execution in progress; current-format producer/readback measurement foundation implemented and behaviour-verified, but whole-journey/enterprise inputs, the fixed campaign and numerical response budgets remain outstanding. **Dependencies:** RESP-00.

Use existing phase records and a proposed fixed offline workload/run matrix to record first paint, complete load/render, verification, SQL, content assembly, allocations/memory and audit-stage costs for the journeys below.
Distinguish new-run handoff, a fresh-process saved-run opening, warm browsing and close/reopen, identify binaries/input hashes and modelling limits, and recommend numerical per-journey response budgets after measuring the enterprise-shaped workload.
Complete with one retained baseline and an engineering-owned batch scope/format/UI proposal tied to those costs, without live access, recycled old service timings, rerunning completed campaigns by default or asking the owner to design the solution.

**Approved scope packet:** [RESP-01 baseline and execution scope](C:/Users/jistrand/.copilot/session-state/4ea6589b-ca69-49ce-88bf-295f68d91d87/files/resp01-baseline-execution-scope.md) - current-format inputs/settings, fixed whole-journey matrix, complete render/resource endpoints, budget method and recommended integrated RESP-02/03/04 batch; application/format/UI implementation not approved

**Preservation checkpoint:** expected branch/HEAD; all 18 arrival-file hashes and nine retained test-output assembly hashes matched the handoff; no build, test, measurement or application-source/format/UI change in packet preparation

**Execution checkpoint:** [current state and evidence map](C:/Users/jistrand/.copilot/session-state/4ea6589b-ca69-49ce-88bf-295f68d91d87/files/resp01/current-state.json) - explicit control-only measurement mode; 343 objects, 795 original member occurrences, 32 current rules and saved Groups/LAPS/Tier 0/permission readback; 72 focused regression checks passed; all 16 new cases mutation-covered across nine rebuilt defects with 20 failing and 20 rebuilt restored observations; final correct-source Release rebuild, 0 errors/866 warnings

**Not enterprise acceptance:** no startup/Home/render/requested-detail journey measurements, ENT75 eligibility or numerical response budgets yet; control-owned inspection opens are not real producer/completion/viewer handoff timings; seven production assemblies remain byte-identical to arrival, while the measurement/test assemblies changed and their originals remain retained

### RESP-02 - Unify protected run lifetimes and trustworthy stage handoffs

**Status:** open. **Dependencies:** RESP-01.

Give one explicit owner responsibility for exact captured/derived/judged generations through analysis, completion and browsing, reusing already established verification only while unchanged-file protection is continuous.
Eliminate demonstrated cross-stage reopening/rehashing and repeated deep consistency work where its guarantee can safely be retained, while preserving cancellation, lease disposal, source/resource binding and cheap current-request checks.
Complete with actual verification/read observations and rebuilt corruption, replacement, stale-generation, handoff-failure and lifetime controls, not a persisted already-verified flag or a more permissive reader.

### RESP-03 - Make launch, Home and results entry lightweight and consistent

**Status:** open. **Dependencies:** RESP-01.

Show the shell without a synchronous whole-library refresh, load authoritative compact run headers asynchronously, and refresh Home without needlessly reopening run payloads or losing the selected-run context.
Use the existing Dashboard results landing as the proposed common destination for both a newly finished audit and a saved library run, retaining the current presentation unless a specifically approved loading/behaviour mockup changes it.
Complete against launch/first-paint, large-library/Home-return, new/existing-run entry and selection-preservation journeys, including slow/unavailable storage and cancellation.

### RESP-04 - Finish lightweight serving for every ordinary view

**Status:** open. **Dependencies:** RESP-01.

Reuse the implemented Dashboard/Rules/Objects/Findings/Groups/Tier 0 foundations and remove remaining ordinary-view dependencies on unrelated bulk, beginning with LAPS inventory in the classification-heavy Facts product and the direct/group-held Delegations query path.
Produce required metadata/indexes in their proper capture/derivation/judging stage with exact scope/count/qualification/source binding, preserving capture-only reads, original proof separately, missing-judgement refusals and no compatibility fallback.
Complete with every ordinary tab, filter/page/revisit/reopen and supporting action exercised against the integrated services while unrelated bulk is inaccessible, followed by complete-view measurements rather than only reader timings.

### RESP-05 - Implement one requested-detail read and integrity boundary

**Status:** open - concrete native format/public-contract scope must be confirmed. **Dependencies:** RESP-02, RESP-04.

Define and implement one coherent boundary spanning captured attributes/member values, original descriptors/entries, saved per-right classifications/schema support and requested path/control/member proof, selecting only the object/family/page the consumer needs.
Choose the native storage/integrity mechanism from RESP-01's costs, retain shared descriptors/proof components and exact original bytes/occurrences, and prove requested data independently without silently weakening existing seal/WAL checks or returning partial objects from whole-object APIs.
Complete with all four detail families integrated through the same protected selected-run ownership, strict missing/corrupt/foreign/oversized-data refusals and rebuilt end-to-end controls, leaving no parallel obsolete production reader or unapproved custom block adapter.

### RESP-06 - Make search, filters, counts and continuation match the requested scope

**Status:** open. **Dependencies:** RESP-04, RESP-05.

Use observed query/assembly costs to complete indexed scope lookups, stable continuation and genuinely bounded reads across ordinary and detail views, retaining the sound Navigation and membership paging already implemented.
Preserve exact substring/literal/Unicode behaviour, Base/One level/Subtree inclusion, original order/duplicates and generation/question-bound marks, and keep authoritative totals and risk/coverage independent of loaded pages.
Complete first/later/last/empty-page and changed-filter/scope journeys with actual SQL/payload observations, without promising constant-time arbitrary full-scope searches or substituting approximate counts.

### RESP-07 - Finish large-value presentation and the integrated UI lifecycle

**Status:** open - any new wording/layout needs a concrete mockup. **Dependencies:** RESP-03, RESP-04, RESP-05, RESP-06.

Wire the bounded backend through every caller and render only requested branches/visible rows, retaining correct object-window, return/revisit/selection state and cancellation of superseded reads.
Where the current card genuinely requests an entire large collection/value, recommend one grouped paging/streaming/loading presentation and obtain its visual approval rather than truncating data, freezing the UI or calling an eagerly reconstructed object paged.
Complete the whole operator journey at the two existing test widths with actual drawing/visibility endpoints and ordinary laptop/external-display checks, keeping unperformed physical checks outstanding rather than creating another monitor project.

### RESP-08 - Reduce the dominant judgement/requester/path workload

**Status:** open; batch 3 priority. **Dependencies:** RESP-01.

Use current phase/source measurements to remove remaining repeated requester/target/context preparation, permission evaluation, proof assembly/serialisation and database work in the dominant path-processing envelope.
Extend the existing unique-question work plan, shared proof/descriptor representation, prepared commands and batching, with reuse keyed to exact generation/resource/requester/membership assumptions rather than another planner or reused authorisation verdict.
Complete with equal-input saved-answer/occurrence/binding comparisons, full-stage time/statement/memory accounting and cancellation/publication controls, accepting justified modest browsing-preparation cost without hiding substantial regressions or reviving a sub-millisecond automatic blocker.

### RESP-09 - Correct measured capture acquisition/storage costs

**Status:** open; implementation requiring live/SYSVOL/scope/concurrency changes remains separately authorised. **Dependencies:** RESP-01.

Separate controller/network/ranged-value/recovery/SYSVOL costs from write/index/seal costs using permitted records and offline storage fixtures, then address the demonstrated dominant cause rather than simply increasing parallelism.
Preserve full capture scope, originals, descriptor sharing, batched writes, recovery/cancellation and inventory/navigation preparation, coordinating any new read products with capture's existing pass.
Complete with an honestly bounded before/after result and unchanged evidence/coverage semantics, while real lab/production acquisition validation and any SYSVOL or controller-load change require their own explicit authorisation.

### RESP-10 - Remove derivation overhead only where it matters

**Status:** conditional on RESP-01 showing material cost or memory pressure. **Dependencies:** RESP-01.

Keep derivation offline and reuse its membership/protection/cycle facts rather than rebuilding them in judgement or the viewer, correcting demonstrated repeated graph expansion, excessive input reads or working-set growth.
Preserve security/distribution/primary-group/resource distinctions and explicit incomplete links without all-group-closure persistence, reduced scope or new limits as an assumed speed fix.
Complete with the same derived facts and bindings plus measured stage/resource improvement, or record a measured not-needed disposition instead of redesigning a historically short stage to fill the queue.

### RESP-11 - Isolate heavy work if it still harms interaction

**Status:** conditional on measured UI contention remaining after bounded reads/rendering. **Dependencies:** RESP-01, RESP-07.

Determine whether analysis-process allocations, garbage collection or CPU/disk saturation still interrupt the UI despite background execution and bounded requests.
If demonstrated necessary, implement an analysis-worker boundary with explicit resource/progress/cancellation/publication and trust-handoff ownership, rather than treating a new process, more threads or a new database engine as an automatic performance fix.
Complete with concurrent-interaction observations, worker failure/recovery controls and unchanged saved answers, or retain a measured not-needed disposition.

### RESP-12 - Prove enterprise-shaped whole-journey responsiveness

**Status:** open. **Dependencies:** RESP-02 through RESP-07; all activated RESP-08 through RESP-11.

Run the fixed approved complete-UI and audit-stage protocol against current source/binaries and approved lab/synthetic inputs informed by the nine-domain production shape, preserving outliers and separating behavioural correctness from response-budget success.
Include all journey-matrix cells, new-run/cold/warm/reopen modes, exact answers/counts/qualifications, adverse inputs, ordinary displays and resource contention, while repairing or explicitly retaining the three pre-existing null-default signatures as code-quality debt without weakening the gate.
Complete only with the RESP-01 budgets met or precise named failures still open in this queue, a final correct-source Release rebuild after every rebuilt isolated defect/restored control, and compact provenance rather than a green label from a small fixture or a subset of screens.

### RESP-13 - Deliver one coherent result and honest rollout boundary

**Status:** open. **Dependencies:** RESP-12.

Reconcile this queue to the delivered code, measured results, source/binary/input fingerprints and exact remaining limitations, retaining compact fixtures/settings/failures and removing only reviewed owned disposable outputs.
Provide a self-contained handoff that starts at the next unfinished RESP item and never sends the next session back through historical ARCH/PERF prioritisation or another architecture review.
Any commit, push, deployment, package replacement or owner-side production validation remains a separately requested action, and no deliverable may depend at runtime on a session folder.

## Whole-journey verification matrix

For each applicable row record initial load, revisit, question changes and reopen separately;
include complete bindings/layout/drawing, not just service completion.
Measures must distinguish file checking, query execution, content reconstruction and UI rendering.

| Journey | Required result and failure coverage |
|---|---|
| Launch / Home | First window before library bulk; authoritative run headers; large/slow/unavailable library; selected-run retention; no background AD contact |
| Capture -> derive -> judge | Per-stage and end-to-end cost, continuous immutable-input ownership where possible, progress/cancel/failure, no hidden preparation time |
| Finish -> View results | Exact finished generation, aggregate completion without full-result reconstruction, consistent landing, no needless producer/completion/viewer rechecking |
| Existing saved run | Fresh process and protected same-session behaviour distinguished; initial view does not verify unrelated bulk |
| Dashboard / Rules | Exact inventory/coverage/rule outcomes and unavailable states, no unrelated proof or repeated analysis |
| Objects / tree / search | Actual forest-root selection, requested branches, exact search/scope/counts, literal/Unicode names, stable first/later/last pages |
| Findings | All saved display kinds, filters/counts/qualifications, object findings/help, requested evidence/routes and return |
| Groups | Direct versus known totals, reference limitations/cycles, type/scope/sort/page controls, membership/object/findings actions and return |
| Tier 0 | Classification versus reachability/grade, summaries and saved limitations, selected original route/control proof and return; no safety or successful-operation inference |
| LAPS | All-scope search/state/domain filters before paging, authoritative totals, requested computer/permission/route details without classification bulk on ordinary list arrival |
| Delegations | Direct and group-held permission queries, scoped identities, exact independent membership/permission counts, continuation and requested supporting proof |
| Object details | Identity, each requested attribute family, original membership pages, descriptor/entries, saved classifications/schema support, control/member/path proof, oversized values and unloaded sections |
| Home / return / another object | No stale result, accidental selection reset, repeat full-file check under continuous protection or full-forest rebuilding just to return |
| Cancellation / replacement / corruption | Wrong sources/generations/roles/questions, changed/missing/truncated/oversized bytes, WAL exclusion, protected reader disposal and previous-completed-root preservation |
| Interaction / display / resources | Existing 900/1300-width checks plus ordinary laptop/external displays, real drawing and visible content, UI interaction during background work, memory/CPU/disk/GC effects |

## How execution is kept on this plan

1. Start by reading this queue and preserving the actual checkout, not resetting to the base HEAD.
2. Take the next ready item in the current batch; do not substitute an unrelated old finding or
   propose a fresh single-click milestone.
3. Before changing an integrity/public format, new measurement tooling/campaign or UI behaviour,
   present the concrete cross-surface batch and practical cost once for the relevant confirmation.
4. Update status here at each validated handoff, with concise evidence references and remaining
   budget failures; keep historical evidence in its original place rather than copying it into prose.
5. Use focused tests during implementation and a combined affected checkpoint for a batch;
   mutation-test new behaviour checks in isolated explicitly rebuilt sources, rebuild restored
   controls and finally rebuild correct live Release sources with fresh TEMP/TMP before discovery.
6. Do not add tests comparing this queue or another document to code; the existing stage-table
   exception is unchanged.
7. A contained defect is recorded here and work continues; false audit claims, vacuous checks,
   frozen-value changes and genuine owner-only product choices are raised explicitly.
8. No live AD, production capture/database/profile exports, recapture, discovery activation,
   changed production budgets, SYSVOL change, compatibility/migration, deployment, commit or push
   is authorised by writing this plan.
   Lab/synthetic inputs and permitted production logs/summaries inform the work; production data
   stays in its environment and any later owner-side validation has its own authorisation.

**Next action:** continue the existing RESP-01 approval by completing the whole-journey
UI/endpoint/overhead adapters and current-format control/tail/library/refusal corpus, then prove
ENT75 input eligibility before the fixed enterprise-shaped campaign and numerical response budgets.
The producer/readback foundation is not a substitute for those endpoints; application/format/UI
implementation and the interrupted checksum-adapter proposal remain unapproved.
