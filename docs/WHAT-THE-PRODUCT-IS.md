# What SecureAD is

An Active Directory security audit tool. **It reads a forest once, seals that reading as evidence,
and everything it says afterwards it says from that file.**

The product makes two separable claims, and keeping them separable is the whole design:

1. **This is what your directory said, at this moment.** Provable years later, on a machine that
   never saw the forest.
2. **This is what we conclude from it.** Re-runnable under better rules without touching claim 1.

**This is orientation, not authority.** Nothing here states the product's position; only a record in
[`decisions/`](decisions/) with `Status: Accepted` does that. Where this file and a record disagree,
the record wins and this file is wrong.

## The shape of a run

| Stage | What happens | State |
|---|---|---|
| Connect | Find the forest itself; climb an ordered ladder of protection and record which rung each controller answered on | built |
| Preflight | Prove a controller can serve what it will be asked, before the run commits | built |
| Capture | Read objects, permissions, group memberships, schema, extended rights, SYSVOL/GPO files | built |
| Reconcile and seal | Reconcile referrals with authorized scope, record uncertainty, then fingerprint immutable Evidence | built |
| Derive | Compute reusable cross-object facts into a disposable store beside Evidence | built; group expansion, membership cycles and AdminSDHolder products persisted and readable |
| Judge | Stream the bundle once, offer every object to every scheduled rule, write findings to a separate store | built, 17 rules |
| Read back | Run library, directory tree, object detail and findings | built |
| Dashboard | Coverage and inventory: how much of the forest was read, and what it held | built |
| Reports, compare and export | — | not built |

**The counts and states in that table are checked rather than maintained by hand.**
`StageStatusGateTests` holds each state to a witness — a type that exists if and only if that stage
is built — and asserts both directions, so a stage cannot be quietly finished any more than it can
be claimed early. The rule count is checked the same way, and `next/tools/check-stage-status.ps1` is
the same check as a diagnostic a person can run. A status goes false when the code moves and the
document sits still, so it cannot be protected by proof-reading; this file claimed *two rules* for
long enough that twelve more were built underneath it. **Until 2026-09-12 this paragraph overstated
itself**: eight of the nine states above were unchecked while it said they were not, which is the
shape this repository rates worst. See `P-135`, and `ROADMAP.md` § *Where we are* for the per-stage
witnesses of the build order, which are a separate table answering a separate question.

`0008` fixes the boundary: **the only component that touches a domain controller is capture.** A
screen showing a permission is reading a file, not asking the directory.

**The application is the product; the command line runs unattended.** The owner's words, 2026-08-26:
*"this whole app is a GUI, the cli is just to capture overnight."* The GUI is where an operator
works and is what every screen is designed for. The command line exists so a long run can happen
overnight without the application open, and **it is intended to grow judging too** — the owner,
later the same day: *"i will be making it so the user can run the audit and it complete the judging
via CLI, so it can run overnight."* So the command line is not capture-only forever; it is the
unattended path, and the GUI is the worked path.

## Fix and feature priority

**Owner-approved next work: Stage 7 — paths to Tier 0.** The bounded correctness pass **P-41,
P-136, P-162, P-173** is implemented and offline verified, as recorded in
[the work queue](PUNCH-LIST.md#agreed-next-work); P-136's reported case was already guarded and
received regression coverage rather than a production change. Do not replace the next feature with
general capture cleanup or require the punch list to be empty; retain validated, self-contained
checkpoints and the existing stop rules for false security claims, evidence loss and invalid verification.

The remaining P-216 caller-status gap, nonblocking presentation/readback work, standalone rule and
inventory additions, and speculative performance tuning are deferred as listed in
[the work queue](PUNCH-LIST.md#deferred-from-the-next-pass). P-217 gates deletion of valuable evidence;
P-157 must be addressed before relying on the affected LAPS results, without automatically blocking all
path development. P-93 remains a Stage 10 acceptance-lifecycle question and P-96 waits for actual path
results; production requester discovery and P-143 declarations remain Stage 7 work, while P-142's
bounded enterprise CA classification is implemented and offline verified.
This order does not accept unperformed laboratory, customer-scale or display checks, authorize new
live access, or waive the normal approval of concrete product and UI changes.

**What the product is for, and what it is not for — the owner, 2026-09-22.** The focus is **control
edges, the rules, and pathing to Tier 0**. Reading an individual object's permissions is not where
users spend their time; most of the time nobody will open that screen. Performance work therefore
belongs on **judging**, and specifically on the object interval where 98.6% of the added elapsed
cost sits — not on making saved results pleasanter to browse.

**The consequence, applied the same day.** The bounded paging reader and the Permissions-screen
paging were cut from P-249 rather than built, and the work retained at
`next/artifacts/p249-final-b/continuation-06/reverted/`. The trial's own evidence agreed with the
owner before he was asked: `run-1-a/reader-3.json` measured the largest object in the laboratory
capture at 79 entries, materialised whole in 4.25 ms using 1.1 MB, with the other sampled extremes
at 2.23–3.43 ms; and the production forest averages about 17 access control entries per object
against the laboratory's 25, so production objects are **smaller** on average, not larger. A screen
change costing an owner approval and a session of work, to save four milliseconds on a screen nobody
opens, is the wrong target however well it is built.

**Owner-approved follow-on order: finish Stage 7, then reconcile the reviewed replacement rule
specifications and implement the remaining rule coverage.** The review and its retained source set are
recorded as P-235–P-239 in [the work queue](PUNCH-LIST.md#rule-specification-review--after-stage-7).
The proposed handoff is a basis for later bounded implementation, not blanket approval of its severities,
thresholds, collection extensions, compatibility requirements or screen changes; inventory/correlation
dispositions must not become duplicate scheduled rules merely to reproduce the predecessor's rule count.
Stage 7's own requester coverage, supported path compositions, SEC-071 findings and presentation remain
Stage 7 work, not postponed to that later rule pass. Existing safety stops and outstanding acceptance,
including the published CI failure recorded under P-227, remain explicit rather than accepted by this order.

**Owner requirement for Stage 7 completion: automatic normal audits, not separate manual path tools.**
A normal GUI or CLI audit must select the relevant account questions from captured evidence, run the
Stage 7 analysis, and save its findings, routes and coverage without an administrator-maintained
requester list or a separate per-object analysis step. This completion requirement covers the remaining
Stage 7 scope, not merely automatic execution of the three currently supported requester families;
SEC-071 findings, broader approved compositions, P-143 declarations and run-wide presentation/counts
remain owed. Screens read and validate saved results rather than starting new analysis, and missing
evidence, unsupported analysis and failed or unfinished work remain explicit rather than becoming safe
answers. Automatic analysis does not authorize changes to AD; the existing separate approval boundaries
for production activation, budgets and paused measurements still apply.

**Owner-selected next Stage 7 priority: production requester coverage**, before broader path
compositions, P-143 declarations, SEC-071 findings and path presentation. Start from checkpoint 7's
offline permission-led selector and checkpoint 8's shared targets, and prepare a bounded proposal
for normal GUI/CLI account selection, execution and coverage accounting, including the representative
measurements and activation decisions needed for approval. This priority is not authorization for
new implementation, requester activation, budgets, screen changes, live access, optimization or new
measurement-harness code, commit or push; it does not reopen the rule-catalogue review or require an
administrator-maintained requester list.

**Separately owner-approved measurement scope, for a later session only:** preservation-safe offline
measurement of the three supported requester families, including minimal runner code, using isolated
sealed-evidence copies and retained synthetic workloads at the documented nine-domain forest scale.
Record exact source/build and evidence-generation provenance, verify that each family actually does
work, vary relevant-group/member density, and measure selection, each proof family, storage, reopening,
memory and cancellation response without changing originals or frozen historical artifacts. This is
scope approval, not authorization to start during preparation; the subsequent implementation approval
below authorizes starting this work, while production activation, numerical budgets, screen changes, optimization, live access, recapture,
commit and push still require separate authorization.

**Owner-approved implementation: shared GUI/CLI requester coverage.** The subsequent request
"approved lets implement it" authorizes the proposed integration and approved offline measurement work.
Both hosts use one explicit selection policy, disabled in production pending activation approval, for
the same three checkpoint-7 families and checkpoint-8 shared targets without widening authorization.
Read coverage from saved selection sources and proof batches, reconcile question identities before
publication, and keep missing inputs, unsupported analysis, unresolved identities and unrequested work
distinct; empty or completed supported scans never establish safety or forest-wide coverage.
Failed, cancelled and unfinished attempts remain separate from the previous valid generation, with
passive reopening and independent group-held permission counts preserved. Verification includes both
hosts, rebuilt deliberate-defect checks, focused coverage, the full offline suite and the approved
measurements; activation is a subsequent explicit decision, not an unrelated backlog prerequisite.
No screen changes, numerical budgets, broader path compositions, optimization, live access, recapture,
commit or push are authorized; P-227, P-240 verification and P-241 remain independently open.

**P-242: integration implemented and offline verified; measurements paused and unfinished.** The full
offline suite passes 5,432 cases and focused coverage passes all 42 new cases, with rebuilt
deliberate-defect witnesses and an additional check that the coverage verdict cannot claim unrequested
or unavailable work completed. The failed first full run, unchanged historical records and hash-checked
source-snapshot archive are retained with the qualified implementation handoff at
`next/artifacts/stage7-requester-integration-validation/6c4fc88314a14c2788580ed29d93f5c5/implementation-summary.json`;
this is not production activation, completed Stage 7, measurement acceptance or closure of P-227,
P-240 verification or P-241.

The preservation-safe runner is now offline verified with 5,444 full-suite cases and 54 focused
coverage cases, including 12 runner checks with rebuilt deliberate-defect witnesses. Initial
measurements and retained failures are qualified in
`next/artifacts/p242-measurement/d48f66126b064a9f8157fe1a1a79f6f0/measurement-handoff.json`;
the small synthetic workload executes all three families, including post-membership authorization,
but its combined authorization answers remain Unknown rather than established routes. The retained
lab capture uses evidence version 10 while this build reads version 12; it was not migrated or
recaptured. Nine-domain volume/density results and separate established combined-authorization
workloads remain outstanding, not customer-scale acceptance or grounds for activation or budgets.

**Owner-directed return to ordinary Stage 7 development:** measurements are paused, not accepted or
permanently cancelled; do not resume them, investigate the stopped process, optimize, or activate
requester discovery by interpreting "continue" as authorization. The first nine-domain volume input
was generated and independently verified, but its measurement stopped without a completed result;
the other two variants never started, and the termination cause remains unproven. Retain all inputs,
partial databases, WAL files, failures, diagnostics and historical source-snapshot mappings unchanged;
older launch records do not establish current liveness. P-242 plan steps 1–8 remain complete,
step 9 unfinished and step 10 pending. Reconcile the remaining Stage 7 requirements and propose one
small non-measurement feature for explicit scope and UI approval before implementation, without
reopening the approved P-242 integration or treating Stage 7 as complete.

**Owner-approved reduced offline pilot, authorized to start by "ok lets do it":** generate a separate
synthetic input of 34,700 objects, 590,000 physical permission entries and nine domains using the
existing configurable workload generator and preservation-safe runner. Retain meaningful membership
density and route scenarios across all three requester families, checking actual work and distinguishing
established from unresolved answers rather than accepting empty or uniformly unresolved work as proof
of readiness. Record input/build provenance, elapsed work, memory, storage/readback and cancellation
evidence in fresh output; keep original large inputs, partial databases, failures and historical
source snapshots/mappings untouched. These figures define a pilot input, not a production budget;
do not assume linear scaling or treat a pilot pass as full-forest acceptance. Only this reduced pilot
resumes: the unfinished full-volume series and stopped-process investigation are not restarted,
P-242 step 9 remains unfinished and step 10 pending, and production requester selection remains Disabled
with the legacy discovery budget null. Optimization, new measurement-harness code, production activation,
new budgets, live AD access, recapture, migration, deletion, commit and push require separate approval.

**The reduced pilot's first preflight was blocked by the original synthetic scenarios, not by a renewed pause.**
The selected density is 18 relevant group sets with four members per holder, taken from the retained
workload design: two sets per domain exercise both Self-Membership and Write Members, with 90 stored
membership values; this is a synthetic experiment, not reconstructed customer membership.
The original generator placed each requester's existing holder permission before the obtained group's permission
on the same Tier-0 target, so the combined proof cannot attribute that first grant to the group being
joined and remains Unknown regardless of these size/density inputs.
At that preflight the generator, runner and two relevant evaluators matched the archived source hashes; the retained smoke
has four established direct-requester answers, four established own-account membership answers and zero
established combined answers, and is not new scale evidence.
The no-launch record is `next/artifacts/p242-reduced-pilot/0869cdf29da34de7b5217a3091078319/preflight-blocked.json`;
no reduced input or timing, memory, storage/readback or cancellation measurement was produced in that attempt.
A bounded generator-only extension to separate established combined-route scenarios while retaining
unresolved scenarios is now explicitly approved: "Approve the generator-only scenario extension,
verify it offline, then execute the reduced pilot"; production proof checks must remain unchanged.
The extension adds an opt-in separate synthetic target using the existing fixed Tier-0 definition,
retaining the original target and six-argument generator mode, followed by focused rebuilt
deliberate-defect verification and execution of the already-approved reduced shape.
The current durable authorization is `next/artifacts/p242-reduced-pilot/35f8f6fe210b4689af59c03ced79b9ef/authorization.json`.
The reduced execution approval remains in force with this bounded generator change;
P-242 steps 1–8 remain complete, step 9 unfinished and step 10 pending, with all other boundaries unchanged.

The opt-in extension is implemented and the final Release build passes all 20 focused checks,
including eight new checks witnessed by four rebuilt deliberate-defect variants; the historical full
suite was not repeated and these checks are not scale evidence.
**The reduced pilot and its separate cancellation observation have now completed successfully.**
The independently verified input contains 34,700 objects, 590,000 physical ACEs, nine domains,
90 member values and mean DN length 96.97683; both runs used the same archived Release executable
and separate copies of the same sealed evidence, with original inputs unchanged.
The main process took 24 min 21.551 sec including preparation and validation: requester-enabled
judging took 9 min 7.249 sec, combined proofs 1 min 43.480 sec, and passive reopening/validation
8 min 29.817 sec; peak process working set was 602.984 MiB and the saved judgement was 96.488 MiB.
There are 72 established requester-permission answers, 72 established own-account membership answers,
and 144 combined answers split into 72 Established and 72 Unknown; each membership-permission type
has 36 established and 36 unresolved combined answers, not an all-Unknown substitute for readiness.
All 576 saved/nested proof identity checks matched the evidence and generations, and all 90 counted
group-held permission rows, including supports and uncertainty, match the requester-disabled judgement.
Cancellation was requested 1,035.861 ms into combined-proof work after 81,687,496 managed bytes had
been allocated, and responded in 61.576 ms; this single observation includes unwinding/runner overhead
and is not a guaranteed response bound or processing budget.
That process exited successfully after 19 min 17.927 sec, retaining and passively reopening its previous
valid requester-disabled generation as NotRequested, not publishing an empty successful requester result.
The final handoff and preservation qualifications are retained at
`next/artifacts/p242-reduced-pilot/35f8f6fe210b4689af59c03ced79b9ef/handoff-d0cd092921394478a703aea153763ead/handoff.json`;
earlier launch/progress, failures and incomplete summaries remain historical records, not current liveness.
These timings isolate the shared JudgeAudit path with no scheduled rules, not total normal-audit/UI
runtime; synthetic density is not reconstructed customer membership and no linear extrapolation or
full-forest acceptance follows. Preparation and validated readback costs remain material measured
readiness concerns, not authorization to optimize, weaken proof/readback checks, set budgets or activate
production; P-242 steps 1–8 remain complete, step 9 unfinished and step 10 pending, with full-volume
measurements and the stopped-process investigation still paused and independent open checks unchanged.

**Owner-approved read-only follow-up:** "yes" authorized investigation of preparation and saved-result
validation using retained pilot records and current source, with no new measurements or optimization.
That investigation is complete; its source/data/query-plan findings and bounded proposal are retained in
`next/artifacts/p242-reduced-pilot/35f8f6fe210b4689af59c03ced79b9ef/read-only-review-b614d80e6eeb4bc7b6262f6acfef0aab/findings.json`.
The approved change is an opened-reader, bulk-validation identity lookup that avoids repeated
name scans while retaining every uncertainty witness and proof check; it must preserve SQLite's
name ambiguity/case rules, exact generations and passive readback without changing sealed evidence.
This uses extra temporary memory; at approval, neither its speedup nor the exact share of phase time
spent in name scans had been measured. The owner explicitly approved "the lookup-only optimization,
offline verification, and unchanged reduced-pilot repeat": use the identical sealed input and unchanged
main/cancellation runner modes in fresh outputs, with focused rebuilt deliberate-defect checks before measurement.
Authorization and preserved pre-existing work are recorded under
`next/artifacts/p242-lookup-optimization/75b787807339426eb8a5023a4ad85154/authorization.json`; no permission
evaluator, evidence schema, production policy, budget, full-volume or live-access change is included.

**Lookup-only optimization implemented and reduced repeat completed, with regressions retained.**
All 541 focused reader/path/runner checks pass, and all nine new checks detect rebuilt deliberate
defects across four variants; the case-comparison variant produced two valid failures rather than the
one initially expected, and its failed validation record is retained without weakening either check.
The unchanged runner used fresh copies of the exact original sealed 34,700-object input, not a
regenerated workload: main elapsed fell from 1,461.551 to 698.654 seconds, selected judging from
547.249 to 160.368 seconds, and selected path preparation from 388.429 to 14.105 seconds.
Validated reopening fell only from 509.817 to 459.105 seconds and remains a material readiness concern;
peak process working set increased from 602.984 to 638.754 MiB and reopening managed allocations
increased slightly, so this is not an across-the-board resource improvement.
The saved judgement remains 101,175,296 bytes, with identical normalized saved questions/proofs,
original ACE supports, 90 independent permission rows, 34,700 uncertainty records, 34,701 path outcomes
and 27 anchors; exact after-run generation binding and passive readback were verified separately.
Cancellation preserved and reopened the previous valid NotRequested generation, but its observed
response worsened from 61.576 to 980.318 ms and the nominal 1,000 ms request fired at 2,306.459 ms.
Independent read-only comparison work overlapped that cancellation run, so attribution to the code
change is unproven; the result remains visible rather than selectively rerun or accepted as a bound.
The paired results, unchanged-input/build provenance, retained defects and preservation review are in
`next/artifacts/p242-lookup-optimization/75b787807339426eb8a5023a4ad85154/handoff.json`.
This is one reduced synthetic pair with no scheduled rules, not full normal-audit/UI timing, full-forest
acceptance, a processing budget or production activation; further optimization or additional measurement
requires approval, and P-242 steps 1–8 remain complete, step 9 unfinished and step 10 pending.

**Owner-approved correctness pass — implemented and offline verified as P-243–P-245:**
"begin correction of these defects" authorizes correcting
member-schema name substitution, premature distribution-group exclusion of captured requester SID
history, and saved-path permission-ID/display-cursor confusion, including affected shared consumers.
Use synthetic offline regressions, rebuilt deliberate-defect checks, coverage and full-suite validation;
preserve original evidence and failed records, exact generations, uncertainty and independent counts.
This does not authorize efficiency changes, new measurements, UI wording/layout changes, requester
activation, budgets, live access, migration, recapture, deletion, commit or push; P-242 steps stay unchanged.

The restored solution build and all **5,552 offline tests** pass; all **26 new regression cases** pass
under coverage collection and detect deliberate defects across **10 accepted rebuilt variants**.
Original failures and the superseded display-test witness remain retained, with the final verification
and preservation record at `next/artifacts/stage7-correctness-validation/7a145e4d584d44f8b9b27331c3f81ea9/handoff.json`.
This does not complete Stage 7 or P-242 readiness, close P-227/P-240 verification/P-241, accept unperformed
physical-display checks, or activate requester selection; the production policy remains Disabled and
the legacy discovery budget remains null.

**Owner-approved bounded saved-path-opening performance session (P-246):** "ok continue" authorizes
a baseline on the current P-243–P-245-corrected build, path and coverage from one fully validated
generation-bound result, background loading with cancellation and stale-selection protection,
proof/uncertainty/counting verification, and a before/after comparison using the same workload.
This is the first recommendation only, not batch proof-context optimization or collection indexing.
The retained reduced pilot's 459.105-second validated reopening is neither GUI timing nor measured
attribution to duplicate validation; it must not substitute for the current-build baseline.
Reuse existing measurement tooling and isolated sealed-evidence copies with fresh outputs, identifying
source, executable and evidence/analysis generations for every timing; new measurement-harness code
requires separately approved concrete scope, as does any new loading/cancellation wording or layout.
Preserve full proof replay, evidence validation, independent group-held counts, explicit uncertainty
and generation binding without a global stale-result cache, together with all pre-existing work and
the complete P-243–P-245 handoff, binaries, failures, stronger display assertion and archived snapshot mappings.
Do not restore loose `.cs` files beneath artifacts, restart the full-volume series, investigate the
stopped process, change production budgets, access live AD, recapture, migrate, delete originals,
commit or push; requester policy stays Disabled and the legacy discovery budget stays null.
P-242 steps 1–8 remain complete, step 9 unfinished and step 10 pending; physical-display checks,
P-227, P-240 verification and P-241 remain independently open, with no readiness or activation acceptance.

**The owner subsequently approved the opening-only measurement adapter and proposed loading wording.**
One small, frozen adapter may use isolated copies of retained sealed results, exercise the real saved-section
opening path, and record source/build/generation identity, elapsed time and cancellation response without
regeneration, judging or an old-pilot repeat. Keep the shell's existing test-only access boundary intact.
In the existing Saved result field, use **Loading and validating saved results...** while reading;
both account checks and saved questions then say **Saved results have not been read.** rather than
claiming that nothing was recorded. Navigating away cancels, returning starts a fresh read, and no new
button or layout is approved; this grants no broader measurement or optimization scope.

**The owner approved continuing with a shorter isolated measurement path and verifying opening before timing.**
Use fresh short-path copies and process-start TEMP/TMP isolation, preserve both failed attempts, and require
successful database and current-reader opening before the opening timer starts; do not weaken validation,
rewrite saved generations, or broaden the approved adapter/optimization scope to make the measurement pass.

**The owner approved continuing with the cancellation baseline and the already bounded saved-opening optimization.**
Keep the now-frozen adapter and the two retained opening-baseline executions; cancellation evidence must
distinguish a navigation request queued behind synchronous work from cancellation that actually interrupts
an in-progress read, and any profiler-export failure must remain separate from completed workload results.

**Latest owner requirement — normal readback must not replay expensive analysis (P-248).** Opening an
already judged run or browsing its saved results must not re-execute permission analysis or replay a whole
generation's proofs merely to establish that the results belong to the captured evidence; production-scale
usability is a requirement, not acceptance of a minutes-long readback after a percentage improvement.
The owner clarified that this applies across the completed run: findings are information already decided,
and moving between screens, pages and objects must read saved information rather than repeat judging or
whole-store verification. Fixing only the Saved Tier 0 path section would not satisfy this requirement.
Retain simple, exact evidence/derivation/judgement binding, completion and supported-format checks, explicit
uncertainty and independent holder counts, and refuse unavailable or mismatched results rather than showing safety.
Integrity checking is separate from recomputing conclusions: accepted [0020](decisions/0020-the-seal-detects-corruption-not-tampering.md)
requires corruption verification on opening/export, with the verdict retained only for the protected open-file
lifetime, not repeated per screen or replaced by an on-disk size/timestamp cache; [0030](decisions/0030-the-product-produces-sealed-evidence-never-signed.md)
makes no claim of signed provenance or resistance to deliberate alteration and resealing.
This supersedes the earlier per-opening full-proof-replay requirement for the next readback design, not the
need to establish proof correctly when producing results or to verify that behavior offline; the completed
P-246 implementation and all frozen tests, evidence and measurements remain preserved as history.
The concrete reader/publication boundary, integrity lifetime and compatibility/verification scope must be
presented for approval before implementation; this requirement does not authorize simply deleting safety
checks, changing UI presentation, new measurement-harness code, migration, recapture or production activation.
File-fingerprint verification still reads file bytes, so its opening cost must be distinguished from proof
replay and measured rather than described as free or accepted at customer scale without evidence.

**Owner-approved P-248 checkpoint 1:** “begin” authorizes the local implementation branch, explicit
analysis-attempt publication state, a protected selected-run reading lifetime, and findings/filter/rule
execution reads through that boundary, with isolated regression and rebuilt deliberate-defect verification.
Stop at that checkpoint; it does not authorize the later control/path/LAPS/classification conversion,
database-schema or UI changes, new measurement tooling, migration, recapture, activation, commit or push.
The owner requires a clean replacement of the flawed design, not parallel production implementations,
dead code or permanent transition scaffolding; preserved historical evidence is not a reason to retain
obsolete production code. Preserve the existing instruction-file edit and all retained P-243–P-246 work.

**Owner-approved P-248 checkpoint 2:** continue on `p248-stored-readback` with saved control-edge
and permission evidence, the existing Full Control/ownership conclusions used by those lists,
saved Self-Membership answers, and forward/reverse membership attribution. Replace browsing-time
analysis with saved-result reads through checkpoint 1's protected selected-run lifetime, preserving
exact evidence/derivation/judgement binding, supporting evidence, independent holder/member/route
counts, resource scope and explicit incomplete results. Preserve pre-existing edits, including the
work queue, and all historical artifacts; isolate TEMP/TMP before loading tests and explicitly rebuild
both deliberate defects and restored code. This approval does not reopen checkpoint 1's completed
mutation work or authorize UI/schema changes, later checkpoints, live AD, activation, new measurement
tooling, commit or push; P-241 and unperformed physical-display checks remain open.

**Owner-approved P-248 checkpoint 3:** “approve begin implementation” authorizes the proposed saved
Tier 0 path, path-input and requester-coverage readback replacement through the protected selected-run
lifetime, preserving result-production checks, exact generations, supporting evidence, uncertainty,
independent counts and existing presentation. Verification is synthetic/offline with rebuilt deliberate
defects; checkpoint 1 and 2 verification campaigns are not restarted, and P-241 remains open.
UI/schema changes, live AD, activation, new measurement tooling, commit and push remain unauthorized.

**Owner-approved checkpoint 3 storage correction — zero backward compatibility.**
Before this correction, `ownership_seed` stored routes and a classification fingerprint, not the full
`Tier0Classification`; `PathInputs.Classifications` had to be reconstructed by the classifier.
The owner approved storing the complete classifications and advancing the judgement format, explicitly
requiring **zero backward compatibility because this product has never shipped**. This supersedes
checkpoint 3's no-schema-change and existing-format compatibility limits only: refuse older formats,
with no migration, legacy reader, empty-evidence substitute or hidden replay fallback. Preserve original
evidence/results and historical verification separately; regenerating old results remains outside this
approval, as do UI changes, live AD, activation, new measurement tooling, commit and push.

**Checkpoint 3 is implemented and offline verified in judgement format 39.** All 5,665 offline tests
and all 21 new focused coverage cases pass; every new case detected a relevant defect across four
explicitly rebuilt variants, with successful restoration builds and unchanged original artifact metadata.
The retained verification handoff is
`next/artifacts/p248-c3-6cec41d134044638b2d3d70df7528756/handoff.json`.
Later P-248 checkpoints, P-241, physical-display checks and customer-scale opening-cost acceptance
remain open; this is neither complete P-248 nor complete Stage 7, and requester activation is unchanged.

**Owner-approved P-248 checkpoint 4:** “approved and begin implementation” authorizes judgement
format 40 with a complete all-computer LAPS inventory produced during judging, saved-result reads
through the protected selected-run lifetime, and requested-finding-only SEC-090/093 route reads
with recorded support lengths. Inventory includes healthy, disabled and domain-controller computers
independently of findings; captured support, scoped capture shortfalls and incomplete results survive.
Inventory now requires a completed saved product rather than calculation before judging: the existing
refusal panel says **This run has no saved LAPS inventory.** Raw object attributes remain readable.
Missing or unreadable account flags must remain Unknown rather than Disabled; the existing skip-reason
column says **Account state unknown** or **Domain controller; account state unknown** as applicable.
No layout or finding-text changes are authorized. Replace the old analytical inventory reader rather
than retain a fallback, refuse older formats with zero backward compatibility, and do not regenerate
original results. Verification is synthetic/offline with TEMP/TMP isolated before test-assembly loading
and every new behavior check witnessed by rebuilt deliberate defects and restoration builds; do not
restart checkpoint 1–3 verification campaigns. Preserve intervening work and all historical artifacts,
including failures; P-157, P-174, P-241, later permission/navigation checkpoints, physical-display checks
and customer-scale opening-cost acceptance remain open. No live AD, activation, production-budget
changes, new measurement tooling, commit or push is authorized.

**Checkpoint 4 is implemented and offline verified in judgement format 40.** All 5,705 offline tests
pass, including all 5,665 historical cases and 40 new cases passing under coverage; every new case
detected a relevant defect across seven explicitly rebuilt variants, with successful restoration builds.
The qualified handoff, including retained failed attempts and preservation checks, is
`next/artifacts/p248-c4-6596977645534ef5b49c3893ec5dcd55/handoff.json`.
No original results were regenerated; this completes only the approved LAPS readback checkpoint,
not P-248 or Stage 7, and the independent constraints listed above remain open.

**Owner-approved P-248 checkpoint 5:** “approved and begin implementation” authorizes format 41
saved per-right permission classification, produced during the existing all-object judging stream
and read through the protected selected-run lifetime. Preserve each right's bits, wording, verdict,
reason, original ACE identity/order, inheritance/applicability, captured-schema context and explicit
unclassifiable outcomes; this is not requester authorization, takeover proof or a completed Tier 0 path.
Missing/invalid saved products refuse classification while raw evidence remains readable, with zero
backward compatibility and no migration, regeneration or replay fallback. Keep the grouping, columns,
colors and default-off highlighting, with the approved unavailable/unclassifiable notices, saved-result
counter explanations, per-right reason tooltips and corrected incomplete/order/empty-list statements.
Use isolated offline verification, with TEMP/TMP isolated before test-assembly loading and every new
behavior check witnessed by rebuilt defects and restoration builds; preserve all historical cases,
hashes, artifacts and failures without restarting checkpoint 1–4 campaigns. Hidden navigation, P-157,
P-174, P-241, physical-display checks and customer-scale opening/browsing acceptance remain open;
no live AD, activation, budget changes, new measurement tooling, original-result regeneration,
commit or push is authorized. Approval is not a claim that this checkpoint has been implemented or verified.

**Checkpoint 5 is implemented and offline verified in judgement format 41.** All 5,768 offline
cases pass with no skips, retaining all 5,705 historical cases by test identity; all 63 new cases
pass under coverage and detect relevant defects across ten explicitly rebuilt variants, followed
by exact source restoration and successful restoration builds. The qualified handoff, including
earlier failures, is `next/artifacts/p248-c5-51372c69f37e4fefbaab3133567312c6/handoff.json`.
Saved permission classification retains its evidence and uncertainty without browsing-time risk
replay; unread descriptors are not described as observed noncanonical or incomplete lists.
This completes only checkpoint 5: hidden navigation, P-157, P-174, P-241, physical-display checks
and customer-scale opening/browsing acceptance remain open, with no Stage 7 completion,
activation, original-result regeneration, commit or push.

**Owner-approved P-248 checkpoint 6:** “approved begin implementation” authorizes visible-only
completed-run browsing without changing format 41. Load only the visible listing and selected object
section; resolve the object's captured identity/class before selecting the requested section, without
preparing other sections or their rows. Findings-filter choices load on first Findings display and
belong only to that protected run lifetime. Keep section availability/order, result meanings, columns,
grouping, colors and the existing geometry; replace eager production paths rather than retain a parallel
implementation. An open object belongs to its originating Assets tab: another tab displays its listing
and suspends object reads, while returning reloads the selected section if the run and shared selection
remain valid. Back retains the originating page/position only after checking its protected lifetime,
generation and query; superseding selections cancel reads and reject late success or failure. Tree,
filter and applicable level changes invalidate affected pages but read only the visible destination;
Rules remain whole-run. LAPS starts at its own first page rather than inheriting the Objects page,
without new paging controls or closure of P-174. Leaving Assets cancels work; re-entry retains the
current Objects/root landing behavior. Missing products, changed generations and unpublished attempts
remain explicit refusals, never cached results, empty substitutes or hidden analysis replay.

The approved additional content-area wording is **Loading captured information…**, **Loading saved
results…**, and **This view could not be read.** followed by the underlying reason. Keep the existing
Saved Tier 0 path wording **Loading and validating saved results...**. Loading/refused views do not
present old rows, old finding guidance, zero counts or “nothing found” as current answers; genuine
empty results retain their existing wording. Verification is synthetic/offline with TEMP/TMP isolated
before any test-assembly loading, including discovery; every new behavior check requires a relevant
rebuilt deliberate defect and exact restoration build. Preserve historical cases, frozen values,
measurement tooling, artifacts, failed attempts and intervening work without restarting checkpoint 1–5
campaigns. P-157, P-174, P-241 and independent verification/readiness, physical-display and customer-scale
acceptance remain open; no live AD, activation, budgets, migration, original-result regeneration,
new measurement tooling, commit or push is authorized. Approval is not implementation or verification.

**Checkpoint 6 is implemented and offline verified in judgement format 41:** its corrected protected-read prerequisite passes all 5,784
offline cases, retaining all 5,768 historical cases. All 16 new checks pass under coverage and detect
relevant defects across seven explicitly rebuilt variants with exact restoration; the qualified results
and retained failed attempts are recorded at
`next/artifacts/p248-c6-40e79c89c1e04f049c8ccac4b001e8bc/handoff.json`.
The approved navigation implementation passes all 5,826 offline cases, retaining all 5,784 prior
cases by stable identity; all 42 new cases pass under coverage and detect relevant assertion failures
across five explicitly rebuilt variants, each followed by exact restoration and a passing rebuild.
The qualified navigation handoff and retained failed attempts are
`next/artifacts/p248-c6-navigation-f8a15ebd7cd5463ab874c71f06d2389c/handoff.json`.
This completes checkpoint 6 implementation, not P-248 or Stage 7: P-157/P-174/P-241, independent
verification/readiness, physical-display and customer-scale opening/browsing acceptance remain open.
The owner subsequently authorized committing and publishing this checkpoint; no migration,
regeneration, activation, live access or new measurement tooling was authorized, and completed
prerequisite campaigns were not restarted.

**Owner-approved bounded offline judging diagnosis (P-249):** “Approve bounded offline judging
profiling after identifying the lab build and obtaining an isolated sealed-run copy” authorizes
measurement only after both prerequisites are met. Identify the executable/build for every timing;
the reported previous approximately 40 seconds remains an estimate until comparable baseline
evidence is available, and the current checkout is not proof of the lab executable. Use isolated
sealed-evidence copies offline, with TEMP/TMP isolated before any test-assembly loading or discovery,
and distinguish saved-result production, evidence reads, scope assessment and path preparation.
Preserve original evidence/results, the supplied log, historical measurements, failed attempts and
intervening work; do not restart completed checkpoint or mutation campaigns. This approval does not
authorize optimization, new measurement tooling, live forest access, recapture, original-result
regeneration/deletion, production requester activation/budget changes, UI changes, commits or pushes.
The reported successful lab screen navigation is functional feedback, not physical-display or
customer-scale acceptance.

**P-249 input handoff:** the owner supplied
`C:\Users\jistrand\Downloads\ad.lab-20260919-223420` and confirmed that everything there is a copy,
with the application inside its `secure` folder. Preserve that supplied copy as the intake and use
separate fingerprint-verified working copies for the approved offline investigation. The supplied
application identifies the binaries to investigate; its embedded commit stamp alone does not prove
a clean source revision. This handoff does not authorize new measurement tooling or optimization.

**Owner-approved P-249 profiling driver:** “Approve the dedicated offline profiling driver and bounded
judging profile” now authorizes a separate measurement program for this supplied capture and application
package, superseding the no-new-measurement-tooling boundary only for this driver. Run the normal
17-rule `JudgeAudit` configuration using the fingerprinted supplied libraries, with requester selection
disabled and isolated temporary storage before execution or discovery; do not load the test assembly
or repoint historical benchmarks. Retain provenance, phase timing, result/count checks and all attempts
on fresh working copies without changing production code, security conclusions, budgets or screens.
This approval does not authorize optimization, live access, recapture, original-result changes,
restarting completed verification campaigns, commits or pushes.

**P-249 follow-up scope after the two unsuccessful profiler attempts:** the owner requested
inspection of the second failure and preservation verification **without rerunning judging**, then
authorized retrying the canceled inspection. This follow-up is inspection only, not a further
profiling attempt, driver repair, build, test run or optimization; retain both failed attempts and
any unsuccessful verification records alongside the corrected verification result.

**Owner-approved P-249 build-only repair:** “Fix the profiling driver and validate its build without
rerunning judging” authorizes correcting only the dedicated driver's build/reference wiring and
compiling a separate copy of the failed generated runner. Preserve the supplied binaries, original
generated files, failed attempts and previous verification records; do not invoke benchmark setup,
judging, readback, test discovery or profiling during this repair. A passing build is not a timing
measurement, execution validation or approval of any optimization.

**Owner clarification for P-249:** the supplied run is already a copy; stop creating additional
evidence snapshots and repeating broad preservation reports during driver repair. Keep only the
input/build identification needed for valid measurements, leave existing historical artifacts alone,
and focus on the fix with brief updates. This does not request deletion or a further judging run.

**Owner resumed P-249 profiling after the build repair:** “ok do the profiling” authorizes the
bounded offline profile with the repaired driver and supplied libraries. This supersedes the
build-only pause, not the restrictions on production changes, optimization, live access or budgets.

**Owner-approved bounded P-249 optimization:** implement command/parameter reuse and transaction-local
deduplication of identical schema support in `PermissionClassificationStorage.Write`, keeping one
transaction per object, exact conflict checks, cancellation/rollback, all permission rows and proof
binding unchanged. Approval includes a separate matched before/after configuration against newly built
libraries, focused regression checks with rebuilt deliberate defects, and offline remeasurement; the
supplied-binary benchmark remains frozen. No shared-proof redesign, cross-object batching, format/UI
change, live access, activation, new production budgets, commit or push is authorized.

**Owner-selected order for the P-248 review follow-up:** address P-250 (evidence-reader lease
disposal), then P-251 (exact saved-interpretation sharing), then P-252 (subject-specific path reads).
Use separate bounded sessions; the order does not authorize later format/UI changes, optimization
or new measurements in the lease-repair session. Keep updates brief and do not restart broad
preservation inventories for the supplied copied run.

**Owner-approved bounded P-251 implementation and offline verification:** “Approve the bounded P-251
storage change, separate comparison adapter and offline verification” authorizes generation-local
sharing of exact saved permission interpretations, judgement format 42 and its selected-object reader,
without changing interpretation calculations, individual permission identities/order/duplicates/counts,
schema support, uncertainty or security conclusions. Retain exact-content checks after indexed lookup,
entry/generation binding, one transaction per object, cancellation/rollback and explicit refusals;
replace the old repeated representation with no compatibility reader, migration, analysis replay,
forest-wide memory cache or UI change. The separate P-251 comparison adapter must preserve the frozen
P-249 tooling, establish an identified original-writer baseline before production edits, then use the
same sealed input and procedure for three matched pairs with alternating run order and fresh processes;
retain every timing, build/input identity and failure. Approval includes focused offline correctness
checks with rebuilt deliberate defects and restoration builds, with TEMP/TMP isolated before test
assembly loading or discovery; a smaller store alone is not an accepted judging-speed fix. Preserve
historical evidence, hashes, verification artifacts and pre-existing work; no live access, recapture,
requester activation, production budgets, computation sharing, commits or pushes are authorized.

**Owner-approved bounded permission-entry command reuse:** “Approve the bounded permission-entry
command-reuse change and offline verification” authorizes a lazily prepared insert/read-ID command
and 21 reusable parameters in `SharedPermissionStorage`, with disposal at the four transaction-owning
sites in `ControlEdgeStorage` and `PermissionClassificationStorage`. Keep judgement format 41, the
SQL and stored values, exact keys, fingerprints, entry identities/order/duplicates/counts, shared-proof
behavior and security conclusions unchanged; no interpretation/computation sharing, reader/UI change,
cross-object batching, run-wide cache, discovery or budget change is included. Use the frozen P-251
comparison adapter unchanged, an original control before production edits and three matched pairs
with alternating order and identified fresh-process builds; retain supplementary invocations and
failed attempts separately, and verify the other affected writer paths with focused offline scenarios.
Approval includes new reuse/lifetime/value/rollback checks and relevant existing storage checks, with
TEMP/TMP isolated before test loading/discovery and rebuilt deliberate defects/restoration for every
new behavior check. Accept only repeatable whole-judging improvement with identical security outputs
and no material allocation, memory or readback regression; otherwise restore the original and retain
the trial without broadening it. Preserve pre-existing work and historical evidence/artifacts; no new
measurement program, live access, recapture, commits or pushes are authorized.

**Owner-approved current-object permission-reuse trial:** “OK TEST IT” authorizes testing the
reviewed first scope: reuse the current object's already-read captured permissions when offering that
object to rules, including repeated ownership lookups, while preserving independent mutable inputs
for each lookup and expiring reuse at the end of that object's processing. Preserve exact-name and
ambiguous-name behavior, other-target lookups, missing/unreadable/empty distinctions, resource scope,
reader lifetime and evidence/generation binding; a missing permission provider stays missing. Keep
format 41, all security decisions, path-validation reads, discovery, budgets and UI unchanged. Use the
frozen offline comparison and focused regression checks with rebuilt deliberate defects/restoration,
isolating TEMP/TMP before test loading/discovery and retaining pre-existing work, original evidence,
all measurements and failed attempts; no new measurement program, live access, recapture, commit or
push is authorized. This is permission-reading reuse, not interpretation sharing or removal of checks.

**Owner-approved bounded diagnostic-only timing and verification:** “Approve the bounded
diagnostic-only timing and verification scope” authorizes an unchanged offline reproduction check
using the supplied build/evidence, then a separate source-matched diagnostic build and diagnostic
copy of the existing runner to account for elapsed judging time, not another optimization. Identify
actual binaries, source relationship, runtime, machine and host context; a fast developer-machine
run must not be presented as an explanation of the lab's 108 seconds, and a lab execution, if needed,
must be an explicit offline command/package using copied evidence rather than another capture.
Keep frozen benchmarks and normal production untouched; aggregate exclusive phase timings and work
counts, label nested detail and the unattributed remainder, include enumeration advancement, and
separate permission reading/interpretation/storage, other writes/rules, scope/ownership, path-source
validation/calculation and publication from completion-screen loading. Verify result equivalence,
timing attribution and instrumentation overhead with an uninstrumented/diagnostic/uninstrumented
comparison and rebuilt deliberate defects/restoration; stop and state the limitation if source
equivalence, reproduction or overhead cannot be established. Isolate TEMP/TMP before test loading
or discovery and preserve all prior work, original evidence, measurements and failed attempts; no
rule/result/format/UI change, discovery/budget change, live access, recapture, deletion of originals,
commit or push is authorized.

**Owner-approved pre-P-248/current offline judging comparison:** “lets do it” authorizes isolated
rebuilds of pre-P-248 `efb6fb076ee586cb6fe5dfee8ade8457a630a82e` and current
`2c2b3e3b305347c1cc85ce6beb84d3a3470ead27`, plus a separate small comparison runner that handles
their different saved-judgement formats without changing the frozen runners. Use the same existing
copied evidence and derivation, evaluation date, rules, runtime and disabled requester policy; run
old/current then current/old in four fresh processes without added diagnostic instrumentation, compare
common results, and report P-248's additional saved products separately. This is a contemporary
source-rebuild comparison, not reconstruction of an old lab executable or timing; preserve current
uncommitted work and all original evidence, measurements and failures, isolate TEMP/TMP before loading
any test assembly, and do not recapture, access live AD, optimize, change production behavior, commit
or push. No older audit or application needs to be supplied by the owner for this comparison.

**Owner-approved P-249 per-object permission storage correction:** “Create the branch and implement
the bounded per-object permission storage correction” authorizes work on
`p249-object-permission-storage`, created from `p248-stored-readback` at `2c2b3e3`, with existing
uncommitted work preserved. Replace the per-entry classification persistence with one complete,
ordered saved permission-result payload per object and separately shared schema support; classification
alone must no longer populate the shared control-proof permission tables, while their actual control
proof uses remain intact. Keep permission calculations and public results unchanged, including every
entry, original ordinal, duplicate, raw value, per-right verdict/reason, applicability, inheritance,
captured-schema support, resource scope and missing/empty/unreadable/incomplete distinctions. Preserve
exact evidence/derivation/judgement/object binding, independent counts, publication checks, one
transaction per object and cancellation/rollback; the matching selected-object reader reads saved
answers without analytical replay. This authorizes a distinct new judgement storage format and its
reader, not reuse of the rejected format-42 interpretation-sharing trial, compatibility readers,
migration, UI changes, cross-object batching or a forest-wide cache. Remove superseded production
write/read paths and unused helpers as part of the same correction, not as later cleanup; retain
historical source/tests/fixtures, frozen benchmarks, measurements and failed attempts separately.

Use the retained offline comparison procedure with a separate adapter copy extended to verify every
saved permission interpretation as well as the common results; do not modify frozen runners or
restart completed profiling/mutation campaigns. Run a current control before editing production,
then candidate/candidate/current to complete four fresh-process runs on identical copied inputs,
evaluation date, rules, runtime and disabled requester policy, without added diagnostic timers.
Approval includes focused correctness and damaged-data/binding/order/schema-conflict/cancellation
checks with rebuilt deliberate defects and restored builds, and measurement of judging, output size,
allocations, memory and selected-object reading; isolate TEMP/TMP before any test loading/discovery.
Adoption requires a repeatable whole-judging benefit with identical answers and no material readback,
memory or cancellation regression, not merely fewer writes; otherwise stop and retain the trial
without leaving parallel production implementations. The earlier pre-P-248 comparison is complete
and must not be repeated; laboratory results do not establish nine-domain production performance.
No live AD, recapture, original-result deletion/regeneration, discovery activation, production budgets,
rule/security-result changes, commit or push is authorized, and implementation needs no further
approval within these boundaries.

**P-249 trial disposition, 2026-09-21:** the approved four-run comparison is complete, with every
saved permission answer and all common results matching, but the format-43 candidate is **not adopted**:
repeatable faster judging did not satisfy the no-material-regression gate because peak memory,
full-heap collection frequency and maximum selected-object read latency increased. Original format-41
production and matching tests are restored; the candidate and its verification remain separately at
`next/artifacts/p249-object-storage/comparison-result.json`. P-254/P-255 keep the full-suite failures
explicit, and neither this trial nor its lab speed gain establishes nine-domain production acceptance.

**Owner-approved P-200 SQLite-cache comparison:** following preparation, “Run the bounded 64 MiB
writer-cache comparison” authorizes the four-run comparison, its separate adapter changes and
isolated candidate build described below, but not adoption or a production default change.
The earlier P-200 reader-cache experiments remain recorded as historical results for their builds,
inputs and combined settings, not evidence that reader-cache tuning cannot benefit today's code.
Do not rerun those historical builds as this comparison's baseline: use fresh current-build controls.
A separately bounded current-build reader-cache experiment would be new evidence, not an unnecessary
repeat; the proposed writer-only first contrast does not rule it out or authorize it automatically.
The proposed first contrast keeps the restored format-41 implementation and changes only the single
judgement writer connection's `main.cache_size`: its observed default versus `-65536` (64 MiB).
That is an experimental allowance, not a hard process-memory cap, a proposed production default or
a budget for the nine-domain forest; evidence/derivation/selected-object readers, memory mapping,
temporary storage, page size, journaling, durability and transaction boundaries remain unchanged.

Use a separate copy of the retained full-answer comparison adapter and isolated builds,
leaving active production and frozen runners untouched; reuse the existing sealed 2026-09-19 copied
input, derivation, evaluation date, 17 rules, runtime and disabled requester policy without new captures
or extra preservation snapshots. First verify the current default through its real writer in a
separate untimed preflight process; stop if it is already at least 64 MiB rather than claiming an
increased-cache comparison that changed nothing. Run a fresh current control before introducing
the isolated candidate change, then verify the candidate's effective setting in an untimed preflight,
with a rebuilt negative control that omits the change and an explicitly rebuilt restoration.
Only then run candidate/candidate/current, completing four fresh uninstrumented judging processes;
keep settings checks, semantic comparisons and tests outside the measured interval.

Compare every saved permission answer and the existing common results with exact input/generation
binding, plus whole judging, CPU time, result size, allocations, memory, GC and selected-object reads;
retain forced cancellation/rollback checks instead of relying on a timer that fires after a read ends.
Use short isolated TEMP/TMP before any test loading or discovery, rebuild new deliberate defects and
restorations, and preserve failed attempts and the unresolved P-254/P-255 qualifications.
More cache memory is an intended trade-off, not an automatic failure: report its absolute cost,
observed growth and read/cancellation effects alongside both timing pairs without inventing an
acceptance threshold from the lab. This comparison alone authorizes no adoption, additional cache
sizes, tuning of other connections, UI changes, live access, recapture, discovery activation,
production-budget changes, commits or pushes; execution within this bounded scope is approved.

**P-200 writer-cache comparison completed, 2026-09-21:** effective writer settings were verified at
2,000 KiB for the current build and 65,536 KiB for the isolated candidate; the only candidate source
change was the cache pragma, with SQLite's derived spill threshold following that allowance.
The four current/candidate/candidate/current runs took 51.675/46.675/229.851/48.325 s and every saved
permission answer and all 28 comparison categories matched, but the long second candidate means
no repeatable speed benefit is established; it is retained rather than discarded or rerun.
Its existing object-processing interval grew from 37.786 to 214.474 s between candidate runs,
without establishing why; mean peak process memory rose from 289.153 to 367.147 MB and result size
was unchanged. Forced cancellation/rollback/retry checks passed on both builds after rebuilt negative
controls and restoration; active production, tests and frozen historical runners were never changed,
and no setting is adopted. `next/artifacts/p200-writer-cache/comparison-result.json` retains build
identities, settings, complete results and limitations; P-254/P-255 remain unresolved, and neither
current reader-cache tuning nor nine-domain production performance is settled by this writer-only trial.

**Bounded saved-permission blocks — design-only handoff:** following the external review and its
corrections, the next deliverable is a concrete storage-and-read contract and bounded comparison plan
for owner review, not implementation, new measurement code or execution approval. Keep evidence →
derivation → judgement and completed-run saved answers; the candidate under discussion changes only
permission-classification persistence and retrieval inside SQLite. Preserve the analysis stages,
genuine control-proof products, one transaction per object, cancellation/rollback and generation
publication; exclude cross-object batching, parallel workers, cross-generation reuse, incremental
findings and external payload files from this first candidate. Reviewer recommendations are proposals,
not newly accepted product decisions, and any visible browsing behavior or wording needs approval.

The predecessor was subsequently inspected at
`C:\Users\jistrand\source\repos\razamus\SecureAD\src` (the alternative lab profile is
`C:\Users\ba.admin\source\repos\razamus\SecureAD\src`). Its
`SecureAD.Infrastructure/Storage/MaterializedAclPayload.cs` demonstrates binary records with a local
string dictionary, but `DirectAceWriter.cs` feeds it normalized entries from
`SecureAD.Core/Security/AceNormalizer.cs`: generic rights are expanded, entries sorted and duplicates
removed. That payload lacks Next's original ordinals, callback application data and richer saved
answers; its nullable-string encoding merges null and empty and its reader materializes the whole
object. The predecessor also retains per-entry rows and computes permission aggregation during
object-detail loading in `SecureAD.UI/ViewModels/ObjectDetailPanelViewModel.cs`; inherit the technique,
not its evidence semantics, workload or timing baseline. Its `SecureAD.Infrastructure/Findings/FindingsService.cs`
uses separate readers for parallel evaluators, not a shared connection that would justify parallelizing
Next's existing loop.

The draft contract must make the following concrete before any implementation:
- Ordered SQLite payload blocks and their searchable object/page metadata, bounded encoding and
  decoding buffers, dictionary scope/lifetime and explicit overflow/continuation for an oversized
  entry, string, schema-support record or application-data value; no truncation or arbitrary security
  processing limit disguised as a storage bound.
- Lossless original order, ordinal, occurrence position, duplicates, raw masks/types/flags, GUID
  presence flags, application data, owner/descriptor states, errors, per-right verdicts/reasons,
  applicability/inheritance, schema support, resource scope and missing/empty/unreadable/incomplete
  distinctions; saved interpretations remain distinct from authorization, takeover and Tier-0 paths.
- Exact evidence/derivation/judgement/object binding and reference integrity, independently reconciled
  object/entry/right counts, ordered manifests, block sequence/length/offset/integrity checks,
  complete-object publication and explicit refusals for missing, duplicated, damaged or unsupported
  data; a truncated payload and a correspondingly truncated manifest must not validate each other.
- A genuinely bounded read contract and identified consumers: first page, continuation, total counts,
  ordering/grouping/filtering and cancellation; never silently return a partial object from a
  whole-object API or infer totals/risk from loaded rows. Partial loading is not incomplete captured
  evidence, and a complete-object result must not be rebuilt eagerly behind the paging API.
- Stage-aware interactions: in the scoped flow the first pass records descriptor coverage and
  candidates; detailed control assessment arrives after admission. Coordinate within producing stages,
  not by retaining every object until all later products exist. Schema interpretation is already
  memoized by `PermissionClassificationProducer`; writer-side reuse must still detect conflicting
  values for the same identifier and cannot cache rolled-back database identities as committed.

Keep the two experimental questions separate: first bounded chunking/readback using the same encoding
as the retained format-43 design where practical, then compact binary encoding of that bounded
representation. Format 41 remains the production reference; format 43 changed several mechanisms and
its historical timings are not a fresh control. Define first-use/first-page, subsequent-page and full
object measurements separately, compare every answer across all blocks, and include whole judging,
CPU, output size, allocations, peak memory, actual GC pause time and cancellation. Do not call reading
one page a whole-object speedup, or choose production limits from the small lab; extra 35 MB or a
46 ms read is not by itself proof of an unacceptable trade-off. Any later experiment needs its own
approved bounds, current measured control before optimization, unchanged-input/build/runtime provenance,
and retained outliers; do not silently restart completed campaigns or modify frozen runners.

**Remaining diagnostic questions and evidence anchors for this review:** the returned BAWK1 offline
reproduction took 133.74 s, including 115.12 s of object processing and about 7.03 s of nested rule
clocks, leaving about 108.09 s outside those clocks in that interval; this is not the original reported
108-second audit reconstructed. The supplied libraries and input also ran in about 26.86 s on
S2DMEASOFT; BAWK1 used .NET 10.0.10/eight logical processors and S2DMEASOFT .NET 10.0.12/twenty,
without proving which host/runtime/work effects explain the gap. Returned lab records remain under
`C:\Users\jistrand\Downloads\judging-reproduction-results-20260921-010007-4ef019f0d6d24b3d88e0ee5a750dba7c`.
The latest local diagnostic ledger attributed about 16.26 s of a 27.69 s run to permission storage
including nested work, but controls of 34.18/31.11 s did not establish its timing overhead; do not
double-count children or claim that ledger explains the slow lab or 229.85 s cache-trial execution.
Use `next/artifacts/judging-walltime-diagnostic/timing-continuation/completed-comparison.json`, not
the earlier paused handoff, for that qualification. Pre-P-248/current rebuilt Next comparisons show
9.677→26.956 s mean judging, 23.245→352.264 MB output and 98.6% of the added elapsed cost in the object
interval, but the current build additionally produces required saved products: this is not identical
workload or a comparison against the predecessor application.

All trial outcomes, identities and failures remain in `next/artifacts/`:
`p249-pre248-comparison/comparison-result.json`, `p249-storage-comparison/result.json`,
`permission-entry-command-reuse/comparison-result.json`, `current-object-permission-reuse/comparison-result.json`,
`p251-storage-comparison/comparison-result.json`, `p249-object-storage/comparison-result.json` and
`p200-writer-cache/comparison-result.json`. Active production is restored format 41, with no trial
optimization adopted; P-254/P-255 remain open. The design session should extend an appropriate
specification under `docs/specs/` (or create a clearly marked draft specification if none fits), not
a new session-history document or tests comparing prose to code. Read the existing judgement specs
first, preserve uncommitted work and all original/frozen artifacts, and stop at a concrete proposal
for owner approval; no new builds/tests/profiling are required to draft it, and no live access,
recapture, discovery activation, production-budget change, UI change, commit or push is authorized.

The concrete proposal is now [P-249: bounded saved-permission blocks — draft](specs/P249-SAVED-PERMISSION-BLOCKS-DRAFT.md).
It specifies the lossless storage/read contract, actual caller changes and separately bounded chunking
and encoding comparisons; the subsequent bounded trial approval below supersedes its original design-only
restriction for candidate B only, while format 41 stays active. The historical outcomes and unresolved
qualifications above are unchanged; candidate C and production adoption remain unapproved.

**Owner-approved final bounded P-249 trial:** after clarifying that paging already exists for object
listings and control/membership results, but not for the complete permission list inside one object's
Permissions section, the owner selected **“Approve the complete final trial”** in response to the
explicit scope question covering implementation, offline verification, the Permissions-screen change
and four comparison runs. Implement the draft's **B / chunked JSON** storage and genuinely bounded
readback in an isolated candidate, including its proposed principal/entry paging and explicit large-value
continuation presentation using the existing app pattern; do not change existing object-list or
control/membership pagers. This includes the separate comparison-adapter work and contrast I:
four fresh format-41/candidate/candidate/format-41 judging processes, with the first current control
before candidate optimization, the draft's bounded reader workloads and complete saved-answer comparison.
Preserve the input/build/runtime identities, every original occurrence and interpretation, genuine proof
products, one transaction per object, rollback and generation publication; isolate TEMP/TMP before test
loading/discovery and rebuild new deliberate defects and restorations. Active production remains format
41; trial UI changes belong to the isolated candidate, and adoption requires a subsequent owner decision.

The owner is being asked by a customer to provide a usable product: **this is one final bounded attempt,
not an open-ended storage optimization campaign**. If it does not demonstrate a worthwhile benefit,
retain its results and return to **finishing Stage 7, then the remaining rule coverage**, rather than
starting another storage experiment; report practical speed/read/memory/cancellation trade-offs without
inventing a lab-derived acceptance threshold. No binary-encoding candidate C, cache tuning, fifth judging
run or extra run to chase a better timing is authorized. Preserve all pre-existing work, historical
campaigns/outliers and the unresolved P-254/P-255 qualifications; the 133.74-second and 229.85-second runs
remain unexplained. No live AD, recapture, original-result regeneration/deletion, discovery activation,
production-budget/security-rule changes, migration/legacy readers, commit or push is authorized.

**Final-trial execution checkpoint — unfinished, not a candidate verdict:** the first fresh format-41
control and its bounded selected-object whole-reading workload are retained under
`next/artifacts/p249-final-b/`, with the execution plan, exact source/build/input identities and all failed
attempts. The owner explicitly resumed from that checkpoint without repeating run 1. The preservation
check had found a changed timestamp on the retained original judgement's
SQLite shared-memory companion file during selection preparation; the sealed database hashes still match,
but the prior companion-file bytes were not hashed, so full artifact preservation cannot be claimed
(`P-256`). Protected immutable access and write-denying input protection are now verified with a rebuilt
deliberate defect and restoration; the historical uncertainty remains. B's isolated storage now holds block
framing, exact value fragments, independent producer/source expectations, the publication ledger, exact
large-value continuation, schema reuse with conflict refusal, and the whole per-object answer: descriptor,
trustee, entry and right records, the `pc_group` and `pc_occurrence` directories a principal selection needs,
the object and group projections computed with the screen's existing risk, denial and rights-summary rules,
an independent stored readback that decodes every record again and compares typed values rather than only
digests, and one transaction per object wired through the ledger with rollback and cancellation. Entry
application data required exact byte values, so the value stream was extended to carry bytes as well as
UTF-16 through the fragment layer's existing byte path. 154 focused offline checks pass, with ten rebuilt
deliberate defects this session; one of them found a real fault in the new code, where two places decided
one question about whether a value is stored by reference, and one check was split because it carried two
independent claims. **The candidate still writes format 41 and is not qualified**: generation publication in
the candidate writer, bounded readback, the Permissions screen and the remaining B/B/A runs are all still
owed. Those must land as **one change**, because a candidate that writes blocks before its reader exists
would produce a judgement it cannot itself open, and format 44 is selected only when that switchover is
complete; the binding adapter carrying captured object, coverage and descriptor identities also needs a new
public read path in `SecureAD.Evidence`. `next/artifacts/p249-final-b/continuation-04/result.json` records
the bounded checkpoint and verification limits. Format 41 remains active, slot 1 is consumed and must not be
silently repeated, and neither a completed comparison nor a benefit/failure of B has been established.

**Owner priority reaffirmed:** continue the approved storage trial now, before finishing Stage 7 and
the remaining rules, so a worthwhile storage improvement can be in place for later rule work. This
continues the existing B-only implementation and remaining B/B/A comparison, not a new experiment,
permission to repeat run 1 or approval to adopt an unverified candidate; improvements to saved-permission
storage do not promise that every future rule's own calculation will become faster.

**Owner decision, 2026-09-22: small fixed memory differences are not an acceptance criterion.**
His words: *"memory is less of a concern to me. most modern systems have 16 GB of memory, if I run this
on a server it would have a lot more than that, I don't want to quibble over 40 MB of memory."*
A peak working set measured in tens or low hundreds of megabytes is therefore **not** a reason to
reject a candidate or to complicate a design, and no session should trade clarity, fidelity or speed
for a saving of that size. This supersedes the memory half of the P-249 adoption gate recorded above:
judging speed, answer equality, browsing responsiveness and cancellation still decide adoption, and a
memory figure is reported as information rather than weighed against them. It does **not** retire the
*other* two regressions that stopped format 43 — maximum selected-object read latency and full-heap
collection frequency — because those are felt as a screen that stalls, which is a responsiveness
question and not a memory one.

**What this decision does not yet settle:** whether memory that grows with the size of the forest is
equally unimportant. Tens of megabytes on a laboratory of 8,383 objects is a different thing from a
design that holds whole objects, whole principal lists or whole result sets at 347,000 objects and
5.9 million access control entries, where the same shape reaches many gigabytes. Bounded reading is
still required for **time to first screen** and for cancellation, not only for memory. Do not read this
decision as permission for unbounded growth, and do not read it as a prohibition either; ask the owner
when a specific design actually raises it.

**Owner-approved next implementation session: one object's saved path evidence.** After reconciliation
against the existing specifications, the owner selected "Approve for next implementation session" for
the following bounded display scope and wording; this preparation session does not authorize code changes.
The subsequent "begin implementation" request authorizes this bounded implementation with the same
wording, proof and preservation boundaries; measurements remain paused and requester activation disabled.

- Add **Saved Tier 0 path** immediately after **Control edges** in the object view, with three groups:
  **Saved result**, **Recorded route**, and **Coverage and limitations**.
- Word the saved result **Supported route recorded**, **This object is a Tier 0 target**,
  **Not determined**, or **No saved path result**, as applicable; failed validation instead says
  **Saved result unavailable** with its reason, never an empty or negative security answer.
- Show the saved ordered route steps, destination, supporting evidence and assumptions. Label length
  **Shortest proven route**, stating that unsupported alternatives might be shorter; a fixed target's
  zero distance is not an extra hop. Permission to change permissions is not account takeover, obtained
  membership is not an observed successful Add, and a supported route is not proof of live-operation success.
- Keep missing captured evidence, unsupported analysis and unresolved identities distinct. Under
  **Automatic account checks**, show **Not requested**, **Required inputs unavailable**, or
  **Supported questions evaluated** from the typed saved execution-coverage verdict, never from counts;
  a completed supported scan does not establish forest-wide coverage or safety.
- Read and validate saved results from the same exact generation only when the section is opened;
  do not discover accounts, calculate new paths, write results, contact AD or present an older result
  as a failed/unfinished attempt's current result. Preserve original permission supports, independent
  group-held counts and passive readback, including validation of recorded proof questions.
- Verification is synthetic/offline, with rebuilt deliberate-defect checks and normal laptop/external-
  monitor display checks; unperformed checks remain outstanding. No measurement, optimization,
  requester activation, new budget, recapture, original-artifact deletion, commit or push is included.

This makes already-saved analysis inspectable, not broader detection coverage or Stage 7 completion.
SEC-071 finding production, P-143 declarations, wider compositions, summary counts and remediation remain
separate work; P-242's unfinished measurement/acceptance steps and the independent verification issues
remain open. No separate graph screen or changes to existing ownership/permission findings are included.

**Saved-path presentation is implemented and offline verified; physical-display checks remain outstanding.** The retained verification
at `next/artifacts/stage7-saved-path-presentation-validation/24b9a2507ad64923b6943b1c957083c9/verification-df1a23bdf1f04c359a0e97f2bd4a24e3/`
records all 65 new checks passing under coverage collection and all 65 detecting deliberate defects
across ten explicitly rebuilt variants, with successful restoration rebuilds and all six mutation-target
source hashes checked against the restored baseline. The successor verification at
`next/artifacts/stage7-saved-path-presentation-validation/24b9a2507ad64923b6943b1c957083c9/verification-full-suite-e6bd37ae0f124ec5934e767971a2c4b5/`
records an explicit Release rebuild and all 5,509 offline tests passing with no skipped cases, matching
test identities and source/executable hashes, and a preservation review finding only the intended
source changes and no existence/length/last-write changes across the 15,215 original artifact records;
the earlier run without a final result and the subsequent 5,507/5,509 failure remain retained, physical
laptop/external-monitor checks remain unperformed, and this does not accept P-242 measurements,
complete Stage 7 or close P-227, P-240 verification or P-241.

## Stage 7 first checkpoint: saved path inputs

**Owner-approved implementation scope:** save source-bound path inputs in new Judgement generations,
with passive validation/readback and no reachability verdicts, distances, tier counts or screen changes.
Reuse the authoritative Tier-0 classifier; fixed anchor targets are distinct from effective membership
and assessment-admission relationships. Preserve individual uncertainty scopes, resource context,
permission proof and generation binding without treating a permission or admission as a completed path.
Verification is synthetic/offline, with mutation checks and explicit rebuilds; requester discovery,
live access, optimization, commit and push are not authorized. P-142 enterprise CA classification,
P-143 declared assets and Self-Membership requester discovery remain later Stage 7 work; outstanding
Stage 6 acceptance is not a blanket prerequisite.

**No backward compatibility is required.** The owner explicitly clarified this when approving the
checkpoint: new formats need neither migration nor legacy-reading support. Existing evidence,
historical tests, failed validation artifacts and pre-existing uncommitted work must still be preserved.

## Stage 7 second checkpoint: first bounded path calculation

**Owner-approved scope; implemented and offline verified as P-229.** Calculate and save qualified existing membership routes
and terminal DACL-control routes to the shared classifier's fixed Tier-0 targets, without screen changes.
This is not yet an engine for arbitrary chains through account takeovers.

- Fixed targets have distance zero; effective members and assessment candidates are not extra destinations.
- Follow qualified captured security-group membership links, including nested and primary-group links
  where their evidence supports them; retain and count the actual links rather than collapsing a chain.
- An established `WRITE_DAC` or fully established current-owner DACL-rewrite proof may terminate at a
  fixed target only for its supported operation and resource. It does not establish the ability to act
  as the target account. Group membership alone does not establish a member's authority to exercise
  a group-held permission; without the required requester/resource proof, that join remains Unknown.
- General membership-write permission, password reset, key-credential writes, replication rights,
  `WRITE_OWNER`, unresolved owner transitions and Self-Membership candidates remain possible or
  unsupported steps, with their evidence and reasons retained rather than promoted to completed paths.
  Admission, expected administration and a Full Control summary are not independent takeover proof.

Reachable requires a fully supported route. Unknown retains relevant missing evidence or unsupported
steps; NotReachable requires excluding relevant possible routes too, never merely finding no definite
route in incomplete inputs. **The current bounded calculation returns Reachable or Unknown; it does
not emit NotReachable while unsupported alternatives remain.** Keep capture gaps, unsupported analysis, unresolved identities and unfinished
processing separate, preserve symbolic uncertainty scopes, and do not invalidate a proven route for an
unrelated gap. Work backward from fixed targets without an arbitrary path-depth cutoff; save one
deterministic shortest proven route, qualifying its length when uncertain alternatives could be shorter.

Bind saved results to the exact Evidence, Derivation and Judgement generations and analysis versions.
Readers remain passive; cancellation or failure must not replace the previous valid result. Preserve
permission supports and group-held counts independently of member and route counts. Verification is
synthetic/offline, with deliberate-defect checks for every new behavior, explicit rebuilds and retained
artifacts; this grants no customer-scale or outstanding Stage 6 acceptance.

P-142, P-143 and Self-Membership requester discovery remain planning work; requester discovery and new
member-expansion activation stay outside this slice. P-227 remains open. No backward compatibility,
tier counts, remediation, screen changes, optimization, live access, commit or push is included.

## Stage 7 third checkpoint: concrete requester DACL permission proof

**Owner-approved scope; implemented and offline verified as P-230.** After preparation against the
saved P-229 baseline, the owner selected “Approve the requester-proof slice”. Establish whether a
particular captured user can exercise an explicit `WRITE_DAC` permission on a fixed Tier-0 target,
rather than transferring a group-held permission to every member without a requester access check.

- Support direct user authorization or one explicit global-security-group membership, evaluating
  all relevant allows and denies in captured order. Requester, granting group and target must be in
  the same domain, and the target must belong to a verified domain naming context. Reuse the existing
  authoritative fixed-target classifier; this narrower new proof does not remove existing routes.
- Retain original permission entries, requester identity, membership support, resource context and
  exact Evidence/Derivation/Judgement generations. Preserve the actual membership and permission
  steps in the saved path explanation; requester proofs do not multiply group-held permission counts.
- This is an offline-verified calculation and passive-readback building block, not production
  requester coverage. Both hosts' scheduling and requester discovery remain unchanged; no manual
  administrator-maintained selection list, screen changes or production processing budget is approved.
- Existing ownership findings and independent owner proofs remain unchanged. No account takeover,
  new ownership-transition inference or hypothetical membership-change step is included.
- Missing evidence, unsupported authorization routes, unresolved identities and work not performed
  remain distinct. Relevant uncertainty must not become a definite route; unrelated gaps must not
  erase one. The bounded calculation continues to emit Reachable or Unknown, not NotReachable.

The examined follow-on route is an own-account addition to a same-domain global security group,
followed only by qualified existing memberships to a fixed Tier-0 target. It remains preparation
work: Self-Membership authorization alone does not establish Add readiness, and an omitted captured
member value does not prove non-membership. A separately justified operation rule is required before
promoting that candidate; this approval does not weaken the existing readiness safeguard or authorize
recapture. Verification of the approved requester slice must cover positive routes, applicable denies,
unsupported contexts, unchanged counts, source mismatches and cancelled publication, with deliberate
defects for every new behavior check and explicit rebuilds. No live access, optimization, commit or
push is authorized.

Judgement format 33 saves these explicit requester answers and their source-bound path steps, with
passive proof validation and unchanged production scheduling. All 5,058 offline tests pass normally,
all 156 focused cases pass under separate coverage, and all 50 new cases detect deliberate defects
with explicit rebuilds and verified restoration. The original evidence, historical validation and
deliberate-defect records are preserved; the final validation summary is
`next/artifacts/stage7-requester-dacl-validation/0bf5064e17794e3fa8a34630dd2cb31a/final-summary.json`.
This does not establish production requester coverage, customer-scale acceptance, live-operation
success or the deferred membership-change operation proof; P-227 remains open.

## Stage 7 fourth checkpoint: own-account membership obtainability

**Owner-approved scope; implemented and offline verified as P-231.** After preparation against `812286b`, the owner selected
“Approve the bounded checkpoint” for a separate saved assessment of whether a requester can obtain
membership, without changing genuine Self-Membership authorization or ordinary Add-readiness
answer. The owner subsequently selected “Implement approved checkpoint 4” to start implementation.

**Narrow correctness correction also approved:** the owner selected “Approve correction and continue”
after an offline regression exposed captured right-name metadata redefining Self-Membership as an
arbitrary GUID. Holder and requester interpretation, including the inactive discovery filter, must
use Microsoft's fixed Self-Membership identifier; retain the captured metadata as evidence rather than
rewriting it. Genuine permissions and ordinary Add readiness stay unchanged, and this does not
authorize changes to unrelated rights or activation of requester discovery.

- Support one captured ordinary user and one same-domain global security group, with qualified
  identities and domain context. Establish Self-Membership authorization directly or through one
  pre-existing explicit global-security-group membership, retaining relevant allows, denies and
  uncertainty in captured order; never use the proposed new membership to authorize its own creation.
- Assess addition of only the requester's own DN, not another account, replacement of the member
  list or removal. Validate applicable membership-operation prerequisites separately; missing required
  schema, identity or resource evidence remains Unknown, never defaulted to supported.
- Where membership is already proved, retain the existing route without inventing an Add. Where
  current membership is unknown, establish obtainability only if both possibilities are justified:
  already a member, or absent and a supported own-account Add is authorized. Keep current membership
  and ordinary Add readiness Unknown; an unresolved branch cannot become a proven path.
- Follow the resulting membership only through qualified existing memberships to the shared fixed
  Tier-0 targets, including a target group that is itself fixed. Do not transfer every group-held
  permission, infer account takeover or chain additional hypothetical changes; general member-write
  rights and unsupported requester routes remain outside this slice.
- A disabled account blocks the new operation proof without erasing permission evidence; an enabled
  flag does not prove authentication. Keep missing captured evidence, unsupported analysis, unresolved
  identities and work not performed distinct, preserve independently proven routes despite unrelated
  gaps, and emit no new NotReachable claim.
- Save original permissions, operation assumptions, membership witnesses and exact source generations
  for passive readback. Keep operation assessments separate from holder counts, distinguish the inferred operation from captured
  membership, qualify path length, and preserve the previous valid result on cancellation or failure.

Microsoft's [member validated-write rule](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1dea6a2c-a692-427f-8571-68a8a5c7b735)
and [modify constraints](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/76df255d-dc67-4c1f-adc6-1e5b60021304)
anchor the distinction between own-account permission and operation success. The two-case obtainability
inference is the approved product rule, not evidence that a missing member value proves absence or that
a live Add succeeded. Verification must be synthetic/offline, with deliberate-defect checks for each
new behavior and explicit rebuilds; original evidence, historical tests and validation artifacts remain
untouched. Requester discovery stays inactive, with no production budget, screen changes, live access,
optimization, commit or push authorized; P-227 and outstanding acceptance remain open.

Judgement format 34 and path-calculation version 3 implement this bounded checkpoint, including the
approved fixed-identifier correction, with unchanged production scheduling and passive readback.
All **5,128 offline tests pass**, all **523 focused cases pass under separately verified coverage**,
and all **70 new cases detect deliberate defects across 13 accepted variants**, with explicit rebuilds
and verified source restoration. Original evidence and validation artifacts remain preserved, including
the initially masked mutation check and the unsuccessful coverage-collector attempt; the final record is
`next/artifacts/stage7-own-account-validation/f881c28fc86e4e98b79301c0636b5e00/final-summary.json`.
This is not production requester coverage, customer-scale acceptance or proof of live-operation success;
further operation/path expansion requires a separately approved checkpoint.

## Stage 7 fifth checkpoint: own-account addition through ordinary Write Members

**Owner-approved scope; implemented and offline verified as P-233.** After reviewing the saved
`e48fca4` baseline, the owner selected “Approve bounded scope” for the next implementation checkpoint.
The owner subsequently selected “Implement approved checkpoint 5”, authorizing implementation without
activating production requester coverage or changing the other boundaries below.

**P-232 correction also approved:** after a raw-GENERIC_WRITE regression exposed the shared reader
expanding stored permission bits into authorization, the owner selected “Approve correction and continue”.
Preserve raw stored masks for permission interpretation, leave comparison/hashing normalization unchanged,
and verify affected consumers offline before accepting checkpoint 5; repair the separate malformed
callback fixture without weakening its expected uncertainty. Preserve failed runs and frozen evidence,
and stop again if a frozen expectation needs editing; no screen wording/layout or scheduling change is authorized.

- Support one captured ordinary user obtaining membership in one same-domain global security group
  through ordinary write access to `member`, followed only by qualified existing memberships to the
  authoritative fixed Tier-0 targets, including a target group that is itself fixed.
- Establish concrete requester authorization directly or through one proved, pre-existing explicit
  membership in a same-domain global security group. Evaluate applicable allows and denies together
  in captured order; do not transfer the holder's permission to every member without this check.
- Support member-specific and all-properties writes, plus class/property-set scopes where captured
  schema establishes that they cover `member`. Preserve original entries and scope evidence; neither
  a Full Control summary nor Self-Membership authorization substitutes for ordinary member-write proof.
- Assess adding only the requester's own distinguished name. This is the checkpoint's deliberate
  restriction, not a restriction inherent in ordinary Write Members; adding other accounts or groups
  remains later work, not a claim that those operations are impossible. Reuse P-231's identity,
  account-status, group, schema and verified-domain operation safeguards without relabeling its
  Self-Membership assessment.
- Retain a proved existing membership without inventing an Add. If current membership is unknown,
  establish obtainability only when both the already-present branch and the absent-with-supported-
  authorized-Add branch hold; current membership and ordinary Add readiness remain Unknown.
- Permit at most one hypothetical membership step. Never use the proposed membership to authorize
  its own creation, exercise another group-held permission, chain a further change or infer account
  takeover. Afterwards follow only qualified captured membership links, retaining the actual links
  and qualified shortest-proven length rather than inventing a new Tier-0 definition or depth limit.
- Keep missing captured evidence, unsupported analysis, unresolved identities and unrequested or
  unfinished work distinct. Unsupported authorization nesting, primary-group/SID-history routes,
  cross-domain/resource contexts and conditional or uninterpreted permission entries remain possible
  where relevant, not denied or safe; these limits do not remove previously supported membership paths.
- A disabled requester blocks the new operation proof without erasing permission evidence or proved
  existing membership; enabled status does not establish authentication. Failure of ordinary-write
  authorization does not invalidate an independently proved Self-Membership route, and unrelated gaps
  do not erase a proved route. Continue to emit Reachable or Unknown, not a new NotReachable claim.
- Save ordinary-write authorization separately from Self-Membership while reusing operation safeguards
  and membership continuation. Retain original permission references, membership witnesses, assumptions
  and exact Evidence/Derivation/Judgement generations; keep holder counts independent, readers passive
  and previous valid results intact on cancellation or failure. No backward compatibility is required,
  and historical evidence or generations must not be rewritten.

Verification must be synthetic/offline and cover permission separation, ordered denies, property scope,
unknown membership, self-authorization prevention, membership-only continuation, unchanged counts,
source mismatches and cancelled/failed publication. Every new behavior check must detect a deliberate
defect, with explicit rebuilds before mutations and after restoration; retain all original and new
validation artifacts. Requester discovery and host scheduling remain unchanged; no new production
budgets, live access, optimization, screen changes, commit or push are authorized. This is a calculation
and passive-readback building block, not production requester coverage or live-operation/customer-scale
acceptance; P-227 remains open.

Judgement format 35 and path-calculation version 4 implement this checkpoint, including P-232's
approved raw-mask correction without changing comparison normalization or historical layout hashes.
All **5,200 offline tests pass**, all **778 focused cases pass under verified coverage**, and all
**95 new or updated behavior cases detect deliberate defects across 11 accepted variants**, with
explicit rebuilds and verified restoration. Original artifacts, failed runs, the interrupted mutation
and the corrected masked proof check are retained with exact source/build provenance in
`next/artifacts/stage7-member-write-validation/ef9369e3a2db4e7285912e1fd3c71d75/final-summary.json`;
further operation/path expansion still requires a separately approved checkpoint.

## Stage 7 sixth checkpoint: obtained membership followed by requester DACL permission

**Owner-approved scope; implemented and offline verified as P-234.** After preparation
against `3fb945b`, the owner selected "Approve scope for next implementation session" for one supported
own-account membership-obtainability step followed by concrete requester `WRITE_DAC` authorization on
a same-domain fixed Tier-0 target. This approval records the supported-step and uncertainty boundaries;
the preparation session did not authorize implementation. The owner subsequently selected
"Implement approved checkpoint 6", explicitly authorizing implementation with the same boundaries.

- Support one captured ordinary user obtaining membership in one same-domain global security group
  through either the existing Self-Membership or ordinary Write Members proof, keeping those permissions
  separate. Reuse the identity, account-status, schema and verified-domain safeguards; authorize the
  membership using pre-change evidence only, directly or through the supported pre-existing explicit
  global-group membership, never using the proposed membership to authorize itself.
- Retain proved existing membership without inventing an Add or widening existing requester support.
  Where current membership is unknown, require both the already-present and absent-with-supported-
  authorized-Add branches; current membership and ordinary Add readiness remain Unknown.
- The terminal grant must name the obtained group and carry concrete `WRITE_DAC` applying to the
  authoritative classifier's fixed target in the same verified domain. No intervening nested-group
  permission route, second hypothetical membership, ownership transition, account takeover or onward
  operation is included; configuration/schema-partition authorization remains outside this slice.
- Evaluate the target's DACL for the user in a separate post-membership context, not as the group.
  The obtained group's SID participates in both allows and denies, without removing the user's other
  applicable identities or fabricating captured membership. Evaluate relevant entries in captured order,
  including denies for the user, obtained group, supported pre-existing groups and applicable broad
  identities; a later deny does not undo an already completed grant.
- Reassess trustee applicability after the membership change. Relevant unresolved nested-group,
  primary-group, SID-history, conditional or uninterpreted permission effects remain Unknown where
  they could change the answer, not excluded using the pre-change context. An earlier potentially
  applicable deny prevents a definite positive answer when its applicability cannot be settled.
- State the ordinary authenticated-context assumption with the obtained membership available for
  authorization. This is not a claim that existing sessions or tickets immediately acquire it, that
  authentication or replication convergence was proved, or that any live operation succeeded.
- Save a separate combined proof naming the requester, group, fixed target and membership-permission
  kind, original permission references, witnesses, assumptions and exact Evidence/Derivation/Judgement
  generations. Do not weaken captured-membership proofs, multiply holder counts by requesters or routes,
  activate discovery, or imply an administrator-maintained selection list.
- Keep missing evidence, unsupported analysis, unresolved identity/resource context and unrequested,
  cancelled or unfinished work distinct. Only a fully supported route contributes Reachable; otherwise
  preserve Unknown rather than NotReachable, without erasing independent proven routes or overstating
  shortest-proven length. Readers remain passive and failed/cancelled publication preserves the previous
  valid result; no backward compatibility is required and historical generations are not rewritten.

Microsoft's [ordered access-check rules](https://learn.microsoft.com/windows/win32/secauthz/how-dacls-control-access-to-an-object),
[SID applicability](https://learn.microsoft.com/windows/win32/secauthz/sid-attributes-in-an-access-token)
and [session/ticket membership behavior](https://learn.microsoft.com/troubleshoot/windows-client/group-policy/group-membership-changes-not-updating-over-some-vpn-connections#effects-on-the-user-security-context-and-access-control)
anchor these distinctions. Verification must be synthetic/offline, cover both membership mechanisms,
ordered and newly applicable denies, self-authorization prevention, uncertainty, unchanged counts,
source binding and publication safety, and mutation-test every new behavior with explicit rebuilds
before mutations and after restoration. Preserve original evidence, failed runs and validation records;
checkpoint 5's pre-commit provenance and saved document hashes remain historical, not updated for this
decision. No requester discovery, production host-scheduling changes, new budgets, screen changes,
optimization, live access, commit or push is authorized; P-227 remains open, and P-142/P-143 assets,
broader requester coverage, fuller paths, SEC-071 findings and product presentation remain later work.

Judgement format 36 and path-calculation version 5 implement this bounded checkpoint, including the
saved authorization-context assumption and passive proof validation, without changing production
requester scheduling. All **5,271 offline tests pass**, all **849 focused cases pass under verified
coverage**, and all **71 new behavior cases detect deliberate defects across 11 accepted variants**,
with explicit rebuilds and verified restoration. Original evidence, failed runs and mutation records
remain preserved with exact source/build provenance in
`next/artifacts/stage7-membership-dacl-validation/8c39670d898a4514b72c9d41437203fe/final-summary.json`.
This is not production requester coverage, customer-scale acceptance or proof of live-operation
success; further operation/path expansion requires separately approved scope.

## Stage 7 seventh checkpoint: offline requester selection for supported paths

**Owner-approved scope and implementation; implemented and focused-offline verified as P-240; full-suite verification remains open.** After preparation
against published `385e312` and review of the preserved P-227 failure, the owner selected
"Approve scope for next session" for permission-led selection of requester questions for the three
existing supported path families. This records the next bounded scope, not permission to implement
it during preparation, activate discovery in normal audits or claim Stage 7 complete.
The owner subsequently selected "Implement approved checkpoint 7", authorizing implementation
with the same boundaries; that authorization remains recorded when recovering an interrupted chat.

- Derive questions from captured permissions and the shared classifier's fixed Tier-0 targets,
  rather than every possible user/object pair or an administrator-maintained requester list.
  Cover existing requester `WRITE_DAC`, own-account membership followed by qualified existing
  memberships, and P-234's obtained-membership-to-requester-`WRITE_DAC` composition.
- Include relevant non-Tier-0 intermediate groups; do not require the group where a route begins
  to be Tier 0. Keep the existing ordinary-user, same-domain and direct/single-global-group requester
  authorization boundaries, including the existing qualified membership continuations; this adds
  selection, not new nested-group authorization, permission semantics or hypothetical operations.
- Selection identifies questions, not proven permissions or paths. Reuse the existing permission,
  operation and combined-proof evaluators, including pre-change authorization, post-membership
  ordered denies and both Self-Membership and ordinary Write Members mechanisms without merging them.
  Preserve Unknown current membership and ordinary Add readiness, independent holder counts,
  existing ownership findings and independently proven routes.
- Save the source reasons for selecting each question and the selection's coverage, bound to the
  exact Evidence, Derivation and Judgement generations and analysis versions. Keep missing captured
  evidence, unsupported analysis, unresolved identities/resource context and unrequested, cancelled
  or unfinished work distinct; broad identities remain explicitly unexpanded rather than absent.
  Neither an empty selection nor a completed supported scan establishes forest-wide requester
  coverage or NotReachable, and relevant uncertainty must not be discarded because no concrete
  requester could be identified.
- Exercise the selector only through synthetic/offline verification in this checkpoint. Both
  production hosts retain inactive requester discovery and unchanged scheduling, without a new
  budget, processing limit or customer-scale acceptance claim. This bounded selector does not
  settle the full production discovery scope or limitation presentation deferred under P-189b.
- Readers remain passive: verify saved questions, source provenance and proofs without discovering
  new requesters on reopening. Failed or cancelled publication must preserve the previous valid
  generation; historical evidence, validation summaries and their pre-commit provenance remain
  unchanged, with no migration or legacy-reading requirement.

Verification must cover all three route families, relevant groups outside Tier 0, applicable denies,
uncertainty, duplicate inputs, independent permission counts, source binding, passive reopening and
cancellation. Every new behavior check must detect a deliberate defect, with explicit rebuilds before
running mutated code and after restoration; retain failed runs and original artifacts. P-227 stays
open with cause unconfirmed: the preserved CI overlap failure is not replaced by local verification,
and neither its assertion nor its watchdog is weakened.

This checkpoint produces no screen changes or SEC-071 findings and does not activate requester
discovery, change budgets, add account-takeover claims, authorize live access or measurement/optimization
work, commit or push. Production requester coverage, further justified path compositions, P-142/P-143
asset coverage, canonical SEC-071 findings and path presentation/counts remain Stage 7 work, ahead of
P-235–P-239 and the broader rule rollout; implementation authorization covers only this bounded checkpoint.

Judgement format 37 and path-calculation version 6 implement this checkpoint with unchanged production
scheduling. All **908 focused cases pass under verified coverage**, including **59 new behavior cases**
that detect deliberate defects across **12 variants**, with explicit rebuilds and verified restoration.
The corrected full offline run passed **5,326 of 5,330 tests**: four unchanged layout checks timed out
under P-241, despite all 46 layout cases passing separately, so no clean full-suite or display-acceptance
claim is made. P-227 remains open independently of its local passing result, and this is not completed
Stage 7 or production requester coverage. Original evidence, failed runs and exact source/build
provenance are preserved in
`next/artifacts/stage7-requester-selection-validation/ffedb6f851754854a0f224d53cfdbfb7/final-summary.json`.

**Subsequent publication verification:** CI run 35157219659 for `9bb8423` completed successfully
with 5,330 tests. This later result does not explain or close P-241's local full-run timeouts or
P-227's earlier CI overlap failure; P-240's qualified full-suite verification remains open.
The handoff above remains a pre-publication record: its commit, publication flags, source hashes
and failed-run history must not be rewritten to describe the later push.

## Stage 7 eighth checkpoint: directory-registered enterprise CA targets

**Owner-approved scope and implementation; implemented and offline verified as P-142.** After preparation
against published `9bb8423`, the owner selected "Approve scope for next session" for the bounded
P-142 scope below. This records the scope, not authorization to implement during preparation;
the subsequent separate request "begin implementation" authorizes implementation with these same
boundaries, without authorizing live access, requester activation, budgets, screens, commit or push.

- Retain `dNSHostName` in future captures, including enterprise CA registrations and computer
  accounts, and retain CA registrations and host values in the source-bound derived inputs.
  The capture catalogue before version 8 omitted this field; reading the configuration partition does not
  capture every attribute. Do not rewrite or recapture historical evidence to supply missing values.
- Recognize `pKIEnrollmentService` registrations in the verified Enrollment Services container of
  the captured configuration partition. Add the registration and its uniquely matched captured
  computer account to the existing authoritative Tier-0 definition, not a separate CA target list.
  Retain the registration, recorded host value, matched identity and exact source generations as
  classification evidence; absent, conflicting or ambiguous host evidence remains unresolved.
  Do not use live DNS, server-name conventions or service-principal-name guesses as substitutes.
- Carry those targets through existing assessment admission and saved path inputs, retaining
  current permission checks, supported operations, independent holder counts and resource scope.
  Asset classification does not make controlling principals expected, suppress edges or change
  severity. A directory-registered CA is not proof of a running service; control of its registration
  is not automatically control of its host, certificate issuance or account takeover.
- Do not newly classify certificate templates or `NTAuthCertificates` in this checkpoint. AD FS
  remains declaration-only under `0099`; P-143 declarations are not included. These exclusions
  do not label unassessed assets safe or remove existing independently supported conclusions.
- Requester discovery remains inactive, with unchanged GUI/CLI scheduling and budgets. No new
  path composition, SEC-071 finding, screen wording/layout or summary count is included; those and
  production requester coverage remain Stage 7 work before P-235–P-239 and the broader rule rollout.
  There is no live access, recapture, optimization/measurement-harness work, commit or push approval.

Verification is synthetic/offline: capture-to-readback retention, correct container and class,
missing or duplicate host identities, shared-target integration, unchanged permission behavior and
counts, exact generation binding, passive reopening and cancellation. Every new behavior check must
detect a deliberate defect, with explicit rebuilds before mutated runs and after restoration;
focused coverage and full-suite results retain failures without weakening watchdogs or assertions.
P-227, P-240's qualified full-suite verification and P-241 remain open despite the later successful
published CI run; no customer-scale or outstanding display acceptance follows from this scope.

Capture catalogue 8, derivation format 15, judgement format 38 and Tier-0 policy/contract 2 implement
this checkpoint; path-calculation version 6 and requester-selection version 1 are unchanged.
All **5,390 offline tests pass**, and all **1,294 focused coverage cases pass**, with execution hits
for all **27 new test methods**. The **59 new cases**, three updated rejection checks and two
presentation-accounting checks have assertion-based negative controls across **10 rebuilt defect
variants**, with explicit rebuilds and verified restoration. The non-display catalogue records the
host field's analysis purpose without changing runtime sections, labels or layout.
Original evidence, historical checkpoints and failed runs remain preserved; the qualified handoff is
`next/artifacts/stage7-enterprise-ca-validation/37e2af93ddd741329736ca392d070b7f/final-summary.json`.
This is not completed Stage 7, production requester coverage, customer-scale or display acceptance,
and does not close P-227, P-240's qualified verification or P-241.

**Subsequent publication verification:** CI run 35174500509 for published `00a5e8f` passed
5,389 of 5,390 tests and failed P-227's capture-overlap assertion at line 72; the matching assertion
does not establish the same cause as earlier failures. The local 5,390-test pass remains a separate
result, and the handoff above keeps its original pre-publication provenance. CI metadata and
failed-step logs are retained under
`next/artifacts/stage7-enterprise-ca-validation/37e2af93ddd741329736ca392d070b7f/ci-35174500509/`.

## CLI and GUI judging parity

**Owner-approved requirement:** the same sealed evidence and analysis inputs must receive the same
judging behavior through the CLI and GUI. Both hosts must use Tier-0 discovery to select detailed
control assessment, while ordinary rules continue to examine every captured object; a host must not
silently select a different assessment scope. Host-specific presentation does not authorize different
security conclusions, and historical all-object test entry points are not the production CLI policy.

Stage 6's implemented, offline-verified slices are not acceptance of every capability or completion of
its outstanding controlled-evidence, customer-scale and display checks. This alignment does not enable
Self-Membership requester discovery: that separate scan remains inactive in both hosts, with its scope,
limitations and enablement deferred to Stage 7 rather than treated as working Tier-0 requester analysis.

## LAPS attribute-read findings: encrypted values

**Owner-approved wording and scope for P-162.** SEC-090 distinguishes permission to read a
password attribute from permission to decrypt its value, and neither is a claim that a password
was retrieved or a machine taken over. High severity, detection, finding identities, membership
paths and scope remain unchanged; no layout change, decryption assessment or rewrite of saved
findings is authorized, and corrected finding text is produced when judging runs again.

- Title: “A broad principal can read LAPS password attributes”.
- Encrypted-attribute explanation: “This attribute stores an encrypted LAPS password. Read
  permission allows retrieval of the encrypted value, if present; it does not by itself grant
  permission to decrypt it. This finding does not establish that this principal can obtain the
  local administrator password or take control of the machine.”
- Clear-text-attribute explanation: “This attribute stores a LAPS password in clear text. If a
  password value is present, reading it exposes the local administrator password and may enable
  local administrative access.”
- Opening of **Why it matters**: “A broad principal has read access to a LAPS password attribute.
  A clear-text value can expose the local administrator password; an encrypted value requires
  separate decryption permission. Read access alone is not proof of password retrieval or control
  of the machine.” The existing subsequent group-nesting explanation remains.
- In **About**, replace “it names can genuinely read the password” with “it names has permission
  to read the attribute. For encrypted values, decryption permission is separate and is not
  established by this rule.”
- In the finding's scope explanation and **What to do**, replace “rather than only the password”
  with “rather than only this LAPS attribute”.

## Enatel SSO object capture scope

**Owner-approved default and presentation, tracked as P-224.** New captures exclude
`enatelSSOAccountParameter`, `enatelUserManagedAuth` and `enatelSSOStorageV3` by default.
On the wizard's review page, an **Object classes** section below the domain list offers
**Include Enatel SSO metadata objects**, unchecked for each new audit and not saved as a setting.
Its help says: “Excluded by default to reduce capture volume. Excluded objects and their permissions
are not assessed.” The command line has the same default and an `--include-enatel-sso` option.
DNS exclusions remain unchanged, all other classes remain in scope, and inclusion does not add
credential attributes to the capture catalogue.

This is an explicit scope trade-off, not a claim that these objects are harmless or unused by all
rules: generic ownership and permission rules can examine them. Exclusions belong in LDAP requests,
not just the display; each saved run must record its actual class scope and disclose it on readback,
and differing choices must not appear as ordinary additions or deletions in a comparison.
Replace the review's “Nothing is being left out of this audit” with “No domains are being left out”
and show class exclusions separately. Existing captures must not be rewritten or relabelled using
the new default; the historical two-thirds observation is not a measured speedup for this change.
The existing no-compatibility decision (`0001`) still applies: an older evidence format is refused,
not migrated, and original files are preserved.

## Capture preflight: domains with no controller

**Owner-approved wording for P-213.** In the existing error area, report:
“No writable controller was found for: {domain names}. Each domain needs an exclusion attestation
before capture can start.” No layout change was approved; saved preflight output must retain those
declared domains separately from any valid exclusion attestations, without claiming they answered.

## Capture connection failures after authentication

**Owner-approved correction and wording for P-214.** Once authentication succeeds, a failed
RootDSE read is an operation failure, not a refusal of connection protection; do not try weaker
protection, and do not return a usable capture connection without the required capabilities.
Use the existing error displays without layout changes: “Connected to {controller} using
{protection level}, but could not read its directory capabilities (RootDSE). This connection cannot
be used for capture. {error details}” The details retain the returned diagnostic message and,
when available, the LDAP result name and number, such as “LDAP result: Busy (51)”.
Classify actual response codes rather than treating every directory error as a security refusal;
existing retry/failover policies and the explicit allowance for unprotected connections are unchanged.

## Capture stops after a domain exhausts recovery

**Owner-approved correction and log wording for P-215.** Existing retries and next-controller
attempts run before a domain failure ends capture. The first terminal domain failure that triggers
shutdown remains the recorded cause; cancel active domain reads, prevent queued reads from starting,
and await connection and writer cleanup rather than abandoning work or sealing incomplete evidence.
An internally stopped domain must not turn the failed run into an operator cancellation; its log
says “partition stopped because another domain failed”. No layout change or new timeout is approved;
cancellation remains cooperative, and the LDAP abort race and pre-seal cancellation remain separate.

## Capture cancellation at publication

**Owner-approved correction and saved wording for P-216.** Honor cancellation during sealing
preparation, including cancellation from the “sealing the bundle” log callback, before one final
publication boundary. If cancellation wins, save: “The run was stopped while sealing the bundle;
no bundle was published.” If publication wins, later cancellation must not relabel completed
evidence as cancelled. No abandoned work may continue modifying or publishing evidence after a
cancelled return, and genuine sealing failures and safe cleanup must be preserved; no layout or
other wording change is approved.
The evidence-publication correction is implemented; the remaining CLI/screen cancelled-versus-ended
status correction is explicitly deferred under the priority decision above.

## SYSVOL acquisition must not hold a run indefinitely

**Owner-approved requirements, 2026-09-13.** A production capture reached “reading the policy
share” and showed no visible disk changes for roughly 1–2 hours before manual abortion; the
blocked operation has not been identified. SYSVOL acquisition must log and flush the start and
outcome of individual operations, naming the GPO, UNC path, operation, elapsed time and actual
progress counts. A cancellation token or a timed-out wait around synchronous SMB work is not
containment: abandoned work must not retain access to evidence persistence, supply late accepted
results, or accumulate without bound.

The owner selected **30 seconds without progress on an individual SMB operation** as a provisional
limit, not a production-measured default. On timeout, retain trustworthy completed evidence,
explicitly mark the affected policy incomplete (or unreadable if nothing usable was acquired),
abandon its remaining operations and **move to the next GPO**. An incomplete enumeration must not
mean an empty or complete listing, and database-integrity failures must still prevent sealing.
Implementation and offline verification are tracked as `P-221`; this does not authorize live access
or claim that the original production stall's cause is established.

## How judging works

**Release-run feedback changes the immediate priority.** The owner's lab investigation of
`ad.lab-20260908-062400` reported judging completing in 222 seconds for 8,407 objects, with a 654 MB
judgement store and 27 findings. The apparent hang was slow, silent judging after Evidence sealed,
not proof of a stuck worker. These are lab-reported observations, not a measurement rerun on this
development machine; comparisons with the older 13-second run include substantial changes in stored
control evidence and require profiling before assigning cost to individual additions or rules.

The owner authorized visible progress through all available audit phases and approved a pinned phase
panel, real counters, elapsed/last-update ages and separate outcomes. The
New Audit progress correction
records the implementation and limits. Performance/storage profiling and logging hardening remain
separate work. Profiling can use sealed copies and representative synthetic data without contacting
a directory; production-shaped synthetic results alone do not establish customer acceptance. Preserve
original lab runs and historical artifacts. The reported clean-clone `ProsePathCitationTests` failure
on local ignored coverage references remains a separate documentation-portability issue; a local pass
where those artifacts exist does not resolve it. No publication or live work is authorized here.
The progress correction built successfully and passed 4,372 offline tests (four stage-status tests
excluded) plus 179 targeted coverage tests. Its detailed verification record is in the linked New Audit
page. It adds no production budget and makes no improvement claim for the reported judging runtime.

Decided, built and measured — see layers/judgement/.

- **One pass over the bundle, not one per rule.** Every object is streamed once and offered to every
  scheduled rule while it is in hand, so judging forty rules costs the same read as judging one.
- **A rule judges one object and nothing else.** No forest, no sibling lookup, no second pass, so a
  rule cannot quietly acquire an input it never declared.
- **A rule declares the data it reads, or the build fails** (`0083`).
- **Atomic per rule, not per run.** A rule that throws loses only itself; its partial findings are
  discarded, because a partial verdict would read as a complete one.
- **Findings live outside the seal** (`0085`), in a store that is disposable and rebuildable.

**What "inside a group" means, and it is an authorization question rather than a directory one.**
Owner's decisions, 2026-09-11. A distribution group nested inside a security group *is* a member of
it and is reported as one, but nothing beneath it is: Microsoft is explicit that an account nested
through a distribution group does not receive the enclosing group's SID in its access token, so
following that hop would name principals who hold nothing. A group whose `groupType` the capture
never read is **not** treated as a distribution group — the route is followed, because refusing it
would hide access that exists, and the answer is marked as one the product cannot vouch for, so a
rule refuses rather than reporting the object clean. A group asked about by a SID it carried before
a migration expands to its real members, because `sIDHistory` is a second identity the principal
answers to rather than a group it belongs to. See `P-165` and `P-166`.

**When a domain was excluded or unread, only principals from that domain lose their protection
answer.** Owner's decision, 2026-09-11, for `P-163`. Making the whole forest's answers unknown
because one domain was deliberately left out would stop ownership findings being reported anywhere,
and judging discards the findings of an object with unresolved inputs. Membership reaching *into* an
unread domain is already covered, because a member nobody captured does not resolve and is recorded
as an unresolved trustee, which qualifies the answer on its own.

**The acknowledged rule-input gap:** rules that depend on cross-object facts need persisted,
Evidence-bound Derivation products and typed missing/degraded input handling. The accepted correction
order is recorded in [`docs/next/WORKFLOW.md`](next/WORKFLOW.md); it is no longer treated as an unbounded
architectural question.

**Stage 6 has started, not finished.** Judging stores WRITE_DAC/WRITE_OWNER, bounded
group-membership control, password-reset permission, key-credential write permission, bounded replication permissions and bounded existing-owner control, with full-control permission summaries and object-first and named-holder-first
views in the object screen.
**Bounded effective-member attribution is implemented and synthetically verified.** The owner accepted
the proposal, exact wording and 0102 timing clarification, then requested implementation. Derivation
schema 11 stores source-linked membership inputs; judgement schema 24/control engine 8 stores budgeted
members, unresolved links and representative independent routes, with resource applicability beneath
existing group-held permissions without multiplying their counts. Member
attribution is not a concrete requester assessment. Full-control supports, independent existing-owner
control and Unknown/uncounted owner transitions retain their current behavior. Both production hosts
remain without an approved expansion budget; discovery, live access and retrying the
cancelled stage-status check are not authorized. The owner subsequently authorized documentation
closeout, commit and push of this completed slice; that is not standing publication authorization.
Synthetic verification and customer-shaped measurement
must be reported separately from production-budget approval and final Stage 6 acceptance.
Final offline verification passed 4,355/4,355 tests with the four stage-status tests explicitly excluded;
targeted coverage passed 799/799, and the solution build succeeded. The
implementation record
records the final artifacts and outstanding acceptance boundaries. No production expansion budget is approved.
General membership writes and own-account-only Self-Membership candidates are separate; concrete
requester answers are not implied by those candidates. Historical schema-16 Self-Membership
candidates remain Unknown, and no general member capabilities are expanded.
The owner-to-DACL transition remains unknown and uncounted. Current judgement schema 27 stores this
product, the bounded Self-Membership requester assessments introduced in schema 17, and discovery
coverage introduced in schema 18; schema 19/control engine 3 introduced reset permission, and
schema 20/control engine 4 added key-credential write permission and the property-set evidence safeguard;
schema 21/control engine 5 added the two replication capabilities on captured naming-context roots;
schema 22/control engine 6 added existing-owner assessments and replay-validated ownership proof;
schema 23/control engine 7 adds bounded full-control summaries with separate source proof and counting links;
schema 24/control engine 8 adds explicitly budgeted member attribution, requiring current Derivation inputs;
principal catalogue version 2 includes the verified BUILTIN domain-scope correction, P-150.
Schema 25 implements the approved shared permission-proof storage,
with unchanged control engine, catalogue and input formats. Complete lab public-model comparison passes,
and the database is 20.8% smaller including indexes and references. Exhaustive export allocation
increased; no runtime or memory improvement is claimed. Production-shaped validation remains outstanding,
and this work authorizes no production expansion budget or publication.

**Scoped ownership during audits is implemented; explicit object requests remain pending.**
The owner approved **core Tier 0 plus its identified controllers and dependencies** as the default
scope for detailed ownership-takeover assessment during an audit. Other objects remain unassessed
until the pending explicit single-object workflow is implemented; that workflow will use the existing
captured evidence rather than contact the directory.
The scope must be determined automatically; this slice adds no user-maintained importance or target
list. Importance follows control relationships toward Tier 0, not everything an administrator owns
or manages. Expected administrative authority remains separate from target importance.

**One Tier-0 definition:** the owner explicitly requires reuse of the existing authoritative
[Tier-0 policy](decisions/0006-tier-0-and-expected-admin-are-separate-sets.md) and its shared
classification implementation. Ownership assessment must not introduce another Tier-0 list or
copy the definition into its own selector. Any gap in evidence-backed classification must be
resolved centrally against that policy. Additional controller/dependency inclusion is an assessment
scope reason, not a second Tier-0 definition or a change to expected-admin policy.

**Shared across the application, not owned by ownership assessment:** the owner agreed that target
importance must come from one shared, evidence-backed Tier-0 model, reusable by ownership assessment,
later path analysis and other features asking the same question. Reuse the broader design's
distinctions between core targets, effective security-group membership, qualifying established direct
control and longer or conditional reachability. Ownership consumes those shared facts and decides
which targets receive detailed assessment; it does not create a parallel definition of importance.
Being included because of a possible route or dependency does not establish that an object is Tier 0.
These answers remain separate from protection, accepted ownership, expected administration and rule
severity; they must not collapse into a universal privileged-or-important flag.

The broader judgement design
already describes these distinctions, but is not a completed shared classifier. Its outdated seed
exclusions must not override the authoritative Tier-0 policy. Existing membership and control evidence
are reusable inputs, not proof that the combined classification is implemented. This agreement settles
the shared direction, not approval of the earlier identifier-only implementation proposal, unresolved
classification semantics or UI changes; revise the bounded implementation proposal against this model
before editing runtime behavior. It does not require building the complete path engine first.

The [revised shared-contract proposal](next/SPEC-stage-6-control-edges.md#15-proposed-shared-tier-0-and-ownership-contracts)
defines classification and relevance separately, their evidence/version bindings, ownership assessment
states and target-specific immutable publication. Its first implementation slice is central policy
reconciliation, shared contracts, supported evidence adapters and offline tests; audit selection,
persisted-format changes, object execution and UI integration were later work at that checkpoint. The owner explicitly
approved that bounded implementation slice, including the 0006/0099 reconciliation, under
[0112](decisions/0112-shared-tier-0-classification-and-ownership-contracts.md). This is implementation
approval for the shared foundation, not approval to activate scoped audits or change the UI.

**The bounded shared foundation is implemented.** Catalogue 3 corrects the canonical Tier-0 identifier
predicate without changing expectedness or owner acceptance. The shared adapter qualifies captured
core identities and supplied same-domain membership witnesses, retaining independent evidence and
explicitly incomplete coverage. It does not yet classify all assets, expand membership or qualify
operational direct control/dependencies. Shared directed relations and ownership result/binding
contracts are built and now consumed by the schema-26 audit integration below. The
implementation record
records that foundation checkpoint; its catalogue-2 compatibility does not override the current schema-version policy.

**The offline selector is implemented as a library** under
[0113](decisions/0113-automatic-ownership-scope-follows-shared-relations.md). It consumes the shared
classifications and follows incoming captured controller relationships, retaining conditional links,
alternative reasons and explicit incomplete results on cancellation. It blocks ambiguous identities,
handles cycles without repeating target visits, and keeps selector version 1 separate from the
classification version. The selector implementation record
states the supported inputs and validation. The selector-only slice added no membership expansion or
production limit; the subsequent integration now uses it during judging.

**Audit integration and status-only presentation are implemented** under
[0114](decisions/0114-scoped-ownership-assessment-during-judging.md): retain basic permissions and the
single rule pass, select ownership scope, assess selected targets, persist coverage and then publish.
The approved change uses schema 26/control engine 9 and requires re-judging older schema generations
for current readback without rewriting those older files. The owner approved explicit assessed,
not-assessed and unavailable-input status wording plus the two scope/assessment progress labels.
No on-demand action button, live work, production expansion budget or performance claim is included.
The schema-26 implementation record
describes proof-preserving staging, readback validation and the remaining acceptance limits. Shared
classification remains partial: incomplete scope is visible, never a declaration that unassessed
objects are safe. Subsequent single-run local diagnosis and read-only storage assessment are recorded
in the proposed bounded proof-storage redesign and validation plan.
They establish diagnostic costs, not a controlled speedup, guaranteed storage saving or production
acceptance. The owner requested this plan before further code changes. Its recommended first slice
shares exact repeated descriptions and complete membership explanations without narrowing basic
auditing or changing its answers. The owner then explicitly approved S1 and exactly one before/one
after lab judging execution under [0115](decisions/0115-share-judgement-explanations-and-membership-proof.md).
S1 is implemented locally as schema 27 and both approved passes are complete. The paired comparison
preserved the checked proof/products and reduced the new database by 10.51%, but measured elapsed time
rose 9.22% and cumulative allocation rose 20.47%. **Performance acceptance is on hold; this is not a
speed improvement or production acceptance.** The candidate and both runs are retained for review,
with no additional timed judging run authorized. Transaction batching,
validation-lifetime changes, graph-memory work and production-scale measurements remain separate work.

This changes the expensive hypothetical owner-transition work, not the existing current-owner
findings or the underlying WRITE_OWNER, WRITE_DAC and full-control evidence. Unassessed objects must
say that they were not assessed automatically, never appear safe. Unknown relevance, unsupported
dependencies and incomplete traversal must retain explicit coverage limitations. This is not approval
to build or claim a complete Tier-0 path engine as a prerequisite to the bounded ownership change.
The audit and object request must share one evaluator, retain alternative relationships and unresolved
prerequisites, and persist generation-bound results rather than recomputing silently when a page opens.
An object request is offline analysis, not a fresh directory observation, and must not rewrite sealed
Evidence or an already-published Judgement generation.

The ownership assignment/server-behavior verification gate remains open: requesting analysis cannot
turn missing evidence into a proven takeover. New audits use scoped assessment. Explicit single-object
execution and its separate target-specific publication remain unimplemented. The status-only UI
changes are approved and implemented; an on-demand action and any further wording/layout changes
retain their separate approval boundary.
No live access, recapture, production expansion budget, commit or push is authorized.

**Owner-confirmed direction: Tier-0-driven detailed assessment.**
The owner clarified that captured owners and permissions already exist in Evidence; asking to
"preserve capture" must not be presented as new work or a reason to build another complete permission
copy. An unrelated ordinary account such as `jimmy.strand` needs those captured facts and applicable
ordinary rule checks, not automatic detailed control/full-control or hypothetical ownership assessment.
Those detailed questions become relevant when discovery working backward from Tier-0 assets reaches
the account, or through an explicit investigation. Ownership is one possible control mechanism along
a route, not a separate justification for deeply assessing the whole forest.

Build the minimal shared path-discovery mechanism and use it to drive assessment admission in the
same slice. Use the existing authoritative Tier-0 definition, captured owner/ACL facts and source-bound
membership inputs; do not require an already-expanded forest-wide control store to discover scope.
Possible/conditional relationships can justify inspection before takeover is proven, avoiding a
circular dependency. Retain uncertainty and independent reasons, and do not label unreached objects
safe when coverage is incomplete. Full path visualization, ranking, remediation and all-path enumeration
are not prerequisites. Ordinary audit findings remain separate from scoped detailed-control products.

The owner requested that this be recorded with an implementation plan for a new session. The
[Tier-0-driven assessment plan](next/PLAN-tier-0-driven-assessment.md) records the pipeline replacement,
contract/read-count consequences, ordinary-versus-reached account acceptance cases, approval gates and
preservation/measurement limits. This is a broader behavior change than 0114's ownership-only gating
or 0115's storage sharing. Exact new contracts and UI wording/layout must follow the repository's
approval process; no further timed runs or new harnesses are authorized.

The concrete contract is accepted as
[0116](decisions/0116-discovery-first-assessment-admission.md). It settles four points the plan left
open: broad principals are recorded as one explicit unresolved candidate rather than expanded into
individual accounts; Judgement schema 28 is required because control-edge counts change meaning from
forest-wide to assessed-scope while their shape does not; the added scope wording is approved in
substance with its exact rendering confirmed before the Shell edit; and discovery retains the
controller/target route it already computes instead of discarding it after admission.

**As of 2026-09-10 this is built and the shell uses it.** `JudgingRun.JudgeWithTier0Discovery` runs
the gated pipeline and is what the audit screen calls; `JudgingRun.Judge` is retained for callers
needing the unscoped contract. The control-edges panel states that its counts cover the objects
discovery reached rather than the whole forest, and says so only for a judgement that was actually
scoped - schema 29 records which kind a stored product is, because the two are otherwise
indistinguishable and a reader would take the first for the second.

### Tier-0 discovery has no work ceiling — decided 2026-09-12

**The owner's decision:** *"why does it stop at a budget is my question. it shouldnt have one, if we
are building an app that is suppose to determine something and we have to stop arbitrarily then we
built it wrong."* Tier-0 discovery now runs until it has read what was captured. **Cancellation is
the only stop**, and it is an honest one: a scan the operator stopped is a fact about the run, where
a constant in the source is not.

`Tier0DiscoveryBudget` and its three `*BudgetExceeded` reasons are deleted rather than defaulted to a
large number. The ceiling that existed was the laboratory bound - 1,000,000 objects against a
recorded production shape of roughly 347,000, so it never bound anything in either forest. With no
ceiling, and cancellation throwing rather than returning, a scan can no longer finish incomplete:
the `ProcessingStopped` verdict and the corresponding `ProcessingIncomplete` mapping go with it,
under the standing rule that a reason the scanner cannot emit tells a reader the product looks for
something it never looks for.

**What replaces it on screen, approved verbatim:** `Finding what can control Tier 0 — 214,000
objects, 3 min 41 sec`. **No progress bar and no time remaining.** An unbounded scan has no endpoint
to forecast from, and a wrong estimate on a screen an auditor trusts is worse than no estimate. The
cost is accepted: at minute seven the operator knows it has taken seven minutes, not how many remain.

### Permissions mirrors the directory; Findings carries the judgement — decided 2026-09-12

**The owner's rule, stated at the screen and governing more than the case that prompted it:**
*"permissions on this screen should 100% mirror what is in AD. Findings is where we identify issues
and risk."*

**This is a separation of two jobs that are easy to blur.** The Permissions and Control-edges views
answer *what does the directory actually say*, and they answer it completely, including the parts
Microsoft shipped and nobody chose. Nothing is suppressed there for being common, routine or
uninteresting, because an operator checking what a principal can do needs the directory's own answer
rather than this product's opinion of which parts are worth mentioning. **A permission hidden because
it is ordinary is a permission the operator will not find when it stops being ordinary.**

Risk, ranking, thresholds and advice belong to Findings, where a rule says why something matters and
what to do about it. That is the place to argue an empty Account Operators is less urgent than a
populated one. Doing the same thing by hiding rows on the Permissions screen would make the two
views disagree about the same directory, which is the defect this product keeps finding in others.

### A true permission is reported, even when Microsoft shipped it — decided 2026-09-12

**The owner's decision, made at the screen.** Opening `CN=Cert Publishers,CN=Users,DC=ad,DC=lab`
showed BUILTIN\Account Operators holding **Full control**, and his answer was: *"now that i know this
is a permission then i have no issue with it showing up here, its the truth so it should show up."*

**This settles the acceptance question P-145 exists to ask.** Account Operators accounts for 15 of
the 29 unexpected control rows in the laboratory forest — just over half — and holds them in every
forest Microsoft has ever shipped, because they are the default ACL rather than anything an
administrator did. The question was whether a stock default dominating the screen means the
classification or presentation model is wrong. It does not: **the permission is real, the group can
genuinely rewrite that object, and a tool that hid it because it is common would be hiding a true
fact about the customer's directory.**

**What this does not license.** It is not a ruling that volume never matters, and it is not
permission to let a real finding become unfindable. The same laboratory run put a genuinely
forest-specific result — a `ph.ad.lab` principal, and `ph.ad.lab` Domain Admins, both holding
WRITE_DAC on the **`ba.ad.lab` domain root** — among those same rows. Cross-domain control of another
domain's root is the kind of thing an operator opens the product to find, and it must stay findable.
The owner accepted the current visibility on the basis that sorting and filtering handle it.

**The empty-group observation stands separately.** Account Operators is empty in all three
laboratory domains, with a *complete* membership summary rather than an unread one, so those fifteen
rows are a latent exposure rather than an active one. That distinction is worth surfacing and is
recorded in the punch list; it is not a reason to suppress anything, because anyone who can add a
member to that group inherits every one of those capabilities at once. **Empty, populated and
membership-unknown are three states, not two**, and nothing may collapse the third into the first.

### Self-membership requester discovery is deferred to Stage 7 — decided 2026-09-12

**Two separate scans were being discussed as one, and only one of them changed.** Tier-0 discovery
starts *at* Tier 0 and walks outward; self-membership discovery starts at *every* group in every
domain and asks who holds the "Add/Remove self as member" right on it. The second is **not** Tier-0
scoped - `JudgingRun` observes it for every streamed object, filtered only to groups - and it is
**inactive in both hosts**, because for that scan a null budget means the scan never starts.

Its budget therefore stays, along with `ProductionBudgetNotConfigured`, which is a true statement
about the product today. **Two questions are deferred rather than answered now:** whether the scan
should be forest-wide or scoped to Tier 0 plus identified controllers, and where its stated
limitations - nested groups not followed, Everyone/Authenticated Users not expanded, computer
accounts not treated as requesters - should surface. The owner's reasoning: both are the same
question as "path to Tier 0", and answering them before the path work exists would mean deciding
twice, the second time with better information.

The argument against Tier-0 scoping, recorded so it need not be rediscovered: **the first hop of an
escalation chain is never a Tier-0 group.** A self-membership right on an unremarkable group matters
because of what that group can reach, which is not knowable until chained-path analysis reads it.

Decision [0117](decisions/0117-naming-context-roots-are-tier-0-assets.md) was accepted alongside it.
A naming-context root holds no SID, so no controller route can reach it, and replication rights are
granted *on the root* — which on a domain root is every credential in the domain. Discovery-first as
originally written would have reported every partition root as not assessed automatically, in every
forest, permanently. Roots are now Tier-0 seeds on the strength of what they are. What a permission on
one *means* still differs by partition: the configuration and schema partitions hold no credential
material, and `ReplicationControlDeriver` already keeps that distinction.

**Assessment admission remains separate from paths.** `OwnershipScopeSelector` performs a backward
walk from Tier-0 seeds and produces an admission decision — `Included`, `OutsideComputedScope` or
`Undetermined` — not a route. Its retained relationships preserve that decision without becoming
completed control steps. The separate [bounded Stage 7 calculation](#stage-7-second-checkpoint-first-bounded-path-calculation)
now consumes qualified saved witnesses; it adds no path presentation, ranking, remediation or
all-path enumeration, and none of those become prerequisites to the admission work.

At the catalogue-2 checkpoint, re-judging alone obtained that correction. The current member-attribution
product requires current Derivation inputs: re-derive and re-judge an isolated copy, without re-capture.
The judgement-store document
records the implementation and before/after lab checks. P-145's expectedness and visibility acceptance
has since passed, as recorded above; separate capability-specific laboratory gates and member-attribution
scale measurements are not discharged by that acceptance. The
membership slice
has automated coverage, an isolated offline comparison and an
isolated live Self-Membership measurement.
The live direct/group-held tests and fresh readback passed. Those measurements did not include
concrete requester evaluation and do not accept the schema-17 implementation below. The new bounded
member-attribution product has separate synthetic verification; it does not widen requester semantics.
The comparison preserved all 65,084 existing primitives and added 10,776 established general
membership writes plus 10,761 unknown self-membership candidates. Re-judge schema-15 results to
obtain it; this does not accept the whole stage-6 proposal or replace the historical baseline.

**Password-reset control is an existing current-build requirement, not a new feature proposal.**
After the R8 checkpoint, the owner clarified: "we also have the stage 6 documentation which is for
this build", then said "begin" to the preparation described against that specification. Start from
`CanResetPassword` in the [Stage 6 catalogue](next/SPEC-stage-6-control-edges.md#5-the-edge-catalogue-for-stage-6),
the judgement-half requirements and accepted decisions. The predecessor banner on SEC-003 does not
make those current-build requirements historical. Identify the unimplemented capability, reusable
code and genuinely unresolved details; do not ask the owner to restate the requirement. This
preparation does not itself approve new UI wording/layout, a reset operation, discovery enablement,
further performance tuning or a commit/push. A stored password-reset capability and a security
finding about unexpected reset authority are separate deliverables.
The bounded implementation preparation
records the implementation path, versioning, verification cases and approved presentation.
The owner subsequently selected **"Approve the capability-first implementation and wording"**.
That approves this bounded stored-capability slice, the existing-table label "Password-reset
permission" and the permission-only/no-tested-sign-in caveat. It does not add a security finding,
member expansion, live directory operation, discovery budget or final Stage 6 acceptance.

**The approved password-reset capability was introduced in schema 19/control engine 3 and is retained
in current schema 22/control engine 6.** Normal
judging evaluates applicable captured reset rights and stores `CanResetPassword` as `CredentialExposure`,
independently of the inactive Self-Membership discovery budget. The existing table shows
"Password-reset permission" and keeps evaluation, expectedness and supporting evidence separate.
This is named-holder permission evidence, not a tested reset, complete requester-token evaluation,
sign-in prediction or SEC-003-style finding. Re-judge sealed evidence to obtain it; no re-capture,
Evidence/Derivation schema change or historical-result rewrite is needed. Validation and limits
are recorded in the linked implementation record; Stage 6 acceptance remains open.

**The key-credential write slice and wording are explicitly approved.** After reviewing the bounded
recommendation, the owner selected **"Approve the bounded implementation and wording"**.
`CanWriteKeyCredentialLink` is an existing current-build Stage 6 requirement, not a new feature
proposal. Schema 20/control engine 4 stores it as `CredentialExposure` and the existing table says
**"Key-credential write permission"**. It evaluates property writes, not the separate validated-write
route, and does not claim a tested write, sign-in, account takeover or completed path to Tier 0.
The implementation record
owns the exact boundary, reproduced defects and validation. No layout, capture/Derivation schema,
finding, discovery budget, performance tuning, commit or push is part of this approval. The separate
password-reset security finding and final Stage 6/P-145 acceptance remain outstanding.

The owner subsequently requested documentation review, a commit/push of this completed slice and a
new-session handoff. That is separate publication authorization, not standing permission to publish
future work.
The next recommended session was bounded replication preparation. The owner subsequently approved
the concrete implementation, wording and grouping ("i approve"), then requested "implement it".

**Replication permissions are stored conclusions for future rules, not new security findings.**
Capture already records the facts. This Stage 6 slice evaluates those facts into
`CanReplicateSecretDomainData` and `CanReplicateFilteredAttributes` as `ReplicationControl`, with
original entries, exact partition roots, component-right checks and uncertainty. Both existing views
show the approved **"Secret-data replication permission"** and **"Filtered-attribute replication
permission"** labels, with non-collapsing holder/root groups limited to the current page. DC holders
are not suppressed or granted an expectedness exemption. Missing/conflicting DC classification
evidence remains unconfirmed. Configuration/Schema scope is explicit; non-domain servicing contexts
remain unverified under P-90, except descriptor-native SYSTEM and NULL-DACL Everyone evidence.
The implementation record
owns validation and limits. This does not perform replication, extract credentials, establish takeover
or complete a path to Tier 0. Separate rules/findings and final Stage 6 acceptance remain outstanding.

**Preserved replication checkpoint:** the full offline suite passed **4,116/4,116**,
the solution builds, and the final targeted coverage selection passed **653/653**, including the
last BUILTIN scope correction. The earlier cancelled coverage attempt is preserved, not counted as
successful. The next recommended bounded session was **ownership-control preparation**, starting from
the existing requirements and accepted decisions, with explicit approval before the next implementation
or live laboratory work. The implementation record above owns the report, warnings and remaining gates.

**The bounded ownership implementation and wording are explicitly approved.** The owner selected
"Approve the bounded implementation and wording; offline only", then requested "implement it".
Schema 22/control engine 6 adds `IsOwnerAndCanRewriteDacl`, shown as **Existing-owner permission
control**, and records the missing steps behind **Owner-change permission control — not verified;
not counted**. Accepted owners and proven-deleted owners produce no ownership edge; incomplete
owner acceptance stays unanswered. Both viewing directions consume the same stored proof.
`CanSetOwner` stays independent and the AD DS owner-transition gate remains Unknown and uncounted.
The shared checks distinguish ordered OWNER RIGHTS permissions, complete class ancestry and missing
serving-DC behavior. No behavior baseline is inferred from a machine name or a heuristic alone.
SEC-031/032 are now version 3 and SEC-060 version 2; rule identities and severities are unchanged.
The ownership implementation record
owns verification and limitations. This approval includes focused shared-check corrections, not live
operations, discovery enablement, member expansion, new findings, final Stage 6 acceptance or publication.

**Ownership is at a verified offline checkpoint:** the full suite passed **4,182/4,182**, the solution
build succeeded, and the targeted coverage selection passed **623/623**. The linked implementation
record owns the saved report, line observations and closeout checks. Live owner-write/SDProp gates and
normal laptop/monitor checks remain outstanding; this is not final Stage 6 acceptance.

**Publication authorization:** the owner subsequently requested "ensure docs are update then commit
and push and give new session handoff". This authorizes publication of the completed replication and
ownership slices and their reviewed documentation/instruction changes, not standing permission to
publish future work. Local ignored coverage outputs and historical evidence remain untouched.

**Bounded full-control aggregation (`HasFullControl`) is implemented after explicit approval.**
The owner requested "implement it" after the recommendation, then "continue". Schema 23/control
engine 7 shows **Full-control permissions** only as a permission-summary assessment, not a new
primitive or an executed operation. All thirteen specific mapped rights must survive ordered
evaluation; raw generic bits are not expanded into grants, and unresolved scoped denies remain Unknown.
One or several grants can establish one counted summary. Supporting permissions and alternative
routes remain stored and visible, without being counted again. A broken or Unknown summary does
not suppress surviving permissions. Existing-owner control remains independent; owner-change
control remains Unknown and uncounted. Principal catalogue 2 is unchanged.
The implementation record
owns the 4,305/4,305 offline suite, successful build, 796/796 targeted coverage, proof-integrity
corrections and remaining gates. Historical tests, hashes and measurement reports are preserved.
No live access, discovery enablement, member expansion, new findings, Stage 7 paths, final Stage 6
acceptance, commit or push was included in the implementation approval. The owner subsequently
requested "commit and push then state next step", authorizing publication of this completed slice
only. The next recommended bounded session is **effective-member expansion preparation**, preserving
group-held counts and captured route evidence, with approval before implementation. The linked
checkpoint owns that boundary. Laptop/monitor checks remain normal outstanding verification.

**The bounded requester design was introduced in judgement schema 17 and is retained in schema 23.** The owner answered "continue then"
after the plain-language explanation. [Decision 0111](decisions/0111-bounded-self-membership-requesters.md)
limits it to direct user grants and one explicit same-domain global-security-
group membership. Requester assessments are stored separately from counted holder edges, with
ordered deny evaluation, an own-account constraint and separate operation readiness. Missing inputs
and unsupported routes remain unknown; the live measurements do not promote historical results.
Explicit request batches are persisted and shown object-first and requester-first without increasing
the named-holder count when supplied to the judging library. **Both hosts now reach the shared
automatic scheduler, but pass no discovery budget**, so ordinary re-judging still schedules no
requester assessments. Explicit batches remain a library input, not an administrator-maintained
selection list or a production scheduling workaround. The authorization
correction retains earlier uncertainty when it could change the ordered result and resolves SELF
to the captured target group's identity and membership, not to the requester. R5 persistence safety
is corrected: malformed stored requester records and mismatched holder references produce a
controlled read failure, including through the Shell adapter, rather than empty or partial answers.
R4 Shell readback safety is also corrected: failed reads and selection changes clear old answers,
and control/requester results from different judging runs are withheld rather than combined.
Requester-grid sizing and the approved R7 selected-answer presentation are implemented and
regression-tested. R8 reconciles the delivered state, not final feature acceptance. Production
enablement and real-product laptop/monitor validation remain outstanding; see the
review status.
This is not a complete token model, whole-feature acceptance or a new live acceptance result.

**R7 presentation approved after the performance checkpoint:** the owner selected
"Approve the recommended table wording and expandable selected-answer evidence". Keep the existing
table, approved sizing and scrolling; show plain-language authorization, own-account restriction and
readiness separately, with expandable stored identities, permission entries and direct/group route
for the selected answer. Keep capture-wide coverage limitations separate. This approves presentation
only, not discovery enablement, a numerical budget, authorization/storage changes or R8 acceptance.
Implementation and offline validation are recorded in the
Assets specification.
The approved presentation is implemented: 137 focused checks and the full 3,837-test suite passed,
and the solution builds. Selected evidence clears with failed or mismatched-generation reads.
This is offline validation, not real-product acceptance; laptop/monitor checks remain outstanding
normal verification and discovery is still inactive in both hosts. The subsequent R8 correction
reconciles these distinctions without accepting the whole feature.

**R8 reconciliation authorized after R7:** after the R7 checkpoint was committed and pushed, the
owner answered "ok do r8" to the bounded recommendation to check the stored-requester-to-screen
workflow offline and reconcile current-state claims across governing documents. This does not
approve discovery enablement, a processing budget, new UI wording/layout, further tuning or final
feature acceptance. Unperformed real-product and laptop/monitor checks remain outstanding; no new
commit or push is included in this instruction.

**R8 current-state reconciliation:** requester authorization, persistence, safe readback and the
approved presentation are implemented. Shared automatic discovery is implemented but inactive in
the shipped Shell and CLI until a numerical processing budget is approved. The new offline
workflow checks connect synthetic sealed evidence through real judging and file readers to both
object-screen directions, including stored proof, holder-count preservation, re-judging and read
failure clearing. They do not establish live-directory success, physical-display usability or
completed chains toward Tier 0. The R8 record
owns verification results and the remaining acceptance gates. R8's documentation correction is
complete for the delivered scope; final requester/Stage 6 acceptance is not.

**R2 owner requirement:** on 2026-09-06 the owner clarified that requester assessment "should always
run on new captures" and asked for a clearer explanation of the proposed interaction. An
existing-capture-only/manual-rejudge-first scope does not meet that requirement. Requester
assessment must run automatically during normal Shell and unattended CLI judging, including after
new Evidence is sealed. The judgement specification supplies the direction: start with a captured
permission's trustee, resolve relevant captured members and validate scope. Decision 0111's concrete
bounded requests do not require an administrator-maintained selection list. Discover questions from
each capture's own permissions and memberships, within the accepted direct-user and single explicit
global-security-group routes, including SELF resolved to the target. At that checkpoint, the remaining
approval boundary was how incomplete discovery, unsupported inputs and budget stops would be stored and
reported without implying negative authorization or complete coverage. This does not authorize a
forest-wide pair cross-product, live lookups, authorization/storage changes or the withdrawn
request-file proposal. Production integration was absent at that checkpoint; its later approval
and delivered-but-inactive implementation are recorded below.
When presented with a partial-coverage recommendation and a proposed 50-pair allowance, the owner
asked work to stop for a plain-language explanation because the proposed implementation was unclear.
That response is not approval of the allowance, partial-result policy or storage/readback changes.

**R2 processing-budget direction approved:** after the recommendation was revised to reject a
blanket 50-pair cutoff and establish a measured processing budget instead, the owner answered
"ok i apporove your proposal". The 50-pair recommendation is withdrawn. The existing library limit
of 100 submitted requests is not a measured forest-wide discovery limit and must not be repurposed
as one. Establish a numerical recommendation through bounded offline measurements before changing
production scheduling limits. No replacement number, silent batch truncation, authorization change
or specific storage/readback extension is approved by this budget-direction answer. Missing captured
evidence, unsupported analysis and processing-budget stops remain distinct. R2 was not implemented
at this budget-direction approval; the later schema-18 integration below supplies it without
approving a numerical production limit.

**R2 contract and integration approved, 2026-09-07:** after the recommendation was explained against
the actual Shell, CLI, evaluator and storage paths, the owner answered "i approve proceed".
This approves one shared permission-first automatic scheduler, both own-account Add and Remove
questions per concrete pair, schema-18 discovery coverage and limitation records beside the existing
answers, strict generation-bound readback, and minimum Shell/CLI coverage notices. The evaluator's
authorization rules, holder counts and explicit submitted-batch refusal remain unchanged. Missing
evidence, unsupported routes and processing stops remain separate. A failed or cancelled attempt
publishes nothing from that attempt. Older judgement results require re-judging, not re-capture or
rewriting historical generations. This approval does not establish a numerical automatic-processing
limit: measurements and approval of that recommendation still precede enabling a new production
limit. Implementation and validation are not implied by approval; P-145 and R2 remain open.

**R2 automatic discovery implemented in judgement schema 18, 2026-09-07, but not enabled in the
production hosts.** The shared judging path can discover own-account membership questions from each
capture's own permissions and memberships, inside the existing single pass over the bundle, when
given a discovery budget, and store answers beside a persisted record of what the scan covered.
Both the Shell and unattended command line currently pass no budget. Denies and uncertain entries
are discovered rather than filtered to the safe cases; broad trustees and NULL DACLs are recorded as
coverage limitations instead of being expanded into invented requesters; missing evidence,
unsupported routes and processing stops stay separate; a failed or cancelled attempt publishes
nothing and leaves the previous results as previous results. The authorization rules, the
own-account constraint and the counted holder edges are unchanged. **No numerical processing limit
has been approved, so the scan performs no work today and both hosts say so rather than staying
silent** — an empty requester product never reads as a forest where nobody can add themselves to a
group. Older judgement results must be re-judged to gain this; no Evidence, Derivation, retained
generation or frozen value was rewritten. Validated offline against synthetic sealed bundles with no
directory contact. The subsequent approved R7 presentation is implemented, and R8 reconciles the
current state. Real-forest verification, an approved budget and final acceptance remain outstanding;
P-145 and R2 production enablement remain open.

**Owner-approved priority after the full-volume performance comparison:** pause further discovery
tuning, preserve the validated permission-read fix, its regression tests and measurement artifacts,
and return to the remaining R2/R7/R8 integration, presentation and acceptance work in bounded
slices. Remeasure when work changes data access or processing volume, and before approving a
production budget, rather than after every presentation change. The completed synthetic measurements
and their limitations are recorded in the judgement store.
This is not approval of a numerical limit, enabling automatic discovery, new authorization behavior,
a new R7 presentation design or final feature acceptance. Laptop/monitor checks remain ordinary
verification work, not an additional session that must precede continued development.

**Session checkpoint requested by the owner:** update the governing documents, commit and push the
validated work, then resume in a new session. This explicitly authorizes that checkpoint commit and
push; it did not approve the then-proposed R7 requester-details presentation. The continuation session
obtained explicit approval before implementation; see the
R7 presentation record.
The owner subsequently requested a separate R7 commit and push, completed as `a92d592` on `main`.
The current R8 instruction includes no further commit or push. Keep further performance tuning
paused unless later work changes the measured workload or a remaining cost blocks the bounded feature.

**R6 presentation review:** the owner reviewed the synthetic gallery comparison and accepted the
proposed sizing, now implemented. The control table is capped
at 240 WPF layout units, the requester table retains its 180-unit cap, notices use their text's
height, and the section scrolls when the pane is short. The accepted trade-off is scrolling within
each table as well as through the section to reach notices, evidence and requester answers.
He plans to test the implemented product in his forest, on his small laptop screen and on a monitor.
The owner clarified that these checks will happen during normal verification, not as a separate
monitor-check session or a prerequisite to continuing R2, R7 and R8.
Those checks have not occurred here; preview approval is not real-product or forest acceptance.
No directory operation or retained-Evidence access is authorized by this presentation decision.

**Where judging time actually goes, measured 2026-09-22 — and it is not the storage format.** The
object pass had one clock on it, covering the rules, and the rules were 7.03 s of a 115.12 s interval
in the reproduction of the reported 108-second audit. The rest was measured by nothing, and three
saved-permission storage redesigns were aimed into it. The first breakdown, on the sealed laboratory
capture of 8,407 objects, put **15,544 ms of a 21,341 ms object pass into storing the saved
permission classifications, against 297 ms to reach the verdicts being stored** — writing cost about
fifty times more than deciding, and accounts for roughly 90% of the 17.3 s that P-248's saved
products added. Deriving the control edges, which is the analysis this product exists for, was
**19 ms**.

**Splitting that write twice over says the cost is SQL statements.** Shared entries 35.8%,
transaction commits 30.5% at 587 µs across 8,407 commits, entry rows 16.5%, schema support 10.2%;
and inside shared entries, 68.2% the insert and 19.4% a nested trustee-meaning proof write, with the
JSON comparison key only 6.1%. About **1.25 million statements** are issued per run, each on a newly
created command with its SQL re-prepared, plus a verification `SELECT` after every schema write,
twice per entry, against a table holding a few hundred rows.

**This is why the storage trials failed, and it was knowable at any point.** P-251 halved the result
file, 352,264,192 to 187,617,280 bytes, with no repeatable judging gain; P-249's first candidate
allocated 8.65% less and ran slower. **Fewer bytes is not fewer statements**, and no format redesign
changes the command, transaction, nested-write or verification counts. The format-44 candidate would
have done the same thing, and its three remaining judging runs were not spent finding that out.
Artifacts are under `next/artifacts/judging-object-breakdown/`; the instrumentation is permanent and
travels to the laboratory and to production, which has still never been measured.

**What was done about it, the same day.** Four changes, none of which alters a decision, a rule or an
answer: statements compiled once and rebound instead of a command created and parsed per row; schema
support verified once per distinct payload per run rather than twice per entry; the three per-object
writes sharing **one** transaction batched across 500 objects, which is stronger atomicity than the
three separate commits it replaced as well as cheaper; and **format 42**, storing each distinct
reading once under a SHA-256 fingerprint. On the laboratory capture the object pass fell
**21,211 → 12,766 ms (−39.8%)**, the permission write **15,410 → 7,157 ms (−53.6%)** and the
judgement file **352,264,192 → 180,301,824 bytes (−48.8%)**, with identical output throughout.

**Two limits on that, stated because they are easy to forget.** Every figure above is the sealed
laboratory capture judged on the development laptop. The 2026-09-22 laboratory run on standard SSD
put **18,463 ms** of a 49,919 ms object pass into commits against 1,979 ms for the same work on the
laptop, so the storage-dependent part of this is untested after the fixes — halving the bytes is
expected to help most exactly where it has not yet been measured. And the batch size of 500 is a
chosen number, not a tuned one; the laboratory showed its cost depends on the disk underneath it.

## The forest this is built for

**The owner's production forest is the scale that matters, and the laboratory is not it.** Recorded
because every performance and budget decision has to be argued against a real shape rather than a
convenient one, and because a session that measures a small synthetic capture and reasons from it
will reach a confident wrong answer.

| | |
|---|---|
| Domains | 9 |
| Objects | ~347,000 |
| Access control entries | ~5.9 million |
| Control edges the predecessor produced | ~9 million |
| Delegations | ~1.3 million |
| Findings | ~34,000 |
| Directory depth | deep, average distinguished name about 97 characters |
| Predecessor's stored output after a production run | ~17 GB |

**Where these come from, exactly.** They were first found in the predecessor's
`tests/SecureAD.Infrastructure.Tests/Performance/ObjectDetailProfiler.cs`, which states them as the
production environment it profiles against. **The owner confirmed them as still correct on
2026-09-07.** They are the shape to design and measure against.

**The 17 GB is the owner's own figure for the predecessor's production output, supplied 2026-09-22,**
and it is the only production *size* measurement this project has. Treat it as the order of magnitude
to plan against, not as a budget the rebuild must beat: the predecessor stored a deduplicated,
canonically ordered, generic-expanded ACL projection and **no raw descriptor bytes at all**, while
this product keeps the sealed original bytes and every distinction that projection dropped. The two
are not measuring the same thing, and the rebuild also splits its output into a sealed evidence file
and a separate judgement file. No production size has been measured for this product, and the
approved P-249 comparison runs are laboratory runs, so they will not establish one.

**The laboratory is `ad.lab`, about 8,383 objects, and the owner's words for it are that it "falls
far short" of production in both scale and complexity.** It is genuinely useful for testing
behaviour — that a rule fires, that an answer is right, that a screen refuses to mislead — and it is
not evidence about cost, volume or what a real directory contains. The 111,627 control edges
[`0097`](decisions/0097-a-group-held-permission-is-counted-at-the-group.md) argues against were a
*lab* number; production produced roughly eighty times more. A budget, threshold or timing measured
only on the lab or on a small synthetic capture is not a claim about a customer forest, and stating
it as one is the failure [`0002`](decisions/0002-absent-view-means-degraded-run.md) exists to
prevent.

## The five commitments

1. **Evidence is permanent.** Sealed once, never re-sealed. Re-analysis copies the source and seals
   the copy; the original is opened read-only (`0021`).
2. **A gap is a fact about the capture, never about the forest** (`0002`). A domain left out by
   choice never looks like one that could not be reached (`0063`); an unfinished run reports nothing
   at all rather than partially (`0068`).
3. **Say what you know, with its uncertainty — except when claiming completeness** (`0086`). Silence
   is reserved for *this is complete*, where a wrong answer makes someone stop looking.
4. **Severity belongs to the rule and the customer cannot move it** (`0066`, `0082`) — lowering a
   severity is quieter than accepting a finding and leaves nothing behind.
5. **A finding carries typed evidence and a permanent identity** (`0080`, `0023`, `0024`), so an
   acceptance made today still attaches after a rename.

## What it deliberately is not

- **Not a live tool.** No live effective access, inheritance, ACL compare or delegation reporting
  (`0008`).
- **Not a policy compliance checker.** Password policy is captured and shown; nothing grades it.
  Plenty of software measures password strength.
- **Not tunable.** No assessment modes (`0031`), no customer-editable catalogue (`0082`).
- **Not an auditor of audit configuration.** The SACL is never requested (`0036`).
- **Not a reporter of account activity, decided 2026-09-01.** Whether an account is really in use
  cannot be answered from one controller: `lastLogon` is per-controller and never replicated, and the
  replicated `lastLogonTimestamp` is documented by Microsoft as updating only once it is already 9 to
  14 days old, and as capable of holding a future value after a clock skew or a Kerberos S4U2Self
  request. Reporting a stale-account threshold from that would print an estimate as a finding, and it
  would under-report as readily as over-report. Sign-in telemetry — Defender for Identity — answers
  this properly and a directory attribute does not. `P-113` keeps two possibilities open: the
  timestamp shown as *information* on an asset rather than as an indicator of activity, and a
  separately named *rough estimate* rule, for customers without that telemetry, whose own wording
  would have to say it is an estimate.

## What tests are for, decided 2026-09-12

**Tests keep the code honest, never a document.** The owner's words: *"i dont want any test that point to
documenation. its done thing but slow developemnt way down. test to me should keep the code and how its
supposed to work honest."*

- **A test may check code against code, or code against an outside authority.** Microsoft's published
  specifications, a recorded output of the predecessor, a frozen lab result. Only those can say the
  product is wrong.
- **A test that checks whether a document and the code agree is deleted.** So is one comparing two
  documents. It confirms an opinion back to itself and doubles the cost of every change. `F-S44-2` is
  the price: three sound suites agreeing in both directions while fifteen captured attributes were
  silently missing, because the whole circle was anchored to the rules already written.
- **A drifting document is a documentation problem**, fixed by reading it, not by a failing build.
- **One exception, granted explicitly: the stage table** at the top of this file, held to the code by
  `StageStatusGateTests` and `next/tools/check-stage-status.ps1`. That table claimed *two* judging rules
  for long enough that twelve more were built underneath it. A stale stage table misleads the owner
  about his own product, which is a cost no other document here carries.

This removed 24 test classes on 2026-09-12, on top of the 260 deleted on 2026-09-11. **What it does not
buy is any claim that nothing in the product is dead.** The check that would prove that — every public
type reachable from a running entry point, gate 5b — was never built; see `docs/next/README.md` § Gates
and `F-S7-42`. The surface register retired with the other paperwork gates was never that proof, and its
own page said so.

## Where it departs from the predecessor

There is an old application. It worked, the owner ran it, and it is why this rebuild knows what it
is aiming at. **Its architecture is not this one's, and nothing below is a design to follow.** Its
inventory and component map were archived and are deliberately absent from this repository, so that
nobody treats it as a specification.

**The code, however, is on disk at `C:\Users\ba.admin\source\repos\razamus\SecureAD`, and the owner
has said to read it** — *"treat this as a source not a answer, look at what it did but also consider
if there is a better way"*, 2026-08-26. It is the only place a working findings screen for a real
forest exists. Read it for **how something performed**; never for **what the product permits**,
which the decision records settle and which it frequently contradicts.

Thirty-nine of seventy-nine decision records reference it. The load-bearing differences:

| | Old app | Here |
|---|---|---|
| Live directory | kept a live connection alongside the bundle | removed entirely (`0008`) |
| Sealing | signed at the end over evidence *and* conclusions; re-analysis re-signed in place | evidence sealed alone at capture, never re-sealed (`0030`, `0085`) |
| Analysis | eleven dependent phases writing into the same file | one streaming pass into a separate store |
| Failure | phases fault-tolerant, degraded results still presented | unfinished run reports nothing (`0068`) |
| Severity | overridable by policy file | fixed by rule card (`0066`) |
| Capture scope | two class filters as radio buttons | every class except a shipped noise list (`0034`) |
| Schema partition | not read | read every run (`0014`) — what makes object-specific ACE evaluation possible |
| Vocabulary | *Accept* on screen, *Suppression* in code | one word, **finding**, everywhere (`0066`) |

### Why it took hours, and why that is not inherent

**The owner's measurement, 2026-09-03: capture took 30 to 45 minutes across nine domains, and the
run took three to five hours.** Capture was never the problem. The time went on the graph.

Its own CONTROL-EDGES-AND-PATHS document, under docs/ in the predecessor tree, says how, and it is
costs stacked on each other:

- **`fact_group_membership_closure`** — the full transitive closure of every group, materialised.
  Quadratic in the forest.
- **"Traversal: BFS from each non-high-value principal to discover shortest paths to targets."**
  With a hundred thousand principals that is a hundred thousand traversals of a graph holding
  millions of edges.

**Neither is required by the question being asked.** *Who can reach Tier 0* is answered by walking
**backwards from the targets** — there are perhaps dozens of high-value targets against a hundred
thousand principals, so the same answers cost three or four orders of magnitude less. The old
application even built the reverse graph, as step 3 of that document, and then traversed forward
from every principal anyway.

**So the hours were an algorithmic choice, not the price of the analysis.** This matters now because
escalation paths are unbuilt here and will be asked for eventually. Two things follow:

- The closure is already refused: `what-stage-2a-derives.md` walks membership on demand, because
  *the transitive closure of every group is quadratic in a real forest, while every consumer asks
  about a handful of named principals*. That decision was taken for a different reason and happens
  to remove the first cost entirely.
- **When paths are built, traverse from the targets.** Reverse traversal needs `memberOf` edges,
  which are linear in memberships and already persisted, and never needs the closure.

**One correction to a claim made in this session and left here so it is not repeated.** SYSVOL was
suspected of being a runtime risk on the strength of lab capture rising from 7 to 11 seconds when it
began working. The owner's account is that the old application captured little of SYSVOL and he is
not sure it was ever used in production, so there is no prior measurement to lean on either way.
It is unmeasured at scale rather than known to be slow.

### What its findings grid did, and what of it is worth having

Read 2026-08-26 from `SecureAD.Infrastructure/Paging/`, `Findings/FindingsService.Queries.cs`,
`Storage/DerivedStoreSchema.Views.cs` and `SecureAD.UI/ViewModels/FindingsGridViewModel.cs`.

**Keyset paging, and it is better than the obvious alternative.** `KeysetQueryBuilder` pages by
where the last page ended rather than by `LIMIT`/`OFFSET`. Offset paging makes the database walk and
discard every row before the page, so page 500 of a large forest costs 500 pages of work; keyset
paging costs one. Three details are the actual engineering, and all three are easy to omit and hard
to debug afterwards:

- **Every sort ends in a unique tie-breaker** — `severity, rule_id, target_dn`. Without it, rows
  that sort equal can straddle a page boundary and be shown twice or not at all.
- **The continuation token records the sort and a hash of the filter**, and a token that does not
  match them restarts from the first page rather than silently skipping rows.
- **Identifiers are validated against a strict pattern** before they reach the SQL text.

Its page size was 50, in `GridViewModelBase`.

**Filter values are read from the data**, so a filter cannot be set to something no finding has.

**Its grid resolved names by joining** `dim_principal` and `dim_object`, because findings and objects
were in one file. **They are not here** — findings are in `judgement.db` and evidence in the sealed
`evidence.db` — so what the grid shows is stored on the finding when it is made. That costs nothing
at judging time, because the object is already in hand when a rule fires, and it avoids the
alternative: fifty lookups into the evidence to paint one page, on every page and every re-sort.

**Three things in it are not worth having, and two are positions this product has reversed.**
`context_json` is the schemaless blob the judgement schema's own comments record as having silently
downgraded a finding when a value would not parse. `suppressed`/`suppression_reason` are `0066` and
`0082` reversed. And `v_grid_findings` rewrites a finding's coverage to *complete* inside the view,
by matching a `coverage_reason` string — a judgement made in presentation, where nobody reading the
finding can see it, which is `0002` exactly.

**Reading it found a defect here.** The old app's severity sorts correctly because its view does not
order on the text. This judgement store writes `severity` as the enum name, so `ORDER BY severity`
gives Critical, High, Low, Medium — alphabetical, putting Low above Medium. A rank is stored beside
the name to fix it.

### What its finding detail view showed, and what of it is worth having

Read 2026-09-01 from three screenshots the owner supplied of the predecessor's finding window
(`SEC-014`, `SEC-024`). This is the screen an administrator actually works from, so what it did well
matters more than most of the old code.

**Its blocks, in order:** a header carrying rule identifier, title, category (`Delegation`,
`CredentialTheft`), a MITRE technique link and a severity badge; **What was found**; **Evidence
context**; **Why it matters**; **How to fix**; a strip reading `Coverage: Complete  Suppressed: No
Tags: …`; and the buttons *View evidence*, *Accept risk*, *Copy finding key*.

**Worth having, and settled 2026-09-01:** the category, the MITRE link, **Why it matters**, **How to
fix**, and the coverage signal. The owner's decision on where they belong: **in the product, not only
in an exported report** — *"I can see server admins using this as a working app on what to clean up,
and seeing it on screen in a UI is sometimes easier to consume than a report if done right."* So the
finding view is a working surface, not a preview of a document.

**The one thing to change is duplication, not volume.** Of the eleven rows in *Evidence context*,
seven repeat the panel directly above them — rule id, source SID, subject name, target DN, target
name, control type and classification are all already on screen. Of the remaining four, three
(`Source Is Well Known Admin`, `Source Is Privileged By Membership`, `Source Is Broad Principal`) are
the *working behind* the classification line rather than an answer, and the fourth is an internal
edge identifier. The `Detail` sentence then states the same facts a third time, using a raw SID where
the name is two lines above.

**This is not a matter of taste, and the screenshots prove it.** On the owner's laptop the duplicated
block pushed **Why it matters** and **How to fix** below the fold, so the two things he most needed
were the two he could not see. Removing what is printed twice is what brings them onto the first
screen.

**The agreed shape, 2026-09-01:** four blocks — header, *What was found*, *Why it matters*, *What to
do* — with everything raw (identifiers, GUIDs, ACE hashes, the classification working) behind *View
evidence*, which the predecessor already did well. The rule to apply when deciding where something
goes: **the finding page answers what, how bad, why and what do I do; the evidence view answers prove
it.**

**Not worth having:** `Suppressed`, which [`0066`](decisions/) and [`0082`](decisions/) reversed, and
the *Evidence context* table on the front page.

**What must not creep in.** *How to fix* states an action and what it may break. It must never state
that the action makes the customer safe — that is a claim about every path to the object, which
`AC-15` and `AC-21` require to be proven, and it is stage 8 work. Guidance copy is where that line
gets crossed by accident.

**Content is stage 4; presentation is stage 9.** The guidance is written as each rule is built, while
the Microsoft research behind it is in hand; the screen that displays it is designed later, around
content that already exists.

**Every rule gets an About section, and it is where a limitation is stated, decided 2026-09-02.** The
owner: *"we will have an about section that describes each rule and what its looks for so we will have
the ability to surface the limitations to the user in that capacity."* So a rule has three kinds of
copy, and they answer different questions:

| | Answers | Scope |
|---|---|---|
| A finding | what is true about **this object** | one object |
| Guidance (\`RuleGuidance\`) | why that matters and what to do about it | the rule |
| About | **what this rule looks for, and what it does not** | the rule |

**This is what makes a bounded rule honest.** A rule that reports a subset is not free to let its
silence read as *nothing else is wrong*; About is where the boundary is stated to the operator rather
than only to a reviewer reading the rule document. \`SEC-027\` is the first rule to need it: it reports
SID history containing a **well-known** privileged identifier and cannot rank a custom group from a
domain that no longer exists, and an operator must be able to read that without opening this
repository.

It is content, so it is written as each rule is built, alongside the guidance. Where it is displayed
is stage 9 with the rest of the presentation.

**Built 2026-09-03, and it is required on every rule.** `RuleGuidance.About` is not nullable and
`RuleGuidanceTests` refuses a blank one. Optional was the cheaper choice and was refused for a
reason worth keeping: a field populated for some rules and empty for others is rendered by a screen
as *this rule has no limitations*, which for a bounded rule is the exact false statement the section
exists to prevent. Being obliged to write it is also how an unstated limit gets found — writing the
eleven turned up three nobody had said out loud, including that `SEC-028` reports an account
**exempt** from the password length rule rather than one with no password.

**It is shown on the findings panel, which is half of what it is for.** The operator who most needs
a rule's boundary is the one reading a rule that reported *nothing*, and he never opens a finding.
The rest waits for a screen that lists the rules themselves.

## Build order, and two scope decisions

**The dashboard is built before the remaining rules, decided 2026-09-05.** The owner asked whether
it had to wait until every rule existed; it does not, and it should not. Stage 2 depends on nothing
unbuilt. Building it early puts the wording in front of an administrator, which is the only way to
find out whether it reads correctly to the person who has to act on it. The order the owner set:
**dashboard, then a punch-list session, then stage 6**.

**A correction: this paragraph claimed the product had *no screen that shows findings to anybody*,
and that was false.** Corrected 2026-09-05 against the code. `AssetsPane` has had four working
panes bound to live stores for some time — `Objects` and `Laps` over sealed evidence, `Findings` and
`Rules` over the judgement store — and the findings pane already distinguishes *every rule ran and
matched nothing* from *nobody has judged this bundle*. The claim survived into this document because
it was written from a roadmap row rather than from `AssetsViewModel`. What was genuinely missing was
the answer to *what am I looking at*, which is what stage 2 supplies.

**The dashboard was built 2026-09-05 and the owner settled four things about it.**

1. **Coverage first, counts underneath.** How much of the forest was read is stated before any
   number on the screen, and stated every time — including when nothing was missed, so that its
   absence is never read as reassurance.
2. **Counted per domain, totalled afterwards.** A single forest-wide figure cannot show a hole: a
   run that read two domains of three produces a smaller number, and a smaller number looks exactly
   like a smaller forest. An uncovered domain is a visibly present row carrying no figures.
3. **Where a shortfall can be counted exactly, both numbers are shown.** The owner's wording: *if we
   can show how many were read and how many were not then we show the exact numbers.* This applies
   to Group Policy, the one place a sealed bundle can state an exact shortfall — the policies are
   declared by the directory, which is read all-or-nothing, while their files come from SYSVOL,
   which `0044` allows to fail without failing the run.
4. **The dashboard is the landing screen for an opened run.** A failed, interrupted or damaged run
   never reaches it: the owner's observation, confirmed in the code, is that such a run *never
   finished capture*, so there is no sealed evidence to land in. The library states what became of
   it instead.

**A domain cannot be reported as partly read, and the owner was right to question it.** Asked what
the screen should say for a partly read domain, he asked when that could happen — *wouldn't the run
be discarded?* It would. Capture is fail-fast per `0003`: a domain that cannot be read ends the run
before the seal, `UnreadOutcomeIsUnreachableTests` holds that no production code records a unit as
unread, and `BundleReader.ReadScope` refuses outright to open a bundle claiming otherwise. The
reachable gaps in an openable bundle are a domain excluded by choice, a domain the forest named no
writable controller for, and a SYSVOL read that partly failed.

**A count is never rendered for a domain that was not read, and the type enforces it.**
`DomainInventory` holds its counts behind `TryGetCounts`, which answers false for every outcome but
`Read`, and its factories refuse both contradictions at construction. There is no zero available to
render for an unread domain even if the screen's markup were wrong. See
layers/shell/what-a-run-counted.md.

**Tier 1 means what Microsoft says it means, decided 2026-09-05.** Per the
[tier model](https://learn.microsoft.com/windows-server/identity/ad-ds/tier-model), Tier 1 is
*enterprise servers and applications*: member servers and server administrator roles, the solutions
that manage them (backup, monitoring, patching, hypervisors), Microsoft server applications such as
Exchange, SharePoint and SQL Server, third-party server solutions, and line-of-business
applications. Tier 2 is end-user devices and accounts.

**Tracing to Tier 1 servers is deferred to the very end and may never be built, decided
2026-09-12.** The owner: *"i care about teir 0 and teir 0 adjecent."* Tier 0 is derivable from the
directory - Microsoft names the groups. **Tier 1 is not.** Nothing in Active Directory marks a
member server as an Exchange server or a line-of-business host; the tier model is an operational
structure an organisation adopts, expressed in OUs and groups it chose the names of.
`operatingSystem` distinguishes a server from a workstation and says nothing about what it carries.
So a Tier 1 rule must either read a customer-supplied definition or infer one, and **inferring it
would be this product asserting a tier boundary the customer never drew**. Recorded as `F-S45-12`;
nothing is waiting on it.

**This does not defer `SEC-073` and `SEC-074`, which the owner does want.** Despite their names,
neither rule targets a member server. Both name a fixed set of built-in groups - Account Operators,
Server Operators, Print Operators, Backup Operators, Cert Publishers, RAS and IAS Servers, Remote
Desktop Users, Incoming Forest Trust Builders - and every one is already known to the product
through `ProtectedGroupCatalogue` and `WellKnownSidCatalog`, with membership resolved by
`ProtectedPrincipalClosure`. They need no customer-supplied anything. What they need is multi-hop
path chaining, which is Stage 6 control-edge work. Recorded as `F-S45-11`.

**Group Policy is deferred to the end, decided 2026-09-05.** The owner: *"i may leave until the end
unless it will be harder then but i dont see why it would be."* **It will not be harder later**, and
the reason is worth recording: the five GPO rules are blocked on a capability the product does not
have - reading policy *content* out of files on SYSVOL, rather than reading the policy object in the
directory. That capability is self-contained, it is the same amount of work whenever it is done, and
nothing else in the roadmap depends on it. Deferring it costs nothing but the findings themselves.

**Stop throws the work away, at every stage, decided 2026-09-12.** The owner: *"at any stage of the
audit, if the user hit stop, it should get thrown away. im not going to try and figure out how to
handle incomplete data from a user hitting stop."* **This is already how capture, derivation and
judging behave** - each writes `<name>.db.partial` and renames it as its last act, so a run that was
stopped has no file under the name a reader opens. A cancelled re-judging leaves the previous
judgement intact, which is the same guarantee a crash gets by the same mechanism.

**The rule is recorded here because the shell cannot yet re-judge or re-derive, and will be able
to.** `securead-cli` has `--derive` and `--judge` for a bundle already captured; the shell has no
equivalent command, only *New audit*. When those buttons are built they must follow the rule above -
delete whatever the interrupted attempt produced rather than keeping it for the operator to
interpret. **No screen may offer partial results from a stop**, and nothing may ask an operator to
decide what an incomplete judgement means.

## What a control edge means, decided 2026-09-05

Stage 6 turns permissions into *this principal can take over that object*. Four things about what an
edge **means** were settled before any of it was built, because building it first would have chosen
all four by accident.

**The following edge and screen descriptions are accepted requirements, not built features.**
Control edges, their executable control-plane catalogue and these two views remain stage 6 work.

**A correction first: the product already judges ownership, and `P-70` said it did not.** `SEC-031`
reports an ordinary object owned by a principal that is not administrative at `Low`, `SEC-032`
reports the same for objects `AdminSDHolder` protects at `Medium`, both are registered in
`RuleCatalogue.All`, and `ObjectOwnershipEvidence` carries the owner, the object class, a
completeness voucher and whether the owner still exists at all. `SEC-060` already treats `WriteOwner`
as takeover-class only where an owner's implicit rights survive, consulting the `OWNER RIGHTS` entry
and the forest's `BlockOwnerImplicitRights` setting and refusing to answer where that setting was
never read. The row was prose, and prose is discussion. Verified by opening `ObjectOwnershipRules.cs`,
`ObjectOwnershipEvidence.cs`, `BroadPrincipalCanTakeOverObject.cs` and `RuleCatalogue.cs`.

1. **Ownership is an edge, but only where the owner is not an administrator** - the same set
   `SEC-031` and `SEC-032` already report, decided using the existing `ObjectOwnershipReading` rather
   than a second definition of *administrative*. An owner implicitly holds Modify Permissions, so
   without this the graph misses the most direct takeover there is; with it, an object owned by
   Domain Admins would produce no ownership edge. Actual edge counts await stage 6 and P-145.
   [`0095`](decisions/0095-ownership-is-a-control-edge-where-the-owner-is-not-an-administrator.md).
2. **Effective permissions are shown two ways over one stored edge set** - object-first (*who can
   take over this object*, the shape of the Windows Effective Access tab) and principal-first (*what
   can this service account reach*). One store, two queries, so the second view is cheap and the two
   can never disagree. A second correction: `EffectiveAccessCalculator` already computes this,
   denies before allows and inheritance included, and `P-71` said nothing did.
   [`0096`](decisions/0096-effective-permissions-are-shown-object-first-and-principal-first.md).
3. **A permission held through a group is counted at the group and expands to its members.** The
   headline reads *Helpdesk (400 members) can take over OU=Finance*; one click lists the 400. The
   counted edge names what an administrator actually changes - the access control entry - while the
   membership size stays visible instead of being multiplied into the total.
   [`0097`](decisions/0097-a-group-held-permission-is-counted-at-the-group.md).
4. **Every edge is tagged expected or unexpected, and the screen defaults to unexpected while saying
   how many it hides.** *42 unexpected control edges (111,585 expected, hidden)*. Nothing is
   discarded and nothing is silently suppressed. A broad principal - `Everyone`, `Authenticated
   Users`, `Domain Users` - is never expected, whatever it holds.
   [`0098`](decisions/0098-a-control-edge-is-expected-or-unexpected.md).

**The fourth is the one the predecessor got wrong, and its number is the evidence.** It reported
**111,627 control edges and 0 escalation paths** on an eight-thousand-object lab. A number that large
is not an answer; it is a number an operator learns to scroll past, and the real one hides inside it.
Stage 6's target is a small *unexpected* count, not a large total.

**The earlier prerequisites are resolved.** `P-85` is settled by
[`0099`](decisions/0099-the-tier-0-control-plane-catalogue.md), and `P-105` was fixed by `0106`:
the stored protection reason uses a nearest root rather than whichever root was processed last.
That single stored reason is not the complete membership explanation now required by `0108`;
P-146 now supplies the separate grouped route evidence and presentation. `P-107` and `P-67` do not
gate stage 6 and remain deferred for the reasons on their rows.

## Control-edge categories, decided 2026-09-06

**Membership changes and replication have their own categories**, accepted by the owner under
[`0110`](decisions/0110-membership-and-replication-have-distinct-control-edge-categories.md).
Add `MembershipEscalation` and `ReplicationControl` without renaming existing categories.
`DirectoryControl` describes authority over the object's security descriptor;
`CredentialExposure` describes credential-related capabilities. The existing specification's
`ConditionalEscalation` vocabulary is retained, not silently removed.

**The distinction is what a capability does, not how bad it is.** Resetting a password,
changing group membership and replicating secrets must not all be described as rewriting an
object's permission list. Self-Membership remains distinct from unrestricted membership changes.
A replication capability keeps its qualifying rights and the partition it reaches.

Microsoft's control-access-right, Self-Membership, Reset Password and replication-right pages
were read in full before the recommendation. They support the different operations; these category
names are SecureAD vocabulary, not Microsoft's taxonomy. Severity, expectedness, group counting,
owner acceptance and the claim-specific laboratory gates are unchanged. In particular, the new
replication category does not make a domain controller's edges expected or hidden.

**This records the accepted category choice, not an implementation.** Stage 6 and P-145 remain
outstanding; the rest of the stage-6 proposal is not accepted merely by this decision.

## Which principals are the control plane, decided 2026-09-06

**The control plane is the set of principals whose control the product may hide as routine, and
nothing wider.** Two questions look like one and are not: *can compromise of this principal reach
Tier 0* is Microsoft's tier model, and *should what it holds be hidden by default* is `0098`. A
principal can be Tier 0-sensitive without every permission it holds being expected.
[`0099`](decisions/0099-the-tier-0-control-plane-catalogue.md) settles `P-85` on that distinction.

**The accepted catalogue requires every entry to declare two scopes**, and an entry that does not declare an unrestricted capability
scope does not get one. **Authority scope** is where the principal is an administrator; **capability
scope** is which powers are normal for it. Unrestricted, within their own domain: the built-in
Administrator (500), Domain Admins (512), `BUILTIN\Administrators` (544); forest-wide: Enterprise
Admins (519). Restricted: **Schema Admins (518)** for the schema partition only, **SYSTEM** only
where a descriptor names it directly, **Enterprise Domain Controllers** only for the capabilities a
controller needs.

**Everything else is out, and out does not mean safe.** Backup Operators (551) and Server Operators
(549) stay Tier 0-sensitive and remain worth watching; excluding them means their edges stay visible
rather than being hidden as routine. Also out: Account Operators (548), Print Operators (550),
Replicator (552), Group Policy Creator Owners (520), Key Admins (526), Enterprise Key Admins (527),
the RODC groups (521, 498) and Domain Controllers (516). **CREATOR OWNER is never a holder at all** -
it is a placeholder for who a holder will be later, so its edges are `Unknown` rather than expected
or unexpected, which is what the product already does everywhere else.

**A correction to the record: the `CN=Keys` claim is true.** Microsoft's domain-wide schema updates,
operation 83, grants Key Admins and Enterprise Key Admins Full Control over the `CN=Keys` container,
inheriting, including rewriting permissions and taking ownership. An earlier draft of section 12
said it was not found; that section has now been corrected. The source is the same page `P-86`
already cited. It does not change the answer - `CN=Keys` holds key credential objects rather than
accounts, and Microsoft's own operation 89 later cut the grant back to a single attribute - but the
row was right and the specification was wrong, and it was caught by fetching the page.

**The earlier ownership implementation conflicted with the control-plane policy.** Its identifier
list and protection fallback accepted five operator groups as owners. P-140 was corrected by
`0107`: owner acceptance is independently derived, and the five groups no longer qualify by that
route. `0109` subsequently added schema-only acceptance. None of this means the stage 6 executable
catalogue already exists, or that ownership and control-edge expectedness are one interchangeable
question; `0101` requires the questions to remain separate.

**The accepted policy is automatic certificate-authority discovery and declaration-only AD FS.** An enterprise CA is an object
the directory names, in a partition capture already reads, so classifying it is a read. Nothing marks
an AD FS server, so naming one would be a guess - and a guess printed as a fact is the one thing this
product must not do.

P-142's bounded enterprise CA classification is implemented and offline verified; the declaration
mechanism remains implementation work on P-143.

**Customers may declare Tier 0 assets, never Tier 0 principals.** Declaring an asset adds something
to watch and hides nothing. Declaring a principal would hide edges by default and make conclusions
depend on local configuration. A specific edge that is fine here is handled by accepting the finding,
which stays on the record. **A declaration never moves a severity** - that is fixed by the rule
(`0066`, `0082`).

## What was settled alongside the control plane, 2026-09-06

**SYSTEM is expected where the object's own permissions say so, and nowhere else**
([`0100`](decisions/0100-system-is-a-descriptor-native-expected-trustee.md)). `S-1-5-18` sits with
full control in the default permissions of nearly every object in Active Directory, so treating it
as unexplained would have put tens of thousands of entries on the first screen - the same failure the
predecessor's 111,627 was. Treating it as an administrator everywhere would have been worse. The
answer is neither: **SYSTEM is expected for exactly what an applicable permission entry on that
object grants it, and that expectation transfers to nobody.** A service running as LocalSystem on an
ordinary server is not SYSTEM on the network - Microsoft says it authenticates as the computer - so
the product never lets SYSTEM quieten a computer account's edges. An unreadable descriptor still
produces *unknown*, never *expected*.

**Domain controller edges are grouped, never hidden**
([`0105`](decisions/0105-domain-controller-edges-are-grouped-never-suppressed.md)). Every controller
holding replication rights is normal, and a screen listing them one by one looks like hundreds of
defects. So they are grouped by holder and naming context, labelled as controllers where that is
established, and anything unusual the same account holds is shown apart from the routine block.
Nothing is suppressed. **No *this is just a DC* exception exists**, and it will not until the product
can tell an ordinary controller from a demoted one still holding rights it should have lost - which
is exactly the finding worth having.

**An expansion that ran out of room says so** ([`0102`](decisions/0102-group-expansion-is-budgeted.md)).
Group membership is expanded against explicit budgets - how many objects, how many links, how long,
how much stored. Reaching one never drops the finding and never discards what was found; it marks the
expansion **incomplete**, records which budget stopped it, says so on screen, and refuses to present
the partial number as a total. Microsoft publishes no safe threshold for this, so the product does
not invent one and call it safe.
The accepted timing clarification under `0102` is that deterministic replay covers traversal order
and work-limited prefixes for the same evidence, semantic versions and configured node/link/storage
budgets; elapsed-time cutoffs can stop at different fresh-run prefixes, while persisted partial
results reopen exactly as stored. This clarification does not approve or change production limits.

**Confidence flows one way** ([`0103`](decisions/0103-an-established-primitive-is-not-contaminated-by-an-unverified-compound.md)).
*This principal can take ownership* is proven from the permissions. *Taking ownership then lets it
rewrite everything* depends on a step nobody has verified against a real forest yet. The first is
reported as established and the second as unknown - the uncertain step does not drag the proven one
down with it, because that would make the product quieter about something it can actually prove.

**The replication capability is called `CanReplicateSecretDomainData`**
([`0104`](decisions/0104-the-capability-is-named-canreplicatesecretdomaindata.md)), matching
Microsoft's own words rather than claiming *all* secrets, which filtered attribute sets make untrue.

**One registry of principals, with each question answered separately**
([`0101`](decisions/0101-one-versioned-principal-registry.md)). *Is this group too broad*, *is it
suspicious in SID history*, *is it an acceptable owner*, *is its control routine*, *is it a Tier 0
asset* are five different questions about the same group, and one flat privileged-or-not list would
erase all five. Backup Operators is worth watching, is not an expected controller, and is no longer
an accepted owner - all at once, without contradiction. Nothing is inferred from anything else unless
a decision says so.

## Which membership a finding names, decided 2026-09-05

**One finding must summarize independent membership routes, including longer routes**, decided by
the owner under [`0108`](decisions/0108-a-finding-summarizes-independent-membership-routes.md).
This revises `0106`'s choice to name only the nearest privileged group. The derivation retains
that selected protection basis and now also stores the independent membership-route summary.
SEC-021 version 2 carries that summary in one finding. A principal protected in its own right retains that
direct catalogue basis rather than being relabelled as protected through membership.

**What was wrong.** The walk let each later group overwrite an earlier one, so the *last* one it
happened to process was reported. Three accounts sitting directly in **Enterprise Admins** on
`ad.lab` were each reported under **BUILTIN\Administrators**, because Enterprise Admins is nested
there. Nothing said was false - the accounts really are under both - but the answer shown was the
wrong one to act on. The fix is to remove the account from Enterprise Admins; removing it from
`BUILTIN\Administrators` would not have taken its privilege away, because it is not directly in that
group at all.

**Why not a separate row for every outer group reached.** Where several groups are reached through
the same membership, those outer groups are consequences of that route, not separate removals.
Counting each one would multiply rows by nesting depth rather than by the memberships an operator
can change. That reasoning does not apply to an independent route, even when it is longer.

**A correction from source inspection, 2026-09-05.** This page previously claimed the whole chain
to every outer root was stored and shown on a detail view. At that point `ProtectedPrincipalClosure`
held one basis and one path per principal, stored in `protected_principal_path`. The alternative
route evidence was genuinely missing. P-146 has now added it separately; the result is supporting
chains grouped by initial membership, not an exhaustive list of every possible path.

**The owner selected option 3 for P-146 on 2026-09-05.** Two direct memberships in privileged groups require two
removals, and naming one hides the other. Equally near nested roots can instead share an initial
membership; an independent route can also be longer. The tie-break makes a choice stable, not
complete. These were the three choices; option 3 is accepted and the other two were not selected:

| Option | Example finding text | Cost and limitation |
|---|---|---|
| 1. Name every equally nearest root in one finding | Alice reaches Domain Admins and Enterprise Admins through two direct memberships. | Store multiple roots and paths and update finding evidence and presentation. Avoids duplicate rows, but longer independent routes remain unmentioned. |
| 2. Name one and count the other equally near roots | Alice reaches Domain Admins; one other equally near membership also exists. | Still derive the alternatives and provide their details. Shorter headline, but an extra click is needed to learn the other membership. |
| 3. Summarize independent membership routes in one finding | Alice has two membership routes to privileged groups. Review both. | Most derivation, evidence and presentation work. Include longer independent routes, show the memberships that start them, and group routes sharing an initial membership rather than adding a row per outer group. |

**Why option 3.** Fixing only ties leaves the same failure when another
independent route is longer. An initial membership means the group the account directly belongs to;
it is not every outer group reached through that group. The finding must not claim that removing listed
memberships removes every other form of privilege. That stronger claim requires the later work that
proves a proposed repair covers every route.

**Implemented under 0108.** Derivation schema 10 stores independent initial memberships, the
reachable catalogue roots and supporting chains, including longer routes to the same root. The
chains retain captured names, scoped SIDs, primary-group links and separate authorization/protection
answers. Initial memberships sharing several outer roots produce one detail block, not extra
findings. SEC-021 version 2 persists the evidence in judgement schema 14; both finding screens expose
it through **View membership evidence**. Direct catalogue protection is retained in its own right,
and owner acceptance is neither reconstructed from this summary nor changed by it.

**Incomplete is visible, not discarded.** Limits on principal visits, examined links, estimated
stored evidence and time stop the walk with a named reason. Capture gaps and cycle-limited group
answers are also explicit. Known routes survive, their count is not called a total, and a proven
finding survives with unresolved inputs recorded beside it. This required correcting `JudgingRun`,
which previously discarded findings from an incomplete verdict. A rule that throws still loses its
findings. Distribution nesting can confer protection without authorization; the wording now says
so rather than promising that every protected account has domain administration.

**Checks were observed failing, one mutation at a time.** Retaining only one route failed 17 checks
across derivation, storage, judging and presentation. Erasing completeness failed six; mislabelling
distribution paths failed three; capture-dependent ordering failed one. Disconnecting each real
screen's binding failed separately, naming `SelectedFinding.MembershipDetails` and
`MembershipCompleteness`. Removing SID scope and primary-link labels each failed their dedicated
check. Every mutation was restored. The full-suite architecture checks also required completeness
on each initial-membership block, rather than only on its containing summary.

**P-149's remaining checks are implemented.** Before changing the stored layout, the existing
version-1/version-8 refusal and matching-version tests were verified against their bodies. Disabling
refusal made both mismatch cases fail; an added unversioned production column failed the independent
schema-9 layout checkpoint. Schema 10 has its own checkpoint, and the schema-9 checkpoint is retained.
The guard covers structural changes, not semantic-only changes with identical SQL; those still need
an explicit version decision and behavioral tests. Version-9 refusal is now tested too.

**The same sealed ad.lab evidence was checked again on a new copy.** Existing diagnostics, run with
`pwsh`, derived and judged next/artifacts/membership-routes-0108/ on the measuring machine. SEC-031 remains **10**, SEC-032
remains **0**, and both retain **four undecided objects**. All ten ownership finding details match
the preserved scoped result. Evidence retains SHA-256
2DEF9F8AD4DE01877970B7F97F845716C1FFC1B093B01F388004610526E76BE4. Derivation generation
69c75821-3f63-4045-806d-d9c7513c1fc4 records three initial memberships for `ba.admin`, with outer
Administrators roots grouped under their actual initial membership. Judgement generation is
1685f45e-0ea0-49cc-89b9-34df2b37c5af. Reports are `next/artifacts/p146-lab-*.txt` and
`p146-prior-ownership.txt`. This bundle has no SEC-021 findings; planted end-to-end tests prove the
multi-route finding and partial-finding cases. No control edge or stage 6 implementation was added.

## Who counts as an acceptable owner, decided 2026-09-05

**Owning an object and being repaired by AdminSDHolder are two different questions, and the product
now answers them separately**
([`0107`](decisions/0107-an-accepted-owner-is-a-separate-question-from-protection.md)). An object's
owner can rewrite its permissions without appearing in the permission list, so who owns something is
a control question. The five operator groups `0099` leaves out of the control plane - Account
Operators, Server Operators, Print Operators, Backup Operators and Replicator - are **no longer
accepted owners**, so an object one of them owns is now reported. Out still does not mean safe:
Backup Operators remains Tier 0-sensitive, and this makes its ownership visible rather than hidden.

**CREATOR OWNER and SYSTEM stay accepted**, because an owner recorded as a placeholder or as the
platform is a directory artefact rather than a person. `0099` governs the first and `0100` the
second.

**Two things were found by opening the code, and both changed the work.** First, the shipping list
was not what decided this: where the list did not match, the rule asked whether AdminSDHolder
protects the owner and read that as *administrative*. All five operator groups **are** protected, so
removing them from the list alone would have changed nothing a customer could see, while every test
of the list went green. Second, the answer could not be filtered out of protection afterwards either,
because the derivation records only one group as the reason - an account in both Domain Admins and
Account Operators would have been reported as a non-administrative owner, which is the product
stating something false. So *is this an acceptable owner* is now derived once in its own right,
walked over the accepted groups alone, and stored beside the protection answer rather than inside
it. That is the first of the five questions [`0101`](decisions/0101-one-versioned-principal-registry.md)
requires; the other four are scheduled, not folded in.

### Schema Admins ownership has a target scope, decided 2026-09-05

**Accept the forest-root Schema Admins group and its members as owners only within that forest's
schema partition**, including the schema root itself. The owner selected both the group and its
members, recorded in [0109](decisions/0109-schema-admins-ownership-is-accepted-only-in-the-schema.md).
Ownership elsewhere remains reportable unless a separate accepted membership gives broader authority.
Someone in both Schema Admins and Domain Admins must not lose the broader acceptance.

The group is identified by its forest-root SID, not its name or RID 518 under any domain. The target
must be in the captured forest's schema, not merely under a similarly named container. Protection
by AdminSDHolder does not establish this answer: ownership acceptance remains independently derived.
Distribution nesting is not administrative authority. When a schema membership is proven but other
membership evidence is incomplete, acceptance inside the schema is known and acceptance elsewhere
may remain unknown. Missing forest identity must not authorize the exception.

**Implemented and verified against the same evidence.** `OwnerAcceptance.SchemaOnly` and
`OwnerAcceptance.SchemaOnlyOtherwiseUnknown` preserve the scoped answer and uncertainty outside it.
The unrestricted list still excludes RID 518. Derivation schema 9 refuses older owner semantics;
both ownership rules are version 2. `JudgingContext.ForestFqdn` supplies the captured forest identity
to the target check, and explain mode now supplies the same inputs as normal judging.

On a copy of ad.lab-20260905-212426, re-deriving and judging changed SEC-031 from **1,788 to 10** and
left SEC-032 at **0**. Both still reached 8,379 verdicts with **four undecided objects**. The removed
findings are exactly the 1,778 Schema Admins/schema cases; the ten machine-owned findings remain.
The schema root was also checked through explain mode, which reports a reached verdict and no
ownership finding. Evidence retained SHA-256
2DEF9F8AD4DE01877970B7F97F845716C1FFC1B093B01F388004610526E76BE4. The scoped derivation generation is
f67940b1-105c-4092-916e-d8b2bcb5c730. Artifacts remain in
next/artifacts/ownership-volume-20260905/, with the scoped prefix and scoped bundle copy.

**The checks were observed failing.** Removing the scoped membership roots caused four derivation
test failures, including *expected SchemaOnly, actual NotAccepted*. Inverting the target boundary
caused all ten scope cases to fail: legitimate schema ownership was reported and outside ownership
was accepted. Restoring both changes gave 120 passing targeted derivation, persistence and ownership
tests. The schema-8 refusal test failed before the version bump and passed afterwards; the actual
schema-8 lab store was also refused with both versions named before it was re-derived. These checks
did not detect every future schema edit made without a version bump. P-149's independent structural
checkpoint and disabled-refusal control have since been implemented with P-146, described above.

**P-147's measured blocker is resolved.** That correction built no control edges or multi-route
presentation; P-146 subsequently implemented 0108's route explanation. Stage 6 has since produced
control-edge output, and its measured P-150 correction is linked above. P-145's expectedness and
visibility acceptance subsequently closed on 2026-09-12, without closing separate capability-specific
laboratory or customer-scale gates. The ten remaining ownership
findings and four undecided objects are not a claim of a clean forest.

### Measured ownership volume on ad.lab, 2026-09-05

**This is the five-operator ownership comparison, not P-145.** That row needs control edges and
their expected/unexpected/unknown classifications, which were not implemented when this comparison
was performed. The later initial-slice measurements are in the judgement-store document; they do
not turn this ownership comparison into a P-145 acceptance pass.

**This subsection preserves the earlier schema-8 comparison, before the scoped correction.** The
subsequent schema-9 result and the resolution of P-147 are recorded immediately above it; these
historical version numbers do not state the current derivation schema.

**One capture, two policies.** The CLI captured ad.lab-20260905-212426: three domains and 8,383
objects. A copy of that sealed evidence was derived and judged with 548, 549, 550, 551 and 552
temporarily added to `ProtectedGroupCatalogue.AcceptedOwnerRids`. After restoring the original
source exactly, the original bundle was derived and judged again. This isolates the five groups;
it is not a rollback of every change made by `0107` or a comparison with the predecessor.

The existing `next/tools/explain-derivation.ps1`, `next/tools/judge-bundle.ps1` and
`next/tools/show-findings.ps1` produced and read both results. No throwaway test class or directory
modification was used. The artifacts are in next/artifacts/ownership-volume-20260905/.

| Rule | Five operator groups accepted | Current policy | New findings |
|---|---:|---:|---:|
| SEC-031 | 1,788 | 1,788 | 0 |
| SEC-032 | 0 | 0 | 0 |

**Both rules reached 8,379 verdicts and could not decide four objects, under both policies.** Their
stored outcome is `Indeterminate`, with `ProtectedPrincipals.MembershipIncomplete` recorded for
each rule. These are reported findings, not a claim that every object was judged. The derivation
records four unresolved protection answers: three with `PrimaryGroupTraversalResearchBlocked` and
one with `PrincipalClaimDisputed`. The separate owner-acceptance answer was not unknown.

**The policy switch was observed, not assumed.** Reading the persisted derivations back gave 29
accepted principals before and 13 afterwards. The sixteen changed answers are the five operator
groups in each of the three domains and one account reached through Backup Operators. Both complete
ownership reports, including finding text and targets, are identical after excluding their
bundle/store headers. There are therefore no new findings from this comparison to call wrong.

**What the 1,788 findings are actually about:**

| Owner and target | SEC-031 findings, under both policies |
|---|---:|
| Schema Admins owning the schema partition itself or its descendants | 1,778 |
| Computer accounts owning Windows Virtual Machine service-connection records | 8 |
| BADC and PHDC owning domain-reference objects in the configuration partition | 2 |

**The first 1,778 exposed the reporting defect P-147, not a five-operator volume increase.**
The finding said Schema Admins was *not an administrative principal* on the very schema that
[Microsoft's security-groups reference](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups#schema-admins)
gives it full administrative access to. That was misleading, not merely verbose. The target-scope
decision was subsequently accepted and implemented as `0109`; the current run no longer emits
those 1,778 findings. The ten machine-owned objects carry the stated ownership, but
this measurement does not establish that their ownership is improper or evidence of abuse.

**Verdict at the time of the five-group comparison: no observed increase, but not ready for stage 6.** The
existing Schema Admins volume is already the failure this check was meant to catch. It is recorded
as high severity on P-147; it was subsequently corrected by scoped acceptance under 0109, measured
above, rather than by suppressing findings. This small lab result cannot establish the impact in a forest with years of operator-group
delegation, and the four undecided objects remain undecided.

**Reproducibility:** both evidence files retained SHA-256
2DEF9F8AD4DE01877970B7F97F845716C1FFC1B093B01F388004610526E76BE4. The before derivation generation is
066e66ca-3cc6-48dd-bf00-0b66b4fe3bcc and its judgement generation is
338e54a1-e0fe-4d0a-ae76-261a74e2b5f2. The after generations are
0f3b1913-434e-4a1c-8a03-f72185e537ff and b5abf116-8918-4d44-aa09-492c80d059b9 respectively.
Both derivations in this earlier comparison use schema 8. At its conclusion the temporary catalogue
change was restored and its source hash matched the pre-measurement hash; scoped acceptance was
implemented afterwards.

**A high-severity verification defect was found and fixed during the comparison.**
`ObjectOwnershipRuleTests.OwnershipAndTheControlPlaneClassifyTheSameIdentifierCompatibly` stayed
green while all five operator groups were accepted. Its owner fixture gave built-in groups a null
domain, so the rule's domain-scoped lookup never read the supplied acceptance. Correcting the
fixture in `ObjectOwnershipRuleTests` made the widened policy fail with
*S-1-5-32-548 is outside the control plane under 0099, so ownership must report it.* Restoring the
then-current policy made all 24 ownership-rule tests in that comparison pass. The test still compares against the
repository's written-out `0099` set, not Microsoft's specifications or the unbuilt control-plane
catalogue. It must be retargeted when that catalogue is built; this fixture repair does not discharge
that obligation.

---

**A question the owner has already answered is a defect in this repository.** When he answers one,
it belongs here, in the same turn.

