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
- At programme start the native formats were capture root 3, Navigation 2, overview 1, Evidence 17,
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
| 0: evidence and continuing baseline | RESP-00/01 | Preserve current source/controls and continue the cost map alongside fixes; unfinished baseline tooling is not a blanket implementation gate |
| 1: run lifetime and all ordinary entry points | RESP-02/03/04 | Prompt shell/Home, consistent results entry, continuous trust reuse and lightweight normal data for every ordinary view, including LAPS and Delegations |
| 2: complete requested-detail journey | RESP-05/06/07 | Original attributes/permissions, saved classifications and route/control detail served at the requested boundary, with matching query, paging and UI lifecycle behaviour |
| 3: audit throughput and resource contention | RESP-08/09/10, RESP-11 if demonstrated necessary | Corrections to measured dominant judging/capture costs without weakening coverage, plus derivation/worker changes only where evidence warrants them |
| 4: enterprise proof and delivery | RESP-12/13 | Whole-journey performance evidence, ordinary display checks, accurate unresolved limitations and a self-contained correct-source handoff |

UI responsiveness is the first delivery objective.
**Owner direction, 2026-10-16:** start application fixes now, using the evidence and validated
controls already available rather than extending general measurement preparation first.
RESP-02/03/04 may begin on RESP-00 and their confirmed application scope; finish only the
measurement needed to inform or verify each changed boundary, keeping broader RESP-01/12
coverage and enterprise acceptance explicitly outstanding.
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

**Status:** open - approved RESP-01 execution in progress; producer, ordinary-view and real application-composition/Home/saved-entry controls verified, with an explicitly unaccepted return-selection finding; new-run/full-journey/enterprise inputs, the fixed campaign and numerical response budgets remain outstanding. **Dependencies:** RESP-00.

Use existing phase records and a proposed fixed offline workload/run matrix to record first paint, complete load/render, verification, SQL, content assembly, allocations/memory and audit-stage costs for the journeys below.
Distinguish new-run handoff, a fresh-process saved-run opening, warm browsing and close/reopen, identify binaries/input hashes and modelling limits, and recommend numerical per-journey response budgets after measuring the enterprise-shaped workload.
Complete with one retained baseline and an engineering-owned batch scope/format/UI proposal tied to those costs, without live access, recycled old service timings, rerunning completed campaigns by default or asking the owner to design the solution.

**Historical measurement approval, 2026-10-15:** [RESP-01 baseline and execution scope](C:/Users/jistrand/.copilot/session-state/4ea6589b-ca69-49ce-88bf-295f68d91d87/files/resp01-baseline-execution-scope.md) - retained inputs/settings, matrix and budget protocol; its measurement-only restriction is superseded for the confirmed RESP-02/03/04 batch by the owner's application approval of 2026-10-16

**Preservation checkpoint:** expected branch/HEAD; all 18 arrival-file hashes and nine retained test-output assembly hashes matched the handoff; no build, test, measurement or application-source/format/UI change in packet preparation

**Execution checkpoint:** [current state and evidence map](C:/Users/jistrand/.copilot/session-state/4ea6589b-ca69-49ce-88bf-295f68d91d87/files/resp01/current-state.json) - explicit control-only measurement mode; 343 objects, 795 original member occurrences, 32 current rules and saved Groups/LAPS/Tier 0/permission readback; 72 focused regression checks passed; all 16 new cases mutation-covered across nine rebuilt defects with 20 failing and 20 rebuilt restored observations; final correct-source Release rebuild, 0 errors/866 warnings

**View-control checkpoint:** [current view-control state](C:/Users/jistrand/.copilot/session-state/4ea6589b-ca69-49ce-88bf-295f68d91d87/files/resp01-browsing-v1/current-state.json) - 36 read/draw/dispatcher observations at each of 900/1300 widths through first protected opening, warm revisit and close/reopen; all ordinary surfaces, direct/group-held Delegations and group findings/original-membership/return; 78 focused harness checks passed, six new cases mutation-covered by six rebuilt defects with 12 failing and 12 rebuilt restored observations; final correct-source Release rebuild, 0 errors/866 warnings

**Real application checkpoint:** [startup/Home/saved-entry state](C:/Users/jistrand/.copilot/session-state/4ea6589b-ca69-49ce-88bf-295f68d91d87/files/resp01-startup-v1/current-state.json) - fresh measurement-host processes execute the real App composition and compiled ShellWindow with isolated settings; empty/saved/unavailable libraries at 900/1300, first drawing and Home, selected saved-run Dashboard entry, Home return and reopen; six final process controls/12 window journeys, 97 focused checks passed, eight new trace cases and all six process cases reject rebuilt missing-observation/undrawn defects; five isolated variants with 20 failing and 20 rebuilt restored observations, final correct-source Release 0 errors/866 warnings

**Not enterprise acceptance:** the application control times fresh measurement-host entry, not the installed product executable's loader; synchronous library refresh, default application behaviour and UI wording/layout remain unchanged; new-run handoff, large-library/tail/refusal corpus, remaining selected permission/classification/path/huge-value and accounting/overhead/enterprise endpoints are outstanding, and RESP-07-F01 remains explicitly unaccepted

**Commit boundary:** validated 24-path serving/programme/producer-control checkpoint committed as `fde2eb21c7be89c74812cf777b7f2e06fcc99207` at the owner's request, without push; subsequent view-control work remains uncommitted; earlier binary-equality/provenance records retain their original pre-commit build identity, while later rebuilds identify this committed base

### RESP-02 - Unify protected run lifetimes and trustworthy stage handoffs

**Status:** done - continuous capture publication/first analytical opening and the protected analysis/completion/viewer handoffs are implemented and focused offline behaviour-verified; enterprise-shaped response-budget acceptance remains RESP-12. **Dependencies:** RESP-00; RESP-01 is supporting work, not a blanket gate.

Give one explicit owner responsibility for exact captured/derived/judged generations through analysis, completion and browsing, reusing already established verification only while unchanged-file protection is continuous.
Eliminate demonstrated cross-stage reopening/rehashing and repeated deep consistency work where its guarantee can safely be retained, while preserving cancellation, lease disposal, source/resource binding and cheap current-request checks.
Complete with actual verification/read observations and rebuilt corruption, replacement, stale-generation, handoff-failure and lifetime controls, not a persisted already-verified flag or a more permissive reader.

**Capture-to-analysis checkpoint, 2026-10-16:** [verified current state](C:/Users/jistrand/.copilot/session-state/32d52e66-b752-4eb0-b670-61e4ef9290cc/files/resp02-capture-handoff/current-state.json) - all four captured products stay protected across sealing, rename and atomic root selection, and enter the existing run owner inside capture's reported publication work; the application, CLI, capture summary, capture-only/later opening and failure/cancellation/disposal use that lifetime without a persisted verdict, changed native formats or changed screen wording/layout.
The final correct-source Release rebuild has 0 errors/890 warnings and 606 combined affected cases passing, with 31 new plus five strengthened cases all detecting a rebuilt defect across 22 qualified variants/61 failing and 68 rebuilt restored observations, and two fresh-process application controls/eight window journeys at 900/1300 using the retained current-format input.
The corrected refusal-code regression's earlier 599-pass/one-failure result, the 29/30 mutation-coverage stop and fixture/compiler/script attempts remain retained alongside the earlier 705-pass checkpoint, 704-pass/one-timeout run and repaired ordinal-test survivor, while RESP-07-F01, the unchanged three null-default signatures, coarse requested-proof verification, physical-display checks and enterprise budgets remain unaccepted.

### RESP-03 - Make launch, Home and results entry lightweight and consistent

**Status:** done - launch/Home/results-entry application behaviour implemented and focused offline controls verified on 2026-10-16; actual application loading time remains open under RESP-03-F01, and production-shaped response-budget acceptance remains RESP-12, not a claim made by the small controls. **Dependencies:** RESP-00; RESP-01 is supporting work, not a blanket gate.

Show the shell without a synchronous whole-library refresh, load authoritative compact run headers asynchronously, and refresh Home without needlessly reopening run payloads or losing the selected-run context.
Use the existing Dashboard results landing as the proposed common destination for both a newly finished audit and a saved library run, retaining the current presentation unless a specifically approved loading/behaviour mockup changes it.
Complete against launch/first-paint, large-library/Home-return, new/existing-run entry and selection-preservation journeys, including slow/unavailable storage and cancellation.

**Finding RESP-03-F01 - MEDIUM, open:** on 2026-10-16 the owner reported roughly 12 seconds from launching the application until the UI appeared in the small lab with one run in the library; executable/build provenance was not supplied, so this is an owner-observed delay rather than a controlled current-build baseline.
Revisit the actual launch-to-first-visible-window wait, including executable/runtime startup and work before the first window, identifying the build and where the time is spent without assuming library enumeration is the cause or treating measurement-host timings as the same endpoint.
The owner wants the remaining responsiveness work to continue while this startup follow-up stays open; completed functional changes do not accept loading performance, and this entry alone does not authorize a new measurement campaign/tool or application behaviour change.

### RESP-04 - Finish lightweight serving for every ordinary view

**Status:** done - ordinary LAPS/Delegations serving implemented and offline behaviour-verified alongside the existing ordinary views; first verification of the shared original-descriptor product is still a whole-file unit, and enterprise performance and the separate RESP-07-F01 return-selection defect remain unaccepted. **Dependencies:** RESP-00; RESP-01 is supporting work, not a blanket gate.

Reuse the implemented Dashboard/Rules/Objects/Findings/Groups/Tier 0 foundations and remove remaining ordinary-view dependencies on unrelated bulk, beginning with LAPS inventory in the classification-heavy Facts product and the direct/group-held Delegations query path.
Produce required metadata/indexes in their proper capture/derivation/judging stage with exact scope/count/qualification/source binding, preserving capture-only reads, original proof separately, missing-judgement refusals and no compatibility fallback.
Complete with every ordinary tab, filter/page/revisit/reopen and supporting action exercised against the integrated services while unrelated bulk is inaccessible, followed by complete-view measurements rather than only reader timings.

**Application implementation checkpoint, 2026-10-16:** [verified current state](C:/Users/jistrand/.copilot/session-state/5c372f1d-ec4a-499b-b140-baea9ce24eb1/files/responsive-application/current-state.json) - Home precedes library enumeration; compact published headers, background refresh, selection/stale-error protection and every affected action/return/adoption caller are wired; new and saved completed runs share Dashboard; continuous analysis/completion/viewer protection, ordinary LAPS in the main serving file and captured Delegations/derived Membership products preserve the saved meanings without changing screen wording/layout.
The final correct-source Release rebuild has 0 errors/884 warnings, with 701 combined checks plus four separately run unchanged UI controls passing, 34 qualified rebuilt defects/73 failing and 102 restored unit observations, all 43 new cases detecting a defect, eight refused/eight restored real-application cases and eight final fresh-process application controls covering 20 window journeys at 900/1300 widths.
Current native formats are capture root 4, Navigation 3, overview 1, captured Delegations 1, Evidence 17, Derivation/Membership 17 and Judgement 76 with 32 rules; older formats are refused rather than migrated or rewritten, and the 343-object/seven-descriptor-position control, capture bootstrap gap, first shared-descriptor verification, remaining synchronous annotation/baseline metadata writes, unperformed physical-display checks and enterprise response budgets are not accepted by these results.

### RESP-05 - Implement one requested-detail read and integrity boundary

**Status:** open - path-proof chunks, saved text and seven shared permission/control record producers are source-owned and offline correctness-verified; changed-boundary combined-cost acceptance, original captured payloads, remaining proof fields, generic oversized `WITHOUT ROWID` sources and complete application acceptance remain unfinished. **Paused 2026-10-17:** the owner's corruption-only integrity direction puts per-record verification under review (see Next action). **Dependencies:** RESP-02, RESP-04.

Define and implement one coherent boundary spanning captured attributes/member values, original descriptors/entries, saved per-right classifications/schema support and requested path/control/member proof, selecting only the object/family/page the consumer needs.
Choose the native storage/integrity mechanism from RESP-01's costs, retain shared descriptors/proof components and exact original bytes/occurrences, and prove requested data independently without silently weakening existing seal/WAL checks or returning partial objects from whole-object APIs.
Complete with all four detail families integrated through the same protected selected-run ownership, strict missing/corrupt/foreign/oversized-data refusals and rebuilt end-to-end controls, leaving no parallel obsolete production reader or unapproved custom block adapter.

**Owner-approved scope, 2026-10-16:** implement the single four-family native requested-detail boundary recorded in [product orientation](WHAT-THE-PRODUCT-IS.md#fix-and-feature-priority), using publication-root-anchored logical-page verification rather than a custom SQLite VFS.
Approval includes the necessary native-format/read-contract changes and focused offline boundary/corruption/binding/large-value/cancellation/reopen verification, rebuilt isolated defects/restored controls and a final fresh-provenance Release rebuild, with added preparation/storage costs reported honestly and current wording/layout and explicitly whole-collection cards retained.
This is scope confirmation, not application implementation or performance acceptance; RESP-06/07 and enterprise budgets remain open, and no general measurement campaign, existing-input rewriting, live work, recapture, discovery/budget/SYSVOL change, deployment, commit or push is authorised.

**Foundation checkpoint, 2026-10-16:** [preserved state and exact evidence](C:/Users/jistrand/.copilot/session-state/81f37a59-afea-4c08-a978-b289e4063a0e/files/resp05/current-state.json) records source-owned payloads with bounded logical metadata/value pages, hierarchical SHA-256 commitments in existing atomic roots and requested leases in the existing run owner, with selected captured fields/original membership and the evidence-owned classification descriptor lookup wired through them.
Native formats are capture root 5, Evidence/Derivation/Membership 18 and Judgement 77, with Navigation 3, overview 1, captured Delegations 1 and 32 rules unchanged; the final correct-live-source Release rebuild has 0 errors/892 warnings, 627 of 628 affected cases pass with the explicit no-domain refusal below, all 28 new plus three adapted cases detect rebuilt defects across 21 qualified variants/63 failing and 651 rebuilt restored observations, and the real-source 900/1300 drawing controls pass.
RESP-05 is not complete: original descriptor/entry, saved classification/schema-support and control/member/path application consumers still need the requested boundary, the generic oversized WITHOUT ROWID case still explicitly refuses rather than streams, and preparation/storage cost, whole-journey response budgets and physical-display acceptance remain unaccepted, without live work, migration, deployment, commit or push.

**Consumer continuation checkpoint, 2026-10-16:** [current state and exact evidence](C:/Users/jistrand/.copilot/session-state/80a0c8d8-c171-4c40-abb8-e4a17be33f73/files/resp05-continuation/current-state.json) records original DACLs, saved per-right classifications/schema support and selected control/Self-Membership/member/path consumers using the existing protected logical-page boundary, with saved selection references/counts, complete source/resource/generation binding, separate whole-file checks and unchanged wording/layout; capture root 5, Evidence 19, Derivation/Membership 18 and Judgement 78 are current, while Navigation 3, overview 1, captured Delegations 1 and 32 rules are unchanged.
The final correct-live-source Release rebuild has 0 errors/895 warnings, 933 of 936 affected cases passing with exactly RESP-05-F01 and the two baseline-reproduced RESP-05-F03 fixture failures retained, all 13 new cases detecting rebuilt defects across 20 qualified variants/46 failing and 68 rebuilt restored observations, and 53 focused controls including real-source 900/1300 drawing passing; rejected SQL-slice and stale-binary-staging attempts remain preserved rather than counted as verification.
RESP-05 remains open for the generic oversized native-source limitation below and changed-boundary producing/storage-cost verification, with ordinary Delegations' first shared-descriptor product verification, enterprise budgets, physical displays, RESP-03-F01, RESP-07-F01 and the known null-default gate still unaccepted and no live work, migration, deployment, commit or push authorised.

**Finding RESP-05-F01 - MEDIUM, open:** the existing `ASealedBundleThatReachedNoDomainStillOpensAndSaysSo` check fails because captured-library coverage validation refuses its all-unread-domain run as contradictory.
That validation is unchanged in this correction and the failed result is retained, but an earlier executable was not rebuilt to establish baseline behaviour, so the failure is neither attributed to nor claimed fixed by the new index.
Keep this explicit refusal unaccepted while continuing the approved requested-detail work, without changing coverage semantics or diverting into RESP-03-F01.

**Finding RESP-05-F02 - MEDIUM, open:** generic text/binary values above 64 KiB in a `WITHOUT ROWID` source still explicitly refuse during requested-index preparation rather than publishing truncated evidence.
The retained SQL-slice attempt was rejected because a bounded returned buffer does not establish bounded SQLite internal reads or allocations; the rebuilt refusal controls preserve the complete original value and prevent a partial index from being published.
Resolve the genuinely streamable native source representation before claiming unrestricted large-value coverage, without silently adding a VFS, encoding experiment, sealed-input rewrite or evidence limit.

**Finding RESP-05-F03 - MEDIUM, open:** broader readback verification found two completion controls failing during fixture setup: the GUI completion control requests an exclusive evidence lock during a protected handoff, and the shell derivation control tries to change the protected derivation database.
Both failures reproduce against the hash-matched pre-continuation Release binaries, with the original and current results retained, so neither is attributed to the requested-detail consumer changes or relabelled as a passing check.
Keep these controls unaccepted alongside RESP-05-F01 without changing protected handoffs, restarting RESP-02/03/04 or making their repair a prerequisite to the remaining RESP-05 correction.

**Finding RESP-05-F04 - HIGH, open:** the owner's supplied 2026-10-16 lab log identifies a Release engine module matching the final local build and records requested-detail index preparation at 117.852 seconds out of roughly 163 seconds of judging for 8,444 objects, versus a 9.276-second object-analysis pass and 264 ms of saved-selection preparation.
Source confirms whole-product preparation, per-cell source reopening/hashing and a fresh 64-KiB buffer for every nonempty text/binary value; [fingerprinted existing-log analysis](C:/Users/jistrand/.copilot/session-state/80a0c8d8-c171-4c40-abb8-e4a17be33f73/files/resp05-lab-cost/analysis.json) retains the separate 50.3-second capture-backfill interval, 22.141 GiB of cumulative process allocation during publication rather than peak RAM, and 1.850 seconds of actual judgement-file sealing, without attributing every interval or allocation to one function.
Prioritize the owner-approved source-owned payload replacement below and focused time/storage validation before adoption, preserving original evidence and open findings rather than accepting this build for production, linearly projecting lab runtime, restarting RESP-02/03/04 or beginning another live audit/general measurement campaign.

**Replacement approved to try, 2026-10-16:** the owner agreed to the source-owned verified payload/compact lookup replacement described in [product orientation](WHAT-THE-PRODUCT-IS.md#fix-and-feature-priority), retaining the full working-application requirement, the four detail families and the existing integrity/security-claim boundaries rather than merely tuning the generic catalogue or reducing Stage 6/7.
Use `perf02/source-owned-blocks` in a separate local worktree seeded with the complete current uncommitted sources, leaving `perf02/responsive-browsing` and its existing application binaries intact as the baseline, with [exact preservation and setup evidence](C:/Users/jistrand/.copilot/session-state/80a0c8d8-c171-4c40-abb8-e4a17be33f73/files/resp05-replacement/setup.json).
No improvement or adoption is accepted until focused producing/storage/readback verification and the complete real-application lab journey establish it; all original inputs, failed attempts, frozen anchors and RESP-03-F01/RESP-05-F01/F02/F03/F04 remain preserved, with no rollback, new live audit, production access, deployment/package overwrite, commit or push authorised.

**Source-owned payload checkpoint, 2026-10-17:** [verified state and exact evidence](C:/Users/jistrand/.copilot/session-state/36cc10a6-3c73-4958-a2b5-2eb8c083e562/files/resp05-source-blocks/current-state.json) records final-write path-chunk fingerprints and compact authenticated lookup pages, retaining exact shared proof bytes, complete Stage 6/7 behaviour and separate whole-file verification; requested index 2 and Judgement 79 are current, with 32 rules unchanged.
The final correct-source Release rebuild has 0 errors/899 warnings, 85 focused controls pass, all 17 new cases detect 14 rebuilt isolated defects with 18 failing/22 restored observations, and expanded cross-family verification passes 1,689 of 1,692 cases with only RESP-05-F01 and the two retained RESP-05-F03 fixture failures; four expensive historical paging controls and two interrupted expanded runs remain unaccepted.
The cold 50-chunk header check measures 129,004 native read bytes against its 3,298,724-byte deliberate payload-read control, and the same-source mechanism comparison includes final writing, preparation, readback and logical storage, but this first producer conversion does not complete the four-family replacement, resolve F02/F04 or establish whole-application performance or lab acceptance.

**Integrated saved-text checkpoint, 2026-10-17:** [verified state and exact evidence](C:/Users/jistrand/.copilot/session-state/a91f827f-ef09-493b-b287-363b600857fc/files/resp05-source-blocks/current-state.json) records final-write bounded UTF-8 payloads for saved descriptor/classification/schema support, shared permission explanations/control routes and member expansion/context proofs, with production-time and browsing readers converted together, exact saved answers/bindings retained, raw permission-byte BLOBs unchanged and later membership preparation kept outside the active assessment loop; Judgement 80 and requested index 2 are current, with other formats and all 32 rules unchanged.
The final correct-source normal Release rebuild has 0 errors/902 warnings, all 85 focused controls pass, exact affected verification passes 633 of 638 cases with only F01/F03/F06 retained, all 35 new cases detect 12 rebuilt isolated defects with 36 failing/47 rebuilt restored observations, and the final isolated 42-case selection passes while all 62 historical layout values and 39 XAML files remain unchanged.
Cold 50-piece headers read 126,578/140,102 native bytes against 3,298,724-byte full-read controls, text mechanism comparisons count writing/validation/preparation/checkpoint/close/seal/readback/storage, and the complete offline 343-object/32-rule control retains the same saved-answer fingerprint under generic and source-owned preparation, but these synthetic controls do not accept the original application comparison, F02/F04, remaining source families, physical displays, enterprise budgets or complete owner-lab application journey.

**Finding RESP-05-F05 - HIGH, fixed before handoff:** the new text reader initially cleared the local transaction inherited from `CreateCommand`, so Stage 7's read of earlier control proof during an active writing batch failed in the complete offline audit even though detail-only controls passed.
The reader now preserves that transaction unless an explicit transaction is supplied, matching the installed SQLite provider's documented implementation without changing transaction or protection semantics.
Both direct producing-transaction controls and the complete offline audit detect the rebuilt regression and pass again after an explicit restored rebuild; the failed first audit control remains retained.

**Finding RESP-05-F06 - MEDIUM, open:** expanded exact-method coverage reaches two older segment fixtures absent from the prior accepted selection: the global table-name uniqueness check rejects per-product `detail_selection`, and the WAL fixture expects typed Findings success while its supporting proof has uncheckpointed bytes.
Both fail identically against hash-verified retained format-79 arrival binaries and the final format-80 candidate, with the source-location witness passing in the isolated arrival copy.
Keep these two checks unaccepted alongside F01/F03 rather than changing WAL/protection semantics, weakening the ownership check or attributing their failures to this producer conversion.

**Permission/control record checkpoint, 2026-10-17:** [verified state and exact evidence](C:/Users/jistrand/.copilot/session-state/a91f827f-ef09-493b-b287-363b600857fc/files/resp05-permission-records/current-state.json) records producer-authored fingerprints and bounded temporary metadata for seven immutable permission/control tables, consumed into the same publication index without rereading their payload bodies or retaining another permanent payload copy; native bytes, read contracts, formats, all 32 rules, budgets, wording/layout and raw application-data BLOB storage remain unchanged.
The final normal Release rebuild has 0 errors/904 warnings, all 225 exact affected cases and 32 final focused cases pass on identical modules, all 28 new cases detect 15 explicitly rebuilt isolated defects with 36 failing/86 rebuilt restored observations, and canonical publication roots match generic preparation while all 63 existing layout values and 39 XAML files remain unchanged.
Native preparation reads 81,936 bytes against an 18,780,176-byte deliberate generic payload-read control and the complete offline 343-object/32-rule audit retains the same saved-answer fingerprint, but the mixed small-record combined-cost results below, retained slower prototype, remaining producers, F02/F04/F08, owner-lab journey, physical displays and enterprise budgets are not performance-accepted.

**Finding RESP-05-F07 - HIGH, fixed for the converted record producers:** an independent native-byte check found a large input string stored as 196,611 bytes instead of its original 196,615 when an embedded NUL and following BOM were lost through ordinary string binding.
The affected permission/control INSERTs now bind exact UTF-8 bytes through SQLite's documented BLOB-to-TEXT cast and hash those same bytes, preserving TEXT storage and complete readback without changing the raw application-data BLOB representation.
Both short and large NUL/BOM/Unicode text, original callback bytes and complete permissions round-trip under rebuilt regression controls; this is not a claim that every unconverted capture/string producer has been assessed.

**Finding RESP-05-F08 - HIGH, open, part of F04 acceptance:** reduced payload reads and allocation do not establish lower combined audit cost, and the final 256-row native control measured producer-metadata writing/preparation/seal/readback at 468.3336 ms versus 438.2044 ms for generic preparation, with other retained observations going in both directions.
The first correct two-table staging prototype was retained rather than adopted, and its replacement removes the redundant header write/read and re-encoding of already-bound strings, but all costs, outliers and temporary metadata remain in the accounting.
Keep performance adoption open pending permission-record-shaped combined producing/publication/storage evidence and the separately authorised complete application lab journey; do not accept a smaller preparation number, repeat until green, forecast production linearly or reintroduce a parallel full payload copy.

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

**Finding RESP-07-F01 - MEDIUM, open:** the offline real-view control at 900/1300 widths can return from a selected group's original membership with another group highlighted, despite unchanged saved page contents and generation binding.
The Groups refresh clears the bound collection before its loader captures the selected identity, allowing WPF selection changes to lose the intended row; the existing first-row-only return control did not expose it.
Retain the failed control observations and treat this return journey as unaccepted until the approved UI-lifecycle batch repairs it, without stopping RESP-01's remaining measurements or changing application behaviour under measurement-only approval.

### RESP-08 - Reduce the dominant judgement/requester/path workload

**Status:** not pursued - the owner accepted the 4 h 37 m production judging time on 2026-10-17 (see [WHAT-THE-PRODUCT-IS.md](WHAT-THE-PRODUCT-IS.md)); reopen only if he reverses this or a browsing change regresses judging beyond repeat variability. **Dependencies:** RESP-01.

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

**Finding RESP-12-F01 - HIGH, fixed:** a new ordinary-Delegations comparison let both readers repeat the same incorrect original ACE ordinals, so its first rebuilt ordinal defect survived all eight cases.
The checks now also assert fixture-defined original ordinal sequences, raw access masks, inheritance flags, callback bytes and unknown/qualified capture states independently of the shared reader.
The surviving attempt is retained unchanged, and the rebuilt repaired ordinal/mask defects fail eight/four cases respectively before their rebuilt correct-source controls pass all eight.

**Finding RESP-12-F02 - MEDIUM, open:** the final combined regression run hit the unchanged 30-second drawing-control watchdog at width 900, and its cause has not been established.
The same four unchanged UI controls passed separately and the other 701 affected checks passed together; the earlier 704-pass/one-timeout result is retained rather than relabelled or its watchdog raised.
This does not establish a product contention defect, a numerical response budget or enterprise acceptance, and the ordinary-view controls still explicitly retain RESP-07-F01 at both widths.

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

**Approved batch, 2026-10-16:** background launch/Home library refresh with selected-run retention,
stale-result/error protection and the existing unread state; new and saved completed results both
land on the existing Dashboard; safe run-protection handoffs and lightweight ordinary LAPS/Delegations
serving, including required native serving table/index/version changes, with all evidence/answers/counts/
qualifications/bindings preserved and current wording/layout unchanged

**Next action:** the owner stated on 2026-10-17 that his only integrity concern is accidental corruption and that no earlier decision binds ([product orientation](WHAT-THE-PRODUCT-IS.md)), so make no further source-owned RESP-05 conversions until he chooses a direction.
The last commit (`c690b357`) contains none of the RESP-05 code, so the 117.852-second judging stage that F04 measured does not exist there; what remains is the cost of opening large runs (246 seconds for 38.6 GB in production).
Confirmed 2026-10-17: all 60 uncommitted paths in the original folder are RESP-05 requested-detail work and every one is also saved in `87d8284` (42 identical, 18 changed again there), so building from the clean commit loses nothing; the 2026-10-16 lab summary's Product line shows only `c690b35` although that build carried those uncommitted changes, so hand over only builds from a clean committed folder and name the commit.
The owner approved on 2026-10-17 a build from the clean commit that verifies every product once when a run opens and does no whole-file hashing afterwards, logging each file's size and check time at open; it is built on branch `perf02/verify-once-at-open` in the clean worktree (`SecureAD.Next-blockspike`), whose own queue entry records the current commit, package and lab results, and this paused RESP-05 branch is superseded unless he asks for it (the block-level verification spike and further per-record proofs likewise).
The first package from that branch (commit `e902f878`) wrote a damaged `run.log` in its first lab run and was replaced; use the package named in that worktree's queue entry.
Clean-commit package built 2026-10-17 for that run at `next/artifacts/release-20261017-155530-c690b357-99bbe59d` in the clean worktree: commit `c690b357`, 0 uncommitted entries at publish time, 0 build errors, `SecureAD.exe` SHA-256 `383AF08BE91641AD7BCE72CCAF05AA6D547725B76E84FA3C8B6D06D4370287A1`, and a binary search found none of the `prepare-requested-details`/RequestedDetail code while two control strings present in both builds were found; the owner's lab judging time on it is the gate before any new change.
Checked 2026-10-17 on this box (CLI built from the same commit, run only on scratch copies): a 2026-10-11 lab bundle is refused (Evidence 16 against 17, no `evidence.current.json`), and a bundle in the build's own format opens and can be re-derived and re-judged without recapture; so neither the 2026-10-12 production capture nor the 2026-10-16/17 lab capture (Evidence 19) can be reused, and the gate needs a fresh capture on the clean package, which waits on lab access that was down for maintenance.
**Gate result, 2026-10-17 - passed:** the owner's fresh lab audit on that package (bundle `ad.lab-20261018-000147`; its own log records commit `c690b35` and executable `383AF08B…`, and all 10 segments match their manifests) took 15.2 s to capture, 2.2 s to derive and 49.5 s to judge, against 76.2, 23.3 and 163 s on the RESP-05 build and 1 m 28 s judging on the pre-branch 2026-10-11 build, with all 32 rules' outcomes and counts and the finding totals (6/12,624/8/11) identical to the RESP-05 run and no warnings or errors; RESP-05's own steps were about 197 of that run's roughly 262 seconds by subtraction (capture sealing step 60 s against 2 s, a 22 s derivation gap, 118 s of requested-detail preparation) and its capture bundle peaked at 310 MB against 29 MB.
The 49.5 s exceeds the ~45 s estimate only because `move-generation-file` (opening the finished files) took 11.6 s, which is the one-time first read of freshly written files that the pre-branch build paid as 13.3 s inside `seal-generation` and the RESP-05 build paid inside its 118-second step, so publishing is 17.9 s against 20.3 s before the branch; its cause on the lab VM is unproven (Defender real-time protection with no exclusions is the suspect) and the production log's per-part times will show whether it scales.
Browsing the 8,444-object lab run took 19-449 ms per click over 23 clicks (first Dashboard 882 ms including drawing; opening/checking never over 64 ms) and the final click was refused by the closed-run guard as designed; this lab scale says nothing about 38 GB, where the open-time check is the cost to remove, and the run is kept untouched as the only real lab capture on this box in the clean build's format.
Complete real-application lab acceptance still needs separate authorization.
The RESP-02/03/04 application correction remains implemented and focused offline behaviour-verified.
Continue the programme's supporting RESP-01/12 evidence and budget work without restarting
launch/Home, ordinary LAPS/Delegations or general measurement preparation as an implementation gate.
Retain the RESP-03-F01 startup-delay follow-up, RESP-05-F01/F02/F03/F04/F06/F08, ordinary Delegations' coarse first
shared-descriptor product verification, RESP-07-F01, the known null-default gate and unperformed physical-display checks as explicit
limitations; this application-level detail approval does not authorise a custom SQLite VFS,
new screen wording/layout, live work, deployment, commit or push.

**Historical approval handoff:** [approved application implementation](C:/Users/jistrand/.copilot/session-state/4ea6589b-ca69-49ce-88bf-295f68d91d87/files/approved-implementation-handoff/next-session-handoff.md) - authority and arrival-state preservation record; the implementation checkpoint above supersedes its unimplemented next-action state

**Historical arrival handoff for this correction:** [capture-to-analysis handoff](C:/Users/jistrand/.copilot/session-state/5c372f1d-ec4a-499b-b140-baea9ce24eb1/files/capture-analysis-handoff/next-session-handoff.md) and [copy-ready prompt](C:/Users/jistrand/.copilot/session-state/5c372f1d-ec4a-499b-b140-baea9ce24eb1/files/capture-analysis-handoff/next-session-prompt.txt) - retained authority/preservation history; the verified capture-to-analysis checkpoint above supersedes its unfinished next-action state
