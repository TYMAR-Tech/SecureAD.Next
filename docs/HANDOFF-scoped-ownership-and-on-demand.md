# Handoff: automatic scoped ownership assessment and explicit single-object analysis

## Start here

Start a fresh session for the next implementation slice. This handoff records the owner's settled direction and unfinished work; it is not a claim that the feature is implemented.

The owner approved this default: **core Tier 0 plus its identified controllers and dependencies receive detailed ownership-takeover assessment during an audit; everything else receives that assessment only through an explicit single-object request against captured evidence.** Scope must be automatic, without a user-maintained important-object list.

The owner then explicitly required **one Tier-0 definition**. Reuse the existing authoritative definition and shared classification implementation. Do not invent an ownership-specific list, copy RIDs into a selector, or derive target importance from expected-admin suppression.

The owner knows Tier-0 path analysis is feasible: the predecessor application already did it. Do not restart a feasibility debate or ask the owner to redefine Tier 0. The question is limiting the expensive ownership work without losing potential relationships needed for future paths and remediation.

## Machine and workspace: check before writing

The owner previously had two AI sessions open and was unsure which machine/session was being changed. Confirm the environment before edits:

- Machine observed when this handoff was prepared: **S2DMEASOFT**.
- Workspace: `C:\Users\jistrand\source\repos\razamus\SecureAD.Next`.
- Solution: `next\SecureAD.Next.sln`.
- Branch: `main`.
- HEAD: `7618cebad789a410dae998b52ee83f234da8522e`.
- SDK observed: **10.0.400**; projects target .NET 10.
- Both .NET/Windows Desktop **10.0.11 and 10.0.12** are installed. Recent documentation tests used 10.0.12; earlier storage measurements used 10.0.11. Recheck actual execution runtime for new measurements.

This handoff and the measurement artifacts are local-only under `.vs`, not in Git. A new session on another machine will not obtain them through the remote repository. Do not assume a clean clone contains the current uncommitted implementation or the retained input databases.

## Authorization and pending approval

The automatic scope and explicit offline single-object direction are settled. The owner said: "I agree with this. its definable without the user assigning anything. lets do this so we cna move on" and requested this new-session handoff.

**Read the current `.github/copilot-instructions.md`.** It distinguishes approved scope from implementation approval and explicitly requires approval before UI wording/layout changes. Do not use this handoff as blanket authorization for unreviewed contracts, UI changes, live work or measurement harnesses. The next bounded step is the shared-classifier/contract work and a concrete implementation-ready proposal; do not reopen the already-settled scope or hand engineering choices back to the owner.

The proposed, but not yet explicitly approved, UI is an **Assess ownership takeover** action in the existing object control section, with **Not assessed automatically** outside automatic scope. Confirm exact wording/layout before Shell edits. No extra top-level screen or manual target-management feature was proposed.

No commit, push, pull/reset, live forest access, recapture, Windows service/power-setting changes, production requester/member activation, production expansion budget, or new scale/measurement harness is authorized. Four previously excluded stage-status tests remain unverified and must not be retried without authorization.

## What has and has not been implemented

### Implemented earlier: shared permission-proof storage

- Judgement schema **25**, control engine **8**, principal catalogue **2**, Derivation schema **11**.
- `SharedPermissionStorage` stores complete target/generation/ordinal-bound permission values once, retaining exact metadata, masks, flags, GUID strings and callback bytes.
- Control ACE associations and ordered full-control lists reference shared values, with integrity checks.
- Current-owner findings, primitive permissions, full-control evidence, support links, ownership restrictions and publication behavior were preserved.
- This is already applied locally. **Do not execute the older shared-storage handoff from scratch or restore a pre-storage snapshot.**

### Not implemented: scoped/on-demand ownership behavior

- `ControlEdgeDeriver` still creates `OwnershipControlDeriver.Transition` for every retained WRITE_OWNER assessment.
- The existing detailed owner-change result remains Unknown and uncounted because its verification gate is open.
- No complete automatic ownership target selector, explicit single-object runner, target-specific result store or new UI action has been implemented.
- The approved direction and single-definition constraint are recorded in `docs/WHAT-THE-PRODUCT-IS.md` under **Approved next ownership work**.
- No new accepted-decision file or runtime/schema change for this new scope was made. The last decision file observed was 0111; recheck numbering before creating a record.

## One Tier-0 definition, separate assessment relevance

Read the existing authority; do not restate its membership as another list:

- `docs/decisions/0006-tier-0-and-expected-admin-are-separate-sets.md` owns the existing Tier-0 policy and its corrections.
- `docs/decisions/0099-the-tier-0-control-plane-catalogue.md` governs scoped expectedness. It is not a substitute Tier-0 target list or an administrative blanket exclusion.
- `next/src/SecureAD.Derivation/PrincipalClassificationRegistry.cs` is the current central identifier classifier and exposes nullable `IsTier0Asset`. It is identifier-level and not a complete evidence-backed automatic target selector. Verify conformance and contextual requirements centrally before using it; do not patch gaps with a second ownership-specific definition.

The ownership selector consumes the canonical Tier-0 classification and identifies additional **assessment-relevant controllers/dependencies** through captured relationships. That inclusion reason is not a second Tier-0 definition and must not silently relabel every related object as confirmed Tier 0.

Direction matters:

- Domain Admins owning/managing an ordinary user does not make that user an important target.
- An account or group that can control a core target, or a relevant controller of that target, may need automatic assessment.
- Retain conditional candidate links so unverified ownership cannot disappear from potential routes merely because it has not been assessed.
- Unsupported dependencies, ambiguous identities and interrupted relevance work must disclose incomplete scope, not report safety or silently expand expensive assessment to the entire forest.

This is not authorization to build the whole Tier-0 path engine first. Avoid all-path enumeration or repeatedly calculating ownership for every path using the same relationship.

## Intended behavior and invariants

1. Capture and retain the authorized forest's source evidence. Narrow the expensive hypothetical owner-transition work, not the evidence capture.
2. Preserve current-owner findings, existing-owner control, WRITE_OWNER, WRITE_DAC, full control, expectedness, membership evidence and alternative grants.
3. Automatically assess the approved scope and persist inclusion reasons and coverage/limitations.
4. Outside automatic scope, represent **not assessed automatically** separately from assessed-but-unknown, not-established and unavailable/stale results.
5. An explicit object request uses existing Evidence/Derivation and one shared evaluator with the audit path. It does not contact a directory or silently activate membership/requester expansion.
6. Run the object assessment off the UI thread with cancellation and visible state. Do not promise instant completion or invent safe production limits.
7. Publish a small, immutable, target-specific result bound to the Evidence seal, Derivation generation, target/resource context, relevant audit context and evaluator/policy versions. Do not rewrite sealed Evidence or append to an already-published Judgement, and do not copy/reseal the entire roughly 519-MiB audit for each click.
8. Passive readers display stored results. An explicit assessment command may perform analysis, save it and then display it; ordinary page opening must not silently restart analysis.
9. Unresolved owner assignment or serving-DC behavior remains unverified. A scope change or button click cannot discharge the existing laboratory gate or establish account takeover/a completed Tier-0 path.
10. Preserve group-held counts without multiplying them by member/route counts. Keep candidate relevance separate from proven authorization/reachability.

### Superseded suggestions: do not implement them instead

- Do not blanket-exclude administrative groups from the underlying permission inventory or scope warnings.
- Do not discard ownership alternatives merely because WRITE_DAC/full control already exists. That can conceal an alternative relevant to later path/remediation analysis.
- Do not implement an ownership-local Tier-0 list, name heuristics, adminCount-only classification, or a manual important-target list.
- Do not interpret the read-only cost review's earlier compact-every-transition recommendation as the final approved product direction. Its measurements remain valid; the subsequent scoped-plus-on-demand decision supersedes that recommendation.

## Implementation plan and next actions

An implementation plan titled **Scoped automatic and on-demand ownership assessment** was created. Only step 1 (recording approved direction in the product orientation) was completed. Steps 2–10 remain pending. If the plan is available in the new session, resume it; otherwise recreate it from this handoff without restarting design approval.

1. Completed: record approved direction; single-definition clarification also recorded before this handoff.
2. Define the accepted decision and versioned scope/result contracts, including provenance, completion and not-assessed states. Verify the canonical Tier-0 classifier against the existing policy centrally.
3. Implement the automatic relevance selector with evidence-backed reasons and explicit incomplete coverage, consuming canonical Tier-0 results.
4. Refactor ownership assessment into reusable audit/object evaluation with compact shared proof, rather than repeated explanatory text.
5. Integrate automatic scope into judging, preserving basic findings, primitives, full-control supports and existing publication guarantees.
6. Implement the explicit single-object runner and immutable target-specific publication/cache behavior.
7. Add the approved object action and assessed/not-assessed/cancelled/stale-result presentation after UI approval.
8. Add regression tests for selection, parity, alternative supports, scope/identity ambiguity, corruption, cancellation and generation isolation.
9. Validate unchanged products separately from the explicitly approved assessment/coverage/presentation differences; measure cost with matched source/build/input/runtime identities.
10. Complete governing documentation and validation records, preserving production acceptance limits.

The first implementation-ready contract must settle which persisted result is automatic versus object-requested, how scope incompleteness is represented, how stale results are rejected, and the target-specific immutable publication mechanism. These are necessary engineering contracts, not invitations to invent another product workflow.

## Central code and documents

- `next/src/SecureAD.Judgement/ControlEdgeDeriver.cs`: unconditional transition creation currently occurs immediately after adding a WRITE_OWNER edge.
- `next/src/SecureAD.Judgement/OwnershipControlDeriver.cs`: existing-owner versus hypothetical-owner logic, source snapshot, validation and 15 checks.
- `next/src/SecureAD.Judgement/OwnerRightsReading.cs`: ordered rights checks and unverified behavior constraints.
- `next/src/SecureAD.Judgement/JudgingRun.cs`: audit staging; preserve existing local progress edits and rule-pass behavior.
- `next/src/SecureAD.Judgement/{ControlEdgeStorage,FullControlStorage,SharedPermissionStorage,JudgementSchema,JudgementWriter,JudgementReader}.cs`: current schema-25 shared storage/readback.
- `next/src/SecureAD.Derivation/PrincipalClassificationRegistry.cs`, membership inputs and stored owner-acceptance facts: reuse evidence, do not conflate policy predicates.
- `next/src/SecureAD.Evidence/AnalysisStoreLifecycle.cs` and `BundleLayout`: existing immutable generation pattern. `AnalysisStoreKind` currently has only Derivation and Judgement; no existing target-specific assessment store should be assumed.
- `next/src/SecureAD.Shell/Services/IAssetSource.cs` and `BundleAssetSource.cs`: passive read boundary; do not hide assessment writes in getters.
- `next/src/SecureAD.Shell/ViewModels/ControlEdgesSectionViewModel.cs`, object section templates and presentation resources: existing result UI.
- `docs/next/WORKFLOW.md`, `docs/next/SPEC-stage-6-control-edges.md`, `docs/layers/judgement/the-judgement-store.md`.
- Accepted decisions 0006, 0099, 0102, 0103 and 0111: separate target/expectedness, budget/completeness, primitive/compound and requester boundaries.

Use solution/project enumeration before broad discovery. The predecessor is history, not a design to copy; its feasibility has already been established by the owner. Do not start another predecessor investigation unless a specific contract actually requires it.

## Verified evidence: do not repeat the expensive review

Read-only review: `.vs\OwnershipCostReview-494b0aa0ff3a498f8107ecffe7db543d\RESULT.md` and its CSV/SQL/validation files.

- 32,639 hypothetical owner-change records; all Unknown and uncounted.
- 44 holder/scope identities across 8,407 targets.
- Every hypothetical record already has established same-holder/scope/target WRITE_DAC and an established WRITE_OWNER basis.
- 23,566 also have established full control.
- 989,937 ACE associations and 489,585 check rows (15 per record); 52,667,802 bytes of check name/state/evidence text.
- Ten non-source check types are identical across all candidates: 326,390 rows / 19,518,122 text bytes.
- Only 10 existing-owner control records in this fixture; this is not an ownership finding count.
- 86.83% of hypothetical records belong to administrative/platform identities. The other 4,298 include 4,228 Account Operators records and 70 other identified holders.
- 1,618 Domain Admins records are classified outside expected authority scope, all on Configuration targets. This is a current product classification, not a new claim that all such grants are misconfigured.
- Independent EXCEPT/INTERSECT queries, a missing-witness negative control, actual/declarative row counts, scoped identities and input hashes were checked.

This is lab evidence, not a production distribution or evidence that alternative ownership routes can be thrown away. Text payload bytes are not physical table sizes or guaranteed deletion savings.

## Storage baseline and validation limits

Storage artifacts: `.vs\SharedPermissionStorage-f00d19914b2947839e8aa245d0b124ab\validation-result.json`.

- Supplied capture: **ad.lab-20260908-145954**, not the earlier historical capture.
- Preserved inputs: the same directory's `input-copy`.
- Evidence SHA-256: `1ABE920124537AB380BA5A62A2A1D1C742C553FD7DEFFD6628F473F1FB53CCCF`.
- Derivation file: `derivation.c5079293b41047299b1736b45cbbc2f8.db`.
- Derivation SHA-256: `69A29FD1B6E4B54DBF2AE791A6EB55E7E1C794BA4557168E8DBF92E63396F109`.
- Fixed rule evaluation time: `2026-09-08T15:00:08.7355059+00:00`.
- Fresh schema-24 baseline: `baseline-run-1\bundle\judgement.62604da39fcf4478bd5f1ef797fd0ecb.db`, 686,673,920 bytes.
- Fresh schema-25 result: `candidate-run-1\bundle\judgement.099de2daae6a4e6abdbef1f30b97219b.db`, 543,715,328 bytes.
- Net lab saving: **142,958,592 bytes / 20.819%**, including indexes/references. Schema-25 has 209,032 distinct complete entries; 208,900 full-control source references reuse control entries.
- Complete object-first public proof comparison passed across schemas; altered-case permission export was rejected even with an updated artifact hash and unchanged counts.
- 167 focused storage tests and 35 documentation tests passed; solution build passed.
- An uninstrumented offline suite passed 4,422/4,422. A later repeat passed 4,421/4,422 because the unchanged `AuditProgressTests.DerivationSubphaseIsVisibleWithoutResettingTheReadCounter` intermittently times out. Record it; do not relax or hide it.
- Coverage run: 4,420/4,422, including that timeout and a literal-IL scanner negative-control failure under instrumentation. The scanner passes uninstrumented. Do not claim the coverage run was fully green.
- Exhaustive-export cumulative allocations increased. No runtime or memory improvement claim was made; WAL/temp peaks and production-scale acceptance remain unestablished.
- The first full export hit a 15-minute diagnostic cutoff. Completed export-only workers read four disjoint object sets per schema through unchanged readers. Expensive exports, input copies, failed attempts, source snapshots and reports are retained. Do not regenerate them just to resume this work.

Frozen benchmark: `next/BenchmarkSuite2/LabAuditProfilingBenchmarks.cs`, SHA-256 `4F234E3E93EACB94B271D70D9018DF0C5F9FED4A2168982B677B74656BEDC3DC`. It must remain unchanged. New scope deliberately changes some old output counts: do not weaken the frozen benchmark/comparer or add duplicate compatibility records to make those checks pass. Use explicit scope-aware validation for the approved delta; obtain authorization before adding a new measurement harness.

The existing `SecureAD.Measure` volume harness pairs scan-off with discovery-on, deletes generated captures and primarily uses read-property filler ACEs. It is not a retained, discovery-disabled ownership workload. The production shape is roughly 347,000 objects / 5.9 million ACEs / nine domains. Do not silently substitute that harness, choose unmeasured budgets, or call lab/synthetic results production acceptance.

## Preserve the live working tree

A fresh source-only handoff snapshot is retained at:

`.vs\OwnershipScopeHandoff-fc286b4878064902b7d29c293bae3323`

It contains `source` (1,015 tracked/untracked source files), `source-manifest.csv`, `status.txt`, `working-tree.patch`, `head.txt` and `identity.json`. It includes the latest owner instruction-file edits and the single-definition approval note. `.vs` measurement artifacts are retained in their original locations, not copied into this source snapshot.

Always check the live tree first; snapshots are evidence, **not authority to overwrite later edits**. In particular, `.github/copilot-instructions.md` has changed during this conversation.

Pre-existing work includes the local audit-progress correction across Derivation, Judgement and Shell; solution/documentation changes; the untracked BenchmarkSuite2 project; progress resources/view models/tests; the schema-25 shared-storage implementation and tests; and retained command-reuse regression tests. The command-reuse optimization itself was NOT applied. Keep all of it.

No commits or pushes were performed in these sessions. The clean-clone prose-path artifact-citation issue and broader logging/progress-test hardening remain separate. New governing docs must not require ignored local investigation files to exist in a clean clone.
