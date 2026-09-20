# Implementation handoff: approved shared permission-proof storage

## Start here

The owner has approved implementation of the bounded ownership/full-control shared-input storage proposal below. The investigation and requested predecessor review are complete. **The schema/storage change has NOT been implemented.** Do not ask for the same design approval again unless a material scope change or correctness blocker is discovered.

The owner is an AD/security administrator. Explain practical consequences plainly. This is a focused implementation session, not a restart of the investigation and not a wholesale Stage 6 redesign.

This handoff is intentionally local-only under `.vs`: its evidence references are local investigation artifacts, not portable shipped documentation. Do not turn them into required clean-clone inputs.

## Workspace and preservation

- Root: `C:\Users\jistrand\source\repos\razamus\SecureAD.Next`
- Solution: `next\SecureAD.Next.sln`
- Branch: `main`
- HEAD verified at handoff creation: `7618cebad789a410dae998b52ee83f234da8522e`
- Visual Studio Enterprise 2026; .NET 10; recorded SDK 10.0.400/runtime 10.0.11. Recheck actual runtime/build for any new measurement.
- No commit, push, pull/reset, live forest access or recapture is authorized.

**Check the live working tree first and preserve all existing modifications/untracked contents.** Do not restore an entire earlier snapshot: the owner has edited `.github/copilot-instructions.md` since the first preservation snapshot.

Tracked modifications at handoff:
- `.github/copilot-instructions.md`
- `docs/WHAT-THE-PRODUCT-IS.md`
- `docs/layers/judgement/the-judgement-store.md`
- `docs/layers/shell/the-new-audit-screen.md`
- `docs/next/SURFACE-REGISTER.md`
- `next/SecureAD.Next.sln`
- `next/src/SecureAD.Derivation/Stage2aRun.cs`
- `next/src/SecureAD.Judgement/JudgingRun.cs`
- `next/src/SecureAD.Shell/Services/DerivationLauncher.cs`
- `next/src/SecureAD.Shell/Services/IJudgingLauncher.cs`
- `next/src/SecureAD.Shell/Services/JudgingLauncher.cs`
- `next/src/SecureAD.Shell/ViewModels/NewAuditViewModel.cs`
- `next/src/SecureAD.Shell/Views/NewAuditView.xaml`
- `next/tests/SecureAD.Next.Tests/Documentation/ShellLayerTypesTests.cs`

Untracked work to preserve:
- `next/BenchmarkSuite2/` (approved lab benchmark, project and launcher)
- `next/src/SecureAD.Judgement/JudgingPhase.cs`
- `next/src/SecureAD.Shell/Resources/AuditProgress.resx`
- `next/src/SecureAD.Shell/ViewModels/AuditProgressViewModel.cs`
- `next/tests/SecureAD.Next.Tests/Judgement/ControlEdgeCommandReuseTests.cs`
- `next/tests/SecureAD.Next.Tests/Shell/AuditPhaseReportingTests.cs`
- `next/tests/SecureAD.Next.Tests/Shell/AuditProgressTests.cs`
- `next/tests/SecureAD.Next.Tests/Shell/AuditProgressViewTests.cs`

Most tracked changes are the prior approved local audit-progress correction. The current `ControlEdgeStorage.cs` is byte-identical to its pre-command-reuse version, as checked again before this handoff. The command-reuse candidate is NOT applied.

## Required orientation

Read the current `.github/copilot-instructions.md` and opening orientation of `docs/WHAT-THE-PRODUCT-IS.md`. Read relevant sections of:
- `docs/next/WORKFLOW.md` (especially current host behavior and generation/offline boundaries)
- `docs/layers/judgement/the-judgement-store.md` (current full-control, ownership, proof/reader and member-attribution contracts)
- `docs/layers/derivation/what-stage-2a-derives.md` (source-linked membership inputs, completeness and budgets)
- `docs/layers/shell/the-new-audit-screen.md` (local progress changes and verification limitations)
- Accepted decisions `0097-a-group-held-permission-is-counted-at-the-group.md`, `0102-group-expansion-is-budgeted.md`, `0111-bounded-self-membership-requesters.md`, plus ownership/full-control decisions cited by their current implementations.

Use solution/project enumeration before broad code discovery when needed. No active implementation plan exists. Make a bounded plan if tools/context support one; do not reopen already settled product choices.

## Approved goal and implementation boundary

**Store each distinct permission entry once for its target object within the disposable Judgement generation, while preserving every assessment and every association with it.** Ownership/control edges and ordered full-control source lists should refer to shared entries instead of persisting complete repeated values.

First slice:
1. Introduce an internal target-bound shared entry representation with complete required values in structured storage.
2. Control edges keep all their logical ACE associations, including original ordinals. Sharing values is NOT permission to collapse associations or candidates.
3. Full-control sources keep their ordered source lists, referring to the same stored entries when exact values match.
4. Keep ownership preconditions, full-control assessment explanations, alternative-grant evidence, membership routes and support links separate and otherwise unchanged.
5. Keep current per-object transactions, validation order, rollback and final generation publication behavior.
6. Readers reconstruct existing public read models by joining stored records. They must not rerun permission analysis or membership expansion at display time.

Expected production areas:
- `next/src/SecureAD.Judgement/ControlEdgeStorage.cs`
- `next/src/SecureAD.Judgement/FullControlStorage.cs`
- `next/src/SecureAD.Judgement/JudgementSchema.cs`
- One internal shared-proof storage component as needed
- Focused correctness/schema/reader checks and relevant documentation, preserving existing edits

Current versions: Judgement schema 24, control engine 8, Derivation schema 11, principal catalogue 2. A judgement storage schema bump is required (25 if 24 is still current). Evidence and Derivation formats are outside scope. Do not silently introduce a semantic change to justify a control-engine/catalogue change.

### Identity and representation safeguards

- Share only within the same target and judgement generation, with the original ordinal and exact values.
- Preserve ACE type (including allow/deny distinctions), trustee identity/metadata, masks, GUIDs, explicit GUID-presence flags, inheritance/propagation flags and application bytes.
- Different physical ordinals remain distinct even when all other bytes match.
- Null, empty and missing values are not interchangeable.
- Do not introduce normalization of generic masks, captured SELF, case or other values while changing storage. Preserve the values the current product stores/returns.
- A hash may accelerate lookup, but must not replace exact equality or silently merge conflicting values. Legitimately distinct representations must remain distinct; contradictions must not become first-value-wins behavior.
- Full-control JSON currently retains richer trustee metadata than the control-edge table. `ControlEdgeStorage.ReadAces` currently returns null for trustee UnresolvedReason/Meaning, whereas full-control reads deserialize the richer PermissionEntry values. The shared store must not lose the richer fields or silently change either consumer's existing read contract.
- Empty DACL, null DACL, unreadable descriptor, unsupported ACEs and partial capture must retain their distinct states. An empty shared list is not proof that permissions were absent or analysis complete.

### Explicit exclusions

Do not combine this with command reuse, transaction batching, checkpoint/durability tuning, binary compression, a forest-wide cache, rule changes, UI changes, broader ownership semantics, requester/member activation, production-budget changes or Windows-service changes.

This first slice does NOT restructure the 83.6 MB of full-control assessments, 60.9 MB of preconditions, membership-route explanations or holder/capability records. It addresses the shared permission inputs used by ownership AND full control, not every byte in the store at once.

## Non-negotiable security/correctness boundaries

- Count the named holder edge; members/routes do not multiply it.
- Preserve all full-control supports and alternative grants.
- Existing-owner control remains independent.
- `CanBecomeOwnerAndRewriteDacl` remains Unknown/uncounted where currently so; no inferred account takeover or completed Tier 0 path.
- Preserve separate concrete requester assessments and all their limitations.
- Preserve discovered partial results, unresolved nodes, explicit incompleteness and budget stop reasons.
- Bind proof, findings, source/target associations and reader pages to the correct Evidence/Derivation/Judgement generations.
- Reject missing proof, wrong-target references, wrong-generation references, altered ordinals/values/counts and inconsistent supports.
- Preserve validation beyond the current page when corruption there could affect headline counts.
- Never obtain savings by dropping proof, skipping validation or hiding uncertainty.

## Required validation and stopping conditions

Before acceptance:
1. Establish the exact current source/build/input identities in a new isolated working/measurement copy. Preserve old artifacts.
2. Add focused sharing/reader tests: duplicate occurrences, identical values at different ordinals, differing metadata and ACE type, null/empty transitions, callback bytes, SELF, applicability flags, incomplete inputs, alternative grants and ownership restrictions.
3. Retain corruption-test intent, including failures outside the displayed page, and make wrong-target/wrong-generation sharing fail loudly. Account explicitly for schema-specific SQL probes; do not delete/skip checks merely to obtain green results.
4. Verify rollback on late proof failure and cancellation after substantial writes preserves the previous publication.
5. Compare complete before/after PUBLIC READ MODELS across schema versions, not merely the 27 findings or row totals. Include every permission field, precondition, route, support, expectedness and uncertainty. Normalize only independently validated new generation IDs and run timestamps.
6. Keep the frozen benchmark unchanged. Supplement its fixture checks with a schema-aware semantic comparison. The existing same-schema comparer intentionally rejects schema differences; do not weaken that check and call it cross-schema validation.
7. If the needed schema conflicts with a frozen measurement artifact, surface the narrow validation-artifact need rather than editing the frozen artifact or adding compatibility storage solely to appease a check.
8. Measure actual main database size including indexes/reference overhead, not only text/blob savings. Record publication/readback and memory behavior; no runtime speedup claim without comparable measurement conditions.
9. Keep a change only if it preserves required behavior and the measured net storage benefit justifies the complexity. Stop rather than broaden scope or weaken evidence if this cannot be established.

After the lab slice, assess production-shaped synthetic scale (~347,000 objects, 5.9 million physical ACEs, nine domains) with authorized existing tooling where suitable. The existing volume harness pairs scan-off with discovery-on and is not a silent substitute for a discovery-disabled run. No new harness without approval. Synthetic results alone are NOT production acceptance.

## Sealed lab input and measured storage baseline

Use the supplied `ad.lab-20260908-145954`, NOT the earlier historical `ad.lab-20260908-062400`:
- Supplied original: `C:\Users\jistrand\Downloads\SecureAD\ad.lab-20260908-145954`
- Preserved input: `.vs\AuditLab-53015de18a534638b9bf9ea22504410c\original-copy`
- Evidence file: `evidence.db`
- Evidence SHA-256: `1abe920124537ab380ba5a62a2a1d1c742c553fd7deffd6628f473f1fb53cccf`
- Derivation file: `derivation.c5079293b41047299b1736b45cbbc2f8.db`
- Derivation SHA-256: `69a29fd1b6e4b54dbf2ae791a6eb55e7e1c794ba4557168e8dbf92e63396f109`
- Historical judgement: `judgement.b279086c717240f69f8d6d3f5d355527.db`
- Historical judgement SHA-256: `cd6c6ca765338ddf0562fc09d4cc29f88c8aed7459606966d41337605b8b9b3d`
- Fixed rule evaluation time: `2026-09-08T15:00:08.7355059+00:00`

Always use a NEW copy for new output. Preserve originals, seals, manifests, logs, sidecars, previous measurements and partial artifacts. Never recapture the directory.

8,407 objects / three domains; 17 rules; 27 findings; CompletedDegraded. SEC-031 and SEC-032 each record four objects with ProtectedPrincipals.MembershipIncomplete. Membership attribution configuration is null and its tables empty. Requester discovery is NotStarted with null budget, zero visited objects/pairs and zero assessments. Separate reusable membership preparation exists: 4,320 records / 9,278,641 proof bytes in Derivation. Do not conflate it with activated member expansion.

Main judgement: **686,673,920 bytes = 654.863 MiB**; 37 indexes; zero freelist pages; supplied WAL zero bytes. Peak WAL/temp growth has NOT been established. The native SQLite inspected lacked dbstat support, so physical per-table/index pages have not been attributed.

| Stored content | Rows | Measured text/blob bytes |
|---|---:|---:|
| control_ace | 1,327,169 | 148,078,098 |
| full_control_source | 8,392 | 118,655,149 |
| full_control_assessment | 23,751 | 83,646,405 |
| control_precondition | 558,406 | 60,868,565 |
| control_edge | 144,732 | 43,711,951 |
| membership_route_step | 227,382 | 20,247,205 |
| membership_route | 113,635 | 4,792,281 |
| membership_route_summary | 144,732 | 1,915,143 |

All table text/blob payload totals **483,285,179 bytes**. The remainder **203,388,741 bytes** includes indexes, numeric fields, record/page structures and unused space within pages; the split is unmeasured. The entire finding-table family contains only 21,079 text/blob bytes. Do not describe these payload figures as physical per-table disk sizes.

Exact repetition check: 1,327,169 ACE associations reduce to 209,032 distinct target/ordinal/complete CURRENT control_ace-field variants. Their repeated text/blob payload is **123,070,654 bytes**. Links remain necessary. This is not guaranteed net savings, and the full-control representation has richer metadata.

Ownership amplification: 32,639 Unknown/uncounted transition candidates account for 989,937 ACE associations and 489,585 preconditions / 52,667,802 text bytes. OwnerSource JSON itself occupies 24,886,396 bytes across 32,649 conditions (transitions plus existing owners). All 227,382 route steps are attached to control edges. Full-control has 23,566 Established and 185 Unknown assessments, with 72,422 support links.

Full-control input JSON arrays occupy 118,116,190 bytes. Only 6,809,417 bytes are duplicates between byte-identical whole arrays across targets. All 23,751 full-control assessment JSON proofs already have empty Source.Entries; they do NOT each embed the whole source list. Avoid proposing that nonexistent duplication as the fix.

History places the full-control addition at commit 3b028c6 (2026-09-08) and replication/ownership at 8e0865d (2026-09-07). These are introduction history plus current footprints, not a controlled byte-growth comparison between commits.

## Timing baseline and why command reuse is not applied

Historical copied log: capture/sealing ~12 s, Derivation ~2 s, judging through finished log ~221 s; result readback not recorded. The original lab executable/machine identity is not established as equivalent to this development machine. The older 13-second/0.16-MB result predates substantial proof and is NOT equivalent work. The historical ~79-minute synthetic baseline ran zero rules and was subsequently substantially improved; do not attribute it to the 17 rules.

Approved frozen benchmark:
- `next/BenchmarkSuite2/LabAuditProfilingBenchmarks.cs`
- FQN `SecureAD.Measurements.LabAuditProfilingBenchmarks.JudgeLabAndReadBack`
- SHA-256 `4F234E3E93EACB94B271D70D9018DF0C5F9FED4A2168982B677B74656BEDC3DC`
- Calls the real 17-rule JudgingRun.Judge and reader, fixed input/evaluation time, budgets inactive, fresh retained output per invocation.
- Has a 15-minute diagnostic cancellation token, not an expansion/production budget.
- Uses one actual timing observation plus a separate diagnostic invocation. Do not count the latter as another independent BenchmarkDotNet sample.

The initial CPU trace confirmed a control-proof writer hotspot (~74% aggregate CPU samples in ControlEdgeStorage.Write), not the 17 rules as the main cost. These are sampled CPU percentages, not per-function elapsed times.

Command-reuse candidate results:
- Before: 51.5560, 50.5403, 49.4333 s.
- Candidate: 39.4212, 41.1609, 52.8544 s.
- Allocations consistently fell from ~16.19 GB to ~11.94 GB cumulative (~26%); not RAM requirements.
- Candidate correctness: 179 unique targeted tests passed (176 existing + three new). Three complete before/candidate pairs matched all 39 tables after narrowly validated generation/time normalization. A case-only ACE mutation was rejected with unchanged counts.
- Candidate source was restored, NOT retained, because runtime acceptance was not established. The final restored build and the three retained new tests also passed. These are historical checks for this new session, not fresh passes after upcoming edits.

Do not reapply command reuse as part of storage work. Saved candidate patch/binaries remain under `.vs\CommandReuseValidation-5eaab6ba20d74cdeb3d5a821bee47778`.

## Sampling interference: resolved cause, unresolved controlled environment

Raw ETL events establish that `svchost.exe` PID 12240, thread 40188, running `svchost.exe -k whesvc -p -s whesvc`, changed the global sampling interval. Read-only service correlation identified **Windows Health and Optimized Experiences (whesvc)**. Six traces reported zero lost events/buffers.

After aligning ETL interval events with ACTUAL timed invocations:
- All three baseline timings were stable at 1 ms / 1,000 samples per second.
- Candidate 1 changed to 100 ms / 10 samples per second during timing.
- Candidate 2 was stable at 100 ms.
- Candidate 3 was stable at 1 ms and slower than all three baselines.
- Baseline 3 also changed rate later, during its additional diagnostic invocation; do not disqualify its actual timing for that later event or treat its whole CPU trace as uniform.

Do not pool the faster candidate timings into a matched-settings speedup claim. This does not prove sampling explains the entire elapsed difference or that the service caused the owner's original 4–5 minute audit. No Windows service, profiler interval or power setting was changed to solve it. Do not disable a managed service without separate approval/restoration planning. Repeated uncontrolled traces are not the next validation strategy.

## Predecessor review: use the idea, not the old contract

Old repository: `C:\Users\jistrand\source\repos\razamus\SecureAD`, HEAD `f0726569c678ac51d63bb6c83985d8705e0d2f67`. The documented ba.admin path was absent here. The original app is under its `src/` and `tests/`; its `next/` is an obsolete split-time snapshot. Keep the archive read-only, including its preexisting untracked files. No old code/benchmark/database was executed.

Findings from actual writer and reader paths:
- Control edges reference a shared fact_ace using target GUID + ACE hash rather than copying a full list into every edge.
- A separate materialized per-object ACL is stored using a compact binary format with a SID/GUID string table. This inspected path is not Brotli/GZip compression.
- The predecessor therefore demonstrates a useful shared-input design, but is not strictly a single-copy architecture.
- One DerivedFromAceHash per edge plus ON CONFLICT updates to flags does not preserve today's full alternative-support model.
- The inspected ownership path persists an Owns relation, not today's complete distinct ownership/transition proofs.
- Its materialized payload comes from canonically sorted, hash-deduplicated entries; it is not original physical order/duplicate preservation.
- Its ACE fingerprint excludes ACE type, original ordinal and callback bytes. Its payload lacks required modern fields/metadata. Do NOT copy that key/encoding as an equivalent proof contract.
- Old command reuse/batching is history, not permission to change Next's lifecycle/transactions.

The old application had other broader capabilities; do not claim Next has universally surpassed it. Today's ownership/full-control proof is richer than the inspected old representation, but that does not justify repeated storage of identical inputs.

## Local evidence index (relative to repository root)

- `.vs\AuditPerformanceBaseline-773dd984260f425ba735b26974a93e01`: initial source/diff/binary/machine preservation. NOT an authority to overwrite later owner edits.
- `.vs\AuditLab-53015de18a534638b9bf9ea22504410c\INVESTIGATION.md`: sealed-copy identities, initial store inspection and exact-duplication SQL.
- Same directory, `PROFILE-BASELINE.md`: frozen benchmark, baseline, runtime provenance, phase/correctness limits.
- Same directory, `profile-preservation-7d1bee730e1a47c9908025f11d620fdd`: baseline profiled binaries, benchmark and reports.
- `.vs\CommandReuseValidation-5eaab6ba20d74cdeb3d5a821bee47778\RESULT.md`: unapplied candidate, all observations, full-store comparisons, regression tests, raw metrics and preserved binaries.
- `.vs\SamplingConsistency-928d3e8132d440939221119b87da7c6a\FINDINGS.md`: raw interval/service evidence and actual-invocation alignment.
- `.vs\Stage6StorageBreakdown-ab795de2f8c64c8fa673ece313430d85\breakdown.txt`: ownership/full-control/route payload attribution.
- `.vs\PredecessorProofReview-077e1d0eb586423788e878cfb1f4b665\REVIEW.md`: read-only predecessor comparison, source references, copied-source hashes and approval boundary.

## Separate follow-ups / prohibited shortcuts

The previously cancelled stage-status check remains UNVERIFIED. Historical 4,372 offline and 179 progress-targeted tests are not fresh results or performance evidence. The reported clean-clone ProsePathCitationTests artifact-citation failure and broader logging hardening remain separate. Do not hide these by adding local-only reports as shipped required inputs.

No UI wording/layout changes, live access, recapture, discovery/member activation, production-budget changes, deletion of original/earlier artifacts, commit or push. New measurement-harness code requires approval. Preserve the frozen existing benchmark and prior measurement/test artifacts. Escalate genuine correctness or scope changes, not the already-approved shared-input design.
