# Review 02 — Derivation correctness and persistence

**Reviewed:** 2026-08-28  
**Reviewer/model:** GitHub Copilot  
**Baseline:** `review-baseline-2026-08-28` (`d36ddb4`)  
**Status:** Findings open; no production correction accepted by this document

## Executive summary

The derivation layer has a sound conceptual shape: it reads sealed Evidence, separates authorization
membership from AdminSDHolder protection, reconstructs primary-group membership explicitly, scopes
BUILTIN identities by domain, records phase outcomes, persists completeness, seals a disposable store,
and refuses unsupported schemas.

It does not yet deliver that model end to end. Two of the three products Stage 2a says it derives —
protected principals and latent privilege paths — are computed and immediately discarded. The store
contains structural SID/principal/nesting rows and one global completeness record, but no authorization
closure, protected-principal evaluation, or latent path. Judgement opens only Evidence and no current
rule consumes Derivation. Consequently, Stage 2a presently changes no finding.

The review also found that an intact derivation is not checked against the current evidence seal,
unknown `groupType` values can produce speculative authorization paths while persisted completeness
still says complete, and the returned/UI run state can disagree with stored completeness. Replacement
of an existing derivation is not atomic as a database/seal pair, and malformed sealed metadata can
escape typed reader failures.

These are composition and contract defects rather than a reason to replace the layered architecture.
The immediate need is to define and persist the derived-fact contract, bind it to Evidence on read, and
make consumers receive facts together with typed uncertainty. The known AdminSDHolder semantic defects
remain governed by Decision 0089 and `adminsdholder-catalogue-review.md`; this report does not duplicate
them as newly discovered findings.

## Architecture / data-flow map

```text
Shell DerivationLauncher / CLI --derive
  -> Stage2aRun.Derive
     -> read evidence seal
     -> BundleReader.Open + ReadScope + StreamObjects
     -> MembershipNestingPass.Read
        -> SID identities, principals, direct edges, unresolved names, dSHeuristics
     -> NestingGraph.Build
     -> AuthorizationMembershipExpander.ClosureOf       [in memory only]
     -> ProtectedPrincipalDeriver.Derive                [in memory, discarded]
     -> LatentPrivilegeDeriver.Derive                   [in memory, discarded]
     -> DerivationWriter
        -> sid, sid_identity, principal, nesting_edge
        -> phase rows and global completeness
        -> checkpoint -> seal -> overwrite derivation.db
  -> DerivationReader
     -> header, phase rows, structural counts, completeness only

JudgingRun
  -> BundleReader.StreamObjects
  -> IRule.Judge(ObjectAttributes)
  -> no DerivationReader, no derived-fact input
```

## Verified strengths

### S-01 — Authorization and AdminSDHolder protection are separate questions

`NestingGraph` preserves ordinary and primary-group edges separately, and authorization traversal does
not pass through a known distribution group (`NestingGraph.cs:17-28`; `AuthorizationMembershipExpander.cs:150-167`).
The protected-principal algorithm is independently configurable for distribution and primary-group
traversal (`ProtectedPrincipalClosure.cs:121-192`). Microsoft confirms both that distribution groups
confer no access privileges and that protected-account enumeration can include nested distribution
groups. This separation is architecturally necessary.

### S-02 — Identity scoping and SID history are modeled deliberately

The SID dictionary carries scope to avoid cross-domain BUILTIN collisions, while SID history resolves
to the current principal rather than becoming a membership edge (`MembershipNestingPass.cs:150-180`;
`DerivationSchema.cs:100-154`). Microsoft confirms that SID history values enter access tokens and
preserve access associated with former SIDs.

### S-03 — Primary-group membership is reconstructed rather than inferred from linked attributes

`MembershipNestingPass` derives the primary-group SID from `objectSid` and `primaryGroupID`, and
`NestingGraph` stores reverse primary membership independently (`MembershipNestingPass.cs:252-280`;
`NestingGraph.cs:100-146`). Microsoft confirms that a principal is removed from a group's `member`
attribute when that group becomes primary and that `memberOf` excludes the primary group.

### S-04 — Resource limits preserve the distinction between empty and uncomputed

The expansion records a specific limit and names groups it did not reach. Null internal sets become
empty output only beside `PartialGroups`, preventing an uncomputed group from being silently presented
as having no members (`AuthorizationMembershipExpander.cs:175-224`).

### S-05 — The derivation artefact has a strong basic lifecycle

The writer uses a partial file, transactions, deferred indexes, a WAL checkpoint, a seal, and final
promotion. The reader verifies the derivation seal and schema version before opening
(`DerivationWriter.cs:74-117, 453-470`; `DerivationReader.cs:121-190`). Completeness is required and read
back as a non-null part of `StoredDerivation`.

## Findings

## D-01 — Stage 2a discards two advertised derived products and persists no closure

**Severity:** Critical  
**Confidence:** High  
**Release blocker:** Yes, for any derived-fact rule  
**Status:** Confirmed

### Affected files

- `next/src/SecureAD.Derivation/Stage2aRun.cs:15-38, 146-171, 260-386`
- `next/src/SecureAD.Derivation/DerivationSchema.cs:100-313`
- `next/src/SecureAD.Derivation/DerivationWriter.cs:120-384`
- `next/src/SecureAD.Derivation/DerivationReader.cs:37-100, 193-309`
- `next/tests/SecureAD.Next.Tests/Derivation/ProtectedPrincipalDeriverTests.cs`
- `next/tests/SecureAD.Next.Tests/Derivation/LatentPrivilegeDeriverTests.cs`
- `next/tests/SecureAD.Next.Tests/Derivation/Stage2aRunTests.cs:108-156`

### Evidence

`Stage2aRun` describes three derived products and invokes authorization expansion,
`ProtectedPrincipalDeriver.Derive`, and `LatentPrivilegeDeriver.Derive`. `RunProtection` and `RunLatent`
pass their return values through the generic phase wrapper, which records an outcome and then discards
the value. `WriteFacts` persists only SID dictionary, identities, principals and direct nesting edges.
There are no schema tables or writer/reader APIs for authorization closure, protected-principal
results, unknown reasons, catalogue/version/provenance, or latent privilege paths.

The algorithm tests validate direct in-memory return values. Stage-level tests assert phase rows, not
product rows. They therefore prove the algorithms can produce answers but not that Stage 2a delivers
them.

### Customer consequence

Expensive derivation runs successfully and can be reported as complete while the facts expected by
future rules do not exist after the method returns. Reopening the bundle yields only structural input
and counts, so a rule cannot consume the reviewed protected-principal semantics.

### Recommended correction

Define persisted contracts before implementation:

- authorization membership: either persisted closure or a queryable, bounded equivalent;
- protected-principal result: evaluation, per-principal uncertainty, effective roots, catalogue
  version and evidence provenance;
- latent privilege paths: candidate, gained authority and affected principals, each qualified by
  the closure uncertainty it depends on.

Persist each product transactionally and expose typed reader APIs. Do not mark a phase succeeded unless
its promised product has been written. Apply Decision 0089 before persisting protected-principal facts.

### Validation required

- Production `Stage2aRun` writes each product and `DerivationReader` reads exact values back.
- Delete all in-memory references after completion and prove a rule can reach the same answer.
- Degraded/failed phases cannot be read as empty products.
- Real multi-domain bundle round-trip with domain-scoped BUILTIN identities.

## D-02 — Judgement does not consume Derivation

**Severity:** Critical  
**Confidence:** High  
**Release blocker:** Yes, for any rule based on derived facts  
**Status:** Confirmed

### Affected files

- `next/src/SecureAD.Judgement/JudgingRun.cs:79-151`
- `next/src/SecureAD.Judgement/RuleContracts.cs:47-70`
- `next/src/SecureAD.Judgement/RuleCatalogue.cs`
- `next/src/SecureAD.Judgement/UnconstrainedDelegationRules.cs`

### Evidence

Judgement references the Derivation assembly, but `JudgingRun` opens only `BundleReader`, streams
`ObjectAttributes`, and offers each object to `IRule.Judge(ObjectAttributes)`. No production Judgement
code opens `DerivationReader`, reads `StoredDerivation`, or passes derived facts/completeness into a
rule. The current two rules intentionally use only captured object attributes.

This was an accepted seam-only ownership move, not a defect in that change. It remains an unfinished
product contract: the dependency direction now permits derived-fact rules, but no executable path
supplies their inputs.

### Customer consequence

Derivation currently changes no finding. Adding SEC-030 or another cross-object rule without changing
the execution contract would either duplicate derivation inside Judgement or bypass typed uncertainty.

### Recommended correction

After D-01 defines persisted facts, introduce a Judgement-owned declared-input package that opens and
validates both Evidence and Derivation once per judging run. Derived facts must travel with their
completeness/uncertainty; do not add ad hoc reader calls inside individual rules. Preserve the existing
single-object route for rules that require only Evidence if that keeps execution simple.

### Validation required

- End-to-end bundle → derive → judge test where a finding requires a persisted derived fact.
- Missing, stale, degraded and schema-incompatible derivations produce not-judged outcomes, never a
  clean result.
- Existing Evidence-only rules retain behavior.

## D-03 — DerivationReader does not verify the derivation belongs to current Evidence

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes  
**Status:** Confirmed

### Affected files

- `next/src/SecureAD.Derivation/DerivationWriter.cs:60-117, 514-529`
- `next/src/SecureAD.Derivation/DerivationReader.cs:121-190, 213-233`
- `next/src/SecureAD.Derivation/DerivationSchema.cs:57-76`

### Evidence

The writer stores the evidence seal hash and the schema calls it the binding between derived facts and
one capture. `DerivationReader.Open` verifies only `derivation.db` against `derivation.db.seal`, reads
`EvidenceSeal` into the description, and never compares it with the current bundle's evidence seal.
This differs from `JudgementReader`, which performs an evidence-mismatch check.

Reader tests use arbitrary evidence-seal constants and prove only derivation seal/readback. No test
moves a valid derivation pair into another valid bundle.

### Customer consequence

A derivation database and its matching derivation seal can be copied into another bundle and open
successfully even though every derived principal and edge came from different evidence. Future rules
would silently judge one capture using another capture's graph.

### Recommended correction

During `DerivationReader.Open`, read and validate the current evidence seal, compare its hash with
`DerivationDescription.EvidenceSeal` using ordinal comparison, and return a dedicated typed mismatch
error. The reader should not expose any facts before this check passes.

### Validation required

- Copy an intact derivation and seal between two valid bundles; opening must refuse.
- Missing/unreadable current evidence seal receives a distinct actionable failure.
- Correctly paired derivation continues to open.

## D-04 — Unknown group types can be serialized as a complete derivation

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes, before persisting authorization closure  
**Status:** Confirmed

### Affected files

- `next/src/SecureAD.Derivation/AuthorizationMembershipExpander.cs:117-131, 218-239`
- `next/src/SecureAD.Derivation/DerivationCompleteness.cs:74-110`
- `next/src/SecureAD.Derivation/Stage2aRun.cs:146-175`

### Evidence

When a captured group has no `groupType`, authorization expansion follows it conservatively and adds
its SID id to `MembershipClosure.GroupsOfUnknownType`. That uncertainty is held only in memory.
`DerivationCompleteness.Of` considers budget, partial groups, unresolved trustees, missing domains and
unscoped BUILTIN identities, but not `GroupsOfUnknownType`. The writer has no table for it.

The expansion may therefore contain principals who would not be authorized if the unknown group is a
distribution group, while `IsComplete` and the run state can both say complete.

### Customer consequence

Once authorization closure is persisted or consumed, speculative privilege paths can be presented as
established facts. This creates false positives and removes the explanation needed to investigate them.

### Recommended correction

Persist unknown-type groups and make authorization results tri-state or path-qualified. A conservative
superset is acceptable for candidate discovery only if every affected answer carries that basis. Do
not use one global boolean as a substitute where affected paths can be localized.

### Validation required

- Missing `groupType` on a nested group survives persistence and readback.
- Principals reached only through that group are Unknown/qualified, not established authorized.
- Principals with an independent established path remain established.

## D-05 — Returned and displayed run state can contradict persisted completeness

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes  
**Status:** Confirmed

### Affected files

- `next/src/SecureAD.Derivation/Stage2aRun.cs:163-179`
- `next/src/SecureAD.Derivation/DerivationCompleteness.cs:74-110`
- `next/src/SecureAD.Derivation/DerivationWriter.cs:434-470`
- `next/src/SecureAD.Shell/Services/DerivationLauncher.cs:87-99`
- `next/src/SecureAD.Shell/Services/IDerivationLauncher.cs:21-31`
- `next/src/SecureAD.Cli/Program.cs:252-273`

### Evidence

Persisted completeness correctly becomes false for missing domains and unscoped BUILTIN identities.
`Stage2aRun` computes its returned state only from expansion existence/completion and unresolved
trustees. `DerivationWriter.Complete` independently derives its header state only from phase outcomes.
Neither includes the final `DerivationCompleteness.IsComplete` value.

The Shell reads completeness but returns only the Stage2a state, counts and
`EveryPhaseThatRanSucceeded`; it drops the completeness object. The CLI prints the returned state.
Thus a run can persist `is_complete = 0` while its header, CLI and Shell outcome say `Completed`.

### Customer consequence

An operator can be told derivation completed cleanly even though a declared domain was absent or
identity collisions may have corrupted the graph. The truthful detail exists in the store but is not
part of the normal completion result.

### Recommended correction

Make one authoritative completion decision after `DerivationCompleteness` is constructed. Pass that
same value to the writer/header and return it to callers. Extend the Shell outcome to carry typed
completeness or a concise, actionable summary. Ensure `Completed` means phases succeeded and the
result is complete; otherwise use `CompletedDegraded`.

### Validation required

- Missing domain, unscoped BUILTIN, unresolved trustee, budget and unknown-type scenarios each assert
  agreement among stored completeness, header state, returned state, CLI output and Shell outcome.

## D-06 — Replacing derivation data and its seal is not atomic as a pair

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Affected files

- `next/src/SecureAD.Derivation/DerivationWriter.cs:453-470`
- `next/src/SecureAD.Evidence/BundleLayout.cs:131-148`

### Evidence

On re-derivation, the writer overwrites `derivation.db.seal` first, then overwrites `derivation.db`.
A process or filesystem failure between those operations leaves the prior valid database beside the
new seal. The old derivation is then reported as damaged even though its bytes were not changed.

The Shell contract says cancellation leaves an earlier derivation intact. That holds before the final
seal operation, but the same preservation guarantee is not maintained across the two-file promotion.

### Customer consequence

A failed refresh can destroy availability of a previously usable derivation without changing its
database. Evidence remains safe and derivation is rebuildable, but operators lose the last good
analysis until a later run succeeds.

### Recommended correction

Promote a versioned database/seal pair through a recoverable protocol rather than overwriting two live
names independently. Options include generation-specific filenames plus one atomic manifest/pointer,
or backup/restore of the old pair with startup recovery. Specify crash points before implementing.

### Validation required

- Inject failure before seal write, after seal write, and after database replacement.
- At every point, either the old pair or new pair opens; a mixed pair is never the only state.
- Cancellation preserves the old generation.

## D-07 — Validly sealed malformed metadata can escape typed reader failures

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Affected files

- `next/src/SecureAD.Derivation/DerivationReader.cs:149-190, 213-233, 275-376`

### Evidence

`DerivationReader.Open` catches `SqliteException` only. Header parsing can throw for malformed GUID,
enum or date text. `Read()` can throw for absent completeness, invalid expansion/outcome values or an
invalid missing-partition outcome. These are all possible in an intactly sealed file assembled by a
broken writer/tool, which the reader's documentation says should become an actionable refusal.

### Customer consequence

Opening or displaying one malformed derivation can terminate a workflow with an unhandled format or
invalid-operation exception instead of returning `DerivationUnreadable`.

### Recommended correction

Validate stored scalar values explicitly and translate expected representation failures into precise
`AuditError`s. Consider whether `Open` should validate the full required metadata contract so a
successfully opened reader cannot later fail on `Read()` for structural corruption. Do not catch base
`Exception`.

### Validation required

- Reseal stores with invalid generation id, state, timestamps, phase outcome, expansion limit,
  missing completeness and invalid missing-partition outcome.
- Each produces a typed refusal with the offending field/table.

## Known semantic blockers incorporated by reference

The following are not counted again as new Review 02 findings:

- The flat AdminSDHolder catalogue conflates principal protection and member propagation.
- All catalogue entries are currently used as graph seeds despite differing account/group semantics.
- The forest exclusion mask changes group-object protection and propagation together.
- Malformed masks and source conflicts require typed treatment.
- Negative protected-principal completeness is unsound under global unresolved membership.

Authority and evidence are in:

- `docs/decisions/0089-principal-protection-and-member-propagation-are-separate-claims.md`
- `docs/layers/derivation/adminsdholder-catalogue-semantics.md`
- `docs/reviews/adminsdholder-catalogue-review.md`

D-01 must not persist the current flat protected closure before those corrections are applied.

## Source conflicts and unresolved questions

| Subject | Sources/evidence | Status |
|---|---|---|
| Distribution groups do not confer authorization | Microsoft Group Objects / security-groups documentation | Established |
| Protected-account enumeration can traverse distribution groups | Microsoft “Reducing the Active Directory Attack Surface” | Established product guidance; protocol classification remains under Decision 0089 review |
| Primary group is absent from normal member/memberOf linkage | Microsoft security properties and Entra Connect primary-group documentation | Established |
| SID history grants effective access under applicable trust | Microsoft `DsAddSidHistory` documentation | Established |
| Exact persisted representation of large authorization closures | No accepted design yet | Product/storage decision required |
| Atomic replacement protocol for disposable analysis pairs | Current two-file layout is insufficient | Design required |

## Recommended correction order

1. Complete Review 03 before implementation so production-path test requirements are fixed first.
2. Accept the corrected shared AdminSDHolder semantic/storage specification under Decision 0089.
3. D-03 — enforce evidence binding before any derived facts can be consumed.
4. D-05 and D-04 — establish one typed completeness/state contract.
5. D-01 — persist the corrected products and expose reader APIs.
6. D-02 — supply derived facts and uncertainty to Judgement.
7. D-06 — make re-derivation replacement recoverable.
8. D-07 — harden malformed-store refusal.

Coordinate Review 01 E-C02 with D-04/D-05: unplanned-partition reconciliation is another input to
whether derivation may make complete negative claims.

## Files read fully

- All production files in `next/src/SecureAD.Derivation`
- `next/src/SecureAD.Evidence/BundleLayout.cs`
- Relevant `BundleReader` and `BundleSealing` paths
- `next/src/SecureAD.Judgement/JudgingRun.cs`
- `next/src/SecureAD.Judgement/RuleContracts.cs`
- Shell and CLI derivation launchers/output paths
- All relevant Derivation, Judgement and Shell tests cited above

## Tools and external sources consulted

- Microsoft Learn: https://learn.microsoft.com/windows/win32/ad/group-objects#group-types
- Microsoft Learn: https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface
- Microsoft Learn: https://learn.microsoft.com/windows/win32/ad/security-properties#memberof
- Microsoft Learn: https://learn.microsoft.com/troubleshoot/entra/entra-id/user-prov-sync/exclude-user-primary-group
- Microsoft Learn: https://learn.microsoft.com/windows/win32/ad/using-dsaddsidhistory

## Validation performed

- Production call graph traced from Shell/CLI through derivation and into Judgement.
- All Derivation production files reviewed in full.
- Repository-wide reference searches performed for readers, stores and derived products.
- Relevant tests reviewed for production reachability and false-green behavior.
- No production code changed.
- Build/tests: deferred to report-publication validation because this review adds documentation only.
