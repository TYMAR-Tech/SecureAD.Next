# SecureAD.Next application workflow

**Status:** Authoritative current and target workflow  
**Scope:** Product orchestration from operator intent to offline results  
**Supersedes:** Stage/reachability summaries in overview documents where they disagree with this file

## Why this document exists

The projects were built in layers and some overview documents retained the state that existed while a
later layer was still absent. The repository therefore contained several true historical statements
that were false descriptions of the current application. Correction work also exposed contracts only
when independently tested components were joined through production paths.

This file is the single current account of how the application works and where it is going. Layer
documents remain authoritative for the behavior inside one stage. Decisions remain authoritative for
why a contract exists. Review and correction documents remain historical evidence and are not edited
to describe a newer state.

## The invariant workflow

```text
                                      ONLINE
                                         │
Operator chooses a forest and run library
                 │                       │
                 ▼                       │
1. Discover and preflight                │
   - discover forest/domain topology     │
   - choose one controller per unit      │
   - negotiate and record security       │
   - build exact authorized scope        │
                 │                       │
                 ▼                       │
2. Review and authorize scope            │
   - included domain naming contexts     │
   - application partitions not read     │
   - exact per-run exclusion attestations│
                 │                       │
                 ▼                       │
3. Capture                              │
   - Configuration and Schema            │
   - each included domain                │
   - relevant SYSVOL policy files        │
   - atomic whole-partition retry        │
                 │                       │
                 ▼                       │
4. Reconcile discovered scope            │
   - compare referrals with the plan     │
   - persist incomplete visibility       │
   - fail before seal on confirmed       │
     unplanned local scope               │
                 │                       │
                 ▼                       │
5. Seal Evidence                         │
   evidence.db + evidence seal           │
                                         │
─────────────────────────────────────────┴──────────────────────────────────────
                                      OFFLINE
                 │
                 ▼
6. Derive reusable facts
   evidence.db → derivation.db + seal
                 │
                 ▼
7. Judge declared inputs
   evidence.db + derivation.db → judgement.db + seal
                 │
                 ▼
8. Read and present
   run library, coverage, assets, permissions, findings
                 │
                 ▼
9. Compare or export
   separately captured runs; reports and machine-readable output
```

The numbered stages and their ordering are frozen. A correction may strengthen a stage's contract,
change a disposable store schema, or make uncertainty explicit. It must not introduce another route
around these stages without an accepted decision changing this document first.

## Stage contracts

| Stage | Input | Output | Current state | May contact a domain controller? | Failure rule |
|---|---|---|---|---|---|
| 1. Discover and preflight | Optional forest hint, controller overrides, machine network context | Exact `CapturePlan` and preflight record | Built | Yes | No run is created when discovery or authorization prerequisites fail |
| 2. Review and authorize | Preflight plan and operator choices | Included scope and exact `AttestedExclusion` values | Built in Shell; CLI is non-interactive | No additional directory reads | An exclusion that does not match the discovered NC/FQDN pair is refused |
| 3. Capture | Authorized plan | Objects, descriptors, memberships, schema and SYSVOL observations in a partial Evidence database | Built | Yes | A partition is either completed or rolled back; unrecoverable failure seals nothing |
| 4. Reconcile | Plan and completed `PartitionCoverage` referrals | Typed continuation reconciliation | Built | No | Complete reconciliation with unplanned local scope seals nothing; incomplete visibility is persisted as incomplete |
| 5. Seal Evidence | Completed capture, reconciliation and coverage | Immutable `evidence.db`, seal and annotations sidecar | Built | No | The readable filename appears only after database completion and sealing |
| 6. Derive | Intact compatible Evidence | Replaceable derivation store bound to that Evidence | Built; AdminSDHolder products persisted and readable | Never | Evidence remains usable; derivation failure/degradation is recorded and can be rebuilt |
| 7. Judge | Intact compatible Evidence and available declared derived inputs | Replaceable judgement store and findings | Built in Shell; CLI integration incomplete | Never | Independent rules may run when unrelated inputs are missing; affected rules and whole-audit state remain explicit |
| 8. Read and present | Intact compatible artefacts | Operator views and API/CLI output | Built foundation; reports incomplete | Never | Missing, stale, malformed or inaccessible products render as typed unavailable/degraded states, never empty success |
| 9. Compare or export | Intact compatible completed artefacts | Differences or reports | Not built | Never | Refuse incompatible scope/identity rather than compare unlike runs |

## Artefact ownership and lifetime

### Evidence is permanent

`evidence.db` is the captured observation of a forest at one moment. Capture is the only producer and
the only stage that may contact Active Directory. Evidence is never updated after sealing. A schema or
semantic incompatibility requires recapture; it is not repaired by rewriting the sealed file.

### Derivation is disposable but expensive

`derivation.db` contains reusable facts computed only from sealed Evidence. It knows nothing about
rules. It must be bound to the exact Evidence generation from which it was built and may be deleted
and rebuilt without contacting the forest.

### Judgement is disposable and rule-dependent

`judgement.db` records rule execution and findings. It consumes Evidence and only the derived products
its rules declare. It is rebuilt when rules or their contracts change and never writes into Evidence
or Derivation.

### Logs and outcomes describe attempts

A run that seals nothing still leaves a durable outcome where a run directory exists. Logs and outcome
files describe what the application attempted; they are not substitutes for Evidence and cannot make
a partial database readable.

## Current host behavior

The stage implementation is shared, but orchestration is not yet shared:

| Host | Current production path | Known gap |
|---|---|---|
| Shell | discover/review → capture → derive → judge → open run/results | `NewAuditViewModel` coordinates stage launchers and owns some lifecycle wording |
| CLI capture | discover/preflight → capture → derive | It does not invoke Judgement |
| CLI `--derive` | open existing Evidence → derive | Deliberately offline; no directory discovery occurs first |
| Developer judging script | open existing Evidence/Derivation → judge | Developer-only entry point, not the target product workflow |
| Budgeted member-attribution library entry point | open current Evidence/Derivation → `JudgeWithMemberAttribution` → persisted attribution/readback | Offline synthetic validation and budget measurement; no production default or host activation |

The bounded member-attribution component is implemented in judgement schema 24/control engine 8 with
Derivation schema 11 inputs; this is not a claim that its production workflow is enabled. Existing
Shell judging supplies no member-expansion or requester-discovery budget. CLI capture still stops after
derivation and therefore activates neither product. The member views read an existing stored product
and do not start expansion. Any production activation requires separate approval and must follow this
workflow rather than introducing a second orchestrator. See the
[implementation and validation boundary](../layers/judgement/the-judgement-store.md#bounded-effective-member-attribution).

Wave 7 replaces host-specific orchestration with one host-neutral application workflow. The replacement
must delete the stage sequencing from `NewAuditViewModel` and `SecureAD.Cli.Program` in the same change;
it must not leave those methods as alternate routes or compatibility wrappers.

## Rules for changing this workflow

1. **One production orchestrator.** Shell and CLI may format input/output differently but may not decide
   stage order, retry policy, degradation, or artefact lifetime independently.
2. **Replacement includes deletion.** A change introducing the shared workflow removes superseded host
   sequencing, launchers or adapters in the same commit unless an accepted external compatibility
   requirement names a removal date.
3. **No internal compatibility shims by default.** This repository does not preserve internal APIs or
   disposable store schemas merely to avoid compile errors. Call sites migrate and obsolete members
   are removed.
4. **Every stage is reachable through a production path.** A component existing only in tests or a
   developer script is not a built product feature.
5. **Every retained developer path is labeled.** A script may remain for diagnosis or maintenance, but
   documentation states that it is non-product and what event removes it.
6. **No second source of truth.** Overview and layer documents link here for stage/reachability status;
   historical reviews and corrections are not rewritten.
7. **Unknown is durable.** A missing or incomplete input crosses each boundary as a typed state. No host
   may turn it into an empty collection, zero, success message or completed audit.
8. **Offline remains offline.** Derivation, Judgement, reading, comparison and export cannot acquire a
   dependency that opens a directory connection.

## Accepted correction order

The workflow remains fixed while its contracts are repaired:

1. Wave 2a froze this workflow, inventoried every current path and added deletion/reachability gates.
2. Wave 3 binds and atomically replaces Derivation/Judgement generations.
3. Wave 4 introduces one completeness and uncertainty vocabulary across all stages.
4. Wave 5 persisted the corrected reusable AdminSDHolder derivation products. **Built 2026-08-30.**
5. Wave 6 makes Judgement consume validated declared input packages and implements current rules.
6. Wave 7 introduces the single production orchestrator and deletes host-specific sequencing.
7. Wave 8 validates the complete workflow against disposable forests and production-shaped scale.

No new security rule is added before the foundations it consumes pass their correction-wave gates.
