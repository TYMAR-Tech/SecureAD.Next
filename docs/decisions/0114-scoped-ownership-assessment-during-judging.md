# 0114 - Scoped ownership assessment during judging

Date: 2026-09-08
Status: Accepted.

The owner explicitly approved audit integration with schema 26/control engine 9, and separately
approved status-only UI wording and the two additional progress labels. No on-demand action button
was approved in this slice.

## Decision

Judging first retains the existing basic permission products and offers each object to each scheduled
rule once. It then consumes the shared classifier and selector, persists automatic ownership scope
and coverage, assesses hypothetical ownership transitions only for selected targets, and publishes
the completed immutable Judgement generation. The existing current-owner findings, existing-owner
control, WRITE_OWNER, WRITE_DAC, full-control proof/supports, expectedness and group-held counts remain
independent and preserved. Alternative ownership candidates remain represented by retained primitive
source edges even when detailed assessment is not run.

Use reusable indexed captured inputs through the canonical classifier. Do not implement a second
Tier-0 definition or repeatedly scan the entire captured population for every target. This is an
integration requirement, not a measured performance claim.

Missing required ownership-scope inputs produce a stored unavailable/not-assessed status, not fake
binding IDs, a safety verdict or silent forest-wide detailed assessment. Unsupported asset,
membership, control and dependency qualification remain explicit scope limitations. A finished
selector walk cannot erase them. The ownership assignment/server-behavior verification gate remains
open; selection does not prove takeover.

Scope, reasons, input identities, semantic versions and per-target assessment status are written
before publication and validated on readback. Preserve primitive IDs and complete shared permission
values when appending selected-target transitions. Cancellation or failure before publication must
leave the previous published generation intact. A passive reader displays stored answers; it must not
perform fresh discovery or save analysis while opening a page.

## Approved presentation

Add target-specific status beneath the existing control coverage, without a new top-level screen or
an on-demand action button:

- **Assessed automatically from captured evidence.**
- **Not assessed automatically.**
- **Not assessed automatically: required derived inputs are unavailable.**

Where applicable, append **Automatic ownership scope is incomplete; this is not a safety verdict.**
The holder view explains that assessment is target-specific and directs the user to the target view
for the selected object's status; it must not claim that all targets controlled by that holder share
one assessment status.

The additional progress labels are **Selecting ownership assessment scope** and
**Assessing ownership takeover**. Preserve the existing progress correction, phase outcomes and
object counters; no completion may be reported before publication finishes.

## Version and validation boundaries

Use Judgement schema **26** and control engine **9**. Catalogue 3 and the Evidence/Derivation formats
remain unchanged. Older audit generations are not rewritten, relabelled or deleted; the existing
schema policy requires re-judging for current readback. Preserve the previous source and measurement
artifacts rather than weakening frozen comparers to accept intentionally changed assessment counts.

Validate basic-product parity separately from the approved differences in hypothetical assessment
records and coverage. Use synthetic/offline tests for selection, proof/readback integrity, missing
inputs, generation isolation, cancellation and publication failure. No live access, recapture,
production expansion budget, requester/member activation, new measurement harness, frozen benchmark
change, commit or push is authorized. Target-specific on-demand execution/publication remains later
work, and no runtime, storage-saving or production-acceptance claim follows without separate evidence.
