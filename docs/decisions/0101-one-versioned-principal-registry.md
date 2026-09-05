# 0101 - One versioned principal registry, and no classification implies another

Date: 2026-09-06
Status: Accepted.

Settles the consolidation question raised against `P-140`, and constrains how that reconciliation is
allowed to be built.

## Context

The product answers several different questions about the same security identifier, in several
different places:

- `BroadPrincipalCatalogue` - is it too broad to hold a sensitive right?
- `PrivilegedSidCatalogue` - does its presence in an account's SID history indicate privilege?
- `ObjectOwnershipReading` - is an owner administrative, and therefore unreported (`0095`)?
- `0099` - is it an expected control-plane principal?
- `0099` - is it an automatically classified Tier 0 asset?

These drifted apart because each was written where it was needed. `0099` found the consequence: five
operator groups counted as administrative owners and excluded from the control plane, so the product
was on course to answer the same question two ways on two screens.

**The obvious fix is the wrong one.** A single flat `IsPrivileged` or `IsAdministrative` flag would
erase every distinction the product has worked to establish. Backup Operators is legitimately
Tier 0-sensitive for protection and SID-history analysis, legitimately **outside** the expected
control plane, and legitimately **no longer** an accepted administrative owner - all at once. Those
are not contradictions. They are answers to different questions.

## Decision

**The product maintains one versioned principal-classification registry. No classification is
inferred from another unless an accepted decision explicitly defines that implication.**

Each entry can answer, separately and with its own evidence:

1. Is this SID recognised, and what does Microsoft call it?
2. Is it a broad principal?
3. Is it sensitive for privileged `sIDHistory` detection?
4. Is it an expected control-plane principal?
5. Is it an administrative owner?
6. Is it an automatically classified Tier 0 asset?
7. What is its authority scope?
8. What is its capability scope?
9. What evidence or decision supports each classification?
10. Which catalogue version produced the answer?

**Privileged-SID detection, administrative ownership, Tier 0 asset classification, broad-principal
detection and expected control-plane membership remain distinct predicates with separately testable
evidence.** Shared data, separate semantics.

## Consequences

- **Divergence becomes a test failure** rather than a screen-specific behaviour, which is the thing
  the current arrangement cannot do.
- **`P-140`'s reconciliation is bounded by this record.** It removes five operator groups from the
  ownership predicate because `0099` decided that question - not because the control-plane answer
  propagated into it.
- **Every answer carries its version**, so a changed classification reads as a changed version rather
  than as unexplained drift between two runs.
- **The anchor stays outside the registry.** A registry, tests that match the registry and a document
  that matches the tests is `F-S44-2`'s closed loop; each predicate keeps the external anchor it
  already has - MS-DTYP for recognition, Microsoft's group pages for protection, `ad.lab` for the
  measured consequences.
