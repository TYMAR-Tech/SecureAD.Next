# 0035 - Coverage is recorded once per capture unit, and every other statement of coverage is derived from it

Date: 2026-08-13
Status: Accepted

## Context

Six things in the rebuild are called coverage. `PartitionCoverage` in capture and
`PartitionCoverageRecord` in the bundle are twins with identical fields and an identical
`IsComplete`, defined in two projects with no conversion between them. `CoverageId`, `DomainCoverage`
and `RunCoverage` describe a run per *domain*. `ContinuationReferenceReconciliation` describes what
the forest mentioned and the run did not plan to read. `CapturePlan` carries a sixth, for partitions
published and not planned.

They are two systems that have never met. The per-partition rows live in the bundle; the per-domain
model is written nowhere in the schema, which contains the word *domain* once, in a comment. Nothing
reconciles them, so the bundle can record that a partition was read while the run model reports the
domain containing it as unread, and whichever is asked first wins.

Two consequences are already reachable. A domain is not the unit of capture: a run reads the
configuration and schema partitions as well, and those belong to no domain, so a failed schema read
has nowhere to be recorded and every domain still reports as read — while
[`0014`](0014-capture-reads-the-schema-partition.md) makes that failure the one that stops any
permission being resolved at all. And `PartiallyRead` may be unreachable, because capture is
fail-fast and a bundle exists only when every unit completed.

[`0027`](0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) records the same seam
failing once before: it was written in a session that read the run library closely and read the
capture decision not at all.

## Decision

**A capture unit — one naming context on one controller — is the only thing that records coverage
directly.** It is written to the bundle as evidence of what was read, and one type expresses it,
defined in `SecureAD.Evidence` and used by capture across the seam. There is no second definition.

**Every other statement of coverage is derived from those rows and never asserted beside them.** A
domain is read when every unit of its naming context completed. A report that says a domain was not
read must be able to name the unit that failed.

**A partition that belongs to no domain is a run-level fact.** The configuration and schema
partitions are the forest's, not a domain's, and a run that cannot read one is a failed run rather
than a domain with a problem. It is never expressed as domain coverage, because that would make a
forest-wide failure look local.

**`CoverageId` continues to hash what the forest declared, not what was read.** Whether the
declaration was achieved is a different question and stays separate.

**The word is reserved.** *Coverage* means what a run read of the directory. What a run may be
compared against is comparability; what the forest mentioned and the run did not plan is
reconciliation. A seventh meaning is a defect.

## Consequences

A reader can always get from *this domain was not read* to the unit and controller that failed,
because the summary is computed from the evidence rather than recorded next to it. Two statements of
coverage can no longer disagree, because there is only one.

The forest-wide partitions become visible for the first time. A schema partition that could not be
read now fails the run loudly instead of passing as a forest fully covered.

Derivation costs a query where an asserted field would have been free. That is accepted: the
predecessor's coverage was asserted in several places and they drifted, which is the failure this
prevents.

Any state the derivation cannot produce is removed rather than kept for symmetry. A closed set with
permanently dead members is what `0027` was written to avoid building.
