# 0054 - A domain with no candidate controllers is an attested exclusion

Date: 2026-08-15
Status: Accepted

## Context

[`0050`](0050-the-candidate-list-comes-from-the-configuration-partition.md) settled that when the
configuration partition names no controller holding a domain's naming context, the forest itself is
saying so - an orphaned cross-reference, a failed demotion - and that this is a measured fact rather
than a fault of the run. It then said the run **records it and continues**.

That last step does not hold. The run continues to a sealed bundle which is missing an entire
domain, with nothing human attached to the gap. Every other way a domain leaves a run carries an
operator's statement:
`0049` requires a posture, and
[`0052`](0052-the-domain-is-the-only-unit-of-scope.md) forbids a failure being recorded as a
decision. A domain nobody chose to leave out would be the one hole in a bundle that no one signed.

## Decision

**A domain the forest names no controller for is excluded under attestation, exactly as a domain an
operator chose to leave out.** The operator states a posture - *attested empty* or *attested
populated* - and the run proceeds only once he has. The bundle carries the exclusion, the posture,
and the reason the domain had no candidates.

**It is also recorded as a finding about the forest.** The two statements are different things and
both are kept: the forest has a cross-reference no controller backs, which is a defect in the
directory; and a human decided how to proceed in the face of it, which is a decision about the
audit. Neither substitutes for the other.

**Nothing is inferred on the operator's behalf.** A domain with no candidates is not silently
assumed empty, and it is not silently assumed populated. The tool cannot know, and guessing would
produce a bundle asserting something nobody measured, which
[`0002`](0002-absent-view-means-degraded-run.md) forbids.

## Consequences

This corrects `0050` in place. A no-candidate domain now stops at preflight for a human statement
rather than passing through as a bundle entry.

An unattended run cannot complete against a forest with an orphaned cross-reference. That is
intended: the alternative is unattended completion of a bundle missing a domain.

An *attested empty* posture given here is checked after capture on the same terms as any other,
per `0049`. A claim about a domain nothing could be read from is still falsifiable from what the
rest of the forest says about it.
