# 0069 - A baseline is marked deliberately, and refused when a domain is missing

Date: 2026-08-16
Status: Accepted

Sits under [0025](0025-the-run-library-is-a-managed-root.md),
[0026](0026-one-answer-to-whether-runs-may-be-compared.md),
[0061](0061-runs-of-different-scope-are-not-comparable.md) and
[0063](0063-excluded-never-looks-like-unreachable.md). Answers `B6` of the
[S-44 agenda](../next/sessions/S-44-agenda.md).

## Context

A baseline is the run everything else is compared against, so it is the run that decides what
*"changed"* means. Nothing recorded how one is chosen.

The predecessor marked a baseline explicitly and could refuse - its outcomes were `Marked`,
`NotFound` and `RefusedDegradedCoverage`, and eligibility tested whether the run's exclusions were
known.

`0026` records that the predecessor's baseline eligibility *"never checks run state at all, so a
failed run can be made the baseline of a forest and then never compared against"*. That is accurate
and is not contradicted here: eligibility checked **coverage**, not run state. Both were true.

## Decision

**A baseline is marked by the operator, deliberately.** Not the most recent run, and not the most
recent complete one. The run that defines *"normal"* for a forest is a judgement about which
snapshot represents the estate as it is meant to be, and the newest run is frequently not it - it
may be the one taken during a migration, or the week the acquisition landed.

**Marking a baseline can be refused, and the refusal names what is wrong.**

**A run is refused as a baseline when a domain that should have been covered was not read.** A
baseline that is silent about a whole domain makes every later comparison silent about it too, and
the comparison will report *no change* for a domain nobody has looked at since.

**Degraded coverage inside a domain does not refuse it.** A handful of groups that could not be read
is a gap the run states and the comparison carries forward honestly. Refusing a baseline for that
would mean most real forests never get one, which trades a small loss of fidelity for having no
comparison at all.

**The line is the domain**, consistent with
[`0052`](0052-the-domain-is-the-only-unit-of-scope.md) making the domain the only unit of scope. A
missing domain is a missing unit; an unreadable container inside one is a gap within a unit that was
covered.

**A domain deliberately excluded is not a missing domain**, per
[`0063`](0063-excluded-never-looks-like-unreachable.md). It is a stated scope, and
[`0061`](0061-runs-of-different-scope-are-not-comparable.md) already ensures a run of different
scope cannot be compared against it. A run with a declared exclusion may be a baseline for runs
declaring the same exclusion.

**A run that ended badly is not a candidate at all**, and needs no rule here. Under
[`0029`](0029-a-run-that-ends-badly-says-so.md) it produced no `evidence.db`, so there is nothing to
be a baseline of. This closes the gap `0026` describes - not by adding a run-state check to
eligibility, but by there being no such run in the library to mark.

## Consequences

**The library must show why a run cannot be a baseline**, at the moment the operator tries, naming
the domain. A greyed button with no explanation is the defect this record exists to avoid.

**A baseline can stop being valid without changing.** If a later run legitimately covers a domain the
baseline did not, `0061` refuses the comparison, and the operator's remedy is a new baseline. The
product must say that plainly rather than reporting an empty delta.

**Exactly one baseline per forest**, following `0025`'s managed root. Whether a forest may hold
several - one per declared scope, say - is not decided here and is not needed until an operator asks.
