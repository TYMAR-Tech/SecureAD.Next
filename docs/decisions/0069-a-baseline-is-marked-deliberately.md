# 0069 - A baseline is marked deliberately, and refused when a domain is missing

Date: 2026-08-16
Status: Accepted

Amended 2026-08-21. The rule on excluded domains was loosened too far when first written: it
admitted *any* declared exclusion. The owner's position is that only a domain the run can show was
**empty** may be excluded from a baseline. The paragraph beginning *"A domain deliberately
excluded"* was replaced, and two rules were added - a falsified claim of emptiness, and a bundle
that cannot be opened. Nothing else in this record changed; the earlier wording is in git history.

Sits under [0025](0025-the-run-library-is-a-managed-root.md),
[0026](0026-one-answer-to-whether-runs-may-be-compared.md),
[0061](0061-runs-of-different-scope-are-not-comparable.md) and
[0063](0063-excluded-never-looks-like-unreachable.md). Answers `B6` of the
S-44 agenda.

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

**An excluded domain refuses a baseline unless the run can show it was empty.** Excluding a domain
is a stated scope for every other purpose, per
[`0063`](0063-excluded-never-looks-like-unreachable.md), and
[`0061`](0061-runs-of-different-scope-are-not-comparable.md) already stops a run of different scope
being compared against it. A baseline is the one place that is not enough. A baseline is a claim
that later drift can be measured against what this run established, and a run that never looked
inside a populated domain established nothing about the principals in it - so it cannot show that
any account or group is safe.

**"Empty" means no security principal in the domain holds, or could hold, privilege elsewhere in
the forest.** Not *"no users"*. A domain with no domain controller cannot be enumerated at all, and
a populated legacy domain will have one, so *"no users, no DCs"* is the wrong test.

**A domain that could not be reached is not thereby excused.** Being unable to audit a domain is a
reason the run is not a baseline, not a reason to overlook it. A populated domain nobody could
reach is exactly the domain a later comparison would report *no change* for, forever.

**A claim of emptiness is checked against the run's own evidence, not trusted.** The claim is
falsifiable: any unresolved group member belonging to the excluded domain is direct evidence the
domain held a principal that mattered somewhere else. A contradicted claim refuses the baseline,
and the refusal says so in those terms rather than repeating the claim back.

**A bundle that cannot be opened is refused, not admitted.** Every other reader of coverage in this
product degrades toward a weaker claim when it cannot read something. This one would degrade toward
*fit to be a baseline*, which is the single conclusion it exists to be able to withhold.

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
