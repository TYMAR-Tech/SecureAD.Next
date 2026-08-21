# 0069 - A baseline is marked deliberately, and belongs to a scope

Date: 2026-08-16
Status: Accepted

Amended 2026-08-21, twice in one day, and the second amendment withdrew the first.

The original admitted *any* declared exclusion as a baseline. That was loosened too far, and the
first amendment replaced it with the predecessor's rule: an excluded domain refuses a baseline
unless the run can show it was empty, with the operator's claim checked against the run's own
unresolved references.

That rule is now gone too, because it was solving a problem this record had created for itself. It
rested on proving a domain empty *without reading it*, which the product cannot do - the reading is
exactly the work that was skipped. The owner's answer was simpler and better: **runs are grouped by
which domains they covered, and each group has its own baseline.** A baseline then claims nothing
about a domain outside its own scope, so there is nothing left to prove and nothing to refuse. Both
earlier wordings are in git history.

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

**A run that did not read a domain it meant to read cannot be a baseline, and needs no rule here.**
Such a run does not seal: capture refuses to write a bundle where a declared domain was left unread
without an attestation, so there is no such run in the library to mark. What remains is a run that
read everything it set out to read, over a scope it stated.

**The line is the domain**, consistent with
[`0052`](0052-the-domain-is-the-only-unit-of-scope.md) making the domain the only unit of scope. A
missing domain is a missing unit; an unreadable container inside one is a gap within a unit that was
covered.

**A baseline belongs to a scope, not to a forest.** Runs are grouped by which domains they actually
covered - the identity [`0052`](0052-the-domain-is-the-only-unit-of-scope.md) requires `CoverageId`
to carry - and each group holds one baseline of its own. A forest audited three ways has three
groups and may hold three baselines.

**Any sealed run may be the baseline of its own group**, and marking one is never refused for
coverage. This is what makes the record simple: a baseline that speaks only for its own scope
cannot be silent about a domain its comparisons cover, because every run it will ever be compared
against left the same domains out. `0061` already refuses a comparison across scopes, so the
question of a baseline with a hole in it does not arise.

**This replaces the attempt to prove an excluded domain empty.** A domain that was not read cannot
be shown to hold nothing - establishing that is the work the exclusion skipped - so a rule
requiring it would either be unenforceable or would rest on absence of evidence. Grouping removes
the need for the claim entirely.

**A group that does not cover the whole forest must say so wherever it appears.** This is the one
safeguard the simplification costs: *no change since baseline* means something narrower in a group
that left a domain out, and a reader who cannot see the scope will read it as the whole estate. The
wording is not settled here.

## Consequences

**One baseline per scope group**, within `0025`'s managed root. This answers the question the
original record left open - *whether a forest may hold several, one per declared scope* - and the
answer is yes, because that is what makes the rest of this record simple enough to be true.

**A baseline can stop being valid without changing.** If a later run legitimately covers a domain the
baseline did not, `0061` refuses the comparison, and the operator's remedy is to mark a baseline in
that run's own group. The product must say that plainly rather than reporting an empty delta.

**Marking a baseline is not refused for coverage**, so the refusal message the original record
asked for is no longer owed. A run that ended badly still cannot be one, and that needs no rule
here: under [`0029`](0029-a-run-that-ends-badly-says-so.md) it produced no `evidence.db`, so it is
not in the library to mark.
