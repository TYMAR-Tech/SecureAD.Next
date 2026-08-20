# 0052 - The domain is the only unit of scope

Date: 2026-08-15
Status: Accepted. Supersedes 0017 and
0049, which are closed by this record.

## Context

Two records governed scope and they were written a fortnight apart, from opposite directions.
`0017` refused operator-configurable exclusion and said so in absolute terms - *"nothing an operator
can set makes a run smaller"*. `0049` then decided an operator may exclude a whole domain, and
reconciled the two by arguing that `0017` had only ever meant a directory's *contents*.

That reconciliation is defensible and it did not work. Each session read whichever record was
nearer, cited it against the other, and stopped. The same feature was refused twice on `0017`'s
wording, then `0049` was written to overturn a refusal `0017` never intended, and `S-36` had to be
corrected for restating the boundary wrongly. A rule that has to be assembled from two records is a
rule nobody can apply.

This record replaces both with one line that needs no reconciling.

## Decision

**The domain is the only unit of scope. Everything below it is read whole.**

An operator may leave a whole domain out of a run. He may not leave out anything smaller - no
organisational unit, no container, no subtree, no object class beyond the shipped noise list in
[`0034`](0034-capture-excludes-a-shipped-noise-list.md). There is no third case.

**Why the line sits there.** A domain is a unit of capture in its own right: its own controllers,
its own reachability, its own coverage, and a boundary the directory itself draws. A container is
not. Excluding a container does not remove its risk from the evidence, it removes the *owner* of
that risk - the permission held by a principal inside it is still captured, sitting on the target
object, naming an identifier nobody can resolve. Inherited entries reach into it, so every count of
what a permission reaches is understated by exactly the size of the exclusion with nothing saying
so. Groups outside hold members inside. The one thing genuinely hidden is the delegation set **on**
the excluded container, which is the thing an auditor came to look at.

And container relevance expires. The feature that motivated the original refusal was a legal
retention container, reviewed once and judged harmless. That judgement was correct on the day and
nobody re-made it while a service account was created inside and control was delegated to whoever
ran the retention tooling. Security relevance is a property of a container *on a date*.

A domain has none of these properties. Excluding one removes a whole partition, its principals and
its permissions together, and the hole it leaves is the shape of a domain rather than the shape of a
leak.

**An exclusion carries a posture, and a postureless exclusion is unrepresentable.** The posture is
carried by the type that records the exclusion, so one cannot be constructed without it. No posture
is ever defaulted or inferred: manufacturing a claim on an operator's behalf would fabricate the
exact assertion this record exists to be able to test.

**There are two postures and they never render alike.**

- *This domain holds nothing of security value* - no principal in it holds, or could hold, privilege
  anywhere else in the forest. Falsifiable, and therefore tested rather than trusted.
- *This domain is populated and I am excluding it anyway* - not verifiable, because the operator has
  already conceded the point.

**The falsifiable posture is offered only where it can be tested.** Testing it means reading the
captured evidence for a group member belonging to an excluded domain, which requires the group
membership writer and the unresolved-member classification of ledger row `B11`. Until those exist,
the product offers the second posture alone. An attestation the user clicks through is a liability
waiver rather than a safety mechanism; it becomes one by being tested, and a verifier with nothing
to read would report every claim as verified while measuring nothing.

**A failure is never recorded as a decision.** A domain the run could not read is a coverage
failure: the candidate list was exhausted and the run ends, per
[`0040`](0040-a-failed-domain-is-read-again-from-another-controller.md) and
[`0003`](0003-refuse-to-reanalyse-an-incomplete-capture.md). An operator may convert that failure
into an exclusion by stating a posture for it. Nothing else may, and the product never presents a
read it could not make as something the customer chose.

**A run carrying any exclusion is never a baseline and is never comparable with a whole-forest
run.** The run's coverage identity accounts for the excluded set, so the two cannot be compared and
the difference read as change in the directory. This is the guardrail that makes the choice safe to
offer.

**The bundle is never scoped below the domain.** Analysis is performed over everything captured -
the control graph and escalation paths are built complete, because a path passing *through* a
container a customer does not care about, to reach one they do, is a real path.

**Report scope is a reading-layer filter and lives in the sidecar**, beside the notes, suppressions
and tier overrides [`0015`](0015-a-bundle-names-a-pattern-it-never-explains-one-away.md) already
places there. It is the customer's annotation about their organisation, never a claim by the
product, and it applies and un-applies without touching the directory. **A figure that has been
scoped says so** and can name what was left out in one step.

## Consequences

The rule is one sentence and no session has to weigh two records against each other to apply it.

An excluded domain costs comparability, and that is deliberate: an operator cannot produce, by
unticking a box, an artefact carrying this product's name that is clean by omission.

`B11` becomes a prerequisite for the falsifiable posture rather than a later refinement. Until it
lands, an operator who wants a domain left out must concede that it is populated, which is the
honest position for a product that cannot yet check the alternative.

Coverage identity must account for the excluded set. `CoverageId` currently states that there are no
exclusions and cites `0017` for it; that paragraph is wrong under this record and is work.

A customer forwarding a bundle to an auditor forwards the complete analysis of every domain that was
captured, including findings they chose not to see in their own reports. That will surprise someone,
so the product says it plainly.

Escalation paths through a scoped container to an unscoped target are found and reported, naming the
scoped object as a hop.

Ledger rows `B3` and `K10` - organisational unit exclusion - stay deleted.

Nothing may restate this record. Rows, comments and notes cite `0052`.
