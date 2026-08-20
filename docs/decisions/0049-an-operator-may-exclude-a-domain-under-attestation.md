# 0049 - An operator may exclude a domain, and must state a posture for it

Date: 2026-08-14
Status: Superseded by 0052 *(see record)*. Its decision is carried forward whole, with one addition:
the falsifiable posture is offered only once ledger row `B11` makes it testable. This record was
written to sit beside 0017 and the pair proved unusable in practice - each was cited against the
other - so 0052 replaces both. Read this for the reasoning; read
[0052](0052-the-domain-is-the-only-unit-of-scope.md) for the rule.

## Context

[`0017`](0017-capture-reads-the-whole-forest.md) refuses operator-configurable exclusion of part of
a directory's **contents**. Every argument in it is about organisational units and containers: a
legal-retention container whose security relevance expired quietly, inherited entries reaching into
an excluded subtree, `CN=Managed Service Accounts` dropped from an exclusion list without saying so,
`CN=Keys` holding authentication material. It closes by separating a read that failed from a choice
that was made:

> A container that cannot be read is a coverage failure, not a scope. The run is degraded and says
> which part it could not reach. It is never presented as a decision the customer made.

**`0017` says nothing about whether an operator may exclude a whole domain.** The session document
`S-36` restated it as though it
did, and that restatement was used twice to refuse a feature the record never spoke about. It has
been corrected there, and this record exists so the question has an answer of its own rather than
being inferred from a neighbouring one.

The predecessor answered it well and the answer was not carried across. It had a domain selection
step, a dialog that refused to let a domain be excluded without a posture being stated, and
`AttestationVerifier`, which tested the falsifiable posture against the captured data after the run
and demoted the run when the claim turned out to be false. That is a control rather than a warning,
and its own class comment says why: *"an attestation the user clicks through is a liability waiver,
not a safety mechanism. It becomes one by being tested."*

## Decision

**An operator may exclude a domain from a run.** A forest that spans a political boundary, an
acquisition half-migrated, or a domain whose credentials this operator does not hold, is a real
situation, and refusing to model it does not make it go away - it makes the operator lie about scope
somewhere the product cannot see.

**An exclusion is a decision, and a decision is never how a failure is recorded.** These are
different events with opposite meanings and they must never share a representation:

- A domain the run **could not read** is a failure. The candidate list was exhausted, and the run
  ends per [`0040`](0040-a-failed-domain-is-read-again-from-another-controller.md) and
  [`0003`](0003-refuse-to-reanalyse-an-incomplete-capture.md). Nothing about it is a scope, and it
  is never presented as something the customer chose.
- A domain the operator **chose to leave out** is an exclusion, and it carries an attestation.

An operator may convert the first into the second by stating a posture for it. Nothing else may.

**An exclusion without a posture is unrepresentable, not merely rejected.** The posture is carried
by the type that records the exclusion, so a postureless one cannot be constructed. No posture is
ever defaulted or inferred on an operator's behalf: manufacturing a claim of emptiness would
fabricate the exact assertion this record exists to be able to test.

**There are two postures and they never render alike.**

- *This domain holds nothing of security value* - no principal in it holds, or could hold, privilege
  anywhere else in the forest. **Falsifiable, and therefore tested rather than trusted.**
- *This domain is populated and I am excluding it anyway* - not verifiable, because the operator has
  already conceded the point.

**The falsifiable claim is measured against the captured evidence.** After capture, any unresolved
group member belonging to an excluded domain contradicts a claim that the domain was empty. A
contradicted claim demotes the run and the bundle names the domain and its evidence. The claim
itself is left intact rather than rewritten, so a reader sees what was asserted and what it turned
out to be.

**A run carrying any exclusion is never a baseline and is never comparable with a whole-forest
run.** This is the guardrail that makes the choice safe to offer. It follows from the run's coverage
identity accounting for the excluded set, and it means an operator cannot produce, by unticking a
box, an artefact that carries this product's name and is clean by omission - the failure
[`0003`](0003-refuse-to-reanalyse-an-incomplete-capture.md) refuses in one form and
[`0015`](0015-a-bundle-names-a-pattern-it-never-explains-one-away.md) in another.

**The attestation is recorded, not only its effect.** *The run could not reach this domain* and
*someone was told what would be lost and accepted it* are different postures, and the second is the
one an auditor may later have to defend.

**Organisational unit exclusion is not reinstated.** `0017` stands, unaltered, and its reasoning is
untouched by this record. A domain is a unit of capture, with its own controllers, its own coverage
and its own reachability; a container is part of a directory this product reads whole.

## Consequences

The coverage identity of a run must account for the excluded domains, which the rebuild had removed
on the grounds that every run covered the whole forest. That is work, and it is the price of the
guardrail rather than an incidental cost - without it, an excluded run could be compared against a
complete one and the difference read as change in the directory.

The product gains a claim it can be wrong about in public, on purpose. A tool that only makes
statements it cannot be caught out on is not more careful; it is less useful. The check that catches
it is what earns the feature.

The new-audit surface has a domain step again. It is not the predecessor's step returning by
default: it exists because this record decides it should, and it shows a posture prompt rather than
a bare checkbox.

Nothing may restate this record. Rows, comments and notes cite `0049`.
