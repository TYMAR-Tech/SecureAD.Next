# 0061 - Runs of different scope are not comparable

Date: 2026-08-16
Status: Accepted

Adds an outcome to [0026](0026-one-answer-to-whether-runs-may-be-compared.md)'s closed set. Sits
under [0052](0052-the-domain-is-the-only-unit-of-scope.md) and
[0059](0059-an-exclusion-is-attested-once-per-run.md). Answers `A4` of the
S-44 agenda.

## Context

[`0026`](0026-one-answer-to-whether-runs-may-be-compared.md) decided that one component answers
whether two runs may be compared and every door calls it, and that the verdict is a closed set of
named outcomes rather than a boolean. It did not decide the case where one run excluded a domain and
the other read it.

The predecessor is a warning here rather than a model. Its attestation dialog told an operator
excluding a populated domain that *this run will not be usable as a comparison baseline*, and its
dashboard then used the previous run as a baseline for it anyway - a promise made in one place and
broken in another, quietly, because five independent rules answered the same question.

## Decision

**Two runs that did not cover the same set of domains may not be compared. The comparison is
refused, and the refusal is stated.**

**Refused, not degraded.** Not compared-with-a-caveat, not compared-with-the-excluded-domain-greyed.
The verdict is a refusal with a reason naming the domains whose treatment differed.

The alternative - comparing anyway and reporting the excluded domain as *not compared* - was
considered and refused. It is more honest than comparing blindly, but it puts a per-domain
truthfulness obligation on every surface that renders a comparison: the delta counts, the summary
sentence, the report, and every future screen nobody has drawn yet. One of them will eventually
total a column across domains that were not all measured, and it will be right-looking and wrong.
Refusing once, in the one component `0026` established, is a rule that cannot be half-applied.

**This is a statement about scope, not about failure.** A run that *could not read* a domain is
degraded under [`0002`](0002-absent-view-means-degraded-run.md) and is a different case, governed by
its own records. This outcome is about two runs that were each exactly what their operator asked
for, and asked for different things.

## Consequences

**Changing scope starts a new comparison lineage.** The first run after an exclusion changes has
nothing to be compared against, and the product says so rather than inventing a baseline. That is
the correct report: the question *"what changed?"* has no answer across a scope change, and the
honest output is to say the question cannot be asked.

**This is friction, and it compounds with
[`0059`](0059-an-exclusion-is-attested-once-per-run.md).** Because an exclusion is re-attested every
run, an operator who has a permanently out-of-remit domain must exclude it every time *and* must get
it right every time - one forgotten exclusion, or one added by mistake, and that run compares
against nothing. Accepted knowingly. The screen where he confirms scope therefore has real weight,
and it must make the scope he is about to commit to obvious before he commits.

**The refusal must be legible, not a code.** An operator told only *"not comparable"* will assume a
defect. He is told which domains differed and in which direction.

**`0026`'s outcome set grows by one**, and by that record's own rule every door reads it - the run
library, the automatic drift summary, the compare window, acceptance import and baseline marking.
None of them carries its own version of this test.

**Baseline choice is affected and is not yet decided.** A run cannot sensibly be a forest's baseline
if the runs that follow it will have different scope. What the run library does about that is `B6`
of the agenda and remains open.
