# 0026 - One answer to "may these runs be compared", and a card that reports it

Date: 2026-08-12
Status: Accepted. The eleven-state table is superseded by
[`0027`](0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md); the structure it
decides - one component, a closed set of outcomes, eligibility folded in, three card shapes - still
binds.

## Context

The product tells an operator what changed since the last audit, without being asked. That summary
is the first thing most people read and the only thing many of them read.

In the implementation being replaced it was built from five integers. `DescribeDrift` reads
`HasChanges` and five counts, and reads no compatibility verdict, no not-assessed cells and no
withheld reason. A comparison **refused** as incompatible returns a result with every delta
collection empty and `HasChanges` false, so the home screen prints *"No changes since the previous
audit."* for a comparison the system declined to perform, with the success flag set so the card
renders as a clean pass.

That is the failure gate 4 exists to prevent - *found nothing* and *could not compute* rendered
identically - reappearing above the type system, where the gate does not reach. It is also the
defect that makes the tool contradict itself: the attestation dialog tells an operator excluding a
populated domain that *this run will not be usable as a comparison baseline*, and the dashboard
then uses the previous run as a baseline for it anyway.

The cause is structural rather than local. The question *may this run be used* is answered by five
independent rules in the predecessor: three compare commands in one view model, one acceptance
import filter, the drift path, and baseline eligibility - which never checks run state at all, so a
failed run can be made the baseline of a forest and then never compared against. Changing the rule
means finding all five, and the one that is missed does not fail. It disagrees quietly.

## Decision

**One component answers whether two runs may be compared, and every door calls it.** The library,
the automatic drift summary, the compare window, acceptance import and baseline marking read the
same verdict. No caller carries its own predicate, and a rule enforced at one door and not the
other is not enforced.

**The verdict is a closed set of named outcomes, not a boolean and not a count.** Adding an outcome
is an entry, and the compiler then names every place that must handle it. This is what makes the
outcomes cheap to change later without a silent gap: a doorway that has not been updated does not
build.

**Baseline eligibility is part of that verdict, and it includes run state.** The predecessor's
summary said it decided whether a *sealed* run may serve as baseline, and it read coverage only.
A run that did not complete cannot be a baseline.

**The drift card has three shapes, and the shape follows the verdict rather than the counts.**

- **A measured result.** The comparison ran and was fully compatible. This is the only shape
  permitted to say that nothing changed.
- **A qualified result.** The comparison ran, and part of the estate was not assessed or part of
  the analysis was withheld. Counts, plus a statement of what was left out, which cannot be
  dismissed.
- **No result.** No comparison happened. It says so, names the cause in terms of something the
  operator did or can act on, and does not render as a pass.

**The success flag is never set on a path where no comparison occurred.**

The states, and the shape each takes:

| # | Situation | Shape |
|---|---|---|
| 1 | No earlier run exists | No result |
| 2 | The earlier run was deleted | No result |
| 3 | The earlier run never completed | No result |
| 4 | This run excluded a populated domain | No result |
| 5 | The earlier run excluded a populated domain | No result |
| 6 | Coverage differs and the difference is not defensible | No result |
| 7 | Coverage differs and every exclusion is defensible | Qualified |
| 8 | Compatible, but graph findings were withheld | Qualified |
| 9 | Compatible, but the runs came from different major versions | Qualified |
| 10 | Fully compatible, nothing changed | Measured |
| 11 | Fully compatible, changes found | Measured |

**States 1, 2 and 3 stay distinct.** They share an outcome and not a cause. "Nothing to compare
against" reads as *this is your first audit*; if the real reason is that last month's run failed,
or that somebody deleted it, the operator can act on that and cannot act on the other.

**State 7 is a qualified comparison, not a refusal.** A domain decommissioned or an acquisition
finished is a legitimate change to a forest's shape, and refusing to compare across it forever
loses remediation tracking at exactly the moment it is most wanted. The cells only one run covered
are reported as not assessed, which already means *neither fixed nor new*. The predecessor decided
this correctly in its comparison core and then made it unreachable, because the only command that
checked coverage refused every mismatch.

**The state list is documentation and is bound by a test**, in both directions: a state in the code
and not in the document fails the build, and so does a state in the document and not in the code.

## Consequences

Rewording any message costs a string. Moving a state between shapes costs a line. Adding a state
costs an entry, a message and a test, and the compiler finds the rest. That is the property this
decision is buying, and it is bought by the closed set rather than by discipline.

A state that needs a fact capture never recorded is not cheap, because existing bundles cannot
answer it and would have to be re-run. The rules are cheap to change; the evidence is not.

The verdict component is a dependency of the library, the dashboard, compare, acceptance import and
baseline marking. That is deliberate concentration. The alternative is the predecessor's five, and
the concrete cost of those five is a product that promises something in a dialog and contradicts it
on the next screen.

Reporting *no result* honestly will make the product look less capable in cases where it previously
looked confident. That is the correct direction: every one of those cases is a comparison it was
not entitled to make.
