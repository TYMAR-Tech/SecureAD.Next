# 0078 - A run can be deleted, after one confirmation

Date: 2026-08-21
Status: Accepted

Sits under [0025](0025-the-run-library-is-a-managed-root.md) and
[0069](0069-a-baseline-is-marked-deliberately.md). Answers the first of the questions the run
library had left open, carried as `P-76` in [the punch list](../PUNCH-LIST.md) when
The area file docs/areas/the-run-library.md was deleted on 2026-08-24.

## Context

Nothing decided whether a run could be removed from the library, and nothing implemented it. A
managed root that only ever grows is a managed root that fills a disk: a run of a mid-sized forest
is measured in gigabytes, and an operator taking a weekly capture accumulates them faster than he
notices.

The absence had a second cost. An operator who wanted the space back had exactly one option -
delete the folder in Windows Explorer - which is the outcome
[`0025`](0025-the-run-library-is-a-managed-root.md) exists to prevent. A managed root the product
refuses to manage teaches the operator to reach around it, and once he is deleting folders by hand
he is as likely to delete the wrong one, or half of one, as the right one.

## Decision

**A run can be deleted from the library, by the operator, from the library screen.**

**One confirmation, not two.** The operator is asked once, the prompt names the run being deleted,
and confirming does it. A second prompt, a typed run name, or a checkbox saying *I understand* buys
nothing: the operator who is about to delete the wrong run is equally willing to confirm twice, and
every extra step teaches him that this product's prompts are noise to be clicked through. That
lesson is expensive, because the same operator later meets a prompt that matters.

**The prompt names the run, and says the evidence goes with it.** Not *"are you sure?"*. The
operator is choosing between runs that differ by a timestamp, and the thing that makes the choice
safe is seeing which one he picked stated back to him.

**Deletion removes the run's folder and everything in it**, including the annotations sidecar. The
run's own name and notes are part of the run, not a record about it that outlives it.

**Nothing is kept, and no record of the deletion is written to the library.** A tombstone in the
managed root would be a second kind of thing living among runs, and every reader of the library
would need to learn to skip it - the failure
[`0058`](0058-a-run-may-be-stopped-and-stopping-it-keeps-nothing.md) already avoided for cancelled
runs, for the same reason.

**Deleting the baseline is allowed, and the library stops having one.** Refusing would leave an
operator unable to remove the largest run he has, and protecting a mark by making the thing it
points at undeletable inverts which of the two matters. The product says plainly that the forest
has no baseline until one is marked, rather than leaving a mark pointing at nothing.

## Consequences

**The library must survive a run disappearing underneath it.** A folder can also be removed outside
the product, so a listing that assumes what it saw a moment ago is still there is wrong whether or
not this feature exists. Deletion makes the case common rather than creating it.

**A failed deletion is reported and the run stays listed.** A run held open by another process
cannot be removed, and a library that drops the row anyway would tell the operator he has recovered
space he still has not.

**This does not decide archiving, exporting, or moving a run to another machine.** Those remain
undiscussed, and are carried as `P-76` in [the punch list](../PUNCH-LIST.md).
