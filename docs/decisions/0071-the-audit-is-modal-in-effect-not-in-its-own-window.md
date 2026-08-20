# 0071 - The audit is modal in effect, not in its own window

Date: 2026-08-18
Status: Accepted

Amends [0057](0057-starting-an-audit-is-a-modal-act.md), which made the New Audit wizard a modal
`Window` over the shell. Sits under [0056](0056-the-visual-language-encodes-three-states.md).

## Context

`0057` moved the wizard out of the shell and into a modal window of its own. Its reasoning was that
starting an audit is a distinct act with a beginning and an end - it plans a read of every domain in
a forest, commits to gigabytes of evidence, and then runs for hours - and that a surface an operator
can wander away from mid-decision does not match what the act is.

**That reasoning is sound and is not disturbed by this record.** What is disturbed is the mechanism
it chose.

Built out, the product opens as a stack of separate top-level windows, each carrying Windows' own
title bar and its own drop shadow: the shell, `NewAuditWindow` over it, `DomainDetailsWindow` over
that, `ExclusionAttestationWindow` beside them, and a raw `MessageBox` on any refusal. The owner's
judgement, looking at it, was that this is the main reason the product reads as an old Windows
application with a modern coat of paint rather than as one designed thing, and that no amount of
work on colour reaches it. A title bar is drawn by the operating system and takes no part in a
design system.

A second thing showed up in the same reading. `NewAuditWindow` does not only plan the audit - the
capture runs inside it too, with its own Stop button and a "View results" at the end. Because the
window is modal, **a three-hour read holds the whole shell locked** for its duration. `0057`
argued modality for the *planning*, and the argument does not extend to the *running*: a capture is
precisely the thing an operator should be able to walk away from and come back to.

## Decision

**The New Audit wizard is a surface inside the shell window, not a window of its own.** One
top-level window, one title bar, one visual language.

**It is still modal in effect while the audit is being planned.** The navigation rail is visibly
inert - it can be seen but not used - so an operator cannot leave a half-planned run behind a rail
button and find it later in a state nobody remembers choosing. `0057`'s requirement is met by state
rather than by a second window.

**The rail becomes live again once a capture has started.** From that moment the plan is committed
and there is nothing half-decided to wander away from, and the operator is watching something that
runs for hours. Holding him on one screen for that is not modality serving a decision; it is a
locked application. What may and may not run alongside a capture is
[`0072`](0072-analysis-and-capture-do-not-run-at-the-same-time.md), not this record.

**The wizard keeps every piece of chrome `0057` gave it** - the forest it will read, the count of
domains, the question the step asks, and a footer holding the actions. None of that was a
consequence of being a window. It is now drawn by the product rather than by Windows, which is the
whole point.

**Domain details stops being a window** and becomes a panel inside the same surface. It is a
read-only comparison of rows and never needed a modal.

**Refusals are stated in the surface, beside the button they block, and not in a `MessageBox`.**
`0057` already said this - *"a footer holding the actions with any refusal stated beside the button
it blocks"* - and the code called `MessageBox.Show` instead. A `MessageBox` is the one control in
this product that no theme can reach.

**The exclusion attestation stays a real dialog.** It asks one short question with an explicit
yes-or-no outcome, where every way out that is not the one button means "he did not state one".
That is what a modal is for, and it is the only place left on the audit path that uses one.

## Consequences

**"Modal" now means a state the shell is in, and that state has to be visible.** An inert rail that
does not look inert is an application that appears to have hung. This is the one part of this record
that can only be judged against a running window.

**Closing the wizard becomes leaving it, and must still discard the half-planned run.** `0057`
required that a closed window discards its plan; with no window to close, the same discipline now
attaches to whatever ends the surface. A wizard that leaves its state behind for the next opening to
inherit would be the failure this record must not introduce.

**The gates that name `NewAuditWindow` change names, and that is a place a check can quietly stop
measuring.** `ViewColourLiteralGateTests` scans views by filename and asserts this one is among
them; a rename that drops it would leave the gate passing over a smaller set than before. The rename
is made in the assertion, not by widening the scan.

**No view model changes.** The wizard's state already reaches the screen through `INewAuditDialog`,
and that seam is why this is a change of surface rather than a change of behaviour. Nothing said
about a domain, a refusal or a run is reworded by this record.
