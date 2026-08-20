# 0057 - Starting an audit is a modal act

Date: 2026-08-16
Status: Accepted

Sits under [0056](0056-the-visual-language-encodes-three-states.md) and
[0045](0045-the-shell-is-built-before-the-judgement-half.md). Settles ledger row `J3`, which
recorded a navigation rail only and left the header and status bar *"to be decided against the
visual language"*.

## Context

The rebuild's New Audit wizard is a page inside the shell, reached from the navigation rail. That
was what fitted in the session that built it rather than a decision, and it was recorded as unbuilt
work.

The predecessor did it differently, and the owner ran that version in production: the wizard was a
modal window over the shell, with its own header naming the forest, a step indicator, and its own
footer carrying the actions and any refusal.

## Decision

**The New Audit wizard is a modal dialog, not a page in the shell.**

Starting an audit is a distinct act with a beginning and an end. It plans a read of every domain in
a forest, it commits to writing several gigabytes of evidence, and once started it runs for hours.
A surface an operator can wander away from mid-decision, leaving a half-planned run behind a rail
button, does not match what the act is.

**The navigation rail loses its New Audit entry, and Home gains the button that opens the dialog.**
A rail entry is a place the operator goes; a modal act is something he starts. The predecessor drew
the same line, and its rail carried no wizard.

**The wizard carries its own chrome**: the forest it will read, a count of the domains it found, the
step as *"Step n of m"* above the question that step is asking, and a footer holding the actions
with any refusal stated beside the button it blocks.

**The window has no status bar.** Reversing an answer given earlier the same day, on better
information: the predecessor's status bar reported the live controller and a verification flag, and
[`0008`](0008-live-verification-is-removed.md) removed both from the product. What remains — the
forest, the run library path — is already stated on the screens where it matters. A strip of chrome
with nothing true to report is telemetry theatre, and it is easier to add one later than to remove
one operators have learned to read.

## Consequences

**The step indicator becomes capable of indicating.** The current "1. Domains  2. Review" renders
both steps identically bold and shows neither as current. That is a defect the modal header fixes as
a by-product rather than a separate task.

**Home has to be worth returning to.** With the wizard modal, Home is where a run starts and where
the operator lands afterwards, rather than a screen passed through on the way to the rail.

**A modal window is its own view and its own view model lifetime**, and closing it must discard a
half-planned run rather than leaving it to be found later in a state nobody remembers choosing.

**Nothing about what the wizard says changes.** This record moves a surface and adds chrome. The two
wording findings open against the screen stay open and are not fixed in passing.
