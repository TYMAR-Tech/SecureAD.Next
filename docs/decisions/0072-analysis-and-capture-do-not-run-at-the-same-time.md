# 0072 - Analysis and capture do not run at the same time

Date: 2026-08-18
Status: Accepted

Sits beside [0071](0071-the-audit-is-modal-in-effect-not-in-its-own-window.md), which let the
operator leave the wizard while a capture runs, and under
[0045](0045-the-shell-is-built-before-the-judgement-half.md), which built the screens before the
judgement half.

## Context

[`0071`](0071-the-audit-is-modal-in-effect-not-in-its-own-window.md) unlocks the shell once a
capture has started, so an operator can look at Home and at the run library while a read of the
forest is in progress. The owner's concern on reading that proposal was not navigation but
**resources**: opening a run for analysis is heavy work, and doing it on the same machine that is
part-way through a multi-hour capture would have the two compete.

The concern is real and it is **not reachable today**. Nothing in the product can open a bundle.
`RunLibraryViewModel` says so in as many words - *"What a run saw is inside the bundle, and this
product cannot yet open one."* Home lists what became of each run by reading a directory,
which costs nothing worth measuring, and the details card shows what that listing already held.

So the choice is between building a lock today around a screen that does not exist, and recording
the constraint so that the screen is built with it rather than against it. Nothing in this repository
would remind a later session that the concern was ever raised.

## Decision

**When analysis exists, it does not run while a capture is running.** The two are the only two
expensive things this product does, they run on one administrator's workstation, and a capture that
slows down because the operator opened a run is a capture that takes longer than the operator was
told it would.

**The refusal is stated, not implied.** An operator who asks to open a run during a capture is told
that a capture is in progress and that the run will open when it finishes - in the surface, in
words. He is not shown a control that does nothing, and he is not shown a greyed-out button with no
reason attached. A disabled control with no explanation is the shape of a product that appears
broken.

**Listing runs is not analysis and is never refused.** Reading a library directory to say what
became of each run costs nothing, and refusing it would make the run library look unavailable during
every capture for no benefit. The line is drawn at opening a bundle.

**This record is what to cite when analysis is built, and what to revisit if it turns out to be
wrong.** If analysis proves cheap enough to run alongside a capture on the machines this product
actually runs on, that is a measurement, and a measurement is grounds to amend this record. It is
not grounds to quietly allow both.

## Consequences

**Nothing is built by this record.** It is a constraint recorded ahead of the work it constrains,
which is unusual in this tree and is deliberate: the alternative was building a lock now for a
screen that does not exist, and the cost of that is a mechanism nobody can test against the thing it
protects.

**It creates work for the judgement half.** Whatever opens a bundle has to be able to ask whether a
capture is running, which means capture state has to be visible outside the wizard that starts it.
That is a seam that does not exist yet, and this record is why it will be needed.

**A capture that is running must be findable from anywhere the refusal is stated.** Telling an
operator "a capture is in progress" is only useful if he can then go and look at it. The wizard
surface `0071` describes is where he goes, and the path back to it has to exist.
