# 0070 - Red also marks the way out of something that is running

Date: 2026-08-18
Status: Accepted

Amends [0056](0056-the-visual-language-encodes-three-states.md), which reserved red for critical
findings and spent none of it on the capture-side screens.

## Context

[`0056`](0056-the-visual-language-encodes-three-states.md) reserved red so that when red appears it
means one thing. Its reasoning was that a palette which spends its loudest colour on ordinary chrome
has nothing left to say when something is actually wrong, and that capture-side screens - which
report what a run will do rather than what it found - have nothing critical on them to say it about.

That held while the only controls on those screens were Next, Back and Start. It stopped being the
whole picture once the window began starting things that run for hours: the New Audit window now
carries a Cancel beside the pass it begins on opening, and a Stop beside the capture itself.

## Decision

**Red also marks the control that stops something already running.** Cancel and Stop are drawn in it.

**Not because stopping is dangerous.** It is not: a preflight pass writes nothing, and a stopped
capture records why it stopped and leaves its evidence unpromoted. Nothing is lost by pressing
either, and the product's own instruction that any long-running action must offer a way out is the
reason they exist at all.

**Because they must be findable at a glance, by somebody who has decided he wants out.** An operator
looking for the exit of a three-hour read is not reading button labels left to right. He is scanning
for the one control that ends it. Making it the loudest thing on the screen is what a colour is for,
and it costs nothing that the screen was otherwise spending.

**What red still may not do.** It does not mark a fact. No state mark, cell, row or piece of text
about a domain becomes red on a capture-side screen, because those screens report what a run *would*
do and none of it is a finding. `0056`'s three-state vocabulary - filled disc, filled triangle,
hollow ring - is untouched, and the hollow ring stays the quietest thing on the screen.

## Consequences

**Red now carries two meanings, and they are told apart by what wears it.** A control that acts, and
a severity that describes. That is a real cost of this record: an operator who learns *red means
critical* meets a red Stop button that means nothing of the kind. It is accepted because the two are
never adjacent - severity appears on findings screens, which do not exist yet, and Cancel and Stop
appear only in a footer or beside a progress indicator.

**If that collision ever appears on one screen, this record is what to revisit**, not the button
styling. The alternative considered was giving Cancel and Stop a distinct colour of their own, which
was refused for the ordinary reason: a fourth accent nobody can name is a palette getting away from
itself.

**The reference the owner supplied does not do this.** The predecessor's screenshot spends red only
on severity chips and on a refusal message, and its Cancel is unstyled. This record departs from it
deliberately rather than by oversight.
