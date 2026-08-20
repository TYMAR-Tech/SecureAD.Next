# 0074 - Red marks a permission the classifier calls a takeover, when the operator asks

Date: 2026-08-18
Status: Accepted

Amends [0056](0056-the-visual-language-encodes-three-states.md) decision 5, which reserved red for
critical findings, and extends the reasoning of
[0070](0070-red-also-marks-the-way-out.md), which had already spent it
once.

Amended by [0076](0076-the-mark-attaches-to-the-right-that-earned-it.md), which moves the mark from
the row to the right that earned it. What red means here is unchanged; what wears it is no longer
the entry.

## Context

`0056` decision 5 reserved red so that when red appears it means one thing: *this is the thing an
auditor came for*. Its argument was that a palette which has already spent its strongest signal on
gaps has nothing left for a finding. `0070` then let Cancel and Stop wear red, on the grounds that a
control which ends a three-hour read must be findable by somebody scanning for the exit, and noted
that red now carried two meanings told apart by what wears them - a control that acts, and a
severity that describes. `0070` was explicit that **red still may not mark a fact**, because the
screens it was talking about are capture-side and report what a run *would* do.

`S-52` builds the *Highlight risky permissions* toggle, which is the first time
`DangerousPermissionClassifier` runs against sealed evidence. It marks entries the classifier calls
a takeover of the object. That is a fact, on an evidence-side screen, and so it is exactly what
`0070` declined to authorise.

Three things make it a different question from the one `0070` answered:

- **It is not a gap.** `0056`'s worry was a palette spending red on unknowns and unestablished
  facts. This is the opposite end: an entry that was read, understood, and found to hand somebody
  control of the object.
- **Nothing wears it unless the operator asks.** The toggle is off by default. A screen nobody has
  touched carries no red at all.
- **`CriticalFindingBrush` was already the palette's word for it.** The alternative was
  `EstablishedBadBrush`, which is amber and which `0056` gives to *established, and bad* - the state
  a dangerous permission is genuinely in.

## Decision

**A permission the classifier calls `Dangerous` is drawn in red, and only while the operator has
asked for classification.** It binds `CriticalFindingBrush`.

**Because a takeover-class permission is the thing an auditor came for.** `0056` reserved red for
critical findings on the reasoning that the colour should be spent on what the customer is paying
to be told. A delegation that lets somebody rewrite an object's permissions is that thing. Withholding
red until a rule engine exists to call the same entry a finding would mean the product knows the fact
and declines to say it in the language it built for saying it.

**A `DangerousInCombination` permission is marked more quietly than a `Dangerous` one**, and not in
red. It is not a takeover on its own, and one entry cannot say what else its principal holds.

**Nothing else on the permission list becomes red.** `NotDangerous` and `CannotClassify` carry no
mark at all. In particular an entry this build could not classify is not marked in any colour: it is
neither reported as safe nor accused, and the counters say separately that it was not assessed.

**Red still may not mark a gap, and `0056`'s three-state vocabulary is untouched.** The filled disc,
the filled triangle and the hollow ring keep their meanings and their colours, and the hollow ring
stays the quietest thing on any screen. This record adds a mark for a fourth thing - a classifier
verdict - and does not redefine the three.

## Consequences

**Red now carries three meanings.** A control that acts (`0070`), a severity that describes
(`0056`), and now a classifier's opinion of one access control entry. The first two were held apart
by the argument that they are never adjacent. That argument is weaker here: the permission list is
an evidence-side screen and a findings screen will eventually be one too.

**What makes it tolerable is that the third meaning is a subset of the second, not a rival to it.**
A dangerous permission is not a different kind of thing from a critical finding; it is the same kind
of thing, established by a narrower machine. When rules arrive, an entry marked red here should be
among what they report, and if it is not, one of the two is wrong - which is a useful thing for the
screen to be able to show rather than a collision to be avoided.

**The toggle carries the honesty this record depends on.** Red set by nothing would be the failure
`0045` warns about: a colour an administrator reads as a security verdict, with no judgement behind
it. The whole of this record rests on the mark being the answer to a question the operator asked,
and it is void if the toggle ever defaults to on.

**`StateMarks.xaml` said "NO RED" and no longer can.** That comment was true when written and is
corrected in the same change as this record, because a header that describes the file's rule
incorrectly is worse than no header.

**The counters do not follow the colour.** *Dangerous* is a count, not a severity, and it is shown
in ordinary text. Nothing on the strip is red, including when the count is high.
