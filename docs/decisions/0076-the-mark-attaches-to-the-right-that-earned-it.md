# 0076 - The mark attaches to the right that earned it, not to the entry

Date: 2026-08-18
Status: Accepted

Amends [0074](0074-red-marks-a-takeover-permission-when-the-operator-asks.md), which put the
classifier's mark on a row. What red means is unchanged; what wears it is not.

## Context

`0074` authorised red on the permission list for an entry the classifier calls a takeover, while
the operator has asked for classification. It settled the colour question. It did not ask what the
mark is attached to, and the answer it assumed - the row - turns out not to be a thing that can
carry one verdict.

**An `ACCESS_MASK` is a set of bits, and Windows evaluates them independently.** `AccessCheck`
tests each right the caller asked for, accumulates granted bits across the entries that apply, and
returns when the requested set is satisfied or refused. There is no point at which the mask is
judged as a unit.

`DangerousPermissionClassifier` judges them separately too, by construction: write access to
`userAccountControl` hands over the account and reading it does not; `Modify permissions` is a
takeover and `Read permissions` beside it in the same mask is not. Asked about a whole mask it
answers with whichever of its arms is reached first. That is a fair verdict about the entry and a
useless one about a right - the row says *Takeover* and does not say which of the rights on it
earned that.

This is the entry an administrator is looking at when deciding what to remove, so the missing word
is the one that matters.

**The grounds are what a mask is, not how often this happens.** A measurement was run against a lab
bundle to find what proportion of marked rows carry mixed verdicts, and it was deleted. The defect
is structural: a row showing N rights and carrying one mark cannot say which right earned it, and
that does not become more or less true at 5% or 60%. `S-54` records the reasoning and the two
hazards that came with it - that one lab forest is weak evidence for a product shipping to many,
and that calibrating security judgement to observed frequency is backwards, which `0010` already
forbids.

## Decision

**A row stays one access control entry.** An ACE is what the directory holds, what canonical order
applies to, and what an administrator removes. A table of rights would show a list that does not
exist in the object and that nobody can act on. Nothing about the row's identity changes.

**The mark moves inside it, to the right that earned it.** Each right the entry names is rendered
on its own line and carries its own verdict, its own mark and its own reason. The reason is the
right's, because *this hands over the account* is only actionable next to the right it is about.

**The Risk column is removed.** With every right marked in place, a column repeating the loudest of
them would be a second answer to a question already answered on the same row - and two answers
about one entry is the six-places-disagreeing defect `DangerousPermissionClassifier` exists to end.

**The entry keeps a derived verdict that nothing renders.** It is the loudest thing said about any
one of its rights, computed from them and never asked of the classifier a second time. The counters
count entries, and an entry with any dangerous right counts once, so what the strip means is
unchanged.

**No new judgement was introduced.** The classifier is asked one right's bits at a time and its
arms already test single bits; not one verdict about any right changed. This is a change to what
the screen attaches an answer to, not to what the product thinks is dangerous.

**A right this build has no word for is never judged.** The mask can carry bits nothing names, and
asked about those the classifier's unscoped arm would answer `NotDangerous` - reporting access
nobody examined as safe. Such a right is shown, counted, and refused classification.

**`0074` is otherwise untouched.** Red is still spent only on a takeover, still only while the
operator has asked, still never on a gap. `NotDangerous` and `CannotClassify` still carry no mark
at all. The mark is still a word before it is a colour, per `0056`.

## Consequences

**A screen with the toggle on is louder than it was.** An entry with three dangerous rights now
shows three marks where it showed one. That is the intended reading - it is three things to remove
- but it is the first thing to look at on a running window, and if the volume is wrong the answer
is a finding about a universal pattern, not a quieter mark.

**Not-established moved the same way, and for the same reason.** An unworded bit used to grey the
whole cell, which put *we could not read this* on rights the classifier had just called a takeover
- one line asserting both. It now greys only the line it is about. `F-S52-4` still holds: what was
read and what it grants are separate statements, and folding them together would render an unworded
bit and a granted takeover alike.

**A safety net was removed and had to be replaced.** The classifier expanded generic rights out of
the mask itself, so an unexpanded `GENERIC_ALL` reaching the screen was judged a takeover whatever
the wording made of it. Now the wording chooses which bits the classifier is asked about, and
`GENERIC_ALL` is a bit it has no word for - so the most open entry in a forest would have become one
unclassifiable right and the row would have fallen silent. The permission list expands before
wording rather than trusting the evidence's contract. This is `F-S54-2` exactly: a narrowing change
that silences a true verdict while the count moves the reassuring way.

**A per-principal assessment is still owed and is now more obviously owed.** *In combination* is
marked on the right that is a component, and nothing yet asks whether one principal holds the whole
replication set - the question that makes DCSync. `0016` says who owns it.
