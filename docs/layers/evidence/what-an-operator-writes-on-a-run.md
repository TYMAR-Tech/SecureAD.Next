# What an operator writes on a run

**Code:** `next/src/SecureAD.Evidence/Run/RunAnnotations.cs`
**Layer:** Evidence — the one thing in a run's directory a person typed.

[`the-bundle-on-disk.md`](the-bundle-on-disk.md) describes the files a run's directory holds and
[`how-a-bundle-is-read.md`](how-a-bundle-is-read.md) how those directories become rows in a list.
Everything on both of those pages was **observed** — read off a directory or out of a sealed
database, and true whether or not anybody looked. This page is the exception: what an operator
called a run, what he wrote about it, and which run he marked as the thing later runs are measured
against. None of it is evidence, and the whole page exists to keep that line visible.

Was bound by RunAnnotationsDocumentationTests, a documentation gate retired on 2026-09-11,. The `TYPES` table is bound in both directions against
the public types `RunAnnotations.cs` declares, and the doors table against the public members the
class actually exposes, so a method added or removed fails the build rather than leaving a
paragraph describing a product that no longer exists.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `RunAnnotation` | What an operator called a run, what he wrote about it, and whether he marked it as his baseline |
| `RunAnnotations` | Reads and writes that record, in a sidecar beside the evidence and outside the seal |

<!-- TYPES:END -->

This table is the page's claim of ownership. `RunListing.Annotation` is a member of a record
[`how-a-bundle-is-read.md`](how-a-bundle-is-read.md) owns, and that page names these types to say
where the boundary is — a mention, not a claim.

---

## This is annotation and it is not evidence

An operator types it after the fact. He may edit it or delete it at any time. **Nothing may present
it as something the run observed, and no security claim may rest on it** — a run named *clean* is a
run somebody typed the word clean against, and a screen that puts that word beside a finding count
has invited a reader to treat one person's opinion as a measurement.

That is why it lives in its own file rather than in `evidence.db`. The seal proves the evidence is
unmodified since the run finished; a name typed a week later would break that proof if it were
written inside, so the choice would be between an unsealable bundle and a run nobody may rename.
Keeping the note outside makes both possible at once.

---

## The doors, and what each one is allowed to do

<!-- DOORS:BEGIN -->

| Member | What it does |
|---|---|
| `Read` | What the operator wrote about this run, or nothing where he wrote nothing. Never writes |
| `Save` | Records what he wrote, replacing whatever was there. Reports why if it could not |

<!-- DOORS:END -->

**Reading never writes into a bundle.** The sidecar is created by the bundle writer when a run is
sealed, so an ordinary read finds it already there. A run that ended badly has no sidecar and never
gets one from the read path — `Save` creates it, because saving is a write and the operator asked
for it. A read that quietly created a file would modify a customer's evidence directory as a side
effect of listing it.

**A sidecar that will not open is reported as no annotation rather than as a failure.** This is the
one place in this layer where swallowing an error is right, and the reason is narrow: the listing is
how an operator finds a run in the first place, so an unreadable note must not remove the run from
the screen. Nothing security-bearing is lost, because nothing here is security-bearing.

**The absence of the file, of the table, and of a row all mean the same thing:** nobody has
annotated this run. They are not told apart because the difference has no meaning to an operator —
a bundle written before this table existed and a run nobody has named are both unnamed.

**Blank text is stored as nothing**, so clearing a name leaves the run unnamed rather than named
with a space. Surrounding space is dropped for the same reason.

---

## The baseline mark lives here, and that is a decision rather than a convenience

`RunAnnotation.IsBaseline` says whether this run is the one later runs of its scope are compared
against, per [`0069`](../../decisions/0069-a-baseline-is-marked-deliberately.md). It sits beside the
evidence and outside the seal rather than in settings, because **a baseline is a fact about the
library, not about the person looking at it.** An operator opening the same library from another
account must see the same baseline, and one who copies the library to another machine must take it
with him. Per-user settings would give each account a private answer to *what does changed mean
here*, and two people would disagree about whether a forest had drifted while both were reading
correctly.

**False is the honest default.** A library nobody has marked has no baseline, and there is no run
the product may nominate on the operator's behalf — which is the whole of `0069`. Whether a marked
run is *eligible* to be a baseline is a separate question and belongs to
[`whether-two-runs-compare.md`](whether-two-runs-compare.md).

---

## An old sidecar keeps working, and the read path may not repair it

The baseline column was added after the first sidecars were written, so a bundle sealed before it
has a two-column table. Naming `is_baseline` directly would fail the whole read and lose the name
and notes the sidecar *does* have, so the read asks the table what columns it carries and selects a
literal zero where the column is absent.

**The question is asked rather than inferred from a failed query.** A read that failed for some
other reason would otherwise be reported as *not a baseline* — a confident false standing in for a
broken sidecar, which is the shape of claim this product is being rebuilt to stop making.

`Save` repairs the table when the operator marks a run, because `CREATE TABLE IF NOT EXISTS` does
nothing to a table that is already there and every write of the third column would otherwise fail.
The read path cannot do this: it may not write.

---

## Deleting a run takes the annotation with it

Everything in a run's directory goes, the sidecar included, per
[`0078`](../../decisions/0078-a-run-can-be-deleted-after-one-confirmation.md). The name an operator
gave a run is part of the run rather than a record about it that outlives it, and a library holding
notes about runs it no longer has would answer questions about evidence nobody can produce. That
deletion is [`how-a-bundle-is-read.md`](how-a-bundle-is-read.md)'s.

---

## What this document cannot tell you

It does not say what a run *is* or what it read — that is
[`run-identity-and-coverage.md`](run-identity-and-coverage.md) — nor which files sit beside the
sidecar, which is [`the-bundle-on-disk.md`](the-bundle-on-disk.md).

It also cannot tell you that the shell saves what an operator typed against the run he had
selected. That is asserted against the view model rather than here, and the rows below say which
tests carry it.

---

## What is built

**The test is the evidence; this table is only the index.**

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank means
unit-tested but not yet exercised against Active Directory.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| give a run his own name, and see it in the list | `RunAnnotationsTests.TheNameAnOperatorSavesIsReadBack` | 2026-08-21 |
| write notes against a run | `RunAnnotationsTests.TheNotesAnOperatorSavesAreReadBack` | 2026-08-21 |
| correct a name rather than add a second one | `RunAnnotationsTests.SavingAgainReplacesWhatWasThere` |  |
| be certain naming a run cannot damage its sealed evidence | `RunAnnotationsTests.AnnotatingLeavesTheSealedEvidenceUntouched` |  |
| be certain the seal check above can actually fail, so passing it means something | `RunAnnotationsTests.TheSealCheckUsedAboveCanFail` |  |
| be certain a run nobody has named is reported as unnamed rather than as blank | `RunAnnotationsTests.ARunNobodyHasAnnotatedHasNoName` |  |
| be certain a run nobody has written about carries no notes | `RunAnnotationsTests.ARunNobodyHasAnnotatedHasNoNotes` |  |
| be certain a name of nothing but spaces is no name | `RunAnnotationsTests.ANameOfNothingButSpacesIsNoName` |  |
| be certain surrounding space he did not mean to type is not kept | `RunAnnotationsTests.SurroundingSpaceIsNotKept` |  |
| be certain what he typed is saved against the run he selected | `RunLibraryViewModelTests.WhatTheOperatorTypesIsSavedAgainstTheSelectedRun` | 2026-08-21 |
| be told when what he typed could not be saved | `RunLibraryViewModelTests.ASaveThatFailedIsReported` |  |
