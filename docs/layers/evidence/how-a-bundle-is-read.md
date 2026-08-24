# How a bundle is read

**Code:** `next/src/SecureAD.Evidence/Run/RunLibrary.cs`, `RunStateNames.cs`,
`RunCompletionReader.cs`, `RunListing.cs`, `RunState.cs`, `RunMoment.cs`, `RunScope.cs`
**Layer:** Evidence — the managed root, and how a directory on a disk becomes a run in a list.

[`the-bundle-on-disk.md`](the-bundle-on-disk.md) describes the files a bundle directory holds and the
six states a run can be observed in. This page is one level out again: the **library** those
directories live in, the single door every caller-supplied identifier passes through, how a listing
is assembled, and the order it comes back in. The state vocabulary itself is not restated here —
`STATES` lives on the on-disk page, beside the files it is read from.

`RunStateReader` is named below and is **not** owned here. It reads a run's state out of the files
in a bundle directory, so it belongs beside those files, and its observation table is already bound
there. This page calls it; that is a mention, not a claim. Both headers named the file until
2026-08-24, which cost nothing while neither page claimed ownership and would have given one type
two owners the moment either grew a `TYPES` table.

Bound by `RunLibraryDocumentationTests`, which compares the library's public surface against
`RunLibrary` in both directions, the refusals table against the error codes the class actually
constructs in both directions, and the listing table against `RunListing`'s members in both
directions. A member in the code and not here fails the build, and so does a member here and not in
the code.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `RunLibrary` | The managed root: it creates a run's directory, resolves an identifier to a path, deletes a run, and lists what is there |
| `RunListing` | One run as a listing shows it — every field observed, none parsed out of the directory name |
| `RunState` | What became of a run. The one lifecycle vocabulary, used by the writer, the reader and the display |
| `RunStateNames` | The text a state is stored under in a bundle, in both directions, and the refusal when the text is not one this build knows |
| `RunMoment` | When a run happened, and whether the run itself recorded that or the directory's creation time is standing in |
| `RunScope` | Which domains a sealed run covered, read back out of its bundle, and the group of like runs it therefore belongs to |

<!-- TYPES:END -->

This table is the page's claim of ownership, and it is bound in both directions against the public
types the files above declare: one they declare and this table omits fails the build, and so does a
row naming something they do not. `RunCompletionReader.cs` is named in the header and contributes
no row, because the class it declares is internal.

**Six types, one component, and the reason they are one.** `RunListing` is the row a library
produces, and `RunState`, `RunMoment`, `RunScope` and the annotation are its columns. A column's
type described on a page other than the one describing the row is how a reader comes to believe the
two were designed apart. The exception is the annotation, which is on
[`what-an-operator-writes-on-a-run.md`](what-an-operator-writes-on-a-run.md) because it is written
rather than observed — see below.

---

## The library is a managed root, not a save dialog

The operator chooses **where** the root is; the tool chooses the layout inside it. Capture to an
arbitrary path is not offered, and that is
[`0025`](../../decisions/0025-the-run-library-is-a-managed-root.md) rather than a convenience: without a
catalogue there is nothing to list, nowhere for a baseline to live, and comparison cannot offer
*runs comparable with this one*.

**There is no default root and nothing invents one.** It is supplied by the caller, which gets it
from configuration — kept per user and per machine, per
[`0047`](../../decisions/0047-settings-are-per-user-and-per-machine.md), so where an operator keeps
his evidence is his answer and not one this product chose for him. The predecessor hardcoded
`%LOCALAPPDATA%` into two constructors, which is how a tool comes to fill the wrong disk with
several gigabytes of evidence.

The root is normalised once, in the constructor, and created if it is absent. Every run lives
**directly** inside it — there is no nesting, which is what makes *is this one of ours* a question
with an answer.

<!-- LIBRARY:BEGIN -->

| Member | What it does |
|---|---|
| `Root` | The root, normalised. Every run lives directly inside it |
| `CreateRun` | Creates the directory for a new run and returns its path |
| `Resolve` | Turns a run identifier into a full path, refusing anything that would leave the library |
| `DeleteRun` | Removes a run and everything in it |
| `List` | Every run in the library, as observed |

<!-- LIBRARY:END -->

---

## One door, and everything goes through it

`Resolve` is the only place a caller-supplied identifier becomes a path, and `CreateRun` and
`DeleteRun` both call it before they touch the disk. That is the rule `0025` carried across whole,
and the remarks on the method say the quiet part: **it only works if there is one door.**

An identifier is refused if it is `.` or `..`, contains either separator, is rooted, or carries a
character a filename may not. What survives that is combined with the root and normalised, and then
asked whether it is genuinely below the root.

**Containment is a second wall, and the first one makes it unreachable today.** `IsInsideRoot`
normalises both sides and gives the root a trailing separator before comparing, so `C:\runs-elsewhere`
is not mistaken for a child of `C:\runs`. Mutating it to always pass was not observed by any test on
2026-08-14 — and that is structural rather than a gap in coverage, because `Resolve` rejects every
shape that could reach it. It is kept for the reason B9 keeps two walls against an unfinished
attribute: the first can be weakened by somebody who does not know the second is load-bearing.

> **Do not change without reading this.** Nothing here should be read as evidence that the second
> wall fires. It is unreachable *because* the first wall is exhaustive, so weakening `Resolve` does
> not leave containment holding the line — it leaves the guard that was never exercised holding it.
> This is the same shape as the factory guard argued in `F-S18-5`, and it is written down for the
> same reason.

<!-- REFUSALS:BEGIN -->

| Code | When |
|---|---|
| `RunIdentifierIsEmpty` | No identifier was supplied |
| `RunIdentifierIsNotAName` | It is a path, a traversal, or holds a character a filename may not |
| `RunIsOutsideTheLibrary` | It normalised to somewhere the library does not own |
| `RunDirectoryAlreadyExists` | A run of this forest already exists at this second |
| `RunIsNotThere` | Deletion named a run the library does not hold |
| `RunCouldNotBeDeleted` | The directory would not go, and has been left as it was |
| `RunLibraryCannotBeRead` | The root itself could not be enumerated |

<!-- REFUSALS:END -->

---

## The name carries the forest and the moment, and nothing reads it back

A run is created as `{forest}-{yyyyMMdd-HHmmss}`, sanitised so that a forest name arriving with a
separator in it cannot become a path. A name that sanitises away to nothing becomes `forest`.

The name exists so that somebody looking at a folder listing can tell one run from another. **It is
a convenience and nothing reads meaning back out of it** — what a bundle is evidence of is recorded
inside the bundle, and a name is not evidence. `RunListing` keeps that promise on the other side:
every field on it was observed, and none was parsed out of the identifier.

**A second run of the same forest in the same second is refused rather than suffixed.** Two runs that
close together are almost certainly one run started twice, and a silent suffix would produce two
bundles that are hard to tell apart at exactly the moment somebody is confused about what they
started.

---

## What a listing says, and what it refuses to say

`List` enumerates the root, asks `RunStateReader.Observe` about each directory, and builds one row
per run. Two different kinds of "this is not a normal run" are kept apart, deliberately:

- **A directory that is not a run is left out.** `Observe` refuses a directory holding neither
  finished evidence nor a run in progress, and `List` honours that refusal by skipping it. The
  library root is a folder on an operator's disk; something else being in it is not a damaged audit,
  and listing it as one would be a claim about a run that does not exist.
- **A run that is genuinely unreadable is listed, with its state.** `Damaged` says we found a run and
  could not trust it, which an operator must see. Skipping it would hide a real failure among files
  that were never ours.

<!-- LISTING:BEGIN -->

| Member | What it carries |
|---|---|
| `Identifier` | The run's directory name inside the library |
| `Path` | The full path of the run's bundle directory |
| `State` | What became of the run, as observed from the bundle |
| `Detail` | Why, where the state does not speak for itself. Null for a sealed run |
| `Moment` | When the run happened, and whether the run recorded that itself |
| `Annotation` | What the operator called this run and wrote about it. Not evidence |
| `Scope` | Which domains the run covered. **Null means this was not established** |

<!-- LISTING:END -->

**`Scope` is read, never guessed.** The listing carried no coverage at all until 2026-08-21, on the
reasoning that reading it means opening the bundle. Half of that still stands: `Scope` is null rather
than assumed whenever the bundle would not open, and a screen must show such a run apart rather than
among the whole-forest ones. What changed is that runs are now grouped by what they covered, which
cannot be done without knowing it. Only a **sealed** run is opened — anything else has no evidence to
read, and attempting it would turn every damaged run into a failed open on the way past. A failure
there is null for that one row, not an error for the whole library.

**A run that ended badly is listed, and says so**, per
[`0029`](../../decisions/0029-a-run-that-ends-badly-says-so.md). That record also settles how the
state is arrived at: the file system is asked whether a run is still alive, rather than a record
being trusted to have been updated. A record only says what the last thing to write it believed,
and the failures that matter here — a reboot, a disconnect, a full disk — are exactly the ones that
stop anything from writing it. A run the operator stopped is the exception and keeps nothing at all,
per [`0058`](../../decisions/0058-a-run-may-be-stopped-and-stopping-it-keeps-nothing.md), so it shows
no row.

---

## The order is a chronological claim

The newest run is first, and that ordering is made on **the moment each run recorded for itself** —
when a sealed run completed, when a run that ended badly stopped — and never on the run's name.

Sorting names looks chronological with one forest in the library and stops being chronological with
two, because a name sorts by forest before it sorts by time. An operator reading the bottom row as
the latest run would be reading the latest run of whichever forest sorts last. Runs were listed
oldest first until 2026-08-21, and **that cost real lab work auditing the wrong bundle.**

A run that recorded no moment is placed by its directory's creation time, with `RunMoment.Recorded`
false so nothing downstream presents a fallback as the run's own statement. Creation time is true on
the machine that made the bundle and is reset by copying it elsewhere, which is why it is only ever
the fallback. Identifier order breaks a tie, so the list is stable.

---

## Why completion is read outside the bundle reader

`BundleReader.Open` verifies the seal, which hashes the whole evidence file. The library has already
verified that seal, once, in `Observe`. Going through the reader again would hash every bundle in the
library twice to fetch one timestamp, so `RunCompletionReader` reads the single
`capture_completed_utc` column directly, on a **read-only, unpooled** connection — listing a library
must not alter a byte of anybody's evidence.

> **Do not change without reading this.** Verification is not skipped here, only not repeated.
> `RunCompletionReader` is internal, is called from exactly one place, and that call site sits
> immediately after the seal was found intact. It must not be given a second caller that has not
> verified first. A bundle whose seal does not match is never asked what it says about itself.

A bundle that will not answer the question returns null rather than throwing, and the caller marks
the moment as not recorded.

---

## An unrecognised state is a failure, never a default

`RunStateNames` owns the text a state is stored under, in both directions. **There is one
vocabulary for this question at all**, per
[`0028`](../../decisions/0028-one-run-state-vocabulary.md); the predecessor had four with no two
sharing members. The names are in one place because of what happened when they were not: in the
predecessor the strings were private to the
writer while four readers matched bare literals, so renaming one changed what was written without
changing what was read — and the library funnelled the now-unrecognised value into its in-progress
state. **A sealed run degraded silently and vanished from every picker that filtered on sealed.**
Nothing failed; the runs simply stopped being there.

So reading an unknown name is a failure. The plausible cause is a bundle written by a later version
of this product, and the honest answer is that this version cannot read it. Choosing a state instead
means guessing, and the guess is invisible. Writing a state that has no name throws, because that is
a defect in this product rather than an outcome of a run.

This is the **run** vocabulary only. Phase, checkpoint and coverage states are separate vocabularies
that share words with this one and are deliberately not collected here: a type holding all of them
invites a reader of one column to match a constant belonging to another.

**`RunState` is declared here and explained on the on-disk page, and that is not a contradiction.**
This page owns the enum because the listing is what carries it and `RunStateNames` is what stores
it. What each member *means* — which files on disk produce it, and how the reader chooses between
two that both apply — is [`the-bundle-on-disk.md`](the-bundle-on-disk.md), beside the files it is
observed from. A page may explain a type it does not own; it may not carry a second copy of the
table, which is why `STATES` appears there and not here.

---

## What a run covered is read from the bundle, and never assumed

`RunScope` is the answer to *3 of 3 domains* on a screen. It is a different question from
`RunListing.State`: what became of a run is read from the bundle **directory** and costs nothing,
while what a run *saw* is inside the bundle and costs an open. Both are on a listing row because
runs are grouped by what they covered, and that cannot be done without knowing it — one cheap read
of the declaration rows per run.

**Every declared domain has a row, including the ones nobody read.** The denominator is the forest
as the run found it, not the number of domains the run got to, so a domain nobody looked at is never
indistinguishable from one that held nothing. `RunScope.ExcludedCount` is counted apart from
`RunScope.ShortfallCount` per
[`0063`](../../decisions/0063-excluded-never-looks-like-unreachable.md): an operator reading *2 of 3*
needs to know whether the third was a decision he made or a failure he has not heard about, and
those have different remedies.

**`RunScope.Identity` is `CoverageId`'s value read back, not a second answer computed here.** A
grouping key worked out independently from the domain rows would be a second opinion on *same
evidence*, and two opinions is how runs come to sit in two groups with one heading.

> **This is the one place two coverage types sit on two pages.**
> [`run-identity-and-coverage.md`](run-identity-and-coverage.md) owns `RunCoverage`, `DomainCoverage`
> and `CoverageId` — what a run *is* and what it *read*. `RunScope` is owned here instead because it
> is a column of `RunListing`, and splitting a record from its columns was judged the worse of the
> two seams. A reader after coverage as a subject wants that page; a reader after what a listing row
> holds wants this one. `RunScope.Domains` is a list of that page's `DomainCoverage`, and the two
> pages are bound to their own files, so neither can drift without a gate saying so.

---

## Deleting a run takes everything

Everything in the directory goes, including the annotations sidecar, per
[`0078`](../../decisions/0078-a-run-can-be-deleted-after-one-confirmation.md). The name an operator gave
a run is part of the run rather than a record about it that outlives it; a library holding notes
about runs it no longer has would answer questions about evidence nobody can produce.

**Nothing is left behind to mark the deletion.** A tombstone in the managed root would be a second
kind of thing living among runs, and every reader of the library would have to learn to skip it —
the failure [`0058`](../../decisions/0058-a-run-may-be-stopped-and-stopping-it-keeps-nothing.md) already
avoided for cancelled runs.

**A run that is not there is a failure, not a success.** Reporting nothing to do would tell an
operator he has recovered space he never had, and it would hide a library root pointing somewhere
unexpected. The confirmation he answered named a run he could see. A deletion the file system
refuses leaves the run listed and says why, because a library that dropped the row anyway would tell
him he had recovered space he still has not.

---

## What this document cannot tell you

It does not describe what is inside `evidence.db` — that is
[`what-a-bundle-holds.md`](what-a-bundle-holds.md) — nor which files a bundle directory contains and
what each state is observed from, which is
[`the-bundle-on-disk.md`](the-bundle-on-disk.md). Whether two runs may be compared is
[`whether-two-runs-compare.md`](whether-two-runs-compare.md). What an operator typed against a run,
and how that is stored outside the seal, is
[`what-an-operator-writes-on-a-run.md`](what-an-operator-writes-on-a-run.md) — `List` reads it and
puts it on the row, and that read is a call rather than a claim.

It also cannot tell you that `RunLibrary.DeleteRun` behaves as described **at this level**: deletion
is exercised through the view model against a fake, and the library method itself has no direct test.
That is carried as `P-32` rather than fixed here.

---

## What is built

**The test is the evidence; this table is only the index.**

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank means
unit-tested but not yet exercised against Active Directory.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain a run is created inside the library and nowhere else | `RunLibraryTests.ARunIsCreatedInsideTheRoot` |  |
| tell one run from another in a folder listing, by forest and moment | `RunLibraryTests.TheRunIsNamedForTheForestAndTheMoment` |  |
| be certain starting one run twice does not produce two bundles | `RunLibraryTests.ASecondRunOfOneForestInTheSameSecondIsRefused` |  |
| be certain a forest name arriving with a separator cannot become a path | `RunLibraryTests.AForestNameCannotBecomeAPath` |  |
| be certain an identifier supplied from outside cannot reach a directory the tool does not own | `RunLibraryTests.AnIdentifierThatIsNotASingleNameIsRefused` |  |
| be certain a sibling whose name merely begins with the root's is not treated as inside it | `RunLibraryTests.ASiblingWhoseNameBeginsWithTheRootsIsNotInsideIt` |  |
| see a run he can no longer trust, rather than have it quietly omitted | `RunLibraryListTests.ARunWhoseSealDoesNotMatchIsListedAsDamaged` |  |
| be certain a folder that was never a run is not reported as a damaged audit | `RunLibraryListTests.ADirectoryThatIsNotARunIsLeftOut` |  |
| see a sealed run listed | `RunLibraryListTests.ASealedRunIsListed` | 2026-08-21 |
| tell an empty library from one that could not be read | `RunLibraryListTests.AnEmptyLibraryListsNothing` |  |
| read the explanation on a damaged run | `RunLibraryListTests.ADamagedRunCarriesTheExplanation` |  |
| be certain a sealed run carries no explanation, so an explanation always means something | `RunLibraryListTests.ASealedRunCarriesNoExplanation` |  |
| be certain two runs sharing a moment keep a fixed order | `RunLibraryListTests.RunsSharingAMomentAreListedInAStableOrder` |  |
| see how much of the forest a finished run actually covered | `BundleReaderTests.AWholeForestRunReportsEveryDomainRead` |  |
| tell a domain he left out from one the run fell short on | `BundleReaderTests.AnExcludedDomainIsCountedApartFromAShortfall` |  |
| be certain a half-read domain is never counted as read | `BundleReaderTests.APartiallyReadDomainIsNotCountedAsRead` |  |
| be certain a bundle claiming the impossible is refused rather than reported | `BundleReaderTests.ASealedBundleClaimingADomainWasNotReadIsRefused` |  |
| be certain an outcome written by a later build is not guessed at | `BundleReaderTests.AnOutcomeThisBuildDoesNotRecogniseIsRefused` |  |
| read the top row as the latest run, with two forests in the library | `RunLibraryListTests.TheNewestRunIsListedFirst` |  |
| be certain a run is placed by when it said it finished, not by its name | `RunLibraryListTests.ARunThatRecordedWhenItFinishedIsPlacedByThat` |  |
| be certain a run that recorded no moment does not claim one | `RunLibraryListTests.ARunThatRecordedNoMomentDoesNotClaimOne` |  |
| be certain a bundle from a later version is refused rather than silently downgraded | `RunStateNamesTests.AnUnrecognisedStateIsAFailureAndNotADefault` |  |
| be certain the predecessor's silent degrade to in-progress cannot recur | `RunStateNamesTests.AnUnrecognisedStateDoesNotBecomeInProgress` |  |
| be certain good evidence outranks a stale outcome file left beside it | `RunStateReaderTests.AFinishedBundleOutranksAStaleOutcomeFile` |  |
| be certain a run that said why it stopped is believed over the liveness test | `RunStateReaderTests.ARecordedOutcomeIsPreferredToTheLivenessTest` |  |
