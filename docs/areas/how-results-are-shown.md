# How results are shown

**Area.** What an operator sees after a run: what he lands on, what he navigates by, and how he gets
from a summary to a single object. This is the half of the product that turns evidence into
something a person acts on.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| calls what it shows a **finding**, everywhere, with one word for it | [`0066`](../decisions/0066-a-finding-is-called-a-finding.md) |
| encodes every fact in three states, so *unknown* never renders as *no* | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |
| never lets a screen appear clean while carrying unknowns | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |
| builds the shell before the judgement half | [`0045`](../decisions/0045-the-shell-is-built-before-the-judgement-half.md) |
| shows no live directory browsing, and no verification state | [`0008`](../decisions/0008-live-verification-is-removed.md) |
| keeps an accepted finding visible as a finding rather than removing it | [`0067`](../decisions/0067-an-acceptance-names-one-finding.md) |
| surfaces no assessment mode to the operator | `0007` |

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank is the
honest answer for most rows and means unit-tested but not yet exercised against Active Directory -
a test with a synthetic descriptor proves the parser handles those bytes, not that a domain
controller sends them.

**No finding is shown, because none is computed.** What is built is the navigation tree the Assets
screen filters by — an offline rebuild of the directory from the names a bundle already holds. The
screens themselves live in [`how-the-app-looks`](how-the-app-looks.md).

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|---|
| see the tree rooted at the partitions the run read | `DirectoryTreeTests.TheTreeIsRootedAtThePartitionsTheRunRead` |  |  |
| see a container objects were captured under | `DirectoryTreeTests.AContainerObjectsWereCapturedUnderIsInTheTree` |  |  |
| reach a branch whose intermediate container holds nothing directly | `DirectoryTreeTests.AContainerWithNothingDirectlyInItStillJoinsItsBranchToTheRoot` |  |  |
| be certain nothing is invented above a partition the run read | `DirectoryTreeTests.NothingIsInventedAboveARoot` |  |  |
| reach objects under a container that was never captured | `DirectoryTreeTests.AContainerThatWasNeverCapturedIsStillANodeSoItsBranchIsReachable` |  |  |
| tell a container that was never captured from one that was | `DirectoryTreeTests.AContainerThatWasNeverCapturedSaysSoRatherThanLookingCaptured` |  |  |
| be certain a container name carrying a comma is one container | `DirectoryTreeTests.AContainerWhoseNameCarriesACommaIsOneContainer` |  |  |
| see which domains the run could not read, stated on the tree | `DirectoryTreeTests.ADomainTheRunCouldNotReadIsReportedAsAGap` |  |  |
| be certain a tree missing a branch does not claim to be complete | `DirectoryTreeTests.ATreeWithAGapDoesNotClaimItsBranchesAreComplete` |  |  |
| see which partitions this product does not read at all | `DirectoryTreeTests.APartitionThisProductDoesNotReadIsReportedAsAGap` |  |  |
| open a run's assets and see the tree it captured | `AssetsViewModelTests.ARunOpensRootedAtTheForest` |  |  |
| tell a bundle that would not open from a run that captured nothing | `AssetsViewModelTests.ARefusedBundleDoesNotLookLikeARunThatCapturedNothing` |  |  |
| read a refusal in the words the evidence layer used | `AssetsViewModelTests.ARefusalIsShownInTheWordsTheEvidenceLayerUsed` |  |  |
| be certain evidence is not read while a capture is writing it | `AssetsViewModelTests.WhileACaptureIsRunningTheBundleIsNotRead` |  |  |
| be told why analysis will not run, and when it will | `AssetsViewModelTests.WhileACaptureIsRunningTheScreenSaysWhyAndWhatToDo` |  |  |
| see the objects in the container selected in the tree | `AssetsViewModelTests.SelectingAContainerListsThatContainersObjects` |  |  |
| choose between this object, one level, and everything beneath | `AssetsViewModelTests.ChangingTheLevelListsAgainAtThatLevel` |  |  |
| page through a container holding more objects than fit on a screen | `AssetsViewModelTests.GoingToTheNextPageAsksForIt` |  |  |
| see which objects of how many are showing | `AssetsViewModelTests.ThePagerSaysWhichObjectsOfHowManyAreShowing` |  |  |
| tell a short listing from an empty container | `AssetsViewModelTests.AShortListingIsNotReportedAsAnEmptyContainer` |  |  |
| be certain an object whose class did not arrive says so | `AssetsViewModelTests.AnObjectWhoseClassDidNotArriveSaysSoRatherThanShowingABlank` |  |  |
| list only the objects of a container whose name holds a wildcard character | `ObjectListingTests.AContainerWhoseNameHoldsAWildcardCharacterListsOnlyItsOwnObjects` |  |  |
| be certain the first page is really the first objects by name | `ObjectListingTests.TheFirstPageIsTheFirstObjectsByName` |  |  |
| see an empty container in the tree | `DirectoryTreeTests.AContainerHoldingNothingIsStillInTheTree` |  |  |

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This area is deliberately open.** The owner's position on 2026-08-16: *"part of the rebuild is to
rethink through the screens so we will answer this more when we get to it."* That is a considered
deferral rather than an oversight — these are questions about how a screen reads, and those are
expensive to answer in advance and cheap to answer in front of one. **Stop and ask.**

- **What the operator lands on when a run finishes.** The owner leans towards a dashboard.
- **What he navigates by.** The predecessor's spine was the directory tree — forest, domain, OU —
  with tabs as lenses over the current selection. Whether this product keeps that is undecided.
- **How many kinds of detail screen exist.** The predecessor had eight. The owner has asked to
  discuss this when the screens are built.
- **Whether escalation paths and groups keep dedicated surfaces.** Both flagged by the owner as
  needing deeper discussion.
- **Whether a rule may ever have a screen of its own.** The predecessor gave one rule of sixty-two a
  tab; the owner's provisional view is that it could be a query and a report instead.

---

## Open findings

| | | |
|---|---|---|
| `F-0056-3` | a screen may not scroll horizontally, and nine columns of sentences do not fit | open, needs a layout decision |
| `F-0056-4` | cells truncate mid-word, so a sentence written to distinguish measured from unmeasured says something else | open |
| `F-0056-5` | state marks sit at the left of a cell, reading as though they belong to the column before | open |
| `F-0056-6` | an empty table looked exactly like a table that had loaded and found nothing | open |
