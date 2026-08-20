# How the run library stores and lists runs

**Area.** Where finished runs live, how they are named, how the product lists them, and how one is
chosen as the baseline everything else is compared against.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| treats the run library as a managed root that it owns | [`0025`](../decisions/0025-the-run-library-is-a-managed-root.md) |
| uses one vocabulary for the state a run is in | [`0028`](../decisions/0028-one-run-state-vocabulary.md) |
| makes a run that failed say so, and appear in the library | [`0029`](../decisions/0029-a-run-that-ends-badly-says-so.md) |
| keeps nothing at all from a run the operator stopped, and shows no row for it | [`0058`](../decisions/0058-a-run-may-be-stopped-and-stopping-it-keeps-nothing.md) |
| lets the operator mark a baseline deliberately, and refuses one that is missing a domain | [`0069`](../decisions/0069-a-baseline-is-marked-deliberately.md) |
| asks the file system whether a run is alive, rather than trusting a record | [`0029`](../decisions/0029-a-run-that-ends-badly-says-so.md) |
| keeps settings per user and per machine, including where the library is | [`0047`](../decisions/0047-settings-are-per-user-and-per-machine.md) |

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank is the
honest answer for most rows and means unit-tested but not yet exercised against Active Directory -
a test with a synthetic descriptor proves the parser handles those bytes, not that a domain
controller sends them.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|---|
| be certain a run is created inside the library root and nowhere else | `RunLibraryTests.ARunIsCreatedInsideTheRoot` |  |  |
| identify a run by the forest it read and the moment it ran | `RunLibraryTests.TheRunIsNamedForTheForestAndTheMoment` |  |  |
| be certain two runs of one forest in the same second cannot collide | `RunLibraryTests.ASecondRunOfOneForestInTheSameSecondIsRefused` |  |  |
| be certain a forest name can never become a path | `RunLibraryTests.AForestNameCannotBecomeAPath` |  |  |
| be certain a folder beside the root is not mistaken for something inside it | `RunLibraryTests.ASiblingWhoseNameBeginsWithTheRootsIsNotInsideIt` |  |  |
| see a sealed run listed | `RunLibraryListTests.ASealedRunIsListed` |  |  |
| tell an empty library from one that could not be read | `RunLibraryListTests.AnEmptyLibraryListsNothing` |  |  |
| see a run whose seal does not match listed as damaged | `RunLibraryListTests.ARunWhoseSealDoesNotMatchIsListedAsDamaged` |  |  |
| read the explanation on a damaged run | `RunLibraryListTests.ADamagedRunCarriesTheExplanation` |  |  |
| be certain a sealed run carries no explanation, so an explanation always means something | `RunLibraryListTests.ASealedRunCarriesNoExplanation` |  |  |
| be certain a stray folder in the root is left out rather than listed | `RunLibraryListTests.ADirectoryThatIsNotARunIsLeftOut` |  |  |
| see runs listed in a stable order | `RunLibraryListTests.RunsAreListedInIdentifierOrder` |  |  |
| be told why nothing is listed when no library has been chosen | `RunLibraryViewModelTests.WithNoLibraryChosenTheOperatorIsToldWhy` |  |  |
| be certain nothing is claimed about runs when no library has been chosen | `RunLibraryViewModelTests.WithNoLibraryChosenNothingIsClaimedAboutRuns` |  |  |
| tell a library that is empty from one that is unreadable | `RunLibraryViewModelTests.AnUnreadableLibraryIsNotReportedAsEmpty` |  |  |
| see the reason an unreadable library could not be read | `RunLibraryViewModelTests.AnUnreadableLibrarySurfacesTheReason` |  |  |
| be certain a failed refresh clears what was shown before rather than leaving it stale | `RunLibraryViewModelTests.AFailedRefreshClearsWhatWasShownBefore` |  |  |
| have the state of a run read from what is actually on disk | `RunStateReaderTests` |  |  |

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

- **Whether a run can be deleted from the library, and by whom.** Nothing decides this, and a
  managed root that only grows is a managed root that fills a disk.
- **Where the cancellation marker lives.**
  [`0058`](../decisions/0058-a-run-may-be-stopped-and-stopping-it-keeps-nothing.md) requires it to
  be somewhere the library does not read, and does not say where. The owner's position on
  2026-08-16 is that logging around run endings needs thought of its own.
- **Whether a forest may hold more than one baseline** — one per declared scope, say.
  [`0069`](../decisions/0069-a-baseline-is-marked-deliberately.md) leaves this open until an
  operator asks for it.
- **What the library shows about a run before it is opened** — how much of a run's story is legible
  from the list.
- **Whether a run can be moved or copied between machines**, and whether the library notices.

---

## Open findings

| | | |
|---|---|---|
| — | none recorded for this area yet | — |
