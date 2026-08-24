# The home screen

**Code:** `next/src/SecureAD.Shell/ViewModels/HomeViewModel.cs`, `RunLibraryViewModel.cs`,
`RunSummaryViewModel.cs`, `next/src/SecureAD.Shell/Settings/IShellSettingsStore.cs`,
`JsonShellSettingsStore.cs`, `RunLibraryLocation.cs`, `ShellSettings.cs`,
`next/src/SecureAD.Shell/Services/IRunCatalog.cs`, `RunCatalog.cs`
**Layer:** Shell — the first screen: where the run library is, what it holds, and the one place an
audit is started from.

[`ShellSection`](../../../next/src/SecureAD.Shell/ViewModels/ShellSection.cs) describes `Home` as
*where the run library is chosen*, so the library and the home screen are one surface and not two.
The screen an audit is planned on is [`the New Audit screen`](the-new-audit-screen.md).

As with every shell page, the types below are `internal` — the window exports nothing, and
`ShellSurfaceGateTests` fails the build the day it does.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `HomeViewModel` | The first screen: where the run library is |
| `RunLibraryViewModel` | The runs this library holds |
| `RunSummaryViewModel` | One run in the library, as a screen shows it |
| `IRunCatalog` | The runs in a library, as the shell asks for them |
| `RunCatalog` | The run catalogue, over a real run library on a real disk |
| `IShellSettingsStore` | Where the operator's choices are kept between runs of the product |
| `JsonShellSettingsStore` | Settings kept in a small JSON file in the operator's local profile, per machine |
| `ShellSettings` | What the operator has told this installation of the product |
| `RunLibraryLocation` | Where this installation keeps its runs, as one answer shared by everything that asks |

<!-- TYPES:END -->

This table is the page's claim of ownership, bound in both directions against the internal types the
files above declare.

---

## Nothing is claimed about runs until a library is chosen

An unconfigured installation says it is unconfigured. It does not show an empty list, because an
empty list is an answer — *there are no runs* — and the truth is that nobody has said where to look.
The same distinction runs through the whole screen:

- **A library that cannot be read is not reported as empty.** It surfaces the reason instead.
- **A refresh that failed clears what was shown before**, rather than leaving a stale list that looks
  current.
- **An audit cannot be started until a library is chosen**, because a capture with nowhere to write
  is a run that fails at the end instead of refusing at the beginning.

This is the same rule the evidence layer applies to a degraded run, stated at the screen:
[`0002`](../../decisions/0002-absent-view-means-degraded-run.md) forbids rendering *could not
compute* as *nothing found*.

---

## Settings are per machine, and that is not an accident

A run library is a path on a particular machine. `JsonShellSettingsStore` keeps its file in the
**local** profile rather than the roaming one, so a setting does not follow an operator to a
different machine and point at a directory that is not there — or, worse, at a different directory
that is.

The XML comment on that class said *roaming profile* until 2026-08-24 and had never matched the
code, which has always asked for `LocalApplicationData`. The test
`JsonShellSettingsStoreTests.SettingsAreKeptInTheLocalProfileRatherThanTheRoamingOne` is what holds
it, and it is why the disagreement was a comment to correct rather than a behaviour to change.

**An absent settings file and an unreadable one are answered differently.** No file is a new
installation. A file that exists and will not parse is a failure, because silently resetting it
throws away a path the operator chose and then presents the result as though he never chose one.

---

## What is built

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| reach a run written since the library was last read | `RunLibraryViewModelTests.ARunWrittenSinceTheLastReadCanBeAdopted` |  |
| be told when a captured run is not in the library he is pointed at | `RunLibraryViewModelTests.ARunTheLibraryDoesNotHoldSaysSo` |  |
| be certain an audit cannot be started until a run library is chosen | `HomeViewModelTests.AnAuditCannotBeStartedUntilARunLibraryIsChosen` |  |
| start an audit once a library is chosen | `HomeViewModelTests.ChoosingALibraryMakesAnAuditStartable` |  |
| be certain nothing starts an audit until he asks for one | `HomeViewModelTests.NothingStartsAnAuditUntilTheOperatorAsksForOne` |  |
| be told an installation is unconfigured rather than shown an empty path | `HomeViewModelTests.AnUnconfiguredInstallationExplainsItselfRatherThanShowingAnEmptyPath` |  |
| be certain unreadable settings are reported rather than treated as unconfigured | `HomeViewModelTests.UnreadableSettingsAreReportedRatherThanTreatedAsUnconfigured` |  |
| have his library choice remembered between sessions | `JsonShellSettingsStoreTests.APathThatWasWrittenIsReadBack` |  |
| be certain settings are kept per machine rather than following a roaming profile | `JsonShellSettingsStoreTests.SettingsAreKeptInTheLocalProfileRatherThanTheRoamingOne` |  |
| be told why nothing is listed when no library has been chosen | `RunLibraryViewModelTests.WithNoLibraryChosenTheOperatorIsToldWhy` |  |
| be certain nothing is claimed about runs when no library has been chosen | `RunLibraryViewModelTests.WithNoLibraryChosenNothingIsClaimedAboutRuns` |  |
| tell a library that is empty from one that is unreadable | `RunLibraryViewModelTests.AnUnreadableLibraryIsNotReportedAsEmpty` |  |
| see the reason an unreadable library could not be read | `RunLibraryViewModelTests.AnUnreadableLibrarySurfacesTheReason` |  |
| be certain a failed refresh clears what was shown before rather than leaving it stale | `RunLibraryViewModelTests.AFailedRefreshClearsWhatWasShownBefore` |  |
| see the run list gathered into groups of like scope | `RunLibraryViewModelTests.TheRunsAreGroupedByScope` | 2026-08-21 |
| tell a run whose scope is unknown from one that covered the whole forest | `RunLibraryViewModelTests.ARunWhoseScopeIsUnknownIsGroupedApart` | 2026-08-21 |
| mark a run as the baseline of its scope group | `RunLibraryViewModelTests.MarkingABaselineRecordsItAgainstTheRun` | 2026-08-21 |
| be told why a run with no known scope cannot be a baseline | `RunLibraryViewModelTests.ARunWithNoKnownScopeCannotBeABaseline` |  |
| correct a run's name without losing its baseline mark | `RunLibraryViewModelTests.SavingANameDoesNotClearTheBaselineMark` |  |
| open a run from the list and read its evidence | `RunLibraryViewModelTests.OpeningARunHandsOverItsDirectory` | 2026-08-21 |
| be told a run that ended badly has nothing to open | `RunLibraryViewModelTests.ARunThatEndedBadlyHasNothingToOpen` |  |
| delete a run, having been asked once and shown which one | `RunLibraryViewModelTests.DeletingAsksOnceAndNamesTheRun` | 2026-08-21 |
| decline that question and still have the run | `RunLibraryViewModelTests.DecliningTheConfirmationKeepsTheRun` |  |
| be certain confirming removes the run and the list stops showing it | `RunLibraryViewModelTests.ConfirmingDeletesTheRunAndItLeavesTheList` | 2026-08-21 |
| be told when a run could not be deleted, and still see it listed | `RunLibraryViewModelTests.ADeletionThatFailedLeavesTheRunListedAndSaysWhy` |  |
| be certain nothing is deleted, and nothing asked, when no run is selected | `RunLibraryViewModelTests.WithNothingSelectedNothingIsDeletedAndNothingIsAsked` |  |
