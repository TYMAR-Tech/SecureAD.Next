# Running a capture

**Area.** What happens between an operator pressing the button and a run being finished: how the
work is planned, how the domains are read, how a run reports its own state, and what a run that
ended badly says about itself.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| starts a capture exactly one way, whether from the window or the command line | [`0039`](../decisions/0039-one-way-to-start-a-capture.md) |
| reads domains in parallel | [`0041`](../decisions/0041-capture-reads-domains-in-parallel.md) |
| reads a failed domain again from another controller | [`0040`](../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md) |
| has one vocabulary for the state of a run, used everywhere | [`0028`](../decisions/0028-one-run-state-vocabulary.md) |
| makes a run that ended badly say so, rather than leaving it to look finished | [`0029`](../decisions/0029-a-run-that-ends-badly-says-so.md) |
| produces a new bundle when it re-analyses, never editing the old one | [`0021`](../decisions/0021-re-analysis-produces-a-new-bundle.md) |
| refuses to re-analyse a capture that was never complete | [`0003`](../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md) |
| surfaces no assessment mode to the operator | `0007`, [`0031`](../decisions/0031-there-is-no-assessment-mode.md) |
| lets an operator stop a run, and keeps nothing at all when he does | [`0058`](../decisions/0058-a-run-may-be-stopped-and-stopping-it-keeps-nothing.md) |
| shows a line for the run and a row for each domain while a capture is going | [`0060`](../decisions/0060-a-running-capture-reports-one-line-per-domain.md) |
| counts errors per domain as they happen, without calling that domain failed | [`0060`](../decisions/0060-a-running-capture-reports-one-line-per-domain.md) |
| lets nothing on the progress screen reach a bundle, a report or a comparison | [`0060`](../decisions/0060-a-running-capture-reports-one-line-per-domain.md) |
| opens New Audit as a modal act, launched from Home | [`0057`](../decisions/0057-starting-an-audit-is-a-modal-act.md) |

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
|---|---|---|
| be refused a run that would read no domain at all | `CapturePlanTests.APlanThatReadsNoDomainIsRefused` |  |
| see one unit of work planned for every domain in the forest | `CapturePlanTests.AForestWithSeveralDomainsPlansAUnitForEach` |  |
| see a plan called complete only when it covers every declared domain | `CapturePlanTests.APlanCoveringEveryDeclaredDomainIsComplete` |  |
| be told a plan is not complete when it leaves a declared domain out | `CapturePlanTests.APlanThatDoesNotCoverEveryDeclaredDomainIsNotComplete` |  |
| be sure the configuration and schema partitions are read before anything is interpreted | `CapturePlanTests.TheConfigurationAndSchemaPartitionsAreReadFirst` |  |
| see each domain read from the controller chosen for it, not from whichever answered first | `CapturePlanTests.EachDomainIsReadFromItsOwnController` |  |
| learn that a partition the forest declares went unread, instead of it vanishing | `CapturePlanTests.APartitionTheForestDeclaresAndTheRunDoesNotReadIsRecorded` |  |
| trust that list even when the controller publishes an incomplete picture of itself | `CapturePlanTests.TheUnreadListDoesNotDependOnWhatTheControllerPublishes` |  |
| be stopped before a run starts, rather than part-way through, when a controller cannot serve a partition | `CapturePlanTests.APartitionTheControllerDoesNotServeIsRefusedBeforeTheRunStarts` |  |
| tell a controller that answered "none" from one whose question failed | `CapturePlanTests.AControllerThatPublishesNothingIsAFailedQuestionRatherThanAnAnswerOfNo` |  |
| tell a run still going from one nothing is holding any more | `RunStateReaderTests.APartialFileSomethingIsHoldingIsInProgress`, `RunStateReaderTests.APartialFileNothingIsHoldingIsInterrupted` |  |
| tell a run that was cancelled from one that failed | `RunStateReaderTests.AnOutcomeFileRecordingACancellationIsCancelled` |  |
| read what was wrong with a damaged run, not merely that it was damaged | `RunStateReaderTests.ADamagedRunSaysWhatWasWrongWithIt` |  |
| be certain a recorded outcome is believed over a guess about whether the run is alive | `RunStateReaderTests.ARecordedOutcomeIsPreferredToTheLivenessTest` |  |
| be certain a finished bundle outranks a stale outcome file left behind | `RunStateReaderTests.AFinishedBundleOutranksAStaleOutcomeFile` |  |
| be refused a state for a directory that is not a run, rather than given a misleading one | `RunStateReaderTests.ADirectoryThatIsNotARunIsRefusedRatherThanGivenAState` |  |
| rely on one set of names for run states everywhere they appear | `RunStateNamesTests` |  |
| have a capture run end to end and produce a readable bundle | `CaptureRunEndToEndTests` |  |
| start a run from the command line the same way the window does | `CommandLineSurfaceGateTests` |  |

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

- **What a run does when the chosen controller fails part-way through.**
  [`0040`](../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md) decided a
  failed domain is read again from another controller; **nothing walks that path today** (`F-S40-1`).
  Whether the operator is told, and when, is undecided.
**Two questions that stood here on 2026-08-16 are now answered** and have moved into *What is
decided*: whether an operator can stop a run
([`0058`](../decisions/0058-a-run-may-be-stopped-and-stopping-it-keeps-nothing.md) — he can, and it
keeps nothing), and how much of a run is shown while it is going
([`0060`](../decisions/0060-a-running-capture-reports-one-line-per-domain.md)).

- **Where the cancellation marker is written**, and what the product logs about run endings
  generally. `0058` requires the marker to be somewhere the run library does not read, and the owner
  flagged logging as needing thought of its own.
- **Whether the operator sees which error occurred while a run is going, or only how many.** Left
  open by `0060` deliberately, as better answered in front of a running window.
- **How the progress screen behaves when [`0041`](../decisions/0041-capture-reads-domains-in-parallel.md)'s
  parallel reads mean several domain rows are active at once.**
- **Whether a run can be scheduled**, and if so what runs it when nobody is signed in. This collides
  with [`0059`](../decisions/0059-an-exclusion-is-attested-once-per-run.md): a run nobody is signed
  in for cannot attest to an exclusion.
- **What happens when two runs are started against the same forest at once.**

---

## Open findings

**`F-S40-1` moved to [`PUNCH-LIST.md`](../PUNCH-LIST.md) § Audit / Capture as `P-22`** during the
documentation rewrite. How a run reads a forest is now
[the search capture issues](../audit/the-search-capture-issues.md) and
[how a controller's answer is read](../audit/how-a-controller-is-read.md).

| | | |
|---|---|---|
| — | none recorded for this area now | — |
