# The New Audit screen

**Code:** `next/src/SecureAD.Shell/ViewModels/NewAuditViewModel.cs`, `AuditProgressViewModel.cs`, `AuditRowViewModel.cs`,
`ExcludedDomainViewModel.cs`, `ExclusionAttestationViewModel.cs`, `DomainDetailsViewModel.cs`,
`next/src/SecureAD.Shell/Services/AuditPlan.cs`, `AuditReview.cs`, `ExclusionAttestation.cs`,
`INewAuditDialog.cs`, `NewAuditDialog.cs`, `IJudgingLauncher.cs`, `JudgingLauncher.cs`,
`IDerivationLauncher.cs`, `DerivationLauncher.cs`
**Layer:** Shell — the screen an operator starts an audit from: what it discovers, what it asks,
what it refuses, and what it commits to.

This is the first layer document for the shell, and the shell is described differently from every
other subsystem for one reason: **it exports nothing.** `ShellSurfaceGateTests` holds it to that —
the window's surface is its screens, and a view model is not something anything outside the project
can legitimately consume. So the types below are `internal`, and the gate that binds this table
reads visibility from the source rather than from the assembly's exported set, which would be empty.

Which screens exist at all is [`ShellSection`](../../../next/src/SecureAD.Shell/ViewModels/ShellSection.cs),
and a member is added there only when the screen behind it can answer for itself. This page
describes `Audit`. Where the run library is chosen is [`the home screen`](the-home-screen.md).

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `NewAuditViewModel` | The New Audit window: what would be read, from where, and the one place a run is started |
| `AuditProgressViewModel` | Current phase, real counter text, monotonic elapsed/last-update ages and stopping/terminal presentation |
| `AuditScreen` | The screens of the New Audit window, in the order they are reached |
| `AuditRowViewModel` | One row of the New Audit table, whatever kind of domain it is about |
| `DomainRowViewModel` | One domain's row of the New Audit table |
| `ExcludedDomainViewModel` | A row for a domain the forest declares and names no writable controller for |
| `ExclusionView` | One domain leaving a run, as the review screen lists it before the run commits |
| `DomainDetailsViewModel` | The state behind the domain details panel |
| `ExclusionAttestationViewModel` | The state behind the exclusion attestation dialog |
| `ExclusionReasonChoice` | One reason on the attestation dialog: the wording an operator reads, and the value behind it |
| `AuditPlanView` | What a run would read and from where, as discovery established it and before anything was contacted |
| `DomainPlanRow` | One domain's row of the plan: what would be read, from where, and once preflight has run what the forest answered |
| `DomainAnswers` | What preflight established about one domain, and nothing it did not |
| `AuditCheck` | Everything preflight learned, for every domain, from one pass |
| `Established` | What a run established about one fact: nothing, yes, or no |
| `SiteKnowledge` | Why this machine's own site is not known, which is not the same fact as it having none |
| `AuditReview` | The whole audit, as it is put to the operator before he commits to it |
| `ReviewedDomain` | One domain this run will read, and the controller it will read it from |
| `ExclusionAttestation` | What an operator stated when he left a domain out of a run |
| `ExclusionStatement` | What the operator supplied in the attestation dialog, before the run stamps the rest |
| `ExclusionReason` | Why a domain was left out of a run, from the closed list an operator picks from |
| `ExclusionReasons` | The closed reason list, in the words an operator reads and the words a bundle stores |
| `DomainInclusion` | Whether a domain is in this run, and if it is not, which kind of exclusion it is |
| `INewAuditDialog` | Starting an audit, and putting the one question that still needs a dialog in front of the operator |
| `NewAuditDialog` | Puts a freshly planned audit on the shell's audit surface, and takes it off again |
| `IJudgingLauncher` | Judging a sealed bundle, from a window |
| `JudgingLauncher` | Judges a bundle by driving `JudgingRun`, off the interface thread |
| `JudgingOutcome` | What a judging produced, in the shell's own words |
| `UnresolvedCount` | One thing that stopped a rule deciding, and how many objects it left unjudged |
| `IDerivationLauncher` | Deriving from a sealed bundle, from a window |
| `DerivationLauncher` | Derives from a bundle by driving `Stage2aRun`, off the interface thread |
| `DerivingOutcome` | What a derivation produced, in the shell's own words |

<!-- TYPES:END -->

This table is the page's claim of ownership, and it is bound in both directions against the
**internal** types the files above declare: one they declare and this table omits fails the build,
and so does a row naming something they do not.

**Two types the screen uses constantly are not claimed here.** `FactState` and `Notice` are shell
vocabulary — the Assets and Object screens use them too — so a page claiming them would be claiming
the shell's language on behalf of one screen. They belong wherever that vocabulary is described, and
that page is not written yet.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| starts an audit in a modal window rather than a page in the shell | [`0057`](../../decisions/0057-starting-an-audit-is-a-modal-act.md) |
| shows every fact in three states, never as a bare yes or no | [`0056`](../../decisions/0056-the-visual-language-encodes-three-states.md) |
| asks for that attestation from a tick box on the domain row, and raises it as a dialog | S-46, on the owner's answer |
| refuses to start a run carrying an exclusion nobody has answered for | S-46, on the owner's answer |
| tells an operator, before he commits, how many facts the run will not establish | S-46, closing `F-0056-1` |

**Only the decisions about the screen are here.** What a run reads and how a controller is chosen is
governed on [`how the forest is found`](../connect/how-the-forest-is-found.md); what preflight proves
on [`what preflight proves`](../connect/what-preflight-proves.md); what an exclusion attestation must
carry on [`a domain left out on purpose`](../evidence/a-domain-left-out-on-purpose.md).

---

## The three states, and why a bare yes or no is refused

`Established` is the reason this screen can be trusted with a security question. A fact the run has
not established is not `false` — it is *not established*, and the difference is the whole of
[`0056`](../../decisions/0056-the-visual-language-encodes-three-states.md). A screen with two states
has to render "we could not ask" as one of them, and whichever it picks is a lie an operator acts on.

`SiteKnowledge` is the same shape one level down: *this machine's site is unknown* and *this forest
declares no sites* are different facts, and a screen that merged them would tell an administrator his
forest was misconfigured when the truth is that the product could not tell.

---

## An exclusion is answered for before the run starts

A domain leaves a run only where somebody said so and put a name to it. `ExclusionAttestation` is
that statement, `ExclusionReasons` is the closed list it comes from, and `ExclusionStatement` is the
part the operator supplied before the run stamps the rest.

**The account is captured, not typed.** An operator does not name himself; the signed-in account is
recorded. A typed name is an assertion, and an attestation whose author is an assertion is worth
nothing to the auditor reading it later.

**A run carrying an unanswered exclusion does not start.** That is the refusal the screen exists to
make, and it is why the review screen lists every departing domain before anything is committed.

---

## Four columns, and a Details button that cannot hide anything

The table showed nine columns and now shows four: Include, Domain, Read from, and the override. The
principle is one already used on this screen — **a column that says the same thing on every row is a
column nobody reads**, and nine of them turned the one column that mattered into noise.

Site, Connection, Serves it, Password settings and PDC emulator moved behind a single **Details**
button covering every domain at once. That button **carries a warning mark whenever any domain has
something worth attention**, which is the part that matters: without it, trimming a column would have
become a way of hiding something, and the screen would be quieter and less true.

---

## Start lives only in the review dialog

The second wizard step used to show the same table under a different heading and reviewed nothing. It
is now a review dialog that states what the run will read, what it will not and why, who authorised
each exclusion, and how much the run will not establish.

**Start exists only inside that dialog.** That is what keeps opening the window from being one click
away from a capture — an audit reads a customer's entire directory, and a screen that can begin one
by accident is a screen that will.

---

## Deriving follows the capture, and precedes the judging

Once a capture has sealed evidence, the window derives from it before any rule reads it. The shape is
the judging's, for the same reason and on the same date: **the decision to audit was the decision to
derive.** There is no control to press.

**The order is the whole of why it is wired in at all.** What deriving produces are facts about more
than one object — who is really in a group, whose account the protection process manages, which
arrangement is one flag away from being privileged. A judging that ran first would find nothing
written and reach its verdicts from an empty set, and an empty set that should have held a closure
reads as a clean result.

**A derivation that could not be done does not stop the judging.** Every rule that exists today reads
one object and needs nothing derived, so withholding findings that do not depend on a closure would
cost the operator the whole judging to punish a stage none of it used. What went wrong is reported
and the evidence is still offered, because the facts can be derived again from the same bundle.

**A degraded derivation says so.** A closure that was cut short by a budget looks exactly like a
closure that found nothing, and every rule resting on it would inherit that difference without being
told. See [what stage 2a derives](../derivation/what-stage-2a-derives.md) for what the budgets are
and why the outermost groups are the ones that go unanswered.

**`ExpansionBudget.Bulk` is what a whole-bundle derivation runs under.** The launcher chooses no
budget of its own; one that did would be a second opinion about how much of a forest is worth
answering for.

---

## Judging follows the capture without being asked for

Once a capture has sealed evidence, the window judges it.
prompt: **the decision to audit was the decision to judge** — the owner's shape, 2026-08-26. An
operator who has waited hours for a capture should not return to a control he has to press and
another wait he never agreed to.

**Only sealed evidence is judged.** A run can finish and seal nothing, recording why it stopped and
no objects at all; there is nothing there for a rule to read, so nothing is judged and nothing is
offered.

**A judging failure does not invalidate sealed Evidence, but it is not a successful completed audit.** The evidence is the expensive half and the half that
cannot be recovered — it took hours and read a forest that has moved on since. A judging can be made
again from the same bundle whenever the defect behind it is fixed, so a failed judging is reported
and the evidence is still offered. Throwing the capture away would cost the operator the part he
cannot replace to punish the part he can.

**A degraded judging says so.** Where a rule could not reach a verdict, the count that follows is
what the rules that did finish found, and the screen says it is not the whole picture. A count that
quietly omitted what a rule could not read would look exactly like a clean result, and a customer
makes a security decision on that difference.

**The work happens off the interface thread and reports as it goes.** The predecessor took four to
five hours over the owner's production forest, and a window frozen for an afternoon is
indistinguishable from one that has crashed.

### Visible phase progress — approved correction

The owner reported that a copied lab bundle eventually judged in 222 seconds while the Shell appeared
stuck after sealing. Inspection found that the launchers already forwarded progress, but the view
bound neither the derivation/judging reports nor their counters, kept a static capture message on
screen, and discarded the derivation sub-phase name. The owner approved a pinned phase panel, real
counters, elapsed/last-update times and separate outcomes, then authorized this bounded correction.

The panel sits above the scrolling review. It covers discovery/preflight messages, **Capturing and
sealing evidence**, derivation sub-phases, judging input preparation/object evaluation, requester
finalization, findings writes, publication and final readback. Capture still has no per-object progress
channel; it remains indeterminate rather than manufacturing a total. Derivation shows objects read
during its evidence-reading phase. Judging shows unique objects processed, not the sum of per-rule
evaluation counts. No percentage, denominator or completion-time estimate is invented.

An owned, awaited periodic UI refresh updates monotonic elapsed time and the age of the last received
phase/progress event. A timer tick never advances the work counter or resets that event age. The caveat
states that elapsed time is not progress evidence. Cancellation shows stopping until the work exits;
late callbacks are guarded by the run and active phase. Starting another attempt clears old reports,
findings and bundle identity. Separate capture, derivation and judging reports remain visible, including
degraded/refused/stopped outcomes: **Sealed** is a capture result, not judging completion.

This changes transient progress and presentation only. Judgement schema 24/control engine 8,
Derivation schema 11, catalogue 2, permission counting and production activation budgets are unchanged.
It is not the performance/storage fix or the broader logging-hardening session. Tests use held-open
synthetic launchers, controlled clocks, real offline launchers and production XAML at 900×430,
1300×650 and 1600×900; an unbound phase-label mutation must fail the view check. Real lab/display
verification remains outstanding. No new live directory operation is authorized by this correction.

**Verification:** solution build succeeded; the source-verified Release offline selection passed
**4,372/4,372** with no failures or skipped tests within that selection. The four stage-status tests
were explicitly excluded, and the cancelled stage-status script/self-test was not retried. Targeted
coverage passed **179/179**, with both saved command summaries recording exit code 0 and both TRX
reports recording `Completed`. SDK 10.0.400 and `--no-build --no-restore` were used after checking the
assembly against changed inputs. The test assembly SHA-256 is
`F3B05402A7FD2FBBA97344F886D9029F06F0903463C3AE54378BD5E3734C168F`.

The local-only validation folder has identifier `AuditProgress-a10bb329cef741b882f1382063032938` beneath
the development workspace's ignored Visual Studio directory. It contains the offline/targeted TRX
reports, logs, command summaries and Cobertura report; these are not shipped repository inputs.
Selection-specific executable-line observations are AuditProgressViewModel 41/41, NewAuditViewModel
698/789, JudgingLauncher 52/56 and DerivationLauncher 33/35. These are not full branch coverage or a
production-scale performance result. No existing golden hashes, schemas or historical artifacts changed.

The older `ProsePathCitationTests` portability failure reported from the lab clone is not resolved by
this local pass: the earlier ignored reports exist on this machine. Fixing portable evidence references,
broader logging hardening, judging/storage profiling and real Release/display validation remain separate
follow-up work. This progress implementation remains uncommitted until separately authorized.

**`IsJudging` is held apart from `IsCapturing`**, because
[`0072`](../../decisions/0072-analysis-and-capture-do-not-run-at-the-same-time.md) turns on whether a
*capture* is running. Folding the two together would refuse to open any bundle for the whole of a
judging, which is neither what that record says nor what it protects.

---

## What is built

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| see the domain table filled before any controller is contacted | `NewAuditViewModelTests.TheTableIsFilledBeforeAnyControllerIsContacted` |  |
| have sealed evidence judged without asking for it | `NewAuditViewModelTests.EvidenceThatWasSealedIsJudgedWithoutBeingAskedFor` |  |
| be certain a run that sealed nothing is not judged | `NewAuditViewModelTests.ARunThatSealedNothingIsNotJudged` |  |
| see what the judging found | `NewAuditViewModelTests.WhatTheJudgingFoundIsReported` |  |
| be certain a judging that could not finish every rule says so | `NewAuditViewModelTests.AJudgingThatCouldNotFinishEveryRuleSaysSo` |  |
| still be offered evidence when the judging could not be done | `NewAuditViewModelTests.EvidenceIsStillOfferedWhenTheJudgingCouldNotBeDone` |  |
| see how far the judging has got | `NewAuditViewModelTests.HowFarTheJudgingHasGotIsShown` |  |
| have sealed evidence derived from without asking for it | `NewAuditViewModelTests.EvidenceThatWasSealedIsDerivedFromWithoutBeingAskedFor` |  |
| be certain a run that sealed nothing is not derived from | `NewAuditViewModelTests.ARunThatSealedNothingIsNotDerivedFrom` |  |
| be certain deriving happens before judging | `NewAuditViewModelTests.DerivingHappensBeforeJudging` |  |
| see what the derivation produced | `NewAuditViewModelTests.WhatTheDerivationProducedIsReported` |  |
| be certain a derivation that could not be completed says so | `NewAuditViewModelTests.ADerivationThatCouldNotBeCompletedSaysSo` |  |
| still have the evidence judged when the derivation could not be done | `NewAuditViewModelTests.ADerivationThatCouldNotBeDoneDoesNotStopTheJudging` |  |
| still be offered evidence when the derivation could not be done | `NewAuditViewModelTests.EvidenceIsStillOfferedWhenTheDerivationCouldNotBeDone` |  |
| have the window work the whole thing out on opening, without a press | `NewAuditViewModelTests.OpeningTheWindowWorksTheWholeThingOutWithoutAPress` |  |
| be certain opening the window is never one click from a capture | `NewAuditViewModelTests.OpeningTheWindowIsNeverOneClickFromACapture` |  |
| stop the pass the window began | `NewAuditViewModelTests.ThePassTheWindowBeganCanBeStopped` |  |
| be certain a stopped pass calls what it never reached unasked rather than unreachable | `NewAuditViewModelTests.AStoppedPassLeavesWhatItReachedAndAsksNothingOfTheRest` |  |
| check a controller he named without paying for a pass over the forest | `NewAuditViewModelTests.CheckingATypedControllerCostsOneMachineAndNotAForest` |  |
| be told why the window could not work itself out, rather than shown an empty table | `NewAuditViewModelTests.AForestThatCannotBeReachedOnOpeningSaysSoRatherThanShowingAnEmptyTable` |  |
| run the pass again after it failed, without closing the window | `NewAuditViewModelTests.APassThatCouldNotFinishCanBeRunAgain` |  |
| read the connection rung in words rather than as the name the type spells it with | `NewAuditViewModelTests.TheRungIsShownInWordsRatherThanAsAnEnumName` |  |
| see one spelling of a domain per row, being the name the forest declared | `NewAuditViewModelTests.ARowIsHeadedByTheNameTheForestDeclaredForTheDomain` |  |
| see the whole audit before committing to it, and start it from there | `NewAuditViewModelTests.ReachingTheReviewScreenStartsNothing` |  |
| go back from that review and lose nothing | `NewAuditViewModelTests.GoingBackFromTheReviewStartsNothing` |  |
| be certain reviewing asks every domain again rather than trusting the first pass | `NewAuditViewModelTests.ReviewingAsksEveryDomainAgain` |  |
| read what the run will and will not do, and what it cannot say | `NewAuditViewModelTests.TheReviewStatesWhatTheRunWillAndWillNotDo` |  |
| be certain an unanswered exclusion stops the review being reached at all | `NewAuditViewModelTests.AnUnansweredExclusionStopsTheReviewBeingReached` |  |
| see a domain the forest names no controller for in the table rather than beneath it | `NewAuditViewModelTests.ADomainWithNoControllerIsARowOfTheTable` |  |
| be certain such a row offers no choice the product cannot honour | `NewAuditViewModelTests.ADomainWithNoControllerOffersNoChoiceItCannotHonour` |  |
| read that the forest names no controller, rather than an empty cell | `NewAuditViewModelTests.ADomainWithNoControllerSaysSoRatherThanShowingNothing` |  |
| be told where a finished run's evidence is | `NewAuditViewModelTests.AFinishedRunSaysWhereTheEvidenceIs` |  |
| open what a finished run captured, from the control that ends the wizard | `NewAuditViewModelTests.AFinishedRunOffersToViewWhatItCaptured` | 2026-08-21 |
| have that control open the run he just captured, and leave | `NewAuditViewModelTests.ViewingResultsOpensTheRunThatWasJustCaptured` | 2026-08-21 |
| be certain he lands in Assets rather than back on Home | `NewAuditViewModelTests.TheAuditIsLeftBeforeTheRunIsOpened` | 2026-08-21 |
| be certain abandoning a plan that never ran opens nothing | `NewAuditViewModelTests.DiscardingAPlanThatNeverRanOpensNothing` |  |
| be certain a run that sealed nothing is not offered results to view | `NewAuditViewModelTests.ARunThatSealedNothingIsNotOfferedResultsToView` |  |
| be certain a finished run is not offered a way back to change it | `NewAuditViewModelTests.AFinishedRunDoesNotOfferTheWayBack` |  |
| see everything the table stopped carrying, for every domain at once | `NewAuditViewModelTests.DetailsShowsEveryDomainAtOnce` |  |
| be told a trimmed column is hiding an unanswered question | `NewAuditViewModelTests.ADomainWithAnUnansweredQuestionIsWorthAttention` |  |
| have the run captured into the library he chose | `NewAuditViewModelTests.ARunIsCapturedIntoTheChosenLibrary` |  |
| see where a sealed run's evidence is | `NewAuditViewModelTests.ASealedRunReportsWhereItsEvidenceIs` |  |
| be told, when a run produced no bundle, that it did not and where to look | `NewAuditViewModelTests.ARunThatProducedNoBundleSaysSoAndSaysWhereToLook` |  |
| see a stopped run reported as stopped rather than as failed | `NewAuditViewModelTests.AStoppedRunIsReportedAsStoppedRatherThanFailed` |  |
| take a domain out of a run and be asked to account for it | `NewAuditViewModelTests.UntickingADomainAsksTheOperatorToAccountForIt` |  |
| be certain walking away from that question leaves the domain in the run | `NewAuditViewModelTests.ADismissedAttestationLeavesTheDomainInTheRun` |  |
| have an exclusion keep the reason, the note and the authorising name | `NewAuditViewModelTests.AnAttestedExclusionKeepsEverythingTheRecordAsksFor` |  |
| be certain the account behind an exclusion is captured rather than typed | `NewAuditViewModelTests.TheAccountBehindAnExclusionIsCapturedRatherThanTyped` |  |
| be certain putting a domain back drops what was stated for it | `NewAuditViewModelTests.PuttingADomainBackDropsWhatWasStatedForIt` |  |
| put a domain back without being asked anything | `NewAuditViewModelTests.PuttingADomainBackAsksTheOperatorNothing` |  |
| be asked about a domain no controller was found for without going looking for it | `NewAuditViewModelTests.ADomainWithNoControllerIsAttestedWhenTheWindowWorksItselfOut` |  |
| be asked about each unreadable domain separately rather than in one lump | `NewAuditViewModelTests.EveryUnreadableDomainIsPutToTheOperatorSeparately` |  |
| be certain one run does not ask him about the same domain twice | `NewAuditViewModelTests.AnAlreadyAttestedDomainIsNotAskedAboutAgainInTheSameRun` |  |
| be certain an exclusion nobody answered for stops the run | `NewAuditViewModelTests.AnUnreadableDomainNobodyAnsweredForStopsTheRun` |  |
| start that same run once he has answered for it | `NewAuditViewModelTests.AnUnreadableDomainThatWasAttestedLetsTheRunStart` |  |
| tell a domain he took out from one the forest named no controller for | `NewAuditViewModelTests.ADomainExcludedByChoiceIsNotDescribedLikeOneWithNoController` |  |
| be certain an exclusion nobody answered for is not shown as authorised | `NewAuditViewModelTests.AnUnansweredExclusionIsNotShownAsAuthorised` |  |
| see who authorised an exclusion once it has been answered for | `NewAuditViewModelTests.AnAnsweredExclusionSaysWhoAuthorisedIt` |  |
| have every attestation carried into the run he started | `NewAuditViewModelTests.EveryAttestationIsCarriedIntoTheRun` |  |
| have a domain he took out carried into the run as an exclusion | `NewAuditViewModelTests.ADomainTakenOutIsCarriedIntoTheRunAsAnExclusion` |  |
| be told when a run fails unexpectedly, rather than losing the window | `NewAuditViewModelTests.ARunThatThrowsIsReportedRatherThanTakingTheWindowDown` |  |
| see what is leaving the run listed, and not just a heading | `NewAuditViewModelTests.TheListOfWhatIsLeavingTheRunKeepsOneIdentity` |  |
| be certain rewording a reason cannot change what past runs appear to say | `NewAuditViewModelTests.AReasonsStoredNameIsNotItsWording` |  |
| be offered every reason in the closed list, once each | `NewAuditViewModelTests.EveryReasonInTheClosedListIsOfferedExactlyOnce` |  |
| see, before committing, how much this run will not establish | `NewAuditViewModelTests.TheCountOfWhatWillNotBeEstablishedComesFromTheStatesTheTableShows` |  |
| be told that total is not yet known rather than shown a zero | `NewAuditViewModelTests.ATotalThatCannotBeComputedSaysSoRatherThanShowingZero` |  |
| see a domain he excluded counted as establishing none of its facts | `NewAuditViewModelTests.AnExcludedDomainCountsAsEstablishingNoneOfItsFacts` |  |
| be certain that count stays tied to what a row actually carries | `NewAuditViewModelTests.TheFactsCountedForAnAbsentDomainMatchTheFactsARowCarries` |  |
| name a controller himself and have it carried into the run | `NewAuditViewModelTests.AControllerAnOperatorNamesIsCarriedIntoTheRun` |  |
| be certain a controller he named that is ineligible is refused rather than quietly replaced | `NewAuditViewModelTests.AnIneligibleControllerIsNotQuietlyReplacedByTheRankedChoice` |  |
| read that refusal in the library's own words | `NewAuditViewModelTests.AnIneligibleControllerIsRefusedInTheLibrarysOwnWords` |  |
| see the PDC emulator prompt only where the domain has alternatives | `NewAuditViewModelTests.ThePdcEmulatorPromptDoesNotAppearWhereTheDomainHasNoAlternatives` |  |
| be certain a question not yet put is shown as not yet put rather than as a no | `NewAuditViewModelTests.AQuestionNotYetPutIsShownAsNotYetPutRatherThanAsNo` |  |
| be certain the PDC emulator is not reported absent before it is established | `NewAuditViewModelTests.ThePdcEmulatorIsNotReportedAsAbsentBeforeItIsEstablished` |  |
| tell a PDC emulator that could not be established from one holding no role | `NewAuditViewModelTests.APdcEmulatorThatCouldNotBeEstablishedIsNotReportedAsHoldingNoRole` |  |
| be certain a controller nothing answered from is not reported as refusing protection | `NewAuditViewModelTests.AControllerNothingAnsweredFromIsNotReportedAsRefusingProtection` |  |
| be told when his machine has no site, rather than being given one | `NewAuditViewModelTests.AMachineWithNoSiteSaysSoRatherThanNamingOne` |  |
