# What goes into the new audit wizard

**Area.** The screen an operator uses to start an audit: what it discovers, what it asks, what it
refuses, and what it commits to.

> **This file has been consumed down to its screen.** On 2026-08-24 the seven types it governed were
> rehomed and it now owns nothing in
> [`SURFACE-REGISTER.md`](../next/SURFACE-REGISTER.md). What a run reads and how a controller is
> chosen went to [`how-the-forest-is-found.md`](../layers/connect/how-the-forest-is-found.md); what
> preflight proves went to [`what-preflight-proves.md`](../layers/connect/what-preflight-proves.md);
> the exclusion attestation went to
> [`a-domain-left-out-on-purpose.md`](../layers/evidence/a-domain-left-out-on-purpose.md). Eleven of
> the thirteen decisions this file listed are cited on those pages and are not repeated here.
>
> **What remains is the shell**, and it stays because there is nowhere for it to go. The capability
> table below is 84 rows proving the wizard screen, almost all of them
> `NewAuditViewModelTests`, and no layer document describes the shell — that is `P-56`. This file is
> deleted by the pass that writes one, not before. Deleting it now would drop 84 claims that
> nothing else records, which is the defect `P-78` was raised for.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

**Only the decisions about the screen are listed here.** The rest moved with the types they govern
and are cited on the three pages named above.

| The product… | Decided by |
|---|---|
| starts an audit in a modal window rather than a page in the shell | [`0057`](../decisions/0057-starting-an-audit-is-a-modal-act.md) |
| shows every fact in three states, never as a bare yes or no | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |
| asks for that attestation from a tick box on the domain row, and raises it as a dialog | S-46, on the owner's answer |
| refuses to start a run carrying an exclusion nobody has answered for | S-46, on the owner's answer |
| tells an operator, before he commits, how many facts the run will not establish | S-46, closing `F-0056-1` |

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
| see the domain table filled before any controller is contacted | `NewAuditViewModelTests.TheTableIsFilledBeforeAnyControllerIsContacted` |  |
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
| reach a run written since the library was last read | `RunLibraryViewModelTests.ARunWrittenSinceTheLastReadCanBeAdopted` |  |
| be told when a captured run is not in the library he is pointed at | `RunLibraryViewModelTests.ARunTheLibraryDoesNotHoldSaysSo` |  |
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
| be certain a domain he took out is not read after all | `CapturePlanTests.AnExcludedDomainIsNotRead` |  |
| be certain excluding a domain does not flatter the run's coverage | `CapturePlanTests.AnExcludedDomainStillCountsAgainstCoverage` |  |
| have a run that left a domain out still seal, and say why it was not read | `CaptureRunEndToEndTests.ARunThatExcludedADomainSealsAndSaysWhyItWasNotRead` |  |
| be certain such a run does not claim to have covered the forest | `CaptureRunEndToEndTests.ARunThatExcludedADomainDoesNotClaimFullCoverage` |  |
| tell an excluded domain from an unreachable one in the run's own coverage | `RunCoverageTests.AnExcludedDomainNeverRecordsTheSameOutcomeAsAnUnreachableOne` |  |
| be told when a run fails unexpectedly, rather than losing the window | `NewAuditViewModelTests.ARunThatThrowsIsReportedRatherThanTakingTheWindowDown` |  |
| see what is leaving the run listed, and not just a heading | `NewAuditViewModelTests.TheListOfWhatIsLeavingTheRunKeepsOneIdentity` |  |
| be certain rewording a reason cannot change what past runs appear to say | `NewAuditViewModelTests.AReasonsStoredNameIsNotItsWording` |  |
| be offered every reason in the closed list, once each | `NewAuditViewModelTests.EveryReasonInTheClosedListIsOfferedExactlyOnce` |  |
| see, before committing, how much this run will not establish | `NewAuditViewModelTests.TheCountOfWhatWillNotBeEstablishedComesFromTheStatesTheTableShows` |  |
| be told that total is not yet known rather than shown a zero | `NewAuditViewModelTests.ATotalThatCannotBeComputedSaysSoRatherThanShowingZero` |  |
| see a domain he excluded counted as establishing none of its facts | `NewAuditViewModelTests.AnExcludedDomainCountsAsEstablishingNoneOfItsFacts` |  |
| be certain that count stays tied to what a row actually carries | `NewAuditViewModelTests.TheFactsCountedForAnAbsentDomainMatchTheFactsARowCarries` |  |
| find the whole attestation in the bundle months later | `BundleWriterTests.AnExcludedDomainKeepsTheWholeAttestation` |  |
| tell the two kinds of exclusion apart in the bundle | `BundleWriterTests.TheTwoKindsOfExclusionAreStoredApart` |  |
| be certain a run that excluded nothing says so by carrying no rows | `BundleWriterTests.ARunThatExcludedNothingLeavesNoExclusionRows` |  |
| name a controller himself and have it carried into the run | `NewAuditViewModelTests.AControllerAnOperatorNamesIsCarriedIntoTheRun` |  |
| be certain a controller he named that is ineligible is refused rather than quietly replaced | `NewAuditViewModelTests.AnIneligibleControllerIsNotQuietlyReplacedByTheRankedChoice` |  |
| read that refusal in the library's own words | `NewAuditViewModelTests.AnIneligibleControllerIsRefusedInTheLibrarysOwnWords` |  |
| see the PDC emulator prompt only where the domain has alternatives | `NewAuditViewModelTests.ThePdcEmulatorPromptDoesNotAppearWhereTheDomainHasNoAlternatives` |  |
| be certain a question not yet put is shown as not yet put rather than as a no | `NewAuditViewModelTests.AQuestionNotYetPutIsShownAsNotYetPutRatherThanAsNo` |  |
| be certain the PDC emulator is not reported absent before it is established | `NewAuditViewModelTests.ThePdcEmulatorIsNotReportedAsAbsentBeforeItIsEstablished` |  |
| tell a PDC emulator that could not be established from one holding no role | `NewAuditViewModelTests.APdcEmulatorThatCouldNotBeEstablishedIsNotReportedAsHoldingNoRole` |  |
| be certain a controller nothing answered from is not reported as refusing protection | `NewAuditViewModelTests.AControllerNothingAnsweredFromIsNotReportedAsRefusingProtection` |  |
| be told when his machine has no site, rather than being given one | `NewAuditViewModelTests.AMachineWithNoSiteSaysSoRatherThanNamingOne` |  |
| see a domain with no candidates shown rather than omitted | `DiscoveryWiringTests.ADomainWithNoCandidatesIsShownRatherThanOmitted` |  |
| see the failover list ranked, and shown in that order | `DiscoveryWiringTests.TheFailoverListIsRankedAndShownInThatOrder` |  |
| be certain an override naming an ineligible controller stops the run | `DiscoveryWiringTests.AnOverrideNamingAnIneligibleControllerStopsTheRun` |  |
| be certain an override naming a domain this forest does not have stops the run | `DiscoveryWiringTests.AnOverrideNamingADomainThisForestDoesNotHaveStopsTheRun` |  |
| tell a forest with no subnets from one whose subnets did not match | `DiscoveryWiringTests.AForestWithNoSubnetsIsDistinguishedFromOneWhoseSubnetsDidNotMatch` |  |
| be certain a choice made without every input is not called complete | `DiscoveryWiringTests.ThePreflightFileDoesNotCallAnUninformedChoiceComplete` |  |
| be certain an audit cannot be started until a run library is chosen | `HomeViewModelTests.AnAuditCannotBeStartedUntilARunLibraryIsChosen` |  |
| start an audit once a library is chosen | `HomeViewModelTests.ChoosingALibraryMakesAnAuditStartable` |  |
| be certain nothing starts an audit until he asks for one | `HomeViewModelTests.NothingStartsAnAuditUntilTheOperatorAsksForOne` |  |
| be told an installation is unconfigured rather than shown an empty path | `HomeViewModelTests.AnUnconfiguredInstallationExplainsItselfRatherThanShowingAnEmptyPath` |  |
| be certain unreadable settings are reported rather than treated as unconfigured | `HomeViewModelTests.UnreadableSettingsAreReportedRatherThanTreatedAsUnconfigured` |  |
| have his library choice remembered between sessions | `JsonShellSettingsStoreTests.APathThatWasWrittenIsReadBack` |  |
| be certain settings are kept per machine rather than following a roaming profile | `JsonShellSettingsStoreTests.SettingsAreKeptInTheLocalProfileRatherThanTheRoamingOne` |  |

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

- **What the window shows when the forest cannot be reached on open.** **Answered**: the window says
  which stage failed, in the audit layer's own words, and offers the pass again. The stages are told
  apart by the amendment to
  [`0018`](../decisions/0018-connection-security-is-an-ordered-ladder.md) — no domain to start from,
  nothing answered, answered and rejected the account, answered and refused protection, or let the
  run in and would not answer. What remains undecided is whether a name that does not resolve is
  told apart from a host that is switched off; that question lives in
  [`which-controller-we-read`](which-controller-we-read.md).
- **What the wizard shows while a run is in progress**, given
  [`0060`](../decisions/0060-a-running-capture-reports-one-line-per-domain.md) decides the content
  but not where it lives.
- **Whether the modal can be closed while a run is going**, and what that means.
- **Which columns the table carries.** **Answered.** Nine columns became four — Include, Domain,
  Read from, and the override — on the principle already used on this screen: a column that says
  the same thing on every row is a column nobody reads. Site, Connection, Serves it, Password
  settings and PDC emulator moved behind a single **Details** button covering every domain at once,
  and that button carries a warning mark whenever any domain has something worth attention, so
  trimming a column cannot become a way of hiding something.
- **Where the run is reviewed and started.** **Answered.** The second wizard step showed the same
  table under a different heading and reviewed nothing. It was replaced by a review dialog that
  states what the run will read, what it will not and why, who authorised each exclusion, and how
  much the run will not establish. **Start lives only in that dialog**, which is what now keeps
  opening the window from being one click from a capture.

---

## Open findings

| | | |
|---|---|---|
| `F-0056-1` | no pre-capture total of unestablished facts exists | **closed** — the last screen before a run commits carries one forest-wide number, counted from the same three-state marks the table renders, and says the total is not yet known rather than showing zero. `NewAuditViewModelTests.TheCountOfWhatWillNotBeEstablishedComesFromTheStatesTheTableShows` |
| `F-0079-8` | **A finished audit offers no way to see what it captured.** `NewAuditView.xaml` line 525 carries a *View results* button with `IsEnabled="False"`, and the comment beside it explains why: *"there is no screen that reads a bundle yet, and an enabled control that quietly did nothing would be the product claiming a capability it does not have."* **That reasoning was right when written and is now false** - the Assets section reads bundles, and the run library opens one into it as of 2026-08-21. So the wizard ends by telling an operator his evidence is unreachable, immediately after spending hours producing it, and hands him a folder path instead. Raised by the owner, 2026-08-21. | **closed 2026-08-21.** The owner chose the shape: the one footer control's label becomes *View results* once a run has sealed evidence, and pressing it opens that run in Assets and leaves. Not a second button - `LeaveLabel` now has three values, because a run that finished and sealed nothing still says **Done** and has nothing to show. The body button is gone. **Three further statements rested on the same retired premise and moved with it**: `ResultsNote`, its XML doc, and the assertion that it said "not built yet". A fourth defect was found doing it and fixed here: `BundleDirectory` was set from any successful outcome, ignoring `CaptureOutcome.ProducedABundle`, so a run that sealed nothing was told its evidence was at a path holding none. **Shipped with a defect, found in the lab by the owner the same day: View results landed him on Home.** Both acts navigate - leaving the audit shows Home, opening a run shows Assets - and the first version opened and then left, so Home won. `ViewingResultsOpensTheRunThatWasJustCaptured` passed throughout: it asserted the opener was called and the audit was left once, both true, and could not see the order because neither fake models the shell's section. Corrected by leaving first and opening second, and pinned by `TheAuditIsLeftBeforeTheRunIsOpened`, which observes the moment of opening rather than checking afterwards that two things happened |
| `F-0079-10` | **Nothing tests the composition root, and that is where half the View results defect lived.** `App.xaml.cs` wires the shell, the run library, the audit surface and the opener together in `OnStartup`, and no test constructs any of it. The ordering half is now covered, but the other half - that the wizard's opener navigates to Assets at all - is a lambda in `App.xaml.cs` that nothing exercises. A test that rebuilt the same wiring by hand would prove the copy rather than the product, which is the anchoring fault this repository has been bitten by before. | **open.** What would actually anchor it is lifting the wiring out of `OnStartup` into a named internal composer that both the application and a test call, with the catalogue and the capture launcher taken as seams rather than constructed inline. That is a real refactor of the startup path, deliberately not done in the session that found the defect, on the same reasoning that left `F-0049-1` half closed |
