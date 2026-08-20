# Which controller we read, and whether we can

**Area.** How the product finds the forest, decides which domain controller to read each domain
from, and proves it can read it before a run commits.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| finds its own forest — nothing is typed in, and the forest is the one this machine is joined to | [`0053`](../decisions/0053-the-tool-finds-its-own-forest.md) |
| reads every domain in that forest; the domain is the only unit of scope | [`0052`](../decisions/0052-the-domain-is-the-only-unit-of-scope.md) |
| takes its candidate controllers from the configuration partition, not from DNS | [`0050`](../decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md) |
| connects up an ordered ladder of protection, and records which rung it reached | [`0018`](../decisions/0018-connection-security-is-an-ordered-ladder.md) |
| describes what a controller accepts only where that controller answered | [`0018`](../decisions/0018-connection-security-is-an-ordered-ladder.md) |
| asks every domain at once, while asking no controller two things at once | [`0048`](../decisions/0048-preflight-proves-a-controller-before-a-run-commits.md) |
| asks every domain the preflight questions before any object is read | [`0048`](../decisions/0048-preflight-proves-a-controller-before-a-run-commits.md) |
| establishes the PDC emulator at preflight, and prompts only where an operator could have chosen differently | [`0055`](../decisions/0055-the-pdc-emulator-is-established-at-preflight.md) |
| treats a domain with no candidate controllers as an attested exclusion, never a silent gap | [`0054`](../decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md) |
| starts a capture exactly one way, whether from the window or the command line | [`0039`](../decisions/0039-one-way-to-start-a-capture.md) |

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
| see every domain of the forest without naming anything | `ForestDiscoveryTests` |  |  |
| see, per domain, which controller would be read | `ControllerSelectionTests.AControllerInTheOperatorSiteIsPinnedOverALexicallyEarlierOne` |  |  |
| see that a controller in his own site is preferred over one holding a role | `ControllerSelectionTests.SiteOutranksHoldingARole` |  |  |
| see the failover order, and not just the winner | `ControllerSelectionTests.TheFailoverListIsTheRestOfTheRankingInOrder` |  |  |
| be told the choice was made without every input, rather than shown a confident answer | `ControllerSelectionTests.ADomainRankedWithoutItsPdcEmulatorIsNotComplete` |  |  |
| name a different controller, and have it obeyed | `ControllerSelectionTests.AnOverrideIsObeyedAndTheRestRemainAsFailover` |  |  |
| be refused, in the audit layer's own words, when that name is not a candidate | `ControllerSelectionTests.AnOverrideThatIsNotACandidateStopsTheRun` |  |  |
| be certain a refused override never silently falls back to the automatic choice | `ControllerSelectionTests.AnOverrideThatIsNotACandidateNeverFallsBack` |  |  |
| learn that a domain has no readable controller, instead of it vanishing from the run | `ControllerSelectionTests.ADomainWithNoCandidatesIsRecordedRatherThanPlannedAgainst` |  |  |
| be told plainly that this machine's site is unknown, when the forest declares no subnets | `OperatorSiteTests.AForestDeclaringNoRangesLeavesTheRunWithNoSite` |  |  |
| have every domain checked, even after the first one fails | `PreflightTests.EveryDomainIsAskedEvenWhenTheFirstOneFails` |  |  |
| tell "was asked and said no" apart from "was never asked" | `PreflightTests.TheQuestionsAnUnreachableControllerWasNeverAskedAreRecordedAsUnasked` |  |  |
| see how protected each domain's connection was | `PreflightTests.TheFileSaysWhichControllerServedEachDomainAndHowProtectedItWas` |  |  |
| continue when a password settings container cannot be read, and know which domain it was | `PreflightTests.AnUnreadablePasswordSettingsContainerDoesNotStopTheRun` |  |  |
| have every domain asked at once, and no controller asked two things at once | `PreflightTests.TwoDomainsOnOneControllerAreNeverAskedAtTheSameTime` |  |  |
| be certain that pass is genuinely concurrent rather than concurrent in shape | `PreflightTests.DomainsOnDifferentControllersAreAskedAtTheSameTime` |  |  |
| be certain a controller nothing answered from is not described as refusing protection | `ConnectionLadderWalkTests.AControllerThatNeverAnsweredIsNotDescribedAsRefusingProtection` |  |  |
| read a rejected password as a password, rather than as a weakness in his forest | `ConnectionLadderWalkTests.RejectedCredentialsAreReportedAsCredentialsAndNotAsAWeakness` |  |  |
| still be told when a controller genuinely refuses every protected rung | `ConnectionLadderWalkTests.AControllerThatAnsweredAndRefusedProtectionIsStillAFindingAboutTheForest` |  |  |
| be certain a failure nobody classified is not promoted into a security finding | `ConnectionLadderWalkTests.AFailureNobodyClassifiedIsNotPromotedIntoAFinding` |  |  |

**Verified in the lab.** 2026-09-xx, against `ad.lab` with `ba.ad.lab` and `ph.ad.lab`, one
controller per domain, no subnets declared. Two things were checked by eye because no test can
check them: the PDC emulator prompt appeared on no row, and no domain was described as being in
another site.

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

- **What a run does when the chosen controller fails part-way through.** [`0040`](../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md)
  decided a failed domain is read again from another controller; **nothing walks that path today**
  (`F-S40-1`). Whether the operator is told, and when, is undecided.
- **Whether a name that does not resolve is told apart from a host that is switched off.** Both
  arrive as the same protocol error, so the ladder says the two look alike rather than guessing.
  Separating them means resolving the name deliberately, which would need weighing against
  [`0050`](../decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md) —
  DNS is permitted for bootstrapping and nothing else. Raised by the amendment to
  [`0018`](../decisions/0018-connection-security-is-an-ordered-ladder.md), not decided there.
- **What an operator does when he wants to pin controllers permanently.** Referred to as "the
  configuration file" in `A2` of the reference inventory, never designed.
- **How a domain that is deliberately excluded appears here**, as opposed to one that has no
  candidates. **Answered by [`0063`](../decisions/0063-excluded-never-looks-like-unreachable.md)**:
  they are two different events and the product never renders them alike — one is a decision, the
  other is a fact about the network. The seam this file and
  [`domains-we-skip`](domains-we-skip.md) each pointed at the other for is now drawn. Not yet built.

---

## Open findings

| | | |
|---|---|---|
| `F-S40-1` | `0040`'s retry is decided but nothing walks it | open |
