# What the run did and did not cover

**Area.** How a run states its own completeness: which domains and partitions it read in full, which
it read in part, which it never reached, and why. This is the mechanism that keeps a run from
looking clean while carrying gaps.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| records coverage once per capture unit, not once per run | [`0035`](../decisions/0035-coverage-is-recorded-once-per-capture-unit.md) |
| lets coverage vary only because something failed or because the forest changed | [`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) |
| records SYSVOL coverage beside the capture units, in the same terms | [`0044`](../decisions/0044-sysvol-coverage-is-recorded-beside-the-capture-units.md) |
| names the phase that failed when a count cannot be given | [`0004`](../decisions/0004-unknown-counts-name-the-failed-phase.md) |
| treats an absent view as a degraded run, never as a negative answer | [`0002`](../decisions/0002-absent-view-means-degraded-run.md) |
| refuses to re-analyse a capture that was never complete | [`0003`](../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md) |
| never lets a run appear clean while carrying unknowns — the total belongs to coverage | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |

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
| see a run that read every domain called complete, and only then | `RunCoverageTests.ARunThatReadEveryDomainIsComplete` |  |  |
| be certain a domain that was never read makes the whole run incomplete | `RunCoverageTests.ADomainThatWasNotReadAtAllMakesTheRunIncomplete` |  |  |
| be certain a domain read only in part counts as failed, not as read | `RunCoverageTests.ADomainReadOnlyInPartCountsAsFailed` |  |  |
| read the reason a domain was incomplete, beside the fact that it was | `RunCoverageTests.AnIncompleteDomainCarriesTheReasonItWasIncomplete` |  |  |
| be certain a domain read in full carries no reason, so a reason always means something | `RunCoverageTests.ADomainReadInFullCarriesNoReason` |  |  |
| be certain a forest-wide partition that went unread makes the run incomplete | `RunCoverageTests.AForestPartitionThatWasNotReadMakesTheRunIncomplete` |  |  |
| be certain coverage cannot be reported for a domain the forest never declared | `RunCoverageTests.ReportingOnADomainThatWasNeverDeclaredIsRefused` |  |  |
| be certain a declared domain cannot be left with no outcome at all | `RunCoverageTests.ADeclaredDomainWithNoOutcomeIsRefused` |  |  |
| see which Group Policy objects a run missed, named rather than counted | `SysvolCoverageTests.TheRecordNamesThePoliciesThatWereMissed` |  |  |
| see how many policies were read against how many there were | `SysvolCoverageTests.TheCountsAreTheDenominatorAndTheNumerator` |  |  |
| be certain a policy read only in part makes the SYSVOL read partial | `SysvolCoverageTests.APolicyReadOnlyInPartAlsoMakesTheReadPartial` |  |  |
| be certain a policy with no declared path is still counted rather than dropped | `SysvolCoverageTests.APolicyWithNoDeclaredPathIsStillCounted` |  |  |
| be certain no production code can mark a capture unit unread by hand | `UnreadOutcomeIsUnreachableTests.NoProductionCodeRecordsAUnitAsUnread` |  |  |
| be certain that check reads the real production source and would notice | `UnreadOutcomeIsUnreachableTests.TheScanReadsTheRealProductionSource` |  |  |
| tell one run's coverage from another's | `CoverageIdTests` |  |  |

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

- **Whether coverage can produce a run-level count of unestablished facts before a capture runs.**
  Answered for the post-capture case; the pre-capture total does not exist — `F-0056-1`, raised in
  [`how-the-app-looks`](how-the-app-looks.md).
- **How much missing coverage is too much to report on at all.** **Answered by
  [`0068`](../decisions/0068-a-finished-run-reports-with-its-gaps-shown.md)**: there is no threshold.
  A finished run always reports and always states its gaps; an unfinished run reports not at all.
  Not yet built.
- **Whether an operator can accept a gap** — mark a known-unreadable partition as expected — and
  what stops that becoming a way to hide one.
- **How coverage is presented when comparing two runs that covered different things.**

---

## Open findings

| | | |
|---|---|---|
| `F-0056-1` | no pre-capture total of unestablished facts exists | open |
