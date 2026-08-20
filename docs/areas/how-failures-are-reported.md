# How failures are reported

**Area.** What the product does when something goes wrong: how a failure travels from where it
happened to where a person reads it, and what stops a failure being reported as a clean answer. This
is the mechanism behind the product's oldest rule — *found nothing* and *could not compute* must
never look alike.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| treats an absent view as a degraded run, never as a negative answer | [`0002`](../decisions/0002-absent-view-means-degraded-run.md) |
| names the phase that failed when a count cannot be given | [`0004`](../decisions/0004-unknown-counts-name-the-failed-phase.md) |
| makes a run that failed say so, in words meant for the operator | [`0029`](../decisions/0029-a-run-that-ends-badly-says-so.md) |
| asks the file system whether a run is alive, rather than trusting a record | [`0029`](../decisions/0029-a-run-that-ends-badly-says-so.md) |
| says so when a DACL could not be read, rather than reporting no permissions | [`0037`](../decisions/0037-an-unreadable-dacl-says-so.md) |
| reads a failed domain again from another controller | [`0040`](../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md) |
| counts errors per domain while a capture is running, as they happen | [`0060`](../decisions/0060-a-running-capture-reports-one-line-per-domain.md) |
| does not treat a domain with errors as a domain that failed | [`0060`](../decisions/0060-a-running-capture-reports-one-line-per-domain.md) |
| refuses to report at all from a run that did not finish | [`0068`](../decisions/0068-a-finished-run-reports-with-its-gaps-shown.md) |
| distinguishes a domain left out by choice from one it could not reach | [`0063`](../decisions/0063-excluded-never-looks-like-unreachable.md) |
| encodes every fact in three states, so *unknown* never renders as *no* | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

| An operator can… | Proven by |
|---|---|
| be certain a failure carries a code derived from what went wrong and why | `AuditErrorTests.CreateDerivesTheCodeFromTheCategoryAndReason` |
| be certain a failure cannot be raised without a reason | `AuditErrorTests.CreateRejectsAnEmptyReason` |
| be certain a failure cannot be raised without a description | `AuditErrorTests.CreateRejectsAnEmptyDescription` |
| be certain reading the value of a failed result throws and names the code | `ResultTests.ReadingTheValueOfAFailedResultThrowsAndNamesTheCode` |
| be certain a failed result is never mistaken for a successful one | `ResultTests.AFailedResultIsNotSuccessful` |
| be certain an uninitialised result is not mistaken for success | `ResultTests.ADefaultResultIsNotMistakenForSuccess` |
| be certain an uninitialised result reports a self-describing error | `ResultTests.ADefaultResultReportsASelfDescribingError` |
| be certain no public member returns a bare count that cannot say whether it looked | `UnvouchedResultGateTests.NoPublicMemberReturnsABareCount` |
| be certain no public member returns a collection that cannot say whether it looked | `UnvouchedResultGateTests.NoPublicMemberReturnsACollectionThatCannotSayWhetherItLooked` |
| be certain that gate reads the real public surface rather than a copy | `UnvouchedResultGateTests.TheGateReadsTheRealPublicSurface` |
| be certain the exemptions to that gate are still earning their place | `UnvouchedResultGateTests.TheCatalogueExemptionsAreStillEarningTheirPlace` |
| be certain nothing quietly defaults to a value that hides a missing answer | `NullDefaultGateTests` |
| be certain the product's stated invariants are checked rather than intended | `ProductInvariantTests` |

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

- **What the product logs, and where.** Raised by the owner on 2026-08-16 as needing thought of its
  own, and [`0058`](../decisions/0058-a-run-may-be-stopped-and-stopping-it-keeps-nothing.md) leaves
  the location of the cancellation marker resting on it.
- **Whether the operator sees which error occurred while a run is going, or only how many.**
  [`0060`](../decisions/0060-a-running-capture-reports-one-line-per-domain.md) leaves this open
  deliberately, as a question better answered in front of a running window.
- **Whether the operator is told when a domain is retried on another controller**, and when.
  [`0040`](../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md) decided the
  retry; nothing walks that path today (`F-S40-1`).
- **How an error is worded.** The product has a rule that a failure names its phase and carries a
  reason; it has no house style for what those reasons sound like.
- **Whether errors are grouped when the same fault repeats across thousands of objects.**

---

## Open findings

| | | |
|---|---|---|
| `F-S40-1` | `0040`'s retry is decided but nothing walks it | open |

---

## Reference — the old application

**Reference only. Nothing here is owed, and a row existing here does not mean it is being built.**

The predecessor published progress at three levels — run, domain and module — with an error count at
the module level.
[`0060`](../decisions/0060-a-running-capture-reports-one-line-per-domain.md) keeps two of the three
and lifts the error count up to the domain row, because that is the number that changes what an
operator does.
