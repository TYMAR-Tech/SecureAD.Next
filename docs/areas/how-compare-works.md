# How compare works

**Area.** Whether two runs may be compared at all, who answers that question, and what a refusal
says. This is the mechanism that stops the product reporting *"nothing changed"* about a comparison
it declined to perform.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| answers "may these runs be compared" in one component that every door calls | [`0026`](../decisions/0026-one-answer-to-whether-runs-may-be-compared.md) |
| makes that answer a closed set of named outcomes, never a boolean or a count | [`0026`](../decisions/0026-one-answer-to-whether-runs-may-be-compared.md) |
| lets coverage vary only because something failed or because the forest changed | [`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) |
| refuses to compare two runs that did not cover the same set of domains | [`0061`](../decisions/0061-runs-of-different-scope-are-not-comparable.md) |
| applies the same test to acceptance import as to comparison | [`0026`](../decisions/0026-one-answer-to-whether-runs-may-be-compared.md), [`0067`](../decisions/0067-an-acceptance-names-one-finding.md) |
| gives a finding a stable identity, so the same finding is recognisable across runs | [`0023`](../decisions/0023-a-finding-has-a-stable-identity.md) |
| refuses to re-analyse a capture that was never complete | [`0003`](../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md) |

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

| An operator can… | Proven by |
|---|---|
| be certain two complete runs of an unchanged forest compare fully | `RunComparabilityTests.TwoCompleteRunsOfAnUnchangedForestAreFullyComparable` |
| be certain a refused comparison never reports that it may proceed | `RunComparabilityTests.NoRefusedComparisonEverReportsThatItMayProceed` |
| be certain only a fully comparable pair is ever measured | `RunComparabilityTests.OnlyAFullyComparablePairIsEverMeasured` |
| read an explanation on every outcome, rather than a bare verdict | `RunComparabilityTests.EveryOutcomeExplainsItself` |
| be certain every outcome in the set is reachable, so none is decorative | `RunComparabilityTests.EveryOutcomeIsProducible` |
| be certain runs from different forests are refused | `RunComparabilityTests.RunsFromDifferentForestsAreRefused` |
| see a failed domain reported ahead of a changed forest, so the more serious cause wins | `RunComparabilityTests.AFailedDomainIsReportedAheadOfAChangedForest` |
| see an earlier run that never completed reported ahead of this run's coverage | `RunComparabilityTests.AnEarlierRunThatNeverCompletedIsReportedAheadOfThisRunsCoverage` |
| be certain a complete sealed run may be a baseline | `RunComparabilityTests.ACompleteSealedRunMayBeABaseline` |
| be certain a run that did not read every domain may not be a baseline | `RunComparabilityTests.ARunThatDidNotReadEveryDomainMayNotBeABaseline` |
| be certain baseline eligibility agrees with comparing a run against itself | `RunComparabilityTests.EligibilityAgreesWithComparingARunAgainstItself` |
| be certain a run cannot claim to be sealed without saying what it read | `RunComparabilityTests.ARunCannotClaimToBeSealedWithoutSayingWhatItRead` |
| read the same account of comparability in the document and the code | `RunComparabilityDocumentationTests` |

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

- **What a comparison actually shows once it is allowed.** The eligibility half is decided and the
  presentation half is not: what a change looks like, what is worth reporting, and what is noise.
- **How coverage is presented when comparing two runs that covered different things.** Raised as
  open in [`what-the-run-covered`](what-the-run-covered.md) and unresolved.
- **Whether a comparison can be made against something other than a baseline** — the run before
  last, or a run chosen by hand.
- **What happens to a finding that was accepted in the baseline and is still present.** Whether it
  counts as a change is undecided.
- **Whether a severity that rose between runs is itself a change worth reporting.** The predecessor
  computed this; nothing decides it here.

---

## Open findings

| | | |
|---|---|---|
| — | none recorded for this area yet | — |

---

## Reference — the old application

**Reference only. Nothing here is owed, and a row existing here does not mean it is being built.**

The predecessor answered *"may this run be used"* in five independent places — three compare
commands in one view model, an acceptance import filter, the drift path, and baseline eligibility.
A comparison it refused returned every delta collection empty with the success flag set, so the home
screen printed *"No changes since the previous audit."* for a comparison the system had declined to
perform. That defect is why [`0026`](../decisions/0026-one-answer-to-whether-runs-may-be-compared.md)
exists.
