# Whether two runs compare

**Code:** `next/src/SecureAD.Evidence/Run/RunComparability.cs`, `ComparabilityOutcome.cs`,
`RunSummary.cs`
**Layer:** Evidence — the one answer to whether a run may be used.

[`run-identity-and-coverage.md`](run-identity-and-coverage.md) says which forest a run assessed and
how much of it the run read. This page is what is done with those two facts: whether this run may be
measured against that one, whether a run may be nominated as its forest's baseline, and what the
card reporting either is permitted to look like.

Was bound by RunComparabilityDocumentationTests, a documentation gate retired on 2026-09-11,. The outcome table below is bound **in both
directions** — a situation in the code and not here fails the build, and so does a situation here
and not in the code — and the shape in its third column is compared against the shape the code
actually produces, by producing one of every verdict.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `RunComparability` | The one component that decides whether a run may be compared or nominated. Every door calls it |
| `ComparabilityOutcome` | The closed set of situations two runs can be in |
| `ComparabilityVerdict` | One answer about two runs: the situation, whether it permits a comparison, and what to say |
| `BaselineVerdict` | One answer about a single run: whether it may be its scope's baseline, and why not where it may not |
| `DriftCardShape` | What the card reporting a verdict is permitted to look like |
| `RunSummary` | What a caller needs to know about a run in order to decide whether it may be used |

<!-- TYPES:END -->

This table is the page's claim of ownership, bound in both directions against the public types
`RunComparability.cs`, `ComparabilityOutcome.cs` and `RunSummary.cs` declare. `ProfileId`,
`CoverageId` and the coverage records are deliberately absent: what a run *is* and what it *read*
belong to [`run-identity-and-coverage.md`](run-identity-and-coverage.md), and a component described
on two pages is one question answered twice.

---

## One verdict, and every door calls it

`RunComparability` is the only component that decides. The run library, the automatic drift summary,
the compare window, acceptance import and baseline marking are all expected to read the same
verdict, and no caller carries its own predicate. **A rule enforced at one door and not another is
not enforced.**

**The predecessor had five predicates in three files, and they disagreed rather than merely
repeating each other.**

- The drift path checked neither coverage nor eligibility.
- Two of the three library compare commands checked only whether a run was sealed.
- The one command that did check coverage refused *every* mismatch — including the changed-forest
  case its own comparison core had been deliberately rewritten to permit. So an operator who
  decommissioned a domain lost remediation tracking across the transition, and the carefully
  reasoned relaxation was unreachable from the only door that asked.
- Baseline eligibility never read run state at all.

`ComparabilityOutcome` is a closed set for that reason. Adding a situation is one entry, after which
the compiler names every place that has not decided what to do about it. Five independent predicates
do not fail when the rule changes; the one that is missed disagrees quietly.

## What the verdict reads

`RunSummary` is what a caller needs to know about a run in order to decide whether it may be used:
`RunSummary.Profile`, `RunSummary.State`, `RunSummary.Coverage`, `RunSummary.MajorVersion` and
`RunSummary.GraphFindingsWithheld`.

**Only a finished run has coverage, and the two factories are what make that true.**
`RunSummary.OfCompletedRun` takes coverage and is always sealed; `RunSummary.OfUnfinishedRun` takes
a state and refuses `Sealed`, and gives back no coverage. *Sealed with no coverage* and *unfinished
but fully covered* are therefore unrepresentable rather than merely rejected. The predecessor's
equivalent held every field at once and left each caller to work out which of them applied.

`RunSummary.MajorVersion` is compared because two major versions may disagree about what a finding
*is*, which makes a comparison across them worth qualifying rather than refusing.
`RunSummary.GraphFindingsWithheld` is there for the same reason: a comparison against a run with a
hole in its analysis is worth performing and worth saying so about.

The run states themselves are observed from files in the bundle directory and are described in
[`the-bundle-on-disk.md`](the-bundle-on-disk.md). Nothing on this page may carry a second copy of
that vocabulary.

## The three card shapes

`DriftCardShape` says what the card reporting a comparison is allowed to look like, and **the shape
follows the verdict, never the counts.**

<!-- SHAPES:BEGIN -->

| Shape | What it means |
|---|---|
| NoResult | No comparison happened. The card says so, names a cause, and never renders as a pass |
| Qualified | A comparison happened, and something must be stated alongside the numbers |
| Measured | A comparison happened over the whole estate with nothing withheld |

<!-- SHAPES:END -->

**`Measured` is the only shape permitted to say that nothing changed**, and that is the whole point
of the type. The predecessor built its card from five integers and read no compatibility verdict at
all, so a comparison it had **declined to perform** came back with every delta collection empty and
printed *no changes since the previous audit*, with the success flag set. *Found nothing* and *could
not compute* rendered identically, one level above where the type system reaches.

`ComparabilityVerdict` carries `ComparabilityVerdict.Outcome`, `ComparabilityVerdict.Shape`,
`ComparabilityVerdict.Explanation` — what to tell the operator, in terms of something he did or can
act on — and `ComparabilityVerdict.ComparisonMayProceed`, which is false for every `NoResult`
outcome. That makes *the success flag is never set on a path where no comparison occurred* a
property of the type rather than a rule callers are asked to remember.

## The order of the checks is the decision

Decision [`0027`](../../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md).
`RunComparability.Evaluate` takes this run and the earlier one, **the first match wins**, and the
sequence runs from the least recoverable situation to the most: no partner at all, then a partner
that never finished, then evidence with a hole in it, then differences that qualify rather than
refuse.

**A run that both failed a domain and saw a changed forest reports the failure**, because that is
the one the operator has to fix. Reordering the checks is therefore a change to the decision, not a
tidy-up.

The table sits between the two markers around it, so the gate parses only the rows.

<!-- OUTCOMES:BEGIN -->

| Situation | Outcome | Shape |
|---|---|---|
| This is the first audit of the forest | NoEarlierRun | NoResult |
| The earlier audit is no longer in the library | EarlierRunDeleted | NoResult |
| The earlier audit did not finish | EarlierRunNeverCompleted | NoResult |
| This audit did not read every domain in full | ThisRunDidNotReadEveryDomain | NoResult |
| The earlier audit did not read every domain in full | EarlierRunDidNotReadEveryDomain | NoResult |
| The forest gained or lost a domain between the two | ForestDomainSetDiffers | Qualified |
| Some graph analysis was withheld from one of them | GraphFindingsWithheld | Qualified |
| The two were produced by different major versions | DifferentMajorVersions | Qualified |
| Nothing qualifies the comparison | FullyComparable | Measured |

<!-- OUTCOMES:END -->

**Two runs of different forests are not an outcome.** `Evaluate` throws instead. That is not a
comparison with a qualification on it; it is a question nobody asked, and answering it at all would
let a bundle copied in from another machine be offered as a partner for a forest it does not belong
to.

`RunComparability.NoEarlierRun` and `RunComparability.EarlierRunDeleted` are given as their own
factories, because neither has a second run to evaluate against.

**Two pairs share an outcome and not a cause.** `NoEarlierRun` against `EarlierRunDeleted`, and
`ThisRunDidNotReadEveryDomain` against `EarlierRunDidNotReadEveryDomain`. In both pairs only one
member is something the operator can act on today — *this is your first audit* and *somebody deleted
last month's* call for different things — and merging them would send him to fix the wrong thing.
The refusal names the domains, from `RunCoverage.IncompleteDomains`, for the same reason.

**`ForestDomainSetDiffers` is qualified rather than refused.** A decommissioned domain or a
completed acquisition is a legitimate change, and refusing across it forever loses remediation
tracking at the moment it is most wanted. Everything both audits covered is compared; anything only
one of them covered is reported as **not assessed**, which means neither fixed nor new. The
explanation names which domains arrived and which left, rather than showing two hashes that differ.

> The predecessor reasoned this out correctly in its comparison core and then made it unreachable,
> because the only command that checked coverage refused every mismatch. A relaxation nothing can
> reach is worse than no relaxation, because the reasoning survives and reads as though it applies.

## Baseline eligibility is the same predicate, not a second opinion

`RunComparability.MayBeBaseline` gives a `BaselineVerdict` carrying `BaselineVerdict.IsEligible` and
`BaselineVerdict.Explanation`. It asks exactly what reaching a comparison that may proceed asks: the
run sealed, it has coverage, and `RunCoverage.AllDeclaredUnitsAreComplete`.

Keeping it inside the one verdict is the point. **The predecessor's version read coverage and never
state**, so a failed run could become the baseline of a forest and then never be compared against —
the compare command required a sealed baseline, so it refused forever and named no cause, because
there had been no refusal to explain.

A refused nomination says which domains were short, and the whole-forest refusal says why it
matters: *a baseline with a gap in it makes every later comparison understate what changed, without
saying so.*

> **The state test inside `MayBeBaseline` is redundant, and is kept.** `RunSummary`'s factories
> already make *sealed with no coverage* unbuildable, and mutation-testing on 2026-08-12 confirmed
> that removing the check fails no test — that is `F-S18-5`. It stays because the predecessor's
> defect was precisely a coverage-only eligibility check, and because the redundancy costs one
> comparison. **Do not remove the factory guard on the strength of this one, or the other.**

## What is proven about this, and what is not

- **The relaxation is reachable this time.** `ForestDomainSetDiffers` is qualified and
  `ComparabilityVerdict.ComparisonMayProceed` is true for it, asserted directly.
- **No refused comparison can report that it may proceed**, asserted over every producible verdict
  rather than case by case, so an outcome added later cannot slip through as a pass.
- **Only `FullyComparable` is ever `Measured`**, which is the property that stops a refused
  comparison rendering as a clean pass.
- **Eligibility and comparability cannot disagree**, asserted by running both over the same runs.

**Nothing calls `RunComparability` yet.** The rule is written once and the five doors that must
adopt it — the run library, the drift summary, the compare window, acceptance import and baseline
marking — do not exist. That is the honest statement of where the rebuild is, and it is carried as
`P-29` rather than left in a *what is owed* section, because a claim that something is not built is
the least-verified sentence in this repository and rots invisibly where nothing looks at it.

---

> **Where this came from.** The outcome table and its reasoning were `S-18`'s, and `S-18` was
> deleted when this page was written. Its `STATES` half had already moved to
> [`the-bundle-on-disk.md`](the-bundle-on-disk.md) and its identity and coverage half moved to
> [`run-identity-and-coverage.md`](run-identity-and-coverage.md). Its five findings were all
> repaired, checked against the code, and are held by git rather than repeated here; the one live
> consequence was routed to the punch list.

---

## What is built

**The test is the evidence; this table is only the index.**

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank means
unit-tested but not yet exercised against Active Directory.

These rows were carried by an area file the rewrite deleted and were left behind by that pass. Restored 2026-08-24 after an audit of all eight deleted area files found 48 such rows.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain two complete runs of an unchanged forest compare fully | `RunComparabilityTests.TwoCompleteRunsOfAnUnchangedForestAreFullyComparable` |  |
| be certain a refused comparison never reports that it may proceed | `RunComparabilityTests.NoRefusedComparisonEverReportsThatItMayProceed` |  |
| be certain only a fully comparable pair is ever measured | `RunComparabilityTests.OnlyAFullyComparablePairIsEverMeasured` |  |
| read an explanation on every outcome, rather than a bare verdict | `RunComparabilityTests.EveryOutcomeExplainsItself` |  |
| be certain every outcome in the set is reachable, so none is decorative | `RunComparabilityTests.EveryOutcomeIsProducible` |  |
| be certain runs from different forests are refused | `RunComparabilityTests.RunsFromDifferentForestsAreRefused` |  |
| see a failed domain reported ahead of a changed forest, so the more serious cause wins | `RunComparabilityTests.AFailedDomainIsReportedAheadOfAChangedForest` |  |
| see an earlier run that never completed reported ahead of this run's coverage | `RunComparabilityTests.AnEarlierRunThatNeverCompletedIsReportedAheadOfThisRunsCoverage` |  |
| be certain a complete sealed run may be a baseline | `RunComparabilityTests.ACompleteSealedRunMayBeABaseline` |  |
| be certain a run that did not read every domain may not be a baseline | `RunComparabilityTests.ARunThatDidNotReadEveryDomainMayNotBeABaseline` |  |
| be certain baseline eligibility agrees with comparing a run against itself | `RunComparabilityTests.EligibilityAgreesWithComparingARunAgainstItself` |  |
| be certain a run cannot claim to be sealed without saying what it read | `RunComparabilityTests.ARunCannotClaimToBeSealedWithoutSayingWhatItRead` |  |
