# The judgement store

**Code:** `next/src/SecureAD.Judgement/`
**Layer:** Judgement — where what the rules concluded is kept, and why it is not kept with the evidence.

[`what-a-finding-is.md`](what-a-finding-is.md) says what a rule makes of an object. This page is
where that answer goes: a second database in the bundle's own directory, written after capture has
finished and sealed separately from the evidence it judged.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `JudgementSchema` | Every table in a judgement store, and the indexes built once writing is done |
| `JudgingRun` | Judging a sealed bundle: read every object once, offer it to every rule, write what they concluded |
| `JudgementWriter` | The one way a judgement store gets written |
| `JudgementReader` | Reads a store back, and refuses one that does not belong to the bundle it sits in |
| `JudgementDescription` | What one judging recorded about itself |
| `StoredJudgement` | Everything a judging concluded: what it found, and which rules were run to produce it |
| `StoredRuleExecution` | One rule's execution, read back |
| `RuleExecution` | Everything one rule did to one bundle, and the unit the store commits |
| `MissingInput` | One declared attribute that was not captured, and how many objects it cost |
| `JudgementRunState` | What became of a judging run as a whole |
| `RuleExecutionOutcome` | What became of one rule within that run |
| `FindingsQuery` | What a findings grid asks for: which findings, and where to carry on from |
| `FindingsPage` | One page of findings, and whether there is another |
| `FindingsPageMark` | Where a page of findings ended, so the next can start after it |
| `FindingsFilterValues` | What a findings grid's filters may offer, taken from the findings that exist |

<!-- TYPES:END -->

---

## A bundle gains two files, and loses none

A captured bundle holds `evidence.db` and its seal. A judged one also holds `judgement.db` and
`judgement.db.seal`. Nothing opens the evidence for writing at any point, which is what lets the
same bundle be judged repeatedly while still proving what the directory said once.

`BundleLayout` owns all five names, as it owns every other name in a bundle, so no caller composes
one by concatenation.

**The store is disposable and that is a feature.** If an index is wrong, or a rule is improved,
the file is deleted and the bundle judged again. Nothing is lost, because the evidence was never
part of it.

---

## `judgement.db.partial`, then a rename

Judging writes to `judgement.db.partial`. The seal is written and the file renamed only once every
scheduled rule has finished. A reader asks for `judgement.db` and nothing else.

So a judging killed halfway leaves no file by the name a reader wants. This matters more here than
it does for capture: a half-judged bundle presenting the findings it managed to write looks exactly
like a forest with fewer problems than it has.

---

## The store names the capture it judged

`judgement.evidence_seal` holds the SHA-256 the evidence seal carries, and a reader refuses a store
whose value does not match the bundle it was opened beside.

This exists because the store is an ordinary file that can be copied. Two captures of one forest a
week apart produce directories with identical names holding mostly the same objects, so a judgement
moved into the wrong bundle would resolve nearly all of its findings and be wrong about every one of
them. The evidence seal is a permanent fingerprint of exactly one capture — taken once at the end of
capture and never reissued — which makes it the one value that can settle the question.

Copying a store between bundles is possible and unsupported. The check is what makes the attempt
fail loudly rather than silently.

---

## What ran is recorded, not inferred

`rule_execution` carries one row per scheduled rule, whatever became of it.

**This is what makes an empty `finding` table readable.** No findings and no execution rows means
nobody judged this bundle. No findings beside execution rows means every rule ran and nothing
matched. A screen with only the findings to go on would print both as a clean forest.

A rule that was scheduled and never executed gets a row too, with `RuleExecutionOutcome.DidNotRun`,
because an absent row cannot tell *never scheduled* from *scheduled and skipped*.

`objects_judged`, `objects_not_applicable` and `objects_not_judged` are three different answers and
none is derived from the others.

**Not applicable is not a gap.** A rule declares the classes it is about, and an organisational unit
offered to a delegation rule is not an object the rule failed to read — it has no
`userAccountControl` because it is not an account. Judged against a real forest on 2026-08-26 the
delegation rules called 6,279 of 8,361 objects unreadable on exactly that account, three in four,
which would have reported every judging as degraded for ever and taught an operator to ignore the
one signal that says the findings are incomplete.

**`objects_not_judged` is the real gap**: an object the rule *is* about, missing something the rule
declared it reads. That still degrades the run, and still should.

`rule_execution_missing_input` says which declared attributes were absent and on how many objects.
That turns *SEC-010 could not judge 4,000 objects* into *`primaryGroupID` was not captured*, which
is the difference between a mystery and an instruction.

---

## Two state machines, because a run and a rule fail differently

<!-- STATES:BEGIN -->

| `JudgementRunState` | What it means |
|---|---|
| `Running` | One or more scheduled rules has no terminal execution record, which includes the process being killed mid-run |
| `Completed` | Every scheduled rule reached a terminal, non-degraded result |
| `CompletedDegraded` | Every scheduled rule reached a terminal result, but one or more was indeterminate, errored or did not run |
| `Failed` | The coordinator itself failed — scheduling, sealing or recording the result |

| `RuleExecutionOutcome` | What it means |
|---|---|
| `Succeeded` | The rule ran and reached a verdict on every object it was offered |
| `Indeterminate` | The rule ran and could not reach a verdict on one or more objects, because a declared input was not captured |
| `Error` | The rule threw. Other rules continue; this one has no verdict |
| `DidNotRun` | The rule was scheduled and never executed |

<!-- STATES:END -->

`Failed` and an interrupted `Running` are not the same thing. One is a defect in this product; the
other is a claim about a customer's directory, and a store that could not tell them apart would
present a coordinator that never started as a judging that found nothing.

`CompletedDegraded` is not a lesser kind of success. A judging where a rule could not read its
declared inputs has not established that the forest is clean of what that rule looks for.

---

## Writing is atomic per rule, not per run

Each rule's findings commit in one transaction together with its own execution record.

The two alternatives both lose something. One transaction for the whole run throws away every
completed rule when the last one fails. No transaction boundary at all leaves findings written with
nothing saying which rule produced them. Committing per rule means a killed process loses only the
rule that was running, and no finding can exist without the record of what produced it.

---

## What the schema deliberately has no column for

Nothing derived from the graph. There is no derivation-generation identifier and no capability
catalogue version on an execution record, because group expansion, control edges and reachability
are not built and nothing could fill them.

A column that is always null teaches every reader to ignore it, and would still be null a year
later. They arrive in the stage that fills them, and the store being rebuildable is what makes that
free: there is no data to migrate and no compatibility to keep.

---

## Opening checks three different ways of being wrong

`JudgementReader.Open` refuses before it returns anything:

| Check | What it establishes | Refused as |
|---|---|---|
| The judgement seal | These bytes are the bytes that were written | `JudgementSealAbsent`, `JudgementSealUnreadable`, `JudgementSealMismatch` |
| The schema version | This build understands these tables | `JudgementUnreadable` |
| The evidence fingerprint | This judgement is about *this* capture | `JudgementIsNotForThisEvidence` |

The third is the one no care by the writer can establish, because a store is an ordinary file that
can be moved. A bundle with no readable evidence seal is refused on the same footing as a mismatched
one: unverifiable is not the same as verified, and passing it would make the check optional in
exactly the case where the bundle is already odd.

`BundleSealing.VerifyJudgement` does the seal half, sharing one implementation with the evidence
seal so there is one set of four states rather than two copies of it. `BundleSealing.ReadSeal` is
how a judgement gets the fingerprint to record.

---

## Findings never leave the reader on their own

`Read` returns a `StoredJudgement` carrying the findings **and** the rules that ran. There is no way
to ask for one without the other.

That is a type-system decision rather than a documentation one. A caller holding a bare list of
findings can render an empty one as a clean forest without ever asking whether a rule ran, and no
amount of warning in a comment prevents it. `StoredJudgement.DidNotRun` and
`StoredJudgement.EveryRuleReachedEveryVerdict` are the two questions a screen has to answer before
it shows a count.

---

## One pass over the bundle, not one per rule

`JudgingRun.Judge` opens the sealed bundle, streams every object once, and offers each to every
scheduled rule while it is in hand. Judging forty rules costs the same read as judging one, so
adding a rule costs comparisons rather than another walk of the forest.

**How long judging takes is not known, and the numbers measured here do not answer it.** Streaming a
synthetic bundle on the development machine reached 43,409 objects a second on 2026-08-26, but that
is the read alone with no rule running; with the two delegation rules it fell to roughly 4,689. Both
figures come from invented objects carrying a handful of attributes, and the owner's judgement is
that a synthetic bundle is not complex enough to stand in for a forest. **The number that should be
trusted instead is the predecessor's: four to five hours over the owner's production forest.**
Judging is built for that duration rather than for the lab's 0.72 seconds.

**So a judging reports progress and can be stopped.** `Judge` takes an `IProgress<JudgingProgress>`
and a `CancellationToken`, both required rather than defaulted — gate 1 records that progress,
cancellation and the performance log all became quietly unused in the predecessor by being optional,
and a caller with no operator to tell says so by passing `JudgingRun.NobodyIsWatching`.

Progress counts objects rather than a percentage, because nothing counts a bundle before streaming
it and a percentage wrong by a little would stall at 99 in front of someone watching for hours. It
is reported every 1,000 objects, and the final report is unconditional so that a run ending between
two batches does not leave a total short of what was read.

**Cancelling costs the operator nothing but the time it ran.** The partial file is never renamed
over the finished one, so the earlier judgement survives — the same protection a crash gets, by the
same mechanism. A cancel that destroyed the previous answer would teach an operator never to press
it.

**A rule that throws loses only itself.** It is recorded as `Error`, offered no further objects, and
the rules beside it carry on. Its findings are discarded, because a rule that failed part way
through has no verdict and its partial output would read as a complete one.

**Nothing in the coordinator decides what a run means.** Each rule's outcome follows from what it
did, and the run's state follows from those outcomes inside the writer. A coordinator that could
name the state would be able to call a judging complete while a rule had read nothing.

---

## Findings are read a page at a time

A grid cannot hold a forest, so `JudgementReader.ReadPage` hands back one page and where to carry on
from. The approach is the predecessor's, read on 2026-08-26 and taken because it is better than the
obvious alternative.

**A page starts where the last one ended, not at a row number.** `LIMIT` with an `OFFSET` makes the
database walk and discard every row before the page, so the hundredth page costs a hundred pages of
work. `FindingsPageMark` carries the sort values of the last row shown and the next page is the rows
after it, which costs one seek at any depth.

**The sort ends in the distinguished name, and that is load-bearing.** Findings sharing a severity
and a rule have no order between them otherwise, so a page boundary landing inside such a group
shows some of them twice and loses others — silently, and differently each run. A distinguished name
is unique within a forest, so no two findings can tie on all three.

**Ordered by rank rather than by the word.** The stored severity is the enum's name, so ordering on
it is alphabetical — Critical, High, Low, Medium — which puts Low above Medium on a security screen
and looks entirely normal.

**One row more than the page is fetched and not returned.** Its existence is how a page knows another
follows, without a second query counting rows nobody asked to see. There is deliberately no total:
*page 3 of 400* costs the 400 on every page.

**A judging where no rule ran is refused rather than paged as empty.** `Read` hands findings out
beside the rules that ran because an empty list means nothing on its own; a page cannot carry every
rule execution, so it refuses instead, and `FindingsPage.DidNotRun` keeps the distinction reachable
for a screen holding a page.

**Wildcards in a container's own name are escaped before they reach the query.** `%` and `_` are
legal in a distinguished name and mean something to a `LIKE`, so selecting `OU=Test_1` would
otherwise quietly also show findings from `OU=Test01`.

---

## What a filter may offer comes from the findings that exist

`ReadFilterValues` hands back the severities and rules some finding actually has, and a screen
builds its filter lists from those rather than from the enum.

**A filter that cannot be set to nothing.** A list written into a screen offers Critical whether or
not anything is critical, and an operator who picks it and gets an empty grid has learned only to
distrust the control. Taking the values from the data means every choice narrows to something.

**Severities come back worst first, by rank.** The same alphabetical trap as the grid: ordering on
the stored word puts Low above Medium, which on a filter list reads as a mistake rather than as a
sort.

**Empty lists carry the count of rules that ran.** Two unlike things wear the same empty list — a
judged bundle whose rules found nothing, and a bundle nobody judged — so `FindingsFilterValues`
carries `RulesRan` and `DidNotRun` tells them apart rather than leaving a screen to guess.

**Filtering is a question, not a position.** The values narrow what `ReadPage` is asked for, and
because the resulting list is a different list, a `FindingsPageMark` taken from the old one does not
carry over: it points at rows the new list may not contain.

---

## What is built

The schema, the two state machines, the writer and the reader. Nothing runs a rule to fill a store
yet.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain a judging still in progress cannot be opened | `JudgementWritingTests.AJudgementInProgressHasNoNameAReaderAsksFor` |  |
| have a finished judgement named and sealed | `JudgementWritingTests.CompletingNamesTheStoreAndSealsIt` | 2026-08-26 |
| keep the previous answer when a re-judging dies part way | `JudgementWritingTests.AJudgingThatDidNotFinishLeavesTheEarlierOneIntact` |  |
| be certain a judging whose coordinator failed offers nothing to read | `JudgementWritingTests.AnAbandonedJudgingIsNotGivenAReadableName` |  |
| tell a judging where every rule reached a verdict from one where a rule did not | `JudgementWritingTests.EveryRuleReachingEveryVerdictIsCompleted` |  |
| be certain one unreadable input degrades the whole judging | `JudgementWritingTests.OneRuleThatCouldNotReadItsInputsDegradesTheJudging` |  |
| keep the rules around one that threw | `JudgementWritingTests.ARuleThatThrewDoesNotCostTheRulesAroundIt` |  |
| see which capture a judgement was made against | `JudgementWritingTests.TheStoreRecordsTheEvidenceItJudged` |  |
| be certain a rule cannot claim every verdict and also have missed objects | `JudgementWritingTests.ARuleThatReachedEveryVerdictCannotAlsoHaveMissedObjects` |  |
| be certain an unreached verdict says what was missing | `JudgementWritingTests.ARuleThatCouldNotReachAVerdictMustSayWhatWasMissing` |  |
| see what was missing named rather than counted | `JudgementWritingTests.WhatWasMissingIsRecordedByName` |  |
| be certain a finding is not filed under a rule that did not make it | `JudgementWritingTests.AFindingCannotBeFiledUnderAnotherRule` |  |
| be certain a rule that threw does not leave half a verdict behind | `JudgementWritingTests.ARuleThatThrewCannotAlsoCarryFindings` |  |
| be certain one rule is recorded once | `JudgementWritingTests.OneRuleCannotBeRecordedTwice` |  |
| be certain nothing is added to a sealed judgement | `JudgementWritingTests.NothingCanBeAddedAfterTheJudgementIsSealed` |  |
| tell a rule that was skipped from one that was never scheduled | `JudgementWritingTests.ARuleThatDidNotRunIsStillRecorded` |  |
| have a finding survive into a sealed judgement and come back out | `JudgementReadingTests.AFindingComesBackFromASealedJudgement` |  |
| see the evidence a finding rests on come back with it | `JudgementReadingTests.TheEvidenceAFindingRestsOnComesBackWithIt` |  |
| be certain the domain-controller signals are rebuilt rather than trusted | `JudgementReadingTests.TheDomainControllerSignalsAreRebuiltFromWhatWasStored` |  |
| see which version of a rule produced a finding | `JudgementReadingTests.AFindingCarriesTheVersionOfTheRuleThatMadeIt` |  |
| tell a bundle nobody judged from one where every rule ran and nothing matched | `JudgementReadingTests.ABundleNoRuleWasRunOverSaysSoRatherThanLookingClean` |  |
| be certain that distinction is not made by a reader that says it of everything | `JudgementReadingTests.ABundleWhereRulesRanAndNothingMatchedIsNotTheSameThing` |  |
| see what a rule could not read, by name | `JudgementReadingTests.WhatARuleCouldNotReadComesBackNamed` |  |
| see which capture a judgement was made against | `JudgementReadingTests.TheJudgementNamesTheCaptureItWasMadeAgainst` |  |
| be certain a judgement from another capture is refused rather than believed | `JudgementReadingTests.AJudgementMadeAgainstAnotherCaptureIsRefused` |  |
| be certain a judgement that cannot be checked is refused too | `JudgementReadingTests.AJudgementWithNoEvidenceSealToCheckAgainstIsRefused` |  |
| be certain a judging that never finished cannot be opened | `JudgementReadingTests.AJudgingThatNeverFinishedCannotBeOpened` |  |
| be certain a judgement edited after sealing is refused | `JudgementReadingTests.AJudgementThatWasEditedAfterSealingIsRefused` |  |
| be certain the same finding from two judgings keeps one identity | `JudgementIdentityTests.TheSameFindingFromTwoRunsKeepsOneIdentity` |  |
| keep a finding attached to an object that was renamed and moved | `JudgementIdentityTests.AnObjectThatWasRenamedAndMovedIsStillTheSameFinding` |  |
| be certain tightening a rule does not orphan the findings made under it | `JudgementIdentityTests.TighteningARuleDoesNotChangeTheIdentityOfItsFindings` |  |
| see two rules about one object as two findings | `JudgementIdentityTests.TwoRulesAboutOneObjectAreTwoFindings` |  |
| see one rule against two objects as two findings | `JudgementIdentityTests.OneRuleAgainstTwoObjectsIsTwoFindings` |  |
| be certain one finding cannot be stored twice and shown twice | `JudgementIdentityTests.TheSameFindingCannotBeStoredTwiceInOneJudgement` |  |
| be certain evidence that may be missing confidential values does not come back complete | `JudgementIdentityTests.AFindingWhoseEvidenceMayBeIncompleteDoesNotComeBackComplete` |  |
| be certain that is not said of everything | `JudgementIdentityTests.AFindingWhoseEvidenceWasCompleteComesBackComplete` |  |
| be certain evidence with no table is refused rather than quietly dropped | `JudgementIdentityTests.AnEvidenceKindWithNoTableIsRefusedRatherThanDropped` |  |
| see an account trusted for delegation found in a sealed bundle | `JudgingEndToEndTests.AnAccountTrustedForDelegationIsFoundInASealedBundle` | 2026-08-26 |
| be certain a domain controller is not reported for a setting it requires | `JudgingEndToEndTests.ADomainControllerIsNotReported` | 2026-08-26 |
| be certain every scheduled rule is recorded whether it found anything or not | `JudgingEndToEndTests.EveryScheduledRuleIsRecordedWhetherItFoundAnythingOrNot` | 2026-08-26 |
| see which attribute was missing when a rule could not reach a verdict | `JudgingEndToEndTests.AnObjectMissingADeclaredInputDegradesTheJudgingAndNamesTheAttribute` |  |
| be certain a judgement is bound to the bundle it judged | `JudgingEndToEndTests.TheJudgementIsBoundToTheBundleItJudged` | 2026-08-26 |
| judge a bundle again without the earlier judgement being added to | `JudgingEndToEndTests.JudgingTwiceReplacesTheEarlierJudgement` |  |
| be certain an object a rule is not about does not make the judging look degraded | `JudgingEndToEndTests.AnObjectTheRuleIsNotAboutDoesNotDegradeTheJudging` | 2026-08-26 |
| be certain an account genuinely missing an input still degrades it | `JudgingEndToEndTests.AnAccountMissingADeclaredInputStillDegradesTheJudging` |  |
| see how far a judging has got | `JudgingEndToEndTests.AJudgingReportsHowFarItHasGot` |  |
| be certain the last count reported is everything that was read | `JudgingEndToEndTests.TheLastProgressReportedIsEverythingThatWasRead` |  |
| stop a judging that is running | `JudgingEndToEndTests.AJudgingStopsWhenItIsAskedTo` |  |
| keep the earlier judgement after cancelling a re-judging | `JudgingEndToEndTests.CancellingARejudgingLeavesTheEarlierJudgementIntact` |  |
| read one page of findings and be told there is more | `FindingsPagingTests.APageHoldsWhatItWasAskedForAndSaysThereIsMore` |  |
| be certain the last page says there is nothing after it | `FindingsPagingTests.TheLastPageSaysThereIsNothingAfterIt` |  |
| be certain a page that exactly empties the findings offers no empty page after it | `FindingsPagingTests.APageThatExactlyEmptiesTheFindingsHasNothingAfterIt` |  |
| be certain reading every page shows every finding exactly once | `FindingsPagingTests.ReadingEveryPageShowsEveryFindingExactlyOnce` |  |
| see the worst findings first | `FindingsPagingTests.TheWorstFindingsAreOnTheFirstPage` |  |
| narrow a grid to one severity | `FindingsPagingTests.AskingForOneSeverityReturnsOnlyThatSeverity` |  |
| narrow a grid to one rule | `FindingsPagingTests.AskingForOneRuleReturnsOnlyThatRulesFindings` |  |
| narrow a grid to one container | `FindingsPagingTests.AskingForOneContainerReturnsWhatIsBeneathIt` |  |
| be certain a container whose name holds a wildcard does not widen the grid | `FindingsPagingTests.AContainerHoldingAWildcardDoesNotWidenTheGrid` |  |
| be certain a bundle nobody judged is refused rather than shown as a clean grid | `FindingsPagingTests.AJudgingWhereNoRuleRanIsRefusedRatherThanPagedAsEmpty` |  |
| tell that apart from a judging that ran and matched nothing | `FindingsPagingTests.AJudgingThatMatchedNothingGivesAnEmptyPage` |  |
| be certain severity orders by seriousness rather than alphabetically | `JudgementReadingTests.SeverityIsStoredSoThatTheWorstSortsFirst` |  |
| offer a filter only the values some finding actually has | `FindingsPagingTests.TheFilterValuesAreOnlyWhatTheFindingsHave` |  |
| read a filter's severities worst first rather than alphabetically | `FindingsPagingTests.TheFilterSeveritiesComeBackWorstFirst` |  |
| be certain empty filters from a bundle nobody judged say so | `FindingsPagingTests.FilterValuesFromABundleNobodyJudgedSaySoRatherThanLookingEmpty` |  |
| tell that apart from a judging that ran and matched nothing | `FindingsPagingTests.FilterValuesFromAJudgingThatMatchedNothingSayTheRulesRan` |  |
| narrow the findings grid by severity or rule from the screen | `AssetsViewModelTests.ChoosingASeverityNarrowsWhatIsAskedFor`, `AssetsViewModelTests.ChoosingARuleNarrowsWhatIsAskedFor` |  |
| stop narrowing without asking for a rule called "Any" | `AssetsViewModelTests.ClearingTheFiltersStopsNarrowing` |  |
| be certain changing a filter does not open the grid part way down a list that no longer exists | `AssetsViewModelTests.ChangingAFilterStartsTheGridAgainAtItsFirstPage` |  |
| be certain an empty filtered grid does not claim the container is clean | `AssetsViewModelTests.AnEmptyFilteredGridDoesNotSayTheContainerIsClean` |  |

**Confirmed in lab** is the date the owner saw this working against a real forest.

**On 2026-08-26 a finding this product computed reached a screen for the first time.** The owner ran
an audit in the application, pressed *View results*, and read it. Everything above it — capture,
seal, stream, judge, store, page, show — ran in one gesture with nobody at a command line. The run
before that one crashed on a resource key that never existed, which is why
`ViewResourceGateTests` was written.

**Dates are not filled in from that run beyond what it actually exercised.** A run producing a
handful of findings does not confirm a second page, an empty page, or a wildcard in a container
name, and a date against those rows would say the owner had seen something he had not.

**2026-08-26 is the first lab confirmation this product has recorded.** A bundle captured from
`ph.ad.lab` — 8,361 objects — was judged in 0.72 seconds. Both rules reported `Succeeded`, judging
2,082 accounts and passing over 6,279 objects they are not about. One finding: an account planted
for the purpose, `CN=lab.unconstrained`.

**The domain-controller exclusion was confirmed separately, and the first draft of this paragraph
claimed it without grounds.** No controller appeared in the findings, and that had three
explanations — the exclusion worked, the controller does not carry `TRUSTED_FOR_DELEGATION`, or it
was never judged. An absence cannot choose between them, so `judge-bundle.ps1 -Explain` was built to
ask the bundle directly. Against `CN=PHDC,OU=Domain Controllers,DC=ph,DC=ad,DC=lab` it reported
`userAccountControl` 532480 — `SERVER_TRUST_ACCOUNT` and `TRUSTED_FOR_DELEGATION` together — all
three controller signals agreeing, and SEC-011 reaching a verdict of nothing to report. That is the
second explanation eliminated and the third with it: SEC-011 is the computer rule, PHDC is a
computer the rule is about, and the coordinator offers every object in the bundle to every
scheduled rule, so the object the rule judged here is the object it judged in the run. What stood
between a real controller and a finding was the exclusion, and nothing else.

**The same was then observed in every other domain.** The forest carries three controllers, one per
domain, and all three read alike: `CN=baDC,OU=Domain Controllers,DC=ba,DC=ad,DC=lab` and
`CN=adDC,OU=Domain Controllers,DC=ad,DC=lab` each gave `userAccountControl` 532480, all three
signals agreeing, SEC-011 judging them and reporting nothing. So the exclusion holds across a
naming-context boundary, and at the forest root as well as in a child domain — the two places the
organisational-unit signal reads a differently shaped distinguished name.

**A guess about that boundary was wrong and is recorded because it was wrong.** The expectation was
that a controller in another domain is where the three signals part company — the primary-group
check looks for RID 516 or 521, which is domain-relative, and the organisational-unit check reads a
distinguished name in a different partition. Neither faltered. `SignalsDisagree` therefore still has
no lab exercise, and now demonstrably cannot get one here: every controller this forest has been
asked about, and all three agree with themselves. The disagreement path remains proven by test
alone, and the reason it has not been seen is that a healthy forest does not appear to contain such
an object.

The other blank rows were not exercised: nothing threw, no rule was skipped, and no account was
missing a declared input, so the refusals and degraded paths remain proven by test alone.
