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
| `StoredRuleExecutions` | Every scheduled rule's execution, beside the state of the judging that produced them |
| `RuleExecution` | Everything one rule did to one bundle, and the unit the store commits |
| `MissingInput` | One declared attribute that was not captured, and how many objects it cost |
| `JudgementRunState` | What became of a judging run as a whole |
| `RuleExecutionOutcome` | What became of one rule within that run |
| `FindingsQuery` | What a findings grid asks for: which findings, and where to carry on from |
| `FindingsPage` | One page of findings, and whether there is another |
| `FindingsPageMark` | Where a page of findings ended, so the next can start after it |
| `FindingsFilterValues` | What a findings grid's filters may offer, taken from the findings that exist |
| `ControlCapability` | The supported initial control capabilities, not the complete stage-6 catalogue |
| `ControlEdge` | A stored capability attributed to its named trustee, with evidence and independent expectedness |
| `ControlEdgeClass` | Semantic categories, never severity or an ordered risk score |
| `ControlEdgePage` | A bounded page with generation, coverage and counts, including hidden expected edges |
| `ControlEvaluationState` | Whether a capability is established, not established or unknown |
| `ControlExpectedness` | Whether control is expected, unexpected or not yet classified |
| `ControlExpectednessReason` | The stored reason for that separate classification |
| `ControlObjectEvaluation` | Per-object coverage, retained even when no edge can be identified |
| `ControlPrecondition` | A named condition with its own evaluation and evidence source |
| `ControlUncertainty` | Explicit unresolved inputs that limit a capability claim |

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

## Derived evidence is bound to its generation

`judgement.derivation_generation_id` identifies the derivation used by a judging that requires one.
Schema 14 also persists SEC-021's grouped membership evidence and completeness using the same
`MembershipRouteStorage` encoding as Derivation. The finding carries its protection catalogue version
and any direct catalogue basis. Opening or paging it therefore does not reconstruct routes from a
newer derivation or silently lose longer alternatives.

An incomplete verdict may retain established findings beside its unresolved inputs. A rule that
throws still loses its entire output. This distinction was exercised end to end with a known
protected account and an unresolved membership elsewhere in the captured graph.

### Initial control-edge product — schema 15

`JudgingRun` now calls `ControlEdgeDeriver` for each streamed object and persists its result through
`JudgementWriter`. `ControlEdgeStorage` records product completion, per-object descriptor coverage,
edges, supporting ACEs and preconditions. Membership evidence is stored with each edge rather than
reconstructed from a later derivation.

The supported primitives are `CanWriteDacl` and `CanSetOwner`. The supporting
`CanBecomeOwnerAndRewriteDacl` compound remains `Unknown`, research-blocked and uncounted; a proved
owner-setting right does not prove a takeover. Expectedness and capability evaluation are separate.
`JudgementReader.ReadControlEdges` supplies object-first and named-holder-first pages from the same
stored product. The object screen defaults to hiding expected edges, states their count, shows
coverage and evidence, and refuses to mix generations while paging.

This is a started slice, not completed stage 6. Ownership-derived control, membership changes,
credentials, replication, full-control aggregation and effective member expansion are not derived.
Reachability remains unbuilt. The end-to-end witness is
`JudgingEndToEndTests.SealedDescriptorProducesStoredControlEdgesThroughTheRealCoordinator`;
automated tests do not discharge the stage's claim-specific laboratory gates or P-145.

### Captured-lab validation of the initial slice — 2026-09-06

**The catalogue-1 baseline, not stage-6 acceptance.** A fresh evidence-only copy of
`ad.lab-20260905-212426` was derived and judged before the P-150 correction below. This is the newer capture
used by the interrupted session, not the older `03:54` capture named in its brief. All three domains
and 8,383 captured objects were represented. The source, preserved previous copy and new copy retain
Evidence SHA-256 `2DEF9F8AD4DE01877970B7F97F845716C1FFC1B093B01F388004610526E76BE4`.
No directory connection or modification was made.

| Initial-slice measurement | Result |
|---|---:|
| Counted WRITE_DAC primitives | 32,544 |
| Counted WRITE_OWNER primitives | 32,540 |
| Expected primitives | 43,447 |
| Unexpected primitives | 11,805 |
| Expectedness unknown | 9,832 |
| Supporting owner-to-DACL compounds, unknown and uncounted | 32,540 |
| Objects with unanswered supported primitives | 0 |

All 65,084 primitives have evaluation `Established`. **That is separate from whether a right is
expected**, and neither this table nor zero unanswered supported primitives means all stage-6
capabilities were evaluated. Judging produced 27 findings; SEC-031 and SEC-032 each retained their
four unresolved objects, so the overall run remains `CompletedDegraded`.

**The byte-level check did not call SecureAD's parser or access evaluator.** The .NET
`RawSecurityDescriptor` reader parsed the 390 distinct captured descriptors. Its entry ordinals,
types, SIDs, masks, GUID presence, inheritance flags and opaque data matched the 1,547 distinct
supporting signatures representing all 433,561 stored control-ACE records. Generic mapping and
inherit-only interpretation follow [MS-ADTS 6.1.3](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a).
Every counted primitive had an applicable raw allow, and independently enumerating uncomplicated
direct grants found the same 65,084 identities with none omitted. Altering a compared ACE and
removing an edge in memory each made the corresponding check detect the mismatch. These checks
establish provenance and direct-grant coverage, not token-wide effective access.

The previous and fresh generations have identical edge answers and object coverage after excluding
generation identifiers. The planted `SecureADTakeoverOuter` group retains two unexpected primitives
on `OU=SecureADTakeoverTarget,OU=BA Lab,DC=ba,DC=ad,DC=lab` and one unknown, uncounted compound.
Object-first and holder-first reader calls return the same edge identities. The target has 15 stored
rows, seven default-visible rows and six hidden expected primitives; supporting rows are not added
to those primitive counts. An absent target is not presented as a complete empty result.

**The baseline exposed P-150, since corrected below.** All 9,818 `UnknownAuthorityScope`
primitives belong to `BUILTIN\Administrators`: 460 scoped to `ad.lab`, 8,834 to `ba.ad.lab` and 524
to `ph.ad.lab`. The three scoped group objects are captured. `ObjectPermissions` deliberately gives
well-known SID labels no domain; the original `ControlEdgeDeriver` recorded a scoped holder but passed the
unscoped label's domain into its direct expectedness check. Decision `0099` accepts Administrators
within its own domain. The missing scope handoff was the defect, not the accepted catalogue.
Do not resolve a shared BUILTIN SID
by taking the first matching directory row, or remove the uncertainty required for non-domain
resource contexts under P-90.

**Unexpected volume has two large concentrations.** Account Operators contributes 8,426 primitives
(4,260 on groups, 4,120 on users, 24 on foreign security principals, 16 on computers and six on group
managed service accounts). Forest-root Domain Admins contributes 3,210 outside its accepted authority
scope. A large count does not by itself justify widening the catalogue. SYSTEM contributes 16,732
expected primitives; ADDC, BADC and PHDC each contribute six unexpected primitives. Server Operators,
Print Operators, Backup Operators and Replicator have no named-trustee primitives in this slice;
that is not a claim that they have no other capabilities. Enterprise Domain Controllers accounts for
the remaining 14 unknown expectedness answers, with `UnknownCapabilityScope`.

Artifacts, including the two executable checks, raw diagnostic outputs and binary fingerprints,
remain under `next/artifacts/stage6-control-recovery-validation/`. Judgement generation:
`4cfa848c-83c2-42b5-8eb9-c65014d07c72`; derivation generation:
`709c602a-19ad-428d-91bd-5d10efb507a6`. **P-145 remains open:** the remaining capabilities,
member expansion, Tier 0-target analysis and the claim-specific live laboratory gates are not
discharged by this offline check. No application behavior or policy was changed in the baseline pass.

### P-150 corrected — catalogue 2, 2026-09-06

`ControlEdgeDeriver.Expected` now obtains direct BUILTIN domain authority from the target's domain
only when the target is in that domain naming context and its captured domain root supplies a SID.
The well-known label remains domainless. Configuration, schema, application-partition and missing-
scope cases remain unknown; a membership route retains its root's own recorded scope. No first-match
SID lookup or new expected principal was introduced.

`PrincipalClassificationRegistry.Version` is now 2. The storage layout remains judgement schema 15:
new edges carry the changed semantic version, and old generations are read as recorded, not relabeled.
**Re-judge existing evidence to obtain the correction; re-capture and re-derivation are not required.**

The regression uses a real two-domain bundle containing both Administrators groups and real
descriptors, in both capture orders. It verifies that the reader's label is still domainless,
object-first and holder-first identities agree, scopes stay separate, expected primitives are hidden
with their count stated, and the supporting ownership compound remains unknown and uncounted.
Both cases failed before the fix with *expected 2 expected primitives, actual 0*. Two direct-scope
positive cases also failed; the negative scope and cross-domain membership-root cases passed.
After correction and versioning, all 60 targeted tests passed.

A separate copy of the same evidence and sealed derivation was judged into generation
`a0eef917-5c1b-493b-98bf-8b21bbcf63b4`. The preserved baseline was not overwritten.

| Counted primitive classification | Catalogue 1 | Catalogue 2 |
|---|---:|---:|
| Expected | 43,447 | 53,265 |
| Unexpected | 11,805 | 11,805 |
| Unknown | 9,832 | 14 |

Exactly 9,818 counted primitives changed from `UnknownAuthorityScope` to
`ExpectedSameDomainControlPlane`, all scoped BUILTIN Administrators. Another 4,909 supporting
compounds changed only their expectedness: their capability evaluation remains unknown and they are
still uncounted. Each domain already had two expected Administrators primitives; the corrected
holder totals are therefore 462 in `ad.lab`, 8,836 in `ba.ad.lab`, and 526 in `ph.ad.lab`, not merely
the reclassification deltas. The remaining 14 unknown answers still have `UnknownCapabilityScope`
for Enterprise Domain Controllers.

The executable comparison in `next/artifacts/stage6-p150-scope-correction/compare-p150.ps1` checks
both directions: all other stored edge fields (apart from the new generation and catalogue version),
8,383 object-coverage rows, 433,561 control ACEs, 97,620 preconditions, membership-route tables, 27
finding rows and all 17 rule-execution rows match the baseline. The evidence fingerprint is unchanged.
The real reader shows eight hidden expected primitives and four visible rows on the planted target;
the two unexpected takeover-group primitives remain visible. Opening the historical generation
still returns its version-1 answers. **P-150 is closed; P-145 and stage-6 acceptance remain open.**

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

## What every rule did is readable without the findings

`ReadRuleExecutions` hands back one `StoredRuleExecution` per scheduled rule and no findings at all.
It is the other half of the question `ReadPage` answers: a page of findings says what was wrong, and
this says what was checked — including the rules that checked and found nothing, which no list of
findings can contain.

**The count of findings comes from a grouped query, not from the rows.** `SELECT rule_id, COUNT(*)
FROM finding GROUP BY rule_id` is one small read; carrying the findings themselves to count them
would make a screen of eleven rules pay for every finding in the forest.

**`FindingsProduced` sits beside the outcome rather than being inferred from an empty grid.** A rule
recorded as `Succeeded` with zero findings judged everything it was about and established something.
One recorded as `Indeterminate` established nothing about the objects it could not reach. Both write
zero findings, and only the pair of values keeps them apart.

**The list comes back vouched, not bare.** `StoredRuleExecutions` carries the run's state and
`DidNotRun`, because an empty list of executions means either a bundle nobody judged or a judging
that stopped before it recorded anything. Until this read existed the executions were reachable only
through `StoredJudgement`, which says the same thing; handing them back on their own would have taken
that statement away from the one caller whose whole subject is what was and was not checked. Gate 4
caught the omission.

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
