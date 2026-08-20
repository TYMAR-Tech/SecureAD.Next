# S-46 — The exclusion attestation

**What this slice is.** The point in the New Audit window where a domain leaves a run, and what the
product refuses to let happen without a name against it. It also carries the one number that says,
before a run commits, how much of the forest that run will not be able to speak for.

Governed by [`0062`](../decisions/0062-what-an-exclusion-attestation-asks-for.md),
[`0059`](../decisions/0059-an-exclusion-is-attested-once-per-run.md),
[`0054`](../decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md),
[`0063`](../decisions/0063-excluded-never-looks-like-unreachable.md),
[`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) and
[`0052`](../decisions/0052-the-domain-is-the-only-unit-of-scope.md).

---

## What it does

**An operator takes a domain out by unticking it.** The *Include* column is the first column of the
domain table and the only one he acts on rather than reads. Every domain starts ticked, every run —
[`0059`](../decisions/0059-an-exclusion-is-attested-once-per-run.md) forbids the window showing a
domain as pre-excluded, so nothing is remembered from last time and nothing is suggested.

**Unticking asks; it does not exclude.** Clearing the box raises the attestation, and the domain
leaves the run only once the operator has picked a reason from the closed list and typed an
authorising name. The free text is optional.

**A domain the forest names no writable controller for is attested too.** Under
[`0054`](../decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md) that is an
exclusion rather than a gap. It has no tick to untick, so the window raises its attestation itself
once discovery lands — one domain at a time, each named, and never for one already accounted for.

**The account is captured and the authorising name is typed.** Per
[`0062`](../decisions/0062-what-an-exclusion-attestation-asks-for.md) the signed-in Windows account
is taken from Windows rather than asked for, because a name an operator types for himself is a name
he can get wrong. The authorising name is typed because the operator frequently is not the person
whose decision it was.

**The whole attestation reaches the bundle**, in `excluded_domain`: the reason, the free text, both
names, the time, and which kind of exclusion it was.

**And the exclusion reaches the reading.** The domain is taken out of the capture plan, not merely
recorded as having been left out. A bundle that carried an attestation saying nobody looked, filed
beside the objects captured when somebody did, would contradict itself — and the attestation is the
half that looks authoritative. Coverage still measures against every domain the forest declared, so
what comes out is a bundle reporting the domain as **not read**, never one quietly missing it.

**And coverage names the cause.** An excluded domain records
`DomainReadOutcome.ExcludedByChoice` or `ExcludedForWantOfCandidates`, never `NotRead`. Per
[`0063`](../decisions/0063-excluded-never-looks-like-unreachable.md) the distinction holds in the
run's own record of what it covered, and a reader tells the two apart without opening another
table: *we did not look*, *the forest named nothing to look at*, and *we tried and could not* have
three different remedies.

**The window says how much the run will not establish**, as one number over the whole forest,
counted from the same three-state marks the table already renders.

---

## Where these things are shown

The screen changed shape after this slice was first written, on the owner's judgement once he had
seen it filled.

**The table carries four columns**: Include, Domain, Read from, and the override. Site, Connection,
Serves it, Password settings and PDC emulator moved behind a single **Details** button covering
every domain at once — on the principle already used on this screen, that a column saying the same
thing on every row is a column nobody reads. That button carries a **warning mark whenever any
domain has something worth attention**, including a question nobody could answer, so trimming a
column cannot become a way of hiding something.

**The Review step became a review dialog.** The second wizard step showed the same table under a
different heading and reviewed nothing. What replaced it states what the run will read, what it will
not and why, who authorised each exclusion, and how much the run will not establish — facts about
the run as a whole, which is what somebody committing a machine to a read measured in hours is
actually deciding on. **Start lives only in that dialog**, which is what keeps opening the window
from being one click from a capture now that the steps are gone.

*Amended after seeing it on screen: the review is the **second screen** of the window rather than a
pop-out. Its content is unchanged; only its container is. The screen also carries the run itself —
what it will do, what it is doing, and what it produced are three moments of one decision, so an
operator watches the thing he authorised where he authorised it. When it finishes, a disabled
**View results** button names the evidence path and says plainly that reading a bundle inside this
product is not built yet.*

**Every declared domain is a row, readable or not.** A domain the forest names no writable
controller for used to sit in a list beneath the table, and would have vanished when that area was
cleared. It is now a row that says the forest names no controller, refuses the tick box and the
override because there is nothing to honour them with, and always counts as worth attention.

---

## What it refuses

**It refuses an exclusion nobody will answer for.** Dismissing the dialog does not produce a quiet
exclusion:

- A domain the operator **unticked** goes back in, and the box he cleared comes back with it.
- A domain with **no writable controller** cannot go back in — there is nothing to read it from —
  so it stays out, unattested, and the run does not start until he answers.

That asymmetry is not an inconsistency. One is a decision he can reverse; the other is a fact about
the forest that he cannot.

**It refuses to describe the two kinds alike**, per
[`0063`](../decisions/0063-excluded-never-looks-like-unreachable.md). Different wording on screen,
different wording in the dialog that asks, and a separate `kind` column in the bundle — where it
matters most, because there is no screen and no operator to ask.

**It refuses to carry an attestation forward.** Nothing is stored outside the bundle it was made
for and nothing is read back to offer again. Per
[`0059`](../decisions/0059-an-exclusion-is-attested-once-per-run.md) the friction is the control:
a remembered reason presented for confirmation is a button an operator presses without reading by
the third run.

**It refuses to let a reason's wording become its meaning.** The sentence an operator reads and the
value written into evidence are separate, on the footing
[`0024`](../decisions/0024-a-rule-identifier-is-permanent.md) sets for rule identifiers. Rewording
a reason must never rewrite what runs already recorded appear to say.

**It refuses to show a total it has not computed.** Before the opening pass has run there is no
forest to count over, and the window says so rather than showing a confident zero. A count of
unestablished facts is itself a fact.

**It refuses to make inclusion a boolean.** A domain is *included*, *excluded by choice*, or
*excluded for want of candidates*. The tick box renders that; it is not that.

---

## Where the line is drawn

**The command line cannot exclude anything, and this did not change.** An attestation names the
person who authorised leaving a domain out, and a command line has nobody to ask. A forest with a
domain nothing can read still produces no bundle there.
[`0059`](../decisions/0059-an-exclusion-is-attested-once-per-run.md) records that scheduling meets
the same wall and leaves it open.

**The shortfall is checked by count, not by matching names.**
`CapturePlan.IsComplete` compares how many domains were declared against how many were planned, and
says why: a declaration is a DNS name and a unit is a naming context, and pairing them would mean
deciding one can be derived from the other — true only while controllers are reached through
`dnsRoot`, and silently wrong the day a configuration file pins real controllers. The audit layer
therefore checks arithmetic; the shell keys its attestations by naming context, which is where that
fact is actually known.

---

## What this slice does not decide

- **Which columns the table carries.** The *Include* column changes what the rest of the table is
  for, and the owner has asked to judge the columns again now that it exists.
- **Whether a report handed to an auditor must carry the exclusions.** `0062` makes it possible;
  `B4` of the agenda decides whether it is owed.
- **The falsifiable posture.** `0049` offered to test a claim against the captured data and demote
  the run when it proved false — *"the domain is empty"* can be checked, *"I lack credentials"*
  cannot. Still owed to ledger row `B11`.
- **Scheduling**, which cannot attest to anything and is `C1` of the agenda.

---

## Proven by

| The product… | Test |
|---|---|
| asks the operator to account for a domain he unticks | `NewAuditViewModelTests.UntickingADomainAsksTheOperatorToAccountForIt` |
| leaves a domain in the run when the attestation is dismissed | `NewAuditViewModelTests.ADismissedAttestationLeavesTheDomainInTheRun` |
| keeps everything `0062` asks for | `NewAuditViewModelTests.AnAttestedExclusionKeepsEverythingTheRecordAsksFor` |
| captures the account rather than asking him to type it | `NewAuditViewModelTests.TheAccountBehindAnExclusionIsCapturedRatherThanTyped` |
| drops what was stated when a domain goes back in | `NewAuditViewModelTests.PuttingADomainBackDropsWhatWasStatedForIt` |
| asks nothing when a domain goes back in | `NewAuditViewModelTests.PuttingADomainBackAsksTheOperatorNothing` |
| attests a domain with no controller without being sent looking for it | `NewAuditViewModelTests.ADomainWithNoControllerIsAttestedWhenTheWindowWorksItselfOut` |
| puts each unreadable domain separately | `NewAuditViewModelTests.EveryUnreadableDomainIsPutToTheOperatorSeparately` |
| does not ask twice about the same domain in one run | `NewAuditViewModelTests.AnAlreadyAttestedDomainIsNotAskedAboutAgainInTheSameRun` |
| stops a run carrying an exclusion nobody answered for | `NewAuditViewModelTests.AnUnreadableDomainNobodyAnsweredForStopsTheRun` |
| lets the same run start once it is answered for | `NewAuditViewModelTests.AnUnreadableDomainThatWasAttestedLetsTheRunStart` |
| never describes the two kinds of exclusion alike | `NewAuditViewModelTests.ADomainExcludedByChoiceIsNotDescribedLikeOneWithNoController` |
| carries every attestation into the run | `NewAuditViewModelTests.EveryAttestationIsCarriedIntoTheRun` |
| carries a domain taken out as an exclusion | `NewAuditViewModelTests.ADomainTakenOutIsCarriedIntoTheRunAsAnExclusion` |
| does not read a domain that was taken out | `CapturePlanTests.AnExcludedDomainIsNotRead` |
| still measures coverage against the whole forest | `CapturePlanTests.AnExcludedDomainStillCountsAgainstCoverage` |
| keeps a reason's stored name apart from its wording | `NewAuditViewModelTests.AReasonsStoredNameIsNotItsWording` |
| offers every reason in the closed list once | `NewAuditViewModelTests.EveryReasonInTheClosedListIsOfferedExactlyOnce` |
| counts what it will not establish from the marks it shows | `NewAuditViewModelTests.TheCountOfWhatWillNotBeEstablishedComesFromTheStatesTheTableShows` |
| says a total is not known rather than showing zero | `NewAuditViewModelTests.ATotalThatCannotBeComputedSaysSoRatherThanShowingZero` |
| counts an excluded domain as establishing none of its facts | `NewAuditViewModelTests.AnExcludedDomainCountsAsEstablishingNoneOfItsFacts` |
| keeps the absent-domain count tied to what a row carries | `NewAuditViewModelTests.TheFactsCountedForAnAbsentDomainMatchTheFactsARowCarries` |
| keeps the whole attestation in the bundle | `BundleWriterTests.AnExcludedDomainKeepsTheWholeAttestation` |
| stores the two kinds of exclusion apart | `BundleWriterTests.TheTwoKindsOfExclusionAreStoredApart` |
| leaves no exclusion rows for a run that excluded nothing | `BundleWriterTests.ARunThatExcludedNothingLeavesNoExclusionRows` |
