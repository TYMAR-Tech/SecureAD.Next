# Roadmap — what order, and where we are

**This is not a decision.** It states no product position; it records the order the rebuild is being
built in and how far it has got. Only records in `docs/decisions/` state the product's position.

**It is an index, not a second copy.** Every stage points at where its detail already lives. Nothing
here restates a rule card, a criterion or a decision, because two copies of a fact drift and this
repository has paid for that twice already.

---

## What tracks what

Four systems hold the work, and each answers a different question. This document answers the fifth.

| Where | Question it answers |
|---|---|
| [`docs/decisions/`](decisions/) | what did we settle, and why |
| [`PUNCH-LIST.md`](PUNCH-LIST.md) | what is wrong, or unanswered |
| [`JUDGEMENT-HALF-ACCEPTANCE.md`](layers/specs/JUDGEMENT-HALF-ACCEPTANCE.md) | which of the 100 criteria are discharged |
| [`docs/rules/`](rules/) | what each of the 62 rules must do |
| **this file** | **what order, and where were we** |

**Keeping it current is part of finishing a stage, not a courtesy.** A stage is done when its code is
merged, its documents are updated and its row here says so. The owner's standing instruction of
2026-08-25: *update the documentation as we go — I don't want to get to the end and have nothing.*

---

## Where we are

| Stage | What | Status |
|---|---|---|
| — | Connect, capture, seal, browse | **built** |
| 1 | Findings move out of the sealed evidence | **built** |
| 2 | Dashboard: coverage and inventory | not started |
| 3 | One rule, end to end | **built** |
| 4 | The simple posture rules | not started |
| 5 | Group expansion | not started |
| 6 | Control edges | not started |
| 7 | Paths to Tier 0 | not started |
| 8 | Proven remediation | not started |
| 9 | Reports and export | not started |
| 10 | Comparing runs | not started |

**A useful product exists at stage 4.** Stages 5 to 8 are the hard half, and stage 8 is where the
predecessor went wrong.

---

## Stage 1 — findings move out of the sealed evidence

**Built 2026-08-25.** `BundleSchema` carried `finding`, `finding_unconstrained_delegation` and
`evaluated_rule` inside the sealed evidence file, contradicting
[`0085`](decisions/0085-judgement-writes-beside-the-evidence.md). The three tables are gone, with
`BundleWriter.WriteFinding`, `WriteEvaluatedRule`, `BundleReader.ReadFindings` and `FindingReader`.
`BundleSchema.Version` stands at 8.

Nothing in production wrote them, so no capability was lost — but sixteen tests went with them, and
what they proved is owed back at stage 3, where it is listed. `StoredFindings` and `EvaluatedRule`
were kept, unconstructed, because they are the shapes a judgement store has to return.

The documentation moved in the same change:
[`layers/judgement/what-a-finding-is.md`](layers/judgement/what-a-finding-is.md) is new and owns the
fourteen judgement types, and the area file that held them was deleted.

*Needs first:* nothing.

## Stage 2 — dashboard: coverage and inventory

Counts over evidence already captured: users, computers, groups, OUs, GPOs, and which domains and
partitions were fully read. No rules, no graph. The predecessor showed both; the rebuild captures
coverage in more detail than it did.

*Needs first:* nothing. This is the cheapest visible progress available.

## Stage 3 — one rule, end to end

**Built 2026-08-25, confirmed against a real forest 2026-08-26.** Unconstrained delegation now runs
from a sealed bundle to a stored finding: read, evaluate, store, show — with *show* still meaning a
command-line tool rather than a screen.

`SecureAD.Judgement` is a fourth production assembly at layer 4. It holds the judgement store,
written beside the evidence and never into it, and the coordinator that streams a bundle once and
offers every object to every scheduled rule. `docs/layers/judgement/the-judgement-store.md` describes
it.

**What the lab run found that no test could.** The delegation rules were counting every
organisational unit, container and policy as an object they could not read — 6,279 of 8,361, three
in four — and degrading the whole judging. Those objects have no `userAccountControl` because they
are not accounts. A rule now declares the classes it is about, on the same footing as the attributes
it reads, and objects it is not about are counted apart from objects it could not judge.

**The domain-controller exclusion took a second run to confirm.** No controller appeared in the
findings, which has three explanations and that run distinguishes none of them. `-Explain` asks the
bundle about one object instead: PHDC carries `TRUSTED_FOR_DELEGATION`, all three controller signals
agree, and SEC-011 judged it and had nothing to report. The exclusion is what kept it out. The
forest's other two controllers, `baDC` and the root's `adDC`, read the same, so the exclusion holds
across a naming-context boundary and at the root as well as in a child domain.

*Detail:* [`SEC-010`](rules/SEC-010.md), [`SEC-011`](rules/SEC-011.md).
*Criteria:* `AC-56`, `AC-62`, `AC-98`.

*Built since:* judging runs from the shell. It follows a capture without being asked for — the
owner's shape, 2026-08-26 — reports progress, can be stopped, and leaves the earlier judgement
intact when it is. The findings reach a screen: Assets carries a Findings tab beside Objects,
scoped by the same tree selection, paged rather than counted, worst first.

**Seen working end to end on 2026-08-26.** The owner ran a new audit in the application, pressed
*View results*, and read findings the product had computed. That is the whole of stage 3 in one
gesture — capture, seal, judge, show — and it is the first time a finding this product made has
reached a person. The first attempt crashed on an invented resource key; `ViewResourceGateTests`
now holds every resource a view names to the ones the application defines.

*Still owed on that screen:* **how the operator moves around it.** The owner's words on seeing it:
*"there is still a lot of work to be done on how the UI navigates."* Two pieces of that are now
built. Double-clicking a finding opens the object it is about, on its Findings tab; closing it
returns to the grid on the same page, because the grid is left untouched while an object is open.
And the grid filters by severity and rule, offering only the values some finding actually has — a
list built from the enum would offer Critical whether or not anything is critical. Changing a filter
restarts at page one, since a keyset mark from the old list points into rows the new one may not
contain, and an empty filtered grid says nothing matches the filters rather than claiming the
container is clean.

*Still owed there:* the domain and family filters the predecessor carried. `FindingsQuery` takes
both and `JudgementReader.ReadPage` already applies the domain, so each is a property, a line in
`FindingsAsked()`, and a control — which is the shape the two built filters were made to leave
behind. Coverage beside a finding is skipped and recorded below.

*Still owed:* what an operator is shown when the evidence verifies and the judgement is degraded is
still undecided. The command line still only captures, which is deliberate for now — the owner
intends it to judge as well, so a long run can happen unattended.

*Also owed, found by asking:* nothing in the product prints what a bundle covered. Which naming
contexts were read, from which controller, and which were known about but never read are all
recorded — `BundleReader.ReadScope()` returns them — and the only way to find out today is to guess
an object and probe for it. Three such probes are what established this bundle spans three domains,
which is an answer arrived at the wrong way round.

*`P-100`, recorded and discharged 2026-08-26:* the assets screen had no layer document, so the
findings grid, the navigation to an object and the filters over it were all built with nothing
holding them. [`the-assets-screen.md`](layers/shell/the-assets-screen.md) now claims all 29 types
across the eight files behind that screen, and `ShellLayerTypesTests` binds the claim to the code in
both directions. What is still unheld is the XAML: the views declare no types, so only
`ViewBindingGateTests` and `ViewResourceGateTests` stand over them, and the second of those exists
because a view naming a resource nobody defined crashed the product with the build green.

**Owed from stage 1 — discharged 2026-08-25.** Sixteen tests were deleted with the evidence tables,
and every claim they made is proven again against the judgement store. The old names are kept beside
the new ones so that a search for a deleted test finds where its claim went, rather than finding
nothing and concluding it was dropped:

| Deleted with the evidence tables | Proven again by |
|---|---|
| `FindingStorageTests.AFindingComesBackFromASealedBundle` | `JudgementReadingTests.AFindingComesBackFromASealedJudgement` |
| `FindingStorageTests.TheEvidenceAFindingRestsOnComesBackWithIt` | `JudgementReadingTests.TheEvidenceAFindingRestsOnComesBackWithIt` |
| `FindingStorageTests.TheDomainControllerSignalsAreRebuiltFromWhatWasStored` | `JudgementReadingTests.TheDomainControllerSignalsAreRebuiltFromWhatWasStored` |
| `FindingStorageTests.TheSameFindingFromTwoRunsKeepsOneIdentity` | `JudgementIdentityTests.TheSameFindingFromTwoRunsKeepsOneIdentity` |
| `FindingStorageTests.AnObjectThatWasRenamedAndMovedIsStillTheSameFinding` | `JudgementIdentityTests.AnObjectThatWasRenamedAndMovedIsStillTheSameFinding` |
| `FindingStorageTests.TighteningARuleDoesNotChangeTheIdentityOfItsFindings` | `JudgementIdentityTests.TighteningARuleDoesNotChangeTheIdentityOfItsFindings` |
| `FindingStorageTests.TwoRulesAboutOneObjectAreTwoFindings` | `JudgementIdentityTests.TwoRulesAboutOneObjectAreTwoFindings` |
| `FindingStorageTests.OneRuleAgainstTwoObjectsIsTwoFindings` | `JudgementIdentityTests.OneRuleAgainstTwoObjectsIsTwoFindings` |
| `FindingStorageTests.TheSameFindingCannotBeStoredTwiceInOneBundle` | `JudgementIdentityTests.TheSameFindingCannotBeStoredTwiceInOneJudgement` |
| `FindingStorageTests.AFindingWhoseEvidenceMayBeIncompleteDoesNotComeBackComplete` | `JudgementIdentityTests.AFindingWhoseEvidenceMayBeIncompleteDoesNotComeBackComplete` |
| `FindingStorageTests.AFindingWhoseEvidenceWasCompleteComesBackComplete` | `JudgementIdentityTests.AFindingWhoseEvidenceWasCompleteComesBackComplete` |
| `FindingStorageTests.AnEvidenceKindWithNoTableIsRefusedRatherThanDropped` | `JudgementIdentityTests.AnEvidenceKindWithNoTableIsRefusedRatherThanDropped` |
| `FindingStorageTests.AFindingCannotBeAddedAfterTheBundleIsSealed` | `JudgementWritingTests.NothingCanBeAddedAfterTheJudgementIsSealed` |
| `FindingStorageTests.ABundleNoRuleWasRunOverSaysSoRatherThanLookingClean` | `JudgementReadingTests.ABundleNoRuleWasRunOverSaysSoRatherThanLookingClean` |
| `FindingStorageTests.ABundleWhereRulesRanAndNothingMatchedIsNotTheSameThing` | `JudgementReadingTests.ABundleWhereRulesRanAndNothingMatchedIsNotTheSameThing` |
| `FindingStorageTests.TheRulesThatRanAreRecordedWithTheVersionThatRan` | `JudgementReadingTests.AFindingCarriesTheVersionOfTheRuleThatMadeIt` |

The claims themselves live in
[`layers/judgement/the-judgement-store.md`](layers/judgement/the-judgement-store.md), which is where
they stay once this file is deleted.

## Stage 4 — the simple posture rules

Rules that read attributes already captured and need no graph: LAPS, stale accounts, SID history,
AdminSDHolder, Kerberos delegation, ownership, broad write access. Each is small, each has a card,
each restores something the predecessor reported.

*Detail:* the cards in [`docs/rules/`](rules/).
*Needs first:* stage 3.

## Stage 5 — group expansion

Who is really in which group: nesting, primary group, cycles. Everything after this depends on it.

*Criteria:* `AC-10`, `AC-25`, `AC-63`. `AC-26` and `AC-64` are **blocked** pending Microsoft evidence
on what SDProp traverses and must not be implemented from inference.

## Stage 6 — control edges

Turn permissions into *this principal can take over that object*. The largest single piece, and what
makes an AD audit tool worth having.

*Criteria:* `AC-24`, `AC-27`, `AC-37`, `AC-55`, `AC-56`, `AC-76`.

## Stage 7 — paths to Tier 0

Chain the edges: who can reach the control plane, and how far away. Restores escalation paths and the
tier counts.

*Criteria:* `AC-31`, `AC-46`, `AC-71`, `AC-79`, `AC-83`, `AC-85`.
*Watch:* [`P-96`](PUNCH-LIST.md) — revisit the single `SEC-071` severity once a real forest has been
judged, and split by feasibility rather than path length if it proves unusable.

## Stage 8 — proven remediation

Which single change closes the most paths, and **proof that it closes them**. The predecessor built
this from retained representative paths, which cannot prove an action is mandatory, and could
therefore tell an administrator a fix was complete when it was not.

*Criteria:* `AC-21`, `AC-22`, `AC-87`, `AC-89`, `AC-99`.
*Do not* port the predecessor's chokepoint logic.

## Stage 9 — reports and export

The predecessor carried 29 reports plus CSV and HTML export. Mostly straightforward once the data
exists.

## Stage 10 — comparing runs

What got better and what got worse. Findings appearing and disappearing, not object-by-object
diffing: the owner ruled out a granular ACL delta on 2026-08-25.

---

## Deliberately not on this list

- **Live directory reads after a run.** Ruled out by the owner 2026-08-25; the predecessor's live
  connection is not coming back.
- **Granular ACL comparison.** Same ruling.
- **Password policy checking.** [`P-97`](PUNCH-LIST.md) — the data is captured and shown, and nothing
  grades it. SecureAD is not a policy compliance checker.
- **The query tool** — wanted, not urgent, described in
  [`planned/the-query-tool.md`](planned/the-query-tool.md).
- **Effective access** — [`planned/effective-access.md`](planned/effective-access.md).
