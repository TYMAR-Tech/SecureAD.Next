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
| 3 | One rule, end to end | not started |
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

Carry unconstrained delegation from sealed bundle to a findings surface: read, evaluate, store,
show. The point is the pipeline rather than the rule — everything after this is repetition.

*Detail:* [`SEC-010`](rules/SEC-010.md), [`SEC-011`](rules/SEC-011.md).
*Criteria:* `AC-56`, `AC-62`, `AC-98`.
*Needs first:* **the judgement store's shape.** `0085` deliberately left open whether it is one file
per bundle or one per run, and whether a judged result is a record or is recomputed on open. A rule
cannot be wired without the first of those.

**Owed from stage 1.** Sixteen tests were deleted with the evidence tables, and each of these has to
be proven again against whatever the store turns out to be. The old names are kept so the claim is
searchable, not because the new tests must reuse them:

- a finding survives being written and comes back out — `FindingStorageTests.AFindingComesBackFromASealedBundle`
- the evidence a finding rests on comes back with it — `FindingStorageTests.TheEvidenceAFindingRestsOnComesBackWithIt`
- the domain-controller signals are rebuilt from the three stored signals, not from a stored answer — `FindingStorageTests.TheDomainControllerSignalsAreRebuiltFromWhatWasStored`
- the same finding from two separate runs keeps one identity — `FindingStorageTests.TheSameFindingFromTwoRunsKeepsOneIdentity`
- a finding stays attached to an object that was renamed and moved — `FindingStorageTests.AnObjectThatWasRenamedAndMovedIsStillTheSameFinding`
- tightening a rule does not orphan the findings made under it — `FindingStorageTests.TighteningARuleDoesNotChangeTheIdentityOfItsFindings`
- two rules about one object are two findings — `FindingStorageTests.TwoRulesAboutOneObjectAreTwoFindings`
- one rule against two objects is two findings — `FindingStorageTests.OneRuleAgainstTwoObjectsIsTwoFindings`
- the same finding cannot be stored twice and shown twice — `FindingStorageTests.TheSameFindingCannotBeStoredTwiceInOneBundle`
- evidence that may be missing confidential values does not come back complete — `FindingStorageTests.AFindingWhoseEvidenceMayBeIncompleteDoesNotComeBackComplete`
- evidence that was complete comes back complete — `FindingStorageTests.AFindingWhoseEvidenceWasCompleteComesBackComplete`
- evidence with no table is refused rather than quietly dropped — `FindingStorageTests.AnEvidenceKindWithNoTableIsRefusedRatherThanDropped`
- nothing can add a finding after the store is sealed — `FindingStorageTests.AFindingCannotBeAddedAfterTheBundleIsSealed`
- a bundle nobody judged says so rather than looking clean — `FindingStorageTests.ABundleNoRuleWasRunOverSaysSoRatherThanLookingClean`
- a bundle where rules ran and nothing matched is not the same thing — `FindingStorageTests.ABundleWhereRulesRanAndNothingMatchedIsNotTheSameThing`
- the rules that ran are recorded with the version that ran — `FindingStorageTests.TheRulesThatRanAreRecordedWithTheVersionThatRan`

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
