# What we call a finding

**Area.** What the product produces when a rule matches: what it is called, what identifies it, what
it carries, and how severe it is said to be. This is the vocabulary every screen and every report
inherits.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| calls the thing it finds a **finding**, on every screen and in every report | [`0066`](../decisions/0066-a-finding-is-called-a-finding.md) |
| fixes a finding's severity by its rule card, and lets no customer change it | [`0066`](../decisions/0066-a-finding-is-called-a-finding.md) |
| gives a finding a stable identity, so the same finding is recognisable across runs | [`0023`](../decisions/0023-a-finding-has-a-stable-identity.md) |
| never reuses a rule identifier, whatever happens to the rule | [`0024`](../decisions/0024-a-rule-identifier-is-permanent.md) |
| holds the rule catalogue as data and the rule logic as code | [`0010`](../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md) |
| names a pattern in a bundle and never explains one away | [`0015`](../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md) |
| never lets a finding appear clean while its coverage carried unknowns | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |
| rates a privileged variant of a rule above its base, lets both findings stand, and inherits no acceptance between them | [`0079`](../decisions/0079-a-privileged-variant-of-a-rule-escalates.md) |
| carries typed evidence on a finding rather than a free-form blob | [`0080`](../decisions/0080-a-finding-carries-typed-evidence.md) |
| rates every finding at one of four severities, and carries no informational level | [`0081`](../decisions/0081-severity-has-four-levels.md) |
| lets no customer disable a rule, add one, or change a severity | [`0082`](../decisions/0082-the-rule-catalogue-is-not-customer-tunable.md) |
| makes a rule declare the data it depends on, and fails the build when one does not | [`0083`](../decisions/0083-a-rule-declares-its-data-dependencies.md) |

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank is the
honest answer for every row here: the rules are proven against values taken from a real capture,
but nothing has yet been run end to end against a live directory.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain a rule cannot ship without saying what data it reads | `RuleDeclarationTests.EveryRuleDeclaresTheDataItReads` |  |
| be certain that check is looking at real rules rather than an empty set | `RuleDeclarationTests.ThereAreRulesToCheck` |  |
| be certain no two rules claim the same identifier | `RuleDeclarationTests.EveryRuleIdIsUnique` |  |
| see a user account trusted for unconstrained delegation | `UnconstrainedDelegationRuleTests.ThePlantedUserAccountIsFoundBySec010` |  |
| see a member server trusted for unconstrained delegation | `UnconstrainedDelegationRuleTests.AMemberServerWithTheFlagIsFoundBySec011` |  |
| be certain a domain controller is not reported for a setting it requires | `UnconstrainedDelegationRuleTests.ADomainControllerIsExcluded` |  |
| be certain a read-only domain controller is excluded on the same terms | `UnconstrainedDelegationRuleTests.AReadOnlyDomainControllerIsExcluded` |  |
| be told when the three ways of asking "is this a domain controller" disagree | `UnconstrainedDelegationRuleTests.SignalsThatDisagreeAreRecorded` |  |
| tell an account that is clean from one the run could not read | `UnconstrainedDelegationRuleTests.AnObjectMissingADeclaredInputGetsNoVerdictRatherThanACleanOne` |  |
| be certain that distinction is not made by a rule that never reaches a verdict | `UnconstrainedDelegationRuleTests.AnObjectCarryingEveryDeclaredInputReachesAVerdict` |  |
| have a finding survive into a sealed bundle and come back out | `FindingStorageTests.AFindingComesBackFromASealedBundle` |  |
| see the evidence a finding rests on come back with it | `FindingStorageTests.TheEvidenceAFindingRestsOnComesBackWithIt` |  |
| be certain the same finding from two separate runs keeps one identity | `FindingStorageTests.TheSameFindingFromTwoRunsKeepsOneIdentity` |  |
| keep a finding attached to an object that was renamed and moved | `FindingStorageTests.AnObjectThatWasRenamedAndMovedIsStillTheSameFinding` |  |
| be certain tightening a rule does not orphan the findings made under it | `FindingStorageTests.TighteningARuleDoesNotChangeTheIdentityOfItsFindings` |  |
| tell a bundle nobody judged from one where every rule ran and nothing matched | `FindingStorageTests.ABundleNoRuleWasRunOverSaysSoRatherThanLookingClean` |  |
| be certain that distinction is not made by a reader that says it of everything | `FindingStorageTests.ABundleWhereRulesRanAndNothingMatchedIsNotTheSameThing` |  |
| be certain evidence that may be missing confidential values does not come back complete | `FindingStorageTests.AFindingWhoseEvidenceMayBeIncompleteDoesNotComeBackComplete` |  |
| be certain one finding cannot be stored twice and shown twice | `FindingStorageTests.TheSameFindingCannotBeStoredTwiceInOneBundle` |  |
| be certain evidence with no table is refused rather than quietly dropped | `FindingStorageTests.AnEvidenceKindWithNoTableIsRefusedRatherThanDropped` |  |
| be certain nothing can add a finding to a bundle that is already sealed | `FindingStorageTests.AFindingCannotBeAddedAfterTheBundleIsSealed` |  |

**Findings are stored but not shown.** A rule reaches a verdict, the finding is written into the
bundle before it is sealed, and it comes back with one identity across runs. Nothing puts one on a
screen yet, and no acceptance has been written or matched — so the five reasons
[`0023`](../decisions/0023-a-finding-has-a-stable-identity.md) fixes for an unmatched acceptance are
still unbuilt, and belong with comparison.

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

- **How a finding whose coverage was incomplete is presented**, as distinct from one whose coverage
  was whole. [`0083`](../decisions/0083-a-rule-declares-its-data-dependencies.md) decides how the
  product *knows* coverage was incomplete; how it *says so* on a screen or in a report is still open.
- **Whether a finding records how well it was established.** Deferred rather than declined: the
  question is really about how the product states how well it knows a chain, so it belongs to
  [how-privilege-escalates](how-privilege-escalates.md) where the second value would come from. It
  is safe to leave open, because `0023` keeps such a field out of a finding's identity, so adding
  one later orphans no acceptance. A *confidence* scale is ruled out - a rule expressing doubt about
  itself is the hedge `0015` forbids.

---

## Open findings

| | | |
|---|---|---|
| `F-SEC131-1` | `SEC-131` excludes computers and non-privileged users by saying SEC-014 covers them. SEC-014 is a permission rule about RBCD. The real homes are SEC-010 and SEC-011, so the exclusions rest on nothing. | **open** |
| `F-SEC010-1` | `SEC-010.md` and `SEC-011.md` carry no `#` title line. Every other rule card has one. | **open** |
