# What a finding is

**Code:** `next/src/SecureAD.Evidence/Findings/`, `next/src/SecureAD.Judgement/Rule*.cs`,
`next/src/SecureAD.Judgement/UnconstrainedDelegationRules.cs`
**Layer:** Judgement — what executable rules make of captured and derived facts, and the durable data
those answers carry.

The capture half reads a forest and seals it. Judgement is the other half: executable rules consume
declared inputs and write findings outside the seal, keeping *nothing is wrong* apart from *nobody
could look*.

Two rules exist, both about unconstrained delegation. `JudgingRun` executes them over sealed bundles,
stores their findings, and the Shell reads those findings back. The executable contracts and rules
live in `SecureAD.Judgement`; passive finding and rule-definition records stay in Evidence because
they are durable data rather than executable policy.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `Finding` | One thing the product found, about one object, under one rule |
| `FindingSubject` | Who or what a finding is about, as a kind and a key |
| `FindingSubjectKind` | What sort of thing that is |
| `Severity` | How serious a finding is |
| `FindingEvidence` | The values a finding rests on, in a shape its kind declares |
| `AttributeReading` | The one Evidence-owned interpretation of captured attribute values, used by rule definitions, signals and executable rules |
| `StoredFindings` | Findings beside the rules that were run to produce them |
| `EvaluatedRule` | One rule that was run, at the version of its logic that ran |
| `IRule` | A rule: what it is, and what it makes of one object |
| `RuleCatalogue` | Every rule this product runs, as one written-out list |
| `RuleDefinition` | What a rule is as data — its identity, wording and declared inputs |
| `RuleVerdict` | What one rule made of one object, and what it could not read |
| `DerivedFactKind` | A kind of derived fact a rule can declare it reads |
| `DerivedFacts` | The derived facts offered to a rule beside the object it is judging |
| `UnresolvedInput` | One reason a derived fact left a rule unable to decide |
| `UnresolvedReason` | Why it fell short — never derived, disputed, unverified, or unreadable |
| `AdminCountWithoutProtection` | SEC-030 — a protected-account marker with a blocked DACL that nothing protects |
| `AdminCountWithoutProtectionEvidence` | The identity SEC-030 asked the derivation about |
| `UnconstrainedDelegationOnAccount` | SEC-010 — a user or service account trusted for unconstrained delegation |
| `UnconstrainedDelegationOnNonDomainController` | SEC-011 — a member computer trusted for it |
| `UnconstrainedDelegationEvidence` | What an unconstrained delegation finding rests on |
| `DomainControllerSignals` | Whether an object is a domain controller, and whether the three ways of asking agree |

<!-- TYPES:END -->

This table is the page's claim of ownership, bound against the surface register by
`TypesTableOwnershipTests` in both directions, and the register is itself bound to the exported
types of the production assemblies by `SurfaceRegisterTests`.

---

## Today's rules judge one object; Judgement owns the widening seam

`IRule.Judge` takes a single `ObjectAttributes` and returns a `RuleVerdict`. There is no forest, no
sibling lookup and no second pass.

Both delegation rules decide from one object's own attributes, so the narrow shape costs nothing
today. Executable contracts live in Judgement now because that layer can coordinate both Evidence
and Derivation without a dependency cycle. The method remains narrow in this seam-only move; a
declared multi-source input package is the next implementation phase, not hidden inside this one.

Returning nothing is the ordinary case. Most objects are fine, and a rule says so by yielding no
finding rather than by yielding a finding that says nothing is wrong.

---

## The rule set is written out, and it is not the shell's

`RuleCatalogue.All` is the rules this product runs. A list in source rather than a set discovered at
runtime, because [`0082`](../../decisions/0082-the-rule-catalogue-is-not-customer-tunable.md) keeps
the rule set out of the customer's hands and a set assembled by reflection is a set nobody can read
off the page. Adding a rule is a line here, which is a line in a diff a reviewer can be asked to
look at.

**It sits beside `IRule` rather than beside a caller.** Until 2026-08-26 the list lived in the
shell's `JudgingLauncher`, which put the definition of what an audit *is* inside the WPF project — so
a command line judging a bundle overnight would have had to keep a second copy. Two lists that can
disagree about which rules ran is a difference nobody notices until a finding is missing from one of
them, and the store records what was scheduled, so the disagreement would have been written down as
fact.

**It is the set offered, not the record of what happened.** `StoredRuleExecution` is what became of
each rule. One in this list with no execution record did not run, and that is a judging which did not
complete rather than a forest with nothing wrong with it.

---

## A rule declares what it reads, and the build fails if it does not

`RuleDefinition.RequiredAttributes` lists every attribute the rule reads, by LDAP display name.
`RuleDefinition.IsComplete` is false when that list is empty, and `RuleDeclarationTests` fails the
build on it.

Both delegation rules declare `userAccountControl`, `objectClass` and `primaryGroupID`.

The declaration is what makes the next section possible: because the rule has named its inputs, it
can say exactly which of them an object did not carry, instead of falling silent.

---

## Silence has to mean one thing

`RuleVerdict` carries two lists, and the pair is the point:

| Made by | `Findings` | `InputsNotCaptured` | `IsComplete` |
|---|---|---|---|
| `RuleVerdict.Judged` | what was found, often empty | empty | true |
| `RuleVerdict.CouldNotJudge` | empty | the declared attributes that were absent | false |

**Both can carry an empty findings list, and they mean opposite things.** One is *the rule looked
and there was nothing to say*. The other is *the rule was handed an object missing something it
needs, and reached no verdict at all*. A bare `IReadOnlyList<Finding>` return would collapse them
into the same value, and a screen would print both as a clean object.

`StoredFindings` is the same guarantee one level up: findings beside the `EvaluatedRule` rows saying
which rules ran, so that no findings and no rules — *nobody judged this* — cannot be mistaken for no
findings beside rules that ran. `StoredFindings.DidNotRun` is the question a caller must ask before
reporting that nothing was found.

Nothing constructs `StoredFindings` today. It is kept because it is the shape a judgement store has
to return.

---

## What a finding is about, and how it stays that thing

`Finding` names its subject twice over, and the two are for different readers.

`FindingSubject` is a `FindingSubjectKind` and a key — for an account, its `sAMAccountName`, because
that is what an administrator recognises in a report. `FindingSubjectKind` currently declares one
value, `Account`, and widens when a rule is written about something else. It is deliberately not a
security identifier: containers and policies have none, and a subject column that assumes one fails
closed on every finding that is not about an account.

`Finding.ObjectGuid` is the object itself. `objectGUID` is immutable in Active Directory and
survives both rename and move, so a finding made today is still recognisably the same finding after
the object has been renamed into another organisational unit.

`Finding.RuleVersion` sits beside these rather than among them. It records which version of the
rule's logic produced the finding without making the version part of what the finding *is*.

`Finding.DistinguishedName` is where the object was when it was captured — for a reader who has to
go and find it, not for identity.

---

## A finding says whether the evidence under it was whole

`Finding.Coverage` is an `EvidenceCompleteness`, taken from the captured object the rule judged.

A finding is one answer about one object, but its absence has more than one explanation, and they
are not interchangeable: a run that could not read where something lived has not established that
the place is clean. Carrying completeness on the finding keeps that distinction attached to the
answer instead of leaving it in a coverage table somebody has to remember to consult.

---

## Evidence is typed, one shape per kind of finding

`FindingEvidence` is an abstract record with no free-form field on it. `UnconstrainedDelegationEvidence`
derives from it and carries exactly what the two delegation rules looked at: the
`userAccountControl` value the flag was read from, whether the object declared the computer class,
and the three domain-controller signals.

The cost is a type per kind of finding. What it buys is that a reader of a finding's evidence works
against declared members rather than against keys nobody wrote down.

`UnconstrainedDelegationEvidence` stores the three raw signals and neither of the two answers
derived from them. `DomainControllerSignals.IsDomainController` and `SignalsDisagree` are computed
from the three, so storing them as well would create a second copy that can disagree with the first.

---

## Severity belongs to the rule

`Severity` has four levels — `Low`, `Medium`, `High`, `Critical`. There is no `Info`.

The value on a `Finding` is copied from `RuleDefinition.Severity` when the finding is made. It is
fixed by the rule, and nothing in the code takes a severity from anywhere else.

---

## Three ways to ask whether something is a domain controller

A domain controller legitimately holds settings that would be alarming anywhere else — unconstrained
delegation most of all — so both rules must exclude one. `DomainControllerSignals.Of` reads three
signals from the captured object:

| Signal | Read from | Who can set it |
|---|---|---|
| `ServerTrustAccountBit` | `userAccountControl` carries `SERVER_TRUST_ACCOUNT` (`0x2000`) | The directory, during promotion |
| `PrimaryGroupIsDomainController` | `primaryGroupID` is 516 or 521 | Writable by anyone who can edit the object |
| `UnderDomainControllersOu` | the distinguished name contains `,OU=Domain Controllers,` | A naming convention the directory does not enforce |

**Only the first is set by the directory.** An attacker who can write `primaryGroupID`, or move a
computer into the Domain Controllers container, can make an ordinary machine look like a controller.

`IsDomainController` is true if **any** of the three holds. That is the generous direction, chosen
knowingly: a real controller wrongly judged an ordinary computer produces a loud false finding on
every controller in the forest, and an operator learns to ignore the rule.

`SignalsDisagree` is what covers the gap the generosity leaves open — true when something looks like
a controller by one measure and not by another. The product reports the disagreement rather than
settling it by majority.

---

## Two rules, partitioned by object class

SEC-010 handles non-computers; SEC-011 handles computers. An object is a computer or it is not, so
**exactly one of the two can fire on it**, and neither rule needs to know what the other did.

They are partitioned rather than layered on purpose: a rule that disappears when another fires
leaves nothing behind on the day the other one is the one that breaks.

Both run the same sequence, in this order, and the order matters:

1. Any declared attribute the object does not carry → `CouldNotJudge`, naming them.
2. No `objectGuid` → `Judged([])`. This is a verdict reached, not an input missing: the rule can see
   the object and simply has nothing an acceptance could ever attach to.
3. `userAccountControl` unreadable as a number → `CouldNotJudge`.
4. The `TRUSTED_FOR_DELEGATION` bit (`0x80000`) clear, or the object on the wrong side of the
   computer partition → `Judged([])`.
5. `DomainControllerSignals.IsDomainController` → `Judged([])`, because the setting is expected there.
6. Otherwise a finding, keyed on `sAMAccountName` and falling back to the distinguished name.

---

## What is built

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

**Confirmed in lab** is the date the owner saw this working against a real forest. The rules have
now been run end to end against a capture of a live forest — see the capability table in
[`the-judgement-store.md`](the-judgement-store.md) for what that run confirmed and what it did not.

---

## How findings reach the product

`SecureAD.Judgement` holds the store and the coordinator that streams a bundle and offers every
object to every scheduled rule — see [`the-judgement-store.md`](the-judgement-store.md). The Shell
runs judging after derivation and presents findings on the Assets screen. The CLI does not yet invoke
judging; the current and target host paths are stated in
[`../../next/WORKFLOW.md`](../../next/WORKFLOW.md).
