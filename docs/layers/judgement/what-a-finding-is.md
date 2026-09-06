# What a finding is

**Code:** `next/src/SecureAD.Evidence/Findings/`, `next/src/SecureAD.Judgement/Rule*.cs`,
`next/src/SecureAD.Judgement/UnconstrainedDelegationRules.cs`
**Layer:** Judgement — what executable rules make of captured and derived facts, and the durable data
those answers carry.

The capture half reads a forest and seals it. Judgement is the other half: executable rules consume
declared inputs and write findings outside the seal, keeping *nothing is wrong* apart from *nobody
could look*.

`RuleCatalogue.All` is the executable rule set; this page does not keep a second count that can
drift when a rule is added. Some rules use captured attributes alone and others declare derived
facts. `JudgingRun` executes the scheduled rules over sealed bundles and stores their findings.
Both the Shell and CLI invoke judging, and the Shell reads its results back.
The executable contracts and rules live in `SecureAD.Judgement`; passive finding and rule-definition
records stay in Evidence because they are durable data rather than executable policy.

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
| `SidReading` | The security identifiers read off one attribute, and whether every value was readable |
| `TextReading` | The text values read off one attribute, and whether every value was readable |
| `StoredFindings` | Findings beside the rules that were run to produce them |
| `EvaluatedRule` | One rule that was run, at the version of its logic that ran |
| `IRule` | A rule: what it is, and what it makes of one object |
| `RuleCatalogue` | Every rule this product runs, as one written-out list |
| `RuleDefinition` | What a rule is as data — its identity, wording and declared inputs |
| `RuleGuidance` | What an operator is told about a rule — why it matters, and what to do |
| `RuleGuidanceCatalogue` | That guidance, one entry per rule, written out beside the rule list |
| `RuleVerdict` | What one rule made of one object, and what it could not read |
| `DerivedFactKind` | A kind of derived fact a rule can declare it reads |
| `JudgingContext` | The reference time and derived facts offered to a rule beside the object it is judging |
| `UnresolvedInput` | One reason a derived fact left a rule unable to decide |
| `UnresolvedReason` | Why it fell short — never derived, disputed, unverified, or unreadable |
| `AdminCountWithoutProtection` | SEC-030 — a protected-account marker with a blocked DACL that nothing protects |
| `AdminCountWithoutProtectionEvidence` | The identity SEC-030 asked the derivation about |
| `NoKerberosPreauthentication` | SEC-022 — an account a domain controller will answer for without the asker proving anything |
| `UserAccountControlEvidence` | The whole `userAccountControl` value a flag rule read its bit from, shared by every such rule |
| `PrivilegedSidHistory` | SEC-027 — a principal carrying a privileged identifier in its SID history, which no group membership listing shows |
| `PasswordNotRequired` | SEC-028 — an account exempt from the domain's minimum password length, so it may have none |
| `ReversiblePasswordEncryption` | SEC-029 — an account whose password the directory stores in a form that decrypts back to the password |
| `DesEncryptionOnly` | SEC-033 — an account restricted to DES, so its Kerberos tickets are cheap to attack |
| `KerberoastablePrivilegedAccount` | SEC-021 — a privileged account any domain member can request a crackable ticket for |
| `KerberoastableAccountEvidence` | The service names SEC-021 found on the account, and the value its disabled state is read from |
| `MembershipRouteSummary` | Initial memberships and the completeness of their discovery; a partial count is not a total |
| `InitialMembershipRoutes` | Supporting routes sharing one initial membership, with their discovery completeness |
| `MembershipRoute` | One supporting chain to a catalogue root, with authorization and protection stated separately |
| `MembershipRouteStep` | One principal in a chain, marking whether it is reached through primary-group membership |
| `MembershipRoutePrincipal` | A SID, its domain scope where needed, and its captured distinguished name |
| `MembershipRouteAuthorization` | Whether the chain is security-enabled, contains distribution nesting, or has unknown group type |
| `MembershipRouteIncompleteReason` | Typed capture, identity, forest-mask, resource-limit or cycle reasons why a route summary is partial |
| `PrivilegedSidCatalogue` | Which of Microsoft's identifiers this product treats as privileged, as one written-out table |
| `PrivilegedSidHistoryEvidence` | Every SID history value SEC-027 read, which of them are privileged, and whether any could not be read |
| `PrivilegedSidHistoryMatch` | One history value that names a privileged principal, with Microsoft's name for it |
| `UnconstrainedDelegationOnAccount` | SEC-010 — a user or service account trusted for unconstrained delegation |
| `UnconstrainedDelegationOnNonDomainController` | SEC-011 — a member computer trusted for it |
| `UnconstrainedDelegationEvidence` | What an unconstrained delegation finding rests on |
| `DomainControllerSignals` | Whether an object is a domain controller, and whether the three ways of asking agree |
| `LapsCapability` | Which LAPS product a computer is capable of running, and whether that rests on the build number, the operating system name, or nothing at all |
| `LapsCapabilityKind` | The answer: Windows LAPS capable, legacy LAPS only, or unknown |
| `LapsCapabilityBasis` | What the answer rests on, so a finding can say how it was decided rather than only what was decided |
| `LapsPlatformCatalog` | The Microsoft build numbers that place a machine on one side of the Windows LAPS boundary, kept in their own type so gate 4's exemption covers the table and not the classifying |
| `LapsMissingOnComputer` | SEC-091 — a computer carrying neither LAPS expiration timestamp, so nothing visible is rotating its local administrator password |
| `WindowsLapsNotAppliedOnCapableComputer` | SEC-094 — a Windows LAPS-capable computer carrying only the legacy timestamp, which is residue rather than proof of management |
| `LapsRotationStale` | SEC-092 — a computer whose LAPS expiration lapsed more than a day ago, so its local administrator password has stopped rotating |
| `LapsAttributes` | The attribute names, class test and schema-answer reading the two LAPS rules share, kept in their own type so gate 4's exemption covers the table and not the judging |
| `LapsDeploymentEvidence` | Both LAPS timestamps as the directory stored them, with what the machine was capable of running |
| `LapsTimestampReading` | Whether a timestamp was absent, present, or present and undecodable — three states the two rules must never collapse |
| `LapsTimestamp` | One LAPS expiration timestamp as the directory stored it, with the single decoder the rules and the inventory both use |
| `LapsPasswordReadAccess` | SEC-090 — a principal broad in every organisation that can read a machine's LAPS password, found by expanding whichever principal the delegation actually names |
| `LapsPasswordAttributeCatalogue` | The three attributes that carry a LAPS password, in their own type so gate 4's exemption covers the table and not `LapsAttributes.Judgeability` |
| `LapsPasswordReaderEvidence` | The broad principal, the membership path that reached it, the rights the entry carried and the scope it was inherited from |
| `LapsReadRights` | Which of the two rights a confidential attribute needs the entry actually held — the distinction the predecessor's rule collapsed |
| `LapsGrantReach` | Whether the entry names this attribute or reaches every attribute on the object, read from `ACE_OBJECT_TYPE_PRESENT` and not from a null GUID |
| `PathStep` | One principal on a membership path, carrying both its identifier and its name — the identifier survives a rename, the name is the part an operator can act on |
| `LapsDecryptorBroadPrincipal` | SEC-093: a Group Policy Object whose authorized Windows LAPS password decryptor is, or contains through nesting, a principal broad in every organisation |
| `LapsDecryptorEvidence` | The configured decryptor value, the principal it resolved to, the broad principal that can decrypt and the route that reached it |
| `LapsDecryptorForm` | Which of the three forms Microsoft accepts the value was written in, which decides what an unresolved value means |
| `BroadPrincipalCanTakeOverObject` | SEC-060: an object over which a principal broad in every organisation effectively holds the right to rewrite the permission list, directly or by taking ownership |
| `ObjectTakeoverEvidence` | The principal the entry named, the broad principal inside it, the route that reached it, and which takeover-class right was held |
| `ObjectTakeoverRight` | Which of Full Control, Write DACL or Take Ownership was held — kept apart because only the last depends on an owner keeping implicit rights |
| `ObjectOwnedByNonAdministrator` | SEC-031: an object whose owner is not an administrative principal, and which AdminSDHolder does not protect |
| `ProtectedObjectOwnedByNonAdministrator` | SEC-032: the same condition on an object AdminSDHolder does protect, which is a route to privilege rather than latent authority |
| `ObjectOwnershipEvidence` | The owner, whether that account still exists, the object's class, and whether the walk behind the answer finished |
| `ObjectOwnerStanding` | Whether the owning account exists or has been deleted — two states with opposite remedies |

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

`RuleDefinition.RequiredAttributes` lists the captured attributes the rule declares, by LDAP display
name. `RuleDeclarationTests` checks that list directly for absence, duplicate names and empty names.
Derived inputs are declared separately in `RuleDefinition.RequiredDerivedFacts` and acquired by
`JudgingRun` before any object is offered to a rule that needs them.

**Do not confuse definition and verdict completeness.** The legacy `RuleDefinition.IsComplete`
predicate also requires a nonempty class list; it is not the applicability check or the declaration
test described here. `RuleDefinition.IsAbout` treats an empty class list as every object, which the
ownership rules deliberately use. `RuleVerdict.IsComplete` says whether a particular verdict had
missing or unresolved inputs.

Both delegation rules declare `userAccountControl`, `objectClass` and `primaryGroupID`. `SEC-022`
declares the first two and no more, which is why it can judge a bundle that was never derived.

The declaration is what makes the next section possible: because the rule has named its inputs, it
can say exactly which of them an object did not carry, instead of falling silent.

---

## Guidance sits beside a rule, not inside it

A finding tells an operator that something is true about one object. `RuleGuidance` tells him what
that means and what to do about it: a category, an optional MITRE technique, *why it matters*, *what
to do*, an *About* statement of the rule's scope and limitations, and the Microsoft page the reasoning
rests on. `RuleGuidanceCatalogue.All` holds one entry
per rule, and `RuleGuidanceTests` binds the two lists in both directions — a rule with no guidance is
a finding nobody can act on, and guidance naming no rule is copy that quietly rots.

**It is a separate type and a separate file because [`0010`](../../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md)
is Accepted and says so.** Its objection was concrete: in the predecessor, changing a severity and
fixing a typo in remediation text were the same edit to the same file and arrived at review
indistinguishable. Asking a reviewer to treat the behavioural list as security-relevant only works if
the prose that changes weekly is somewhere else.

**Written when the rule is built, not afterwards.** The Microsoft research behind a rule is done once,
at the moment the rule is written. Recorded then, it costs almost nothing; reconstructed later across
sixty-two rules by somebody without the sources open, it is a project. Before this existed, the three
Microsoft pages read for `SEC-022` reached a customer as half a sentence.

**It is current advice, and deliberately not stored on the finding.** A finding records what was true
about an object and is reproducible from the rule version and its inputs, which is what `AC-19` asks.
The advice beside it should improve as we learn more, and an operator reopening last month's run
wants today's best advice rather than last month's.

**`WhatToDo` states an action and what it may break. It must never state that the customer is then
safe** — that is a claim about every route to the object, which `AC-15` and `AC-21` require to be
proven and which belongs to stage 8. `RuleGuidanceTests` refuses the wording, and carries a self-test
so a pattern that stopped matching could not go on reporting nothing. The danger is not that somebody
decides to over-claim; it is that *"this resolves the issue"* reads like ordinary helpful writing.

**A null MITRE technique is an answer.** Mappings belong to individual guidance entries, not to a
default applied to every rule. A null entry makes no technique claim; a non-null entry needs its own
supporting source. `RuleGuidanceCatalogue.All` is the current set, not the original four-rule snapshot.

---

## Silence has to mean one thing

`RuleVerdict` carries three lists, keeping a reached verdict apart from two kinds of missing answer:

| Made by | `Findings` | `InputsNotCaptured` | `Unresolved` | `IsComplete` |
|---|---|---|---|---|
| `RuleVerdict.Judged` | what was found, often empty | empty | empty | true |
| `RuleVerdict.CouldNotJudge` | empty | the declared attributes that were absent | empty | false when missing inputs are named |
| `RuleVerdict.CouldNotResolve` | empty | empty | the derived questions left undecided | false when unresolved inputs are named |

**All three can carry an empty findings list, and they do not mean the same thing.** A reached
verdict with no findings is an answer. A missing captured attribute and an unresolved derived fact
are different reasons the rule could not answer, with different remedies. A bare
`IReadOnlyList<Finding>` would collapse these states and let a screen print them as clean objects.

`StoredFindings` is the same guarantee one level up: findings beside the `EvaluatedRule` rows saying
which rules ran, so that no findings and no rules — *nobody judged this* — cannot be mistaken for no
findings beside rules that ran. `StoredFindings.DidNotRun` is the question a caller must ask before
reporting that nothing was found.

`StoredFindings` currently has no production consumers; it is not the shape the live screen reads.
`JudgementReader` reads the separate judgement generation, its per-rule execution outcomes and its
findings. Those outcomes must be read alongside a finding count to distinguish a quiet rule from
one that did not run or could not reach every verdict.

---

## What a finding is about, and how it stays that thing

`Finding` names its subject twice over, and the two are for different readers.

`FindingSubject` is a `FindingSubjectKind` and a key — for an account, its `sAMAccountName`, because
that is what an administrator recognises in a report. `FindingSubjectKind` declares `Account`,
`Policy` and `DirectoryObject`, so an organizational unit is not represented as an account. It is deliberately not a
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

**Independent membership summaries (`0108`, P-146).** SEC-021 version 2 writes one finding per
account, grouping supporting chains by initial membership rather than emitting a finding per outer
root. Longer independent memberships remain visible, including those reaching the same root as a
shorter route. `KerberoastableAccountEvidence` carries `MembershipRoutes`, the protection catalogue
version and any direct catalogue basis. Names, scoped SIDs, primary links and completeness survive
both disposable stores. The finding's captured-object coverage and route completeness are separate;
the screen cannot show complete coverage when the membership summary is partial.

`JudgingRun` retains established findings from an incomplete `RuleVerdict` alongside its unresolved
inputs. A rule that throws still loses all its findings. Partial membership detail does not erase a
proven protection claim, and an incomplete walk still cannot prove an account unprotected. Protection
through distribution nesting is never described as proof of administrative authorization; neither
the route summary nor the selected protection basis determines owner acceptance.

**Scoped owner acceptance, built 2026-09-05 (`0109`).** Both ownership rules use
`ObjectOwnershipReading` and the independently derived `OwnerAcceptance` answer. The forest-root
Schema Admins group and its members are accepted only within that forest's schema partition.
`JudgingContext.ForestFqdn` comes from sealed evidence; parsed DN ancestors, including the object
itself, establish the boundary without mistaking an escaped comma for a parent separator. Missing
forest identity produces `UnresolvedReason.ForestIdentityUnreadable`, not acceptance. A proven schema
membership with uncertainty elsewhere is accepted in the schema and remains unresolved outside it.
The rule versions are 2; the predicates, both rule consumers, persistence and real-bundle judging
are exercised. The product document records the measured counts and deliberate failing controls.

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
runs judging after derivation and presents findings on the Assets screen. The CLI also invokes the
shared judging path after capture/derive and supports judging an existing bundle. The host paths are stated in
[`../../next/WORKFLOW.md`](../../next/WORKFLOW.md).
