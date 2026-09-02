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
| 4 | The simple posture rules | **started** |
| 5 | Group expansion | not started |
| 6 | Control edges | not started |
| 7 | Paths to Tier 0 | not started |
| 8 | Proven remediation | not started |
| 9 | Reports and export | not started |
| 10 | Comparing runs | not started |

The correction sequence that precedes further rule rollout has completed Wave 6. Wave 5 separated the
AdminSDHolder principal and member-propagation claims and persisted the resulting evaluations,
reasons, bases and paths in Derivation. Wave 6 built the seam above them: a rule declares the derived
facts it reads, judging refuses a bundle whose derivation is absent or belongs to different evidence,
an unresolved derived fact is recorded and shown apart from an uncaptured attribute, and **SEC-030 is
the first rule to consume derived facts without recomputing them**. Verified against `ad.lab` on
2026-08-31, where the generation refusal fired against a stale schema 3 derivation and SEC-030 then
reached a verdict on all 4,236 objects it was about with nothing unresolved.

**Stage 4 is now open with one of its rules built.** The remaining simple posture rules follow the
same shape; those needing only captured attributes need no derived facts and are unaffected by the
Wave 6 seam.

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
still undecided. The command line currently captures and derives but does not judge; the accepted
target is the shared workflow in [`docs/next/WORKFLOW.md`](next/WORKFLOW.md), so a long run can complete
unattended without preserving separate host orchestration.

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

Rules that read attributes already captured and need no graph: LAPS, SID history, AdminSDHolder,
Kerberos delegation, ownership, broad write access. Each is small, each restores something the
predecessor reported.

**Stale accounts is deliberately not among them, decided 2026-09-01.** Doing it accurately means
consolidating `lastLogon` from every domain controller, because that attribute is per-controller and
never replicated; the replicated `lastLogonTimestamp` is documented by Microsoft as updating only
when it is already 9 to 14 days old, and as capable of holding a future value when a controller's
clock skews or Kerberos S4U touches the account. A threshold anywhere near that margin would report
an estimate as a fact. The owner's customer has Defender for Identity, which answers this from
sign-in data rather than from a directory attribute. `P-113` holds the two things worth revisiting:
carrying the timestamp as *information* on an asset rather than as a finding, and a separately named
rough-estimate rule for customers without that telemetry.

**`SEC-030` is built**, 2026-08-31, under
[`0091`](decisions/0091-sec-030-reports-a-marker-without-protection.md). It reports an object
carrying the AdminSDHolder marker with a non-inheriting DACL that nothing establishes as protected,
and it is the first rule to read derived facts rather than only captured attributes. Its
implementation is described in
[`adminsdholder-catalogue-implementation.md`](layers/derivation/adminsdholder-catalogue-implementation.md).

**`SEC-022` is built**, 2026-09-01, described in
[`SEC-022-no-kerberos-preauthentication.md`](layers/judgement/rules/SEC-022-no-kerberos-preauthentication.md).
It reports any account whose `userAccountControl` carries `ADS_UF_DONT_REQUIRE_PREAUTH`, so a domain
controller will hand out material derived from that account's password to anybody who asks. It reads
only captured attributes and declares no derived facts, so it is the first rule to show that the
Wave 6 seam costs an attribute-only rule nothing. It departs from the predecessor twice, both
recorded in its document: **nothing is excluded** — disabled accounts and `krbtgt` are reported,
because no Microsoft source supports excluding them — and the severity is High rather than Medium,
because the attack needs no credentials at all.

**Building it found a defect in the findings grid, now fixed.** `JudgementReader` read a finding's
columns by position while its two queries selected different column lists, so any finding whose
evidence was not the unconstrained-delegation kind had **a severity rank returned as its security
identifier** — the rank 2 came back as the SID `"2"`. It did not throw. Every paging test wrote
SEC-010 findings, so the suite passed over it. Recorded as `P-112`.

**Both verified against `ad.lab` on 2026-09-01.** `lab.nopreauth` was planted in `ba.ad.lab` at
`userAccountControl` 4194818, and SEC-022 fired once, on that account, attributed to that domain,
with the stored evidence matching the directory. The same bundle carries findings of three evidence
kinds, and reading it back through the grid's paging path returned each with its own evidence intact
— which is the `P-112` fix confirmed on real data rather than only on a synthetic bundle.

**Next, decided 2026-09-01: a rule reporting accounts that carry SID history.** `sIDHistory` is
captured, so it needs no new capture work, and there is no card for it — `SEC-123` covers who can
*grant* SID history, not who *has* it. It has to be researched and written before any code, anchored
to Microsoft's *Unsecure SID History attributes* guidance, because nothing was ported: the
predecessor never had this rule. It matters because a non-privileged account carrying a privileged
SID from another domain is effectively privileged and appears in no group membership listing.

**`SEC-027` is built**, 2026-09-02, described in
[`SEC-027-privileged-sid-history.md`](layers/judgement/rules/SEC-027-privileged-sid-history.md). It
reports any security principal — user, computer or group — whose `sIDHistory` contains a SID whose
identifier Microsoft documents as privileged. Severity **High**, and all three classes are reported
identically; both decided by the owner on 2026-09-02. It reads only captured attributes and declares
no derived facts, so it is the second rule to judge a bundle that was never derived.

**The product decision was which accounts to report, and the owner chose the narrow one.** Reporting
*every* account with any SID history is simpler and, after a real migration, thousands of rows of the
benign case Microsoft describes as the attribute's purpose. Reporting only those carrying a
privileged identifier is Microsoft's own worked example and needs no derivation, because the
identifier is in the SID itself. The third option — ranking a value by what it is actually granted in
this forest — was rejected on the evidence: a migrated-from domain usually no longer exists in the
capture, so a derivation would resolve nothing in exactly the case the rule exists for. That
boundary is `P-114`, and it is stated to the operator rather than only to a reviewer.

**It was the first rule to need an About section, and that is now a product commitment.** A rule that
reports a subset is not free to let its silence read as *nothing else is wrong*. The owner, 2026-09-02:
*"we will have an about section that describes each rule and what its looks for so we will have the
ability to surface the limitations to the user."* Recorded in
[`WHAT-THE-PRODUCT-IS.md`](WHAT-THE-PRODUCT-IS.md); content is written with each rule, presentation
is stage 9.

**The anchor test caught a real defect on its first run, which is why it exists.** The six built-in
groups were written as *relative identifiers*, so `S-1-5-21-<any domain>-544` — an ordinary object in
a migrated domain — would have been reported as the built-in Administrators group. Every positive
test passed, because the rule and the tests shared the mistake; only the check that leaves this
repository, against MS-DTYP as transcribed into `WellKnownSidCatalog`, disagreed. This is the
`F-S44-2` shape answered rather than repeated: there was no card and nothing to port, so nothing
internal could have anchored it.

**Gate 4 forced a better rule than the one first written.** It refused a bare list of decoded SIDs,
which cannot say whether every value was readable. The fix — `SidReading`, carrying the count of
values that failed to decode — turned a suppressed finding into a reported one: a privileged
identifier that *was* read is now reported beside a note that other values were not, where before a
single unreadable sibling silenced the whole object. Absent still means clean and unreadable still
means unknown, and there are negative controls for both.

**`SEC-028`, `SEC-029` and `SEC-033` are built**, 2026-09-02, described together in
[`SEC-028-029-033-unsecure-account-flags.md`](layers/judgement/rules/SEC-028-029-033-unsecure-account-flags.md).
They report an account not required to have a password, one whose password is stored reversibly, and
one restricted to DES — three rows of Microsoft's one *Unsecure account attributes* table. High, High
and Medium.

**They are the first batch built to the checklist**, and it worked: the seam cost almost nothing.
`KerberosPreauthenticationEvidence` became `UserAccountControlEvidence` and now serves all four
`userAccountControl` rules, so three new rules needed **no** new table, writer case, reader case or
coverage sample — one shared kind instead of four near-identical ones differing only in which bit
their rule cared about. `EvidenceKindCoverageTests` covers them automatically because it keys on the
evidence kind.

**Three rules rather than one combined finding, deliberately.** Microsoft groups these as a single
assessment. This product does not, because acceptance is per finding: an operator must be able to
accept *"this legacy device genuinely needs DES"* without also accepting *"this account has no
password."*

**`SEC-028` excludes interdomain trust accounts, reversing `SEC-022`'s *nothing is excluded*
position — because here there is a Microsoft source and there was not.** Microsoft states that a
trust account "is exempt from having a password through PASSWD_NOTREQD… because trust objects don't
use the traditional password policy", and that the flag is set on them **by default**. Every trust in
the forest would otherwise be reported, all by design and all false. Decided by the owner
2026-09-02; the exclusion reads the object's own `INTERDOMAIN_TRUST_ACCOUNT` bit rather than its name
or container.

**A mutation lesson worth keeping.** Two mutations run together hid one another: with the flag
constant mutated, the trust-exclusion test passed, because the mutated flag never matched the fixture
so the exclusion was never reached. Run separately, each was caught. **Mutations are run one at a
time from here.**

**Next in stage 4:** `SEC-021` (a *privileged* user account with a service name registered on it).
The owner chose the privileged-only scope on 2026-09-02, which maps onto the predecessor's existing
partition — `SEC-020` is the all-accounts version and stays unbuilt — so unlike `SEC-027` there is a
card to port from. It needs derived facts for the privileged classification, so it is the first
attribute rule of stage 4 that cannot judge an underived bundle.

**Also decided 2026-09-02: the Kerberos AES rule reports only an explicit weak value.**
`msDS-SupportedEncryptionTypes` being unset does **not** mean AES is unavailable — Microsoft
documents the KDC falling back to `DefaultDomainSupportedEncTypes`, which defaults to `0x18`
(AES-SHA1), and states that a value need not be set at all for user accounts without a service name.
That fallback is a registry value on the controller, which capture never reads, so a bundle cannot
know what an unset attribute resolves to. The rule will fire only when the attribute is present and
explicitly excludes AES — Microsoft's own example being `0x4`, RC4 only.

**`SEC-021` is built**, 2026-09-02, described in
[`SEC-021-kerberoastable-privileged-account.md`](layers/judgement/rules/SEC-021-kerberoastable-privileged-account.md).
It reports a **privileged** user account with a service name registered on it — any authenticated
member of the domain can ask for a ticket encrypted with that account's password and crack it
offline, and because the account is privileged that is a single step from ordinary member to domain
administration. **Critical**, the first rule in this product to carry that severity.

**It is the first stage-4 rule that cannot judge an underived bundle.** It declares
`DerivedFactKind.ProtectedPrincipals` — the AdminSDHolder-derived catalogue `SEC-030` already reads —
so `0091` applies and a judging without a matching derivation is refused for the whole run. Using
that product means *privileged* is Microsoft's own designation rather than a list this product
invented.

**The owner chose the privileged-only scope on 2026-09-02, which maps onto the predecessor's own
partition:** `SEC-020` is the every-account version and stays unbuilt. Microsoft scopes its
recommendation the same way — of removing a service principal name it says *"This recommendation
only showed for sensitive accounts."*

**It departs from its card on disabled accounts.** The card excluded them, stating a key distribution
centre will not issue a ticket for a disabled account. Microsoft's Kerberos material was searched for
that statement and it was not found, so the exclusion would rest on a belief this product cannot
evidence — the position `SEC-022` reached about AS-REP. The state travels in the evidence and the
wording instead.

**A trap worth recording, caught by mutation.** A computer's `objectClass` is
`top, person, organizationalPerson, user, computer`, so testing *is `user` in the chain* reports
every domain controller in the forest — each with service names, each in a protected group, each with
a machine-generated 120-character password that rotates. The rule tests the **most derived** class
instead, and the fixtures use the real chain so the mutation fails rather than passing.

*Detail:* the cards in [`docs/rules/`](rules/).
*Needs first:* stage 3.

**`SEC-020` follows, and carries an open question.** It reports a user account with a service name
registered on it, which any authenticated member of the domain can request a ticket for and crack
offline. `servicePrincipalName` is captured, so it is buildable — but Microsoft's *Unsecure account
attributes* assessment recommends removing a service name **only for sensitive accounts**, since
service accounts legitimately hold them. Whether this product reports every such account or only
privileged ones is undecided and changes both the noise and the derived facts the rule must declare.
More research is owed before it is built.

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
