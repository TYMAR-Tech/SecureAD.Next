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

**Five rules verified against `ad.lab` on 2026-09-02, and the forest found a defect nine rules and
2,819 green tests had not.** `SEC-021` reported all three domains' `krbtgt` accounts at **Critical**,
telling the operator to remove the service name or replace the account with a group managed service
account — **both impossible, and either would break Kerberos for the domain.** The rule document had
claimed `krbtgt` "holds no `servicePrincipalName`, so it never reaches the test"; it carries
`kadmin/changepw` by default. Every test agreed with the rule because both were built from the same
wrong belief about Active Directory. **Only the directory disagreed.** Fixed by excluding relative
identifier 502 — which is what the predecessor's card did, and on this the card was right.

**What the lab proved that fixtures could not:**

| Rule | On the untouched forest | Planted |
|---|---|---|
| `SEC-028` | **3 findings** — the built-in `Guest` of each domain, genuinely carrying `PASSWD_NOTREQD` | — |
| `SEC-028` exclusion | sealed evidence holds **7** accounts with the flag; the rule reported **3**. The four not reported are trust accounts at `userAccountControl` **2080** — exactly the `0x820` Microsoft documents as their default. **Without the exclusion, four of seven findings would have been false, on every forest with a trust** | — |
| `SEC-021` | 0 after the fix (3 before) | `lab.kerberoast` → 1, Critical, right domain |
| `SEC-029` | 0 of 2,082 carry `0x80` | `lab.reversible` → 1, High |
| `SEC-033` | 0 of 2,082 carry `0x200000` | `lab.desonly` → 1, Medium |
| `SEC-027` | 0, and **0 objects carry any SID history at all** — so the negative is real, but its reading script has never been seen reporting something, and the positive stays unplantable in one forest | — |

**The command line now runs the whole audit.** `securead-cli --library <dir>` captures, derives and
judges; `--judge <bundle>` re-judges sealed evidence without re-reading the forest. That is what the
owner asked for on 2026-08-26 — *"so it can run overnight"* — and it is what made this verification
possible without opening the application. `ARCHITECTURE.md` previously reasoned that judging in the
command line "has nobody to offer the findings to"; that was wrong twice, since findings go to a
store rather than a person.

**The re-judge is the split working.** The corrected `SEC-021` was run against evidence already
sealed, and the finding count went 9 to 6 without re-reading a single object —
[`0085`](decisions/0085-judgement-writes-beside-the-evidence.md) as intended.

**`SEC-091` and `SEC-094`, LAPS deployment state. Specified 2026-09-03, built 2026-09-03. Run
against `ad.lab` 2026-09-04: both judged all 14 LAPS-relevant computers. `SEC-091` had nothing to
report; `SEC-094` reported one computer carrying the legacy timestamp without the modern one.**

The two rules were split on 2026-09-03, and the reason is not tidiness:

| Rule | Fires when | Severity |
|---|---|---|
| `SEC-091` | a computer carries **neither** LAPS expiration timestamp | Medium |
| `SEC-094` | a **Windows LAPS-capable** computer carries the legacy timestamp and **not** the modern one | Low |

Specified in [`SEC-091`](layers/judgement/rules/SEC-091-laps-missing-on-a-computer.md) and
[`SEC-094`](layers/judgement/rules/SEC-094-windows-laps-not-applied-on-capable-computer.md).

**`SEC-092`, LAPS rotation stale. Specified 2026-09-03, built 2026-09-03. Run against `ad.lab`
2026-09-04: judged all 14 LAPS-relevant computers, nothing to report. A clean result rather than an
untested one — the lab's managed machines are rotating within the 24-hour grace.**

| Rule | Fires when | Severity |
|---|---|---|
| `SEC-092` | a computer's LAPS expiration lapsed **more than 24 hours** before the reference time | Medium |

Specified in [`SEC-092`](layers/judgement/rules/SEC-092-laps-rotation-stale.md).

**`SEC-090`, who can read LAPS passwords. Specified 2026-09-03, built 2026-09-03. Run against
`ad.lab` 2026-09-04: three findings, and one object it refused to judge.**

| Rule | Fires when | Severity |
|---|---|---|
| `SEC-090` | a principal **broad in every organisation** appears in the fully expanded set of principals holding read access to a LAPS password attribute | High |

Specified in [`SEC-090`](layers/judgement/rules/SEC-090-who-can-read-laps-passwords.md).

**Its `Indeterminate` outcome is the rule working, not a defect.** One computer carried a trustee
holding both LAPS read rights whose principal is not in the bundle, so the rule refused to judge it
rather than call it clean — *not found is not "not broad"* — and one unjudged object marks the whole
rule. **Detail in [`SEC-090` §11](layers/judgement/rules/SEC-090-who-can-read-laps-passwords.md).**

**It is the first rule to read a security descriptor against the group expansion**, and it is the
first of the four consumers `P-124` names to be built. What it asserts is deliberately narrow: the
product cannot know which principals an organisation intended to hold LAPS read access, so it
reports only broadness — which needs no local knowledge — states the inherited scope as a fact, and
carries the membership path so an operator can see which link to cut.

**Two places it departs from the predecessor's card, both on Microsoft's authority.** Reading a
confidential attribute requires `READ_PROPERTY` *and* `CONTROL_ACCESS`, and the old evaluator tested
the second alone, so it named principals who cannot retrieve the password. And its `T1003.003` tag
describes credential dumping from the domain database, which reading a LAPS password is not; no
technique is claimed rather than a wrong one asserted.

**`SEC-093`, a broad principal can decrypt LAPS passwords. Specified 2026-09-03, built 2026-09-03,
tested and mutated 2026-09-04. Run against `ad.lab` on 2026-09-04, which found three defects; all
three corrected the same day and the rule confirmed working against the forest.**

| Rule | Fires when | Severity |
|---|---|---|
| `SEC-093` | a Group Policy Object's authorized Windows LAPS password decryptor **is, or contains through nesting,** a principal broad in every organisation | Critical |

Specified in [`SEC-093`](layers/judgement/rules/SEC-093-laps-decryptor-is-a-broad-principal.md).

**It is a second, independent gate on the same passwords `SEC-090` guards.** Microsoft separates
them outright: being granted permission to query a password "doesn't automatically imply that the
user has permission to decrypt an encrypted password". An estate can be tight on the access control
list and open on the decryptor, so a clean `SEC-090` says nothing about this.

**Its subject is the policy and never a machine, and that is a refusal rather than unfinished
work.** Microsoft states the authorized decryptor "can't be changed after a password is encrypted",
so a stored password was encrypted against whatever the policy named at the time — a value the
directory does not record. Naming machines would assert something about the past that no evidence
establishes. The owner settled this on 2026-09-03. It is the first rule whose subject has no
security identifier, which is why `FindingSubjectKind` gained a `Policy` value.

**The lab run earned its place on the checklist, three times over.** Against `ad.lab` on 2026-09-04
the rule was found broken in three separate ways — a registry key that does not exist, a broadness
test gated on an expansion it does not need, and a lookup under the wrong scope — each a false
negative on a Critical rule, and none visible to 3,013 green tests. All three corrected the same
day and the rule confirmed working against the forest. **Detail, and what the tests now anchor to,
in [`SEC-093` §10](layers/judgement/rules/SEC-093-laps-decryptor-is-a-broad-principal.md).**

**It is the first consumer of `gpo_registry_setting`,** which capture has been writing since the
SYSVOL work and nothing had read.

**It closes a hole the other two leave open.** A machine that was onboarded correctly and has since
stopped rotating passes both in silence: its timestamp is present, so `SEC-091` says nothing, and it
is the right timestamp, so `SEC-094` says nothing. The local administrator password has become a
static shared secret and the product reported a clean bill.

**The 24-hour grace is the owner's decision of 2026-09-03**, and it is not caution. Microsoft's own
way of forcing an early rotation, `Set-LapsADPasswordExpirationTime`, sets the expiration to the
current time and lets the next policy cycle act — and a Group Policy cycle takes up to two hours. A
rule with no tolerance reports every healthy machine caught in either window. Severity is Medium for
the reason `SEC-091` is: the password is still unique to the machine, and only its freshness has
lapsed.

**This is the product's first temporal rule**, and it forced a decision that every later staleness
rule inherits: `DerivedFacts` was renamed `JudgingContext` and given a non-nullable `AsOf`, so a rule
is handed the same reference time the judgement records in `evaluation_as_of` and can no longer read
the clock. Re-judging a sealed bundle next year therefore reproduces exactly these findings. That
column had existed since the judgement store was written and nothing had ever used it.

**Acceptance is per finding and suppression in the interface is per rule**, so an estate running
Windows LAPS in legacy emulation mode deliberately must be able to silence the second without
silencing the first. One rule carrying a state field makes that impossible. Same reasoning that kept
`SEC-028`, `SEC-029` and `SEC-033` apart.

**The handoff written here on 2026-09-02 was wrong about the absence problem, and the forest said
so.** It recorded that both LAPS attributes may be withheld silently as confidential. Microsoft's
schema reference gives `msLAPS-PasswordExpirationTime` a `SearchFlags` of **0**, while every
attribute carrying a *password* carries **904**, which includes `fCONFIDENTIAL`. Read from `ad.lab`
on 2026-09-03, both expiration attributes returned 0 and both password attributes 904. **Whether a
machine is managed is not a secret; what the password is, is.** The runtime check is kept anyway,
because the default is what Microsoft ships rather than what a given forest is — but the absence
problem is far narrower than this section claimed.

**A second correction, and this one nearly shipped.** The first draft of `SEC-091` argued that a
modern machine carrying only a legacy timestamp should be silent, because *"its password is being
rotated."* **The legacy attribute is never cleared** — Microsoft's migration procedure removes the
policy and then the software and touches no directory attribute — so a legacy timestamp proves
nothing about whether anything is still rotating. The owner caught it. That is `SEC-021`'s `krbtgt`
defect in the same shape, one step earlier.

**What is built, 2026-09-03:**

- **Catalogue version 6**: `operatingSystemVersion` captured, and shown on the computer object view.
  The predecessor classified by matching the OS *name*, which under-reported twice — Windows 10 and
  Server 2012 both classed *not applicable* when LAPS applies to both. The name is still captured
  because Windows 10 1607 and Server 2016 are **both build 14393**, so the build alone cannot tell a
  client from a server.
- **`LapsPlatformCatalog` and `LapsCapability`**, with fixtures read from `ad.lab` rather than
  invented, so the parser is checked against the format Active Directory actually stores.
  `LapsCapability` carries **how** it decided, so a bundle sealed before version 6 still yields
  findings and the finding records that the answer came from a name.
- **[`0092`](decisions/0092-a-view-filter-is-not-a-change-to-the-catalogue.md)** — a view filter is
  presentation, not the tuning `0082` forbids. Without it a future session deletes the grid filters
  as a violation.
- **[`0093`](decisions/0093-an-export-states-what-it-contains.md)** — an export states its filter and
  its counts. The predecessor's LAPS export ignored the active filter *and* was named for a subset it
  did not contain.
- **The rule-identifier gates now accept a specification under `docs/layers/judgement/rules/`**, not
  only a predecessor card. As written they forbade the rebuild from ever naming a new rule. A bogus
  `SEC-999` was fed to the gate to confirm it still fails.

**What was built on 2026-09-03, after the above:**

- **Both rules through the 18-step checklist.** `LapsMissingOnComputer` and
  `WindowsLapsNotAppliedOnCapableComputer`, sharing one `LapsDeploymentEvidence` kind and one
  `LapsAttributes` constants table so the two cannot disagree about the population they divide.
  Twenty-two tests between them, each rule mutated in both directions one mutation at a time.
- **`AttributeVisibility` is a real Derivation phase with a persisted product**, chosen by the owner
  over the cheaper lookup-delegate precedent that `JudgingContext.Permissions` sets. What declaring a
  `DerivedFactKind` buys is the `0091` whole-run refusal when the answer is absent; what it costs is
  a phase, a store table, `DerivationSchema.Version` 4 to 5, and a re-derive for every sealed
  bundle — and the last of those was free because nothing has shipped. It reads the schema partition
  that is already inside the seal, so it contacts no directory and costs one pass over rows capture
  already took.
- **The visibility answer has four states and none may collapse into another**: readable, withheld,
  not in this forest's schema, and *the schema was never read*. The fourth is not hypothetical —
  `SchemaGuidCatalog.HasCapturedEntries` exists because a run refused the schema partition happens.
- **The confidential branch is unreachable in production and is tested anyway.** Both expiration
  attributes read `searchFlags` 0 in every real forest, so no lab run will ever exercise it. Its
  fixture sets bit 128, and the check was **observed failing** in both directions before it was
  trusted: forced off, three tests failed naming `Confidential` against `Readable`; with Microsoft's
  base-schema exception dropped, two failed the other way.

**What remains:** the About surface — `RuleGuidance` carries no About field yet, so both rules state
their boundaries in `WhyItMatters`, `WhatToDo` and the finding detail — and the inventory's export.

**The LAPS inventory grid was built on 2026-09-03**, as a third view under Assets beside Objects and
Findings, scoped by the same tree selection so one organisational unit can be watched during a
rollout. It reads **sealed evidence**, which is why it cannot be built out of the findings store:
*which machines have modern, which have legacy, which have none* includes the healthy ones, and a
findings store holds only what a rule reported.

It lists **every** computer, including the domain controllers and disabled accounts both rules leave
alone, with a column naming which exclusion applies. That column is the direct answer to the first
`ad.lab` run: two disabled leftover accounts became findings because there was nowhere else in the
product for them to appear.

The four fixes this port owed the predecessor's `v_grid_laps_status` are all in:

- **Both timestamps are shown**, not the one matching the tier the grid assigned — so a migrated
  machine no longer looks like a modern one with nothing else on it.
- **Capability is classified by build number**, through the same `LapsCapability` the rules use, with
  its basis shown beside it, so a bundle sealed before `operatingSystemVersion` was captured says it
  was judged from a name.
- **`DomainControllerSignals` is used once** rather than the predecessor's three different tests in
  one feature.
- The export is deferred until the columns settle, and will state its filter and counts under
  [`0093`](decisions/0093-an-export-states-what-it-contains.md).

**One test is the whole guard against the grid and the rules drifting apart.**
`TheGridAndTheRuleAgreeAboutOneMachine` classifies a Server 2016 machine in the grid, then derives
and judges the same bundle and asserts `SEC-094` stays silent about it. Both answers rest on one
classifier: `LapsCapability` and `DomainControllerSignals` gained raw-value overloads precisely so
the inventory could not re-derive either, and the FILETIME decoder moved into a shared
`LapsTimestamp`.

**A gate was found defective while building it.** The voucher reachability driver called
`SingleOrDefault` on a type's generic arguments and threw *"Sequence contains more than one
element"* on the first read-only dictionary the product declared — failing with a stack trace rather
than a verdict. A gate that crashes on a shape it does not know cannot say *I could not build this*.
It now declines, and builds a keyed collection.

**The Rules tab was built on 2026-09-03**, as a fourth view under Assets, closing `P-118`. It lists
every rule in `RuleCatalogue.All` with what it looks for and what it did to the run being read. The
About text written the same day was reachable only by selecting a finding, so on a forest with
nothing wrong with it the description of what had been checked was on no screen at all.

**What it really adds is a way to tell four silences apart.** A rule that judged everything it was
about and reported nothing, one that could not read a declared attribute, one that failed, and one
that was never scheduled all draw an empty findings grid, and only the first says anything about the
forest. Each row states which in a sentence, and the indeterminate wording names the attribute and
says the result is a floor rather than a total. A rule that found something is marked
established-bad rather than fault: the rule did its job and the forest is what is wrong.

The catalogue is the list and the judgement only annotates it, so a rule the judging never scheduled
still has a row — built the other way round it would simply be absent, and a rule missing from a list
of rules reads as a rule that does not exist. It is deliberately **not scoped by the tree**, because
a rule is a question asked of the whole forest.

**Gate 4 caught a real defect during the build.** Handing the executions back as a bare list removed
the vouching `StoredJudgement` had been providing, so an empty list would have meant either *nobody
judged this bundle* or *the judging stopped before recording anything* with nothing to separate them.
`StoredRuleExecutions` now carries the run's state.

**Gate 4 also refused the first shape of the counts**, which is worth recording because the refusal
was right: a `LapsStateCount` record carrying a bare `int` cannot say whether the listing behind it
was complete. The counts moved onto `LapsPage`, which vouches, and are asked for per state so a
state nothing is in answers zero rather than being absent from a list.

**Step 18 found what 2,866 green tests did not, for the third rule running.** The first `ad.lab` run
produced exactly the predicted counts — 2 `SEC-091` in `ad.lab`, 1 `SEC-094` in `ph.ad.lab`, both
Server 2016 machines silent — and the two `SEC-091` objects were not the machines the specification
predicted. `CN=BADC,CN=Computers,DC=ad,DC=lab` and `CN=PHDC,CN=Computers,DC=ad,DC=lab` carry
`userAccountControl` 4098: workstation trust accounts that are **disabled**, left behind when those
machines were promoted into the child domains. The finding told an operator to deploy Windows LAPS
to machines that do not exist under those accounts.

**The count was right and the reasoning was not**, which is `F-S44-2` in its plainest form and is
the reason step 18 is not optional. Three things followed:

- **The owner excluded disabled computer accounts from both rules**, 2026-09-03. A disabled account
  has no running machine, so there is no local administrator password to rotate and the advice
  cannot be followed. It departs from `SEC-021`, which reports a disabled *user* account, and the
  difference is real: re-enabling a user restores the exposure exactly, while this exposure lives on
  a machine's local security database. Cost, recorded: a machine switched off for a month is
  genuinely unmanaged and is now silent.
- **A claim this repository had made three times was false and is corrected.** `DomainControllerSignals`
  does **not** solve the child-domain trap. It reads three signals off the object in hand, and a
  child controller's parent-domain account carries none of them. What it does solve is the
  predecessor's distinguished-name bug — a controller moved out of its default container — which is
  a narrower claim than the one made here and in both rule documents.
- **`P-120`** — the stale accounts themselves are a real finding of a different kind, and belong to a
  rule that does not exist.

**After the fix, re-judged against the same sealed evidence:** 7 findings where there were 9,
`SEC-091` silent, `SEC-094` still reporting `PHMS1`, both rules judging 14 objects with none
unjudged and nothing unresolved — so the new derivation ran against a real forest. **`SEC-091` now
has no positive case in `ad.lab`**, and a green run there must not be read as confirming it fires;
seeing that needs a planted enabled machine carrying neither timestamp.

**A detail worth keeping.** The rules were offered 14 objects against 11 computers in the forest.
The three extra are group managed service accounts, whose `objectClass` chain contains `computer`.
Both rules test the **most derived** class, so they were excluded — had either asked whether
`computer` was merely present, that would have been three more false findings.

**The inventory grid is the owner's actual goal and it is not a rule.** *Which machines have legacy,
which have modern, which have none* includes the healthy ones, so it cannot come from the findings
store. It reads sealed evidence, which already holds every computer with both timestamps and the OS.
The predecessor had one — `v_grid_laps_status`, with tier, status and expiry health — and it is worth
porting with four fixes: show **both** timestamps rather than only the tier-appropriate one, classify
by build number, use `DomainControllerSignals` once instead of three different domain-controller
tests, and honour the export filter under `0093`.

**A Server 2016 machine carrying a modern timestamp** is an anomaly Microsoft says cannot happen. The
owner asked for it as information not implying risk; `0081` carries no `Info` severity and says
instead that *"the product has other ways to tell an operator a fact about the forest."* It is a grid
state, not a finding.

**The lab holds an untouched positive for both rules** — two unmanaged member servers in `ad.lab`,
and one Server 2022 in `ph.ad.lab` carrying only the legacy timestamp. Nothing needs planting.

**Two things already exist and must be reused rather than rewritten:**

| Need | What already answers it |
|---|---|
| Excluding domain controllers, which the owner chose on 2026-09-02 | `DomainControllerSignals` — three independent signals with their disagreement recorded, used by `SEC-010` and `SEC-011`. It catches a controller moved out of its default container, which is the predecessor's distinguished-name bug. **It does not catch the child-domain case, and this row said it did until the lab run of 2026-09-03 disproved it** — a child domain's controller also holds a computer account in the parent domain, that account carries none of the three signals, and a rule judging one object cannot know the name belongs to a controller elsewhere. What excludes those objects is that they are disabled |
| Seeing what the rules do to a real forest | `securead-cli --library <dir>` then `show-findings.ps1`, one command each |

**Scope, settled by the owner 2026-09-03:** all computers except domain controllers, **clients and
servers reported identically, one severity**. There is no client/server split and no separate rule
for workstations. One consequence: on a real estate the finding count is the count of unmanaged
machines, which during a rollout is most of them — which is why `SEC-091` stays Medium rather than
rising, and why the About text must name what the rule cannot see, particularly passwords backed up
to Microsoft Entra ID, which leave no directory attribute at all.

**`SEC-092` and `SEC-093` are the rest of the family** — rotation stale, and a broad principal able
to decrypt. Both are built. `SEC-093` was expected to need the permission graph and to belong after
stage 5; it does not, because the decryptor is a Group Policy value rather than an access control
entry, and the group expansion it walks arrived with `SEC-090`.

*Detail:* the two specifications under [`docs/layers/judgement/rules/`](layers/judgement/rules/).
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
