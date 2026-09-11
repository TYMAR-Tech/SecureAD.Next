# Building a rule

**What a new rule owes, in order, and which of those debts a test collects.** Written 2026-09-02
after `SEC-027`, where a third of the effort went on discovering these by tripping over them one at a
time.

This is a working document, not a product position. Nothing here overrides a record in
[`docs/decisions/`](../../decisions/).

---

## The order that avoids rework

| # | Step | Held by |
|---|---|---|
| 1 | **Research it against Microsoft first**, through the Learn tools, reading the pages in full | nothing — and it is still the step to skip last |
| 2 | **Write the rule document** under `docs/layers/judgement/rules/`, citing Microsoft for every Active Directory claim | nothing |
| 3 | **Ask the owner the product questions** the document raised, before any code | nothing |
| 4 | Add the evidence record to `SecureAD.Evidence/Findings/` | — |
| 5 | Add a table to `JudgementSchema`, and raise `JudgementSchema.Version` | — |
| 6 | Add the writer case to `JudgementWriter.WriteFindingEvidence` | throws by default on an unknown kind |
| 7 | Add the reader case to `JudgementReader.ReadFinding`, discriminating on a **non-nullable** column | `EvidenceKindCoverageTests` |
| 8 | **Add a sample to `EvidenceKindCoverageTests.Samples`** | `EveryEvidenceKindHasASample` |
| 9 | Write the rule as an `IRule` in `SecureAD.Judgement` | — |
| 10 | Register it in `RuleCatalogue.All` | — |
| 11 | Add its `RuleGuidanceCatalogue` entry | `RuleGuidanceTests`, both directions |
| 12 | Write the rule's own tests, with negative controls | — |
| 13 | Mutate the rule in both directions and record what failed | nothing |
| 16 | Update `docs/ROADMAP.md`; add anything deferred to `PUNCH-LIST.md` | `PunchListIdentifierTests` |
| 17 | Full suite, and `next/tools/check-document-encoding.ps1` — the count must not rise | — |
| 18 | **Run it against `ad.lab` before calling it done** | nothing, and it is the step that catches what the tests cannot |

## Running it against a real forest

**One command does the whole audit**, added 2026-09-02:

```
securead-cli --library C:\Users\ba.admin\SecureAD-Runs      # capture, derive, judge
securead-cli --judge <bundle>                               # re-judge sealed evidence, no re-capture
pwsh -File next\tools\show-findings.ps1 -BundlePath <bundle>
```

`--judge` is the one to reach for after fixing a rule: it runs the corrected logic against evidence
already sealed, so a verification loop costs seconds rather than a re-read of the forest.

**Read the forest's own state as well as the findings.** `count-uac-flag.ps1` and
`list-sid-history.ps1` open sealed evidence directly, so *the forest is clean* can be told from *the
rule is broken*. **A reading script that has only ever returned zero proves nothing** — point it at
something known to be present first. `count-uac-flag.ps1` has been seen returning seven rows;
`list-sid-history.ps1` has not, and `SEC-027` §12 says so.

**Plant with `Set-LabAccountFlags.ps1` and remove with `-Remove`**, then confirm the removal by
re-reading the directory. One of the accounts it creates is a real Domain Admins member while it
exists.

---

## What is deliberately planted in `ad.lab` right now

**Read this before treating anything below as a defect.** The owner's decision of 2026-09-03 is that
these stay in place until the rules are built, so that one large verification can be run over all of
them at the end rather than planting and unplanting per rule. **A capture of `ad.lab` therefore
contains findings that are supposed to be there**, and a session that does not know this will read
them as a broken rule, a broken capture, or a compromised forest.

| Planted | By | What it is for |
|---|---|---|
| `SecureADLapsReaders` → `SecureADLapsMid` → `Domain Users`, with a scoped LAPS read delegation on `OU=Workstations,OU=BA Lab` | `Set-LabLapsDelegation.ps1` | SEC-090's nested path. Expect a High finding on every computer in that unit naming `Domain Users` at depth two |
| `SecureADCycleTest-A` containing itself | `Test-LabOpenQuestions.ps1` | Active Directory permits a direct self-loop, measured 2026-09-03. It is **not** reported as a cycle, because the expander keeps a component only when it holds more than one principal |
| `SecureADCycleTest-A → B → C → A`, with `SecureADCycleTest-U` in `C` | `Test-LabOpenQuestions.ps1` | A real membership cycle for the unbuilt cycle rule, and the measurement that a member of one group in a loop carries every group's SID |
| `SecureADTakeoverOuter` → `SecureADTakeoverInner` → `Domain Users`, holding **WriteDacl and WriteOwner** on `OU=SecureADTakeoverTarget,OU=BA Lab` | `Set-LabOwnershipAndTakeover.ps1` | SEC-060's nested takeover path. Expect one High finding on that unit naming `Domain Users` at depth two, reporting **WriteDacl** — both rights are granted deliberately, so a rule reporting the weaker one is visible |
| `SecureADProtObject`, **a real member of `Backup Operators`**, owned by `SecureADPlainOwner` | `Set-LabOwnershipAndTakeover.ps1` | SEC-032's positive, and the proof that SEC-031 and SEC-032 do not both report one object. Expect one High SEC-032 finding and **no** SEC-031 finding for it |

**`SecureADProtObject` holds Backup Operators membership while it exists**, which is a real privilege
grant in the lab. It is the least powerful of the protected groups and nothing here touches Domain
Admins, but it is the most consequential thing currently planted and `-Remove` is what takes it out.

**Its owner may not stay where it was put.** `F-S45-7` records the open question: `AdminSDHolder`
appears to reset the *owner* of a protected object, not only its permissions. If so, this plant
decays within the hour and a capture taken later will not show the SEC-032 condition at all — so a
session finding no SEC-032 finding here should re-plant before concluding anything.

**Everything planted carries a `SecureAD` prefix**, and all three scripts refuse to delete anything
without it. `-Remove` on each returns the lab to clean.

**Two findings in `ad.lab` are *not* planted and are real**: `BAWK1` and `BAMS1` grant `Everyone`
read of the LAPS password through an entry carrying no object type. Those were there before any of
this and are the estate's own.

**Eight `SEC-031` findings are also real and are not planted.** Every machine carries a
`serviceConnectionPoint` named *Windows Virtual Machine* which the machine account itself owns,
because the machine created it. That is ordinary Active Directory behaviour and a true finding, not
lab residue.

---

## Why step 18 found three defects in one afternoon

**On 2026-09-05 three rules were built, registered, documented, covered by thirty-six of their own
tests, and committed — and all three were reporting nothing.** The suite was green at 3,139
throughout. Every one of the following was found by running against `ad.lab` and by nothing else:

| Defect | What it looked like | Why no test could catch it |
|---|---|---|
| `F-S45-4` | All three rules judged **zero** of 8,378 objects | They declare no subject class to mean *every object*, and an empty list matched nothing. Every rule test calls `Judge` directly, so none reaches the question of whether an object would be offered |
| `F-S45-5` | Both ownership rules refused **every computer** in the forest | A reader queried a table name that does not exist, and the guard above it turned the failure into *the forest setting was never read* — a refusal that looks like correct caution |
| `F-S45-6` | `SEC-032` could not fire at all | It read `objectSid` as text where the directory stores bytes, so every object looked like it had no identifier and was treated as unprotected |

**All three were wrapped in correct-sounding comments**, which is why review would not have caught
them either. The reasoning beside `F-S45-6` — that an organizational unit legitimately has no
identifier, so absence is an answer rather than a gap — is true, and it made the defect look
deliberate.

**Two lessons worth carrying, and both now have a guard.**

- **`show-findings.ps1` cannot tell a clean rule from a dead one.** It lists findings, so zero reads
  the same either way. **The judging summary now names any rule that examined no objects**, and
  `RuleApplicabilityTests.EveryRuleInTheCatalogueIsAboutSomething` fails the build for a rule that is
  about nothing before it ever reaches a forest. Both were mutation-tested against the original
  defect: the gate names all three rules, and the summary prints
  *"WARNING: SEC-032 examined no objects at all"*.
- **A rule that has never been observed firing has not been verified.** Both `SEC-060` and
  `SEC-032` returned zero honestly — the forest really held no such condition — and both were
  broken. Planting a positive is what proved them, and it is what found `F-S45-6`. **No guard
  replaces this one**: a rule can be about the right objects, be offered all of them, and still be
  wrong about every one.

---

---

## Why step 18 is not optional

**On 2026-09-02 the forest found a Critical false finding that 2,819 green tests did not.** `SEC-021`
reported every domain's `krbtgt` at Critical, advising the operator to remove its service name or
replace it with a group managed service account — both impossible, and either would break Kerberos
for the domain.

The rule document had asserted that `krbtgt` carries no `servicePrincipalName`. It carries
`kadmin/changepw` by default. **Twelve tests passed because the tests and the rule were written from
the same wrong belief about Active Directory.** No amount of internal coverage could have caught it;
this is `F-S44-2` again, in the form that survives having an external anchor for the *values* while
the *premise* goes unchecked.

**The lesson, stated as a rule: any claim a document makes about what Active Directory contains is a
claim to check against Active Directory, not against the code.** "This attribute is never present
on X" is exactly the shape that hides.

---

## Mutations are run one at a time

Recorded 2026-09-02 after two simultaneous mutations masked one another while building `SEC-028`:
with the flag constant wrong, the trust-exclusion test passed, because the mutated flag never matched
the fixture so the exclusion was never reached. **A mutation that another mutation makes unreachable
proves nothing about the test.**

**Step 8 is the one that used to be missed, and it is the expensive one to miss.** `P-112` was a
finding's evidence read by column position from two queries with different column lists, and it
survived a month because every paging test wrote one evidence kind. Adding `SEC-027` nearly repeated
it exactly. The sample registry is now found by reflection over the production assembly, so a new
evidence kind fails the build the moment it is declared.

---

## What trips people, in the order it tripped me

**Gate 4 refuses a bare collection or a bare count from a type that cannot say whether it looked.**
If a rule needs to read several values off an attribute, the reader returns a *vouched* type — see
`SidReading`, which carries the count of values that failed to decode beside the values that did.
Finding this late meant rewriting the rule's inputs after its tests were written. Decide it at step 4.

**A compiled table of constants belongs in its own type.** `PrivilegedSidCatalogue` is separate from
`PrivilegedSidHistory` because gate 4's exemption is granted per type, and exempting the rule would
have exempted its judging. `GpoClientSideExtensionCatalog` was split out of `GpoClientSideExtensions`
in August for the same reason.

**A new public boolean voucher moves a census.** `VouchedValueReachabilityGateTests` pins how many
`IsComplete`-shaped members the product has, with a paragraph per change. Two new ones cost two lines
there.

**Absent and unreadable are different, and both differ from clean.** For any attribute most objects
do not carry, absence is the ordinary case and must not be reported as an unread input — or the rule
names a missing input against nearly every object in the forest, which reads as a broken capture. A
value that was present and could not be decoded is the opposite: it must never be silently skipped.
`SEC-027` §9 is the worked example, with a negative control for each.

**The long documents are single-line table rows, and mid-line edits break them.** `PUNCH-LIST.md`
was corrupted twice in one session by replacements that began in the middle of a row. Edit those
files at line boundaries only.

**Never read a file with `Get-Content -Raw`.** On Windows PowerShell 5.1 that decodes with the system
codepage and every em dash comes back wrong; a scripted edit double-encoded a test file this way on
2026-09-02, the same day the instruction warning against it was read. Use
`[System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8)` and write with
`New-Object System.Text.UTF8Encoding $false`.

---

## What a rule must be able to say

Both from `.github/copilot-instructions.md`, and neither is negotiable:

- **What it looks for, and what the organisation running the audit can thereby mitigate.** A rule
  that cannot be explained in those terms does not go in.
- **What it does *not* look for**, when it reports a subset. That belongs in the rule's About text
  and its guidance, not only in a document a reviewer reads — see
  [`WHAT-THE-PRODUCT-IS.md`](../../WHAT-THE-PRODUCT-IS.md), *Every rule gets an About section*.
  `SEC-027` §6 is the first worked example: it ranks only the identifiers Microsoft documents, and
  says so where an operator will see it.

**Guidance states an action and what it may break. It never states that the customer is then safe** —
`RuleGuidanceTests` rejects thirteen phrasings and carries a self-test.

---

## Anchoring, when there is nothing to port

`F-S44-2`: a set of checks that agree with each other proves only internal consistency. A rule with
no card and no predecessor has **no internal anchor**, and no amount of test coverage supplies one.

`SEC-027` is the worked example, and it earned it on the first run: the built-in groups were written
as domain-relative identifiers, so `S-1-5-21-<any domain>-544` would have been reported as the
built-in Administrators group. **Every positive test passed**, because the rule and its tests shared
the mistake. Only the check that left the repository — every identifier the rule names must resolve in
`WellKnownSidCatalog`, which is transcribed from MS-DTYP — disagreed.

**So: whenever a rule names a constant, a name, or a threshold, one test must check it against
something outside this repository.**
