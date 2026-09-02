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
| 14 | Add the public types to `SURFACE-REGISTER.md` and the layer document table | `SurfaceRegisterTests`, `TypesTableOwnershipTests` |
| 15 | If you added a layer document, list it in `SecureAD.Next.sln` | `LayerDocumentGateTests` |
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
