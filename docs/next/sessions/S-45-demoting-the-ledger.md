# S-45 — Demoting the ledger, and making the README tell the truth

Produces: a renamed predecessor inventory, a reworked guard over it, and a corrected
[`docs/next/README.md`](../README.md). Governing records: none new expected — this session changes
documentation and test bindings, and decides nothing about what the product does.

**This is step 7 of [`S-43`](../../history/S-43-the-documentation-transition.md), the last one
outstanding.** Step 5 was finished during [`S-44`](S-44-the-questions-only-the-owner-can-answer.md):
the surface register is keyed to areas, all nineteen area files exist, and the whole
`SecureAD.Next.sln` suite passes at 1152 tests.

## Why this session exists

**`S-43` predicted this would be mechanical. It is not, and that is the whole reason it is its own
session.** Its words: *"By this point nothing in the build depends on it and the edit is mechanical.
It only looks like the hard part."*

Four test surfaces still read the columns being dropped, found on 2026-08-16:

- `OldAppInventory.Columns`, `OldAppInventory.Disposition()` and `OldAppInventory.LedgerStatuses()`
- `InventoryCompletenessTests.EveryLedgerRowDeclaresADisposition`
- three documentation tests — `CapturedAttributeCatalogDocumentationTests`,
  `PermissionClassificationDocumentationTests` and `SchemaGuidDocumentationTests` — which call
  `LedgerStatuses().Keys` for one purpose only: to prove a row they cite is real

So the work removes an existing guard and changes what three documentation tests rest on. That is
test surgery across a 256-row table, not a mechanical edit.

**The README is the more urgent half.** It is the file a session reads to orient, and it now
describes an arrangement that no longer exists.

## What is already decided, so the session does not re-argue it

Both settled with the owner on 2026-08-16.

- **The file is renamed**, not merely retitled. Thirty-one files reference `PORT-LEDGER.md`, eleven
  of them in `docs/history/`. Updating a link inside a history document is acceptable: the owner is
  the sole developer and his position is that preserved narrative history is not worth protecting for
  its own sake. Decision records in `docs/decisions/` are untouched by this — they state the
  product's position, not its history.
- **The disposition guard is replaced by a shape guard**: every row carries an identifier, a working
  link to the map, and an area tag. It asserts the file is well-formed and navigable, and says
  nothing about work being owed.

  The reasoning, so it is not re-opened: the ledger still has one live job — three documentation
  tests use its row list to prove a cited row exists. With nothing holding the file's shape, a row
  can silently become malformed, drop out of that list, and fail nothing. A document citing it would
  then be checked against a list no longer containing it. That is *passes while measuring nothing*,
  arriving by neglect. The area tag is held for the same reason: it is what makes the inventory
  navigable, and nothing enforces that a row keeps one.

## Scope

**In.**

1. **Drop four columns from all 256 rows** — Disposition, Lands in, Status, Docs. These are what make
   a row read as owed.
2. **Rename the file** for what it is: an inventory of the predecessor. Update all thirty-one
   referencing files, including `.github/copilot-instructions.md`.
3. **Rework the test surface.** `OldAppInventory`'s column list and accessors; replace
   `EveryLedgerRowDeclaresADisposition` with the shape guard; rebind the three documentation tests so
   they ask *"is this a real row"* without going through a status they no longer need.
4. **Correct [`docs/next/README.md`](../README.md).** Four faults, all found 2026-08-16:
   - **The orientation table has no row for [`docs/areas/`](../../areas/README.md)**, and sends a
     reader to the ledger for *"What is built, what is left?"* — the exact framing `S-43` existed to
     end, and the habit that produced the preflight wizard.
   - **Gate 5a's description is false.** It says every public type names *"the ledger row expected to
     consume it. An entry that outlives that row fails the build."* Neither clause holds since
     `S-44`; the register names an area.
   - **`next/` has no entry point** appears four times under `docs/`. It stopped being true when the
     shell shipped. `S-43` recorded this and fixed one instance.
   - **Gate 5b's status reads "blocked — needs a runnable entry point."** The entry point exists.
     What blocks 5b now is that nothing traces reachability, which is a different sentence.
5. **Rewrite § The ledger** in that README for the file's new shape and job.

**Out, deliberately.**

- **Any product change.** Nothing here touches what the product does.
- **Gate 5b itself.** Correcting its stated status is in; building the reachability trace is not.
- **The catalogue work `0065` requires.** That is its own session and it is the one with a one-way
  door — every run taken before it lands is permanently silent on those attributes.
- **The reconciliation fixture for `F-S44-2`.** Related, and its own piece of work.

## Where this starts

- [`docs/areas/README.md`](../../areas/README.md) — nineteen areas, all written.
- [`.github/copilot-instructions.md`](../../../.github/copilot-instructions.md) § *Orient before
  proposing anything*.
- [`S-43`](../../history/S-43-the-documentation-transition.md) — what was enforced, and step 7's
  original wording.

**A note on searching this repository.** `git grep` and `git ls-files` are the only searches to
trust here; the built-in file search returns empty results for tracked files under `docs/`.

**A note on scripted edits.** `S-44` corrupted the surface register twice with PowerShell — once by
double-encoding the whole file, once by mangling em-dashes out of a script's own string literals.
Read and write with an explicit `UTF8Encoding($false)`, and check `git diff --numstat` and for
mojibake after every scripted edit.

## Rules

- **Mutation-test the shape guard in both directions**, revert in a `finally`, and record the
  directions observed in the test's own doc comment. `S-43` corrupted the ledger when a script died
  between mutating and reverting.
- **The shape guard carries a scanner self-test**, per `§ Gates` of [`docs/next/README.md`](../README.md).
  A guard that passes against an empty scan is the failure this repository has hit twice.
- **No golden value or frozen fixture is edited.** If one needs changing, that is a finding and the
  work stops.
- **Every claim removed from the README is removed because it is false**, not because it is
  inconvenient. Where a sentence is corrected, say what changed, per
  [`0032`](../../decisions/0032-a-decision-record-is-corrected-in-place.md).

## Finish by

- No row in the inventory reads as work owed, and nothing in the build depends on a status column.
- The shape guard passes, carries its self-test, and has been mutation-tested both ways with the
  directions recorded.
- The README's orientation table names `docs/areas/` first, and none of its four false claims
  survives.
- The solution builds and the whole `SecureAD.Next.sln` suite passes.
- **A session reading only the README and one area file is pointed at the truth, with nothing left
  telling it the ledger is a plan.**

## Findings

### F-S45-1 — the attribute catalogue's decay guard is gone, and fifty forecasts are unattended

**Severity: medium. Status: open, handed to the catalogue session `0065` owes.**

`CapturedAttributeCatalogDocumentationTests.NoAttributeStillWaitsForALedgerRowThatIsFinished` read
the ledger's `Status` column and failed when a forecast row reached `Done`. An entry saying *"nothing
reads this yet, and B20 will"* therefore had an expiry date on it: when B20 finished, the build
stopped until somebody said whether the attribute was genuinely read or should come off the capture
list.

Dropping the `Status` column removed that clock. The guard could not be left as it was — with no row
ever `Done`, nothing would ever fall due and it would have passed forever while measuring nothing,
which is the first category of stop-the-work defect.

**Re-anchoring it to the area files was attempted and rejected.** The area file is what now records
that work has landed, so it looked like the natural replacement. It is too coarse: fifty forecasts
exist, and all but those naming `E19` and `J33` point at rows whose area — `who-is-who`,
`running-a-capture`, `what-a-permission-means`, `group-policy` — has already been reached. The guard
would have gone red on nearly its whole surface, and exempting them would have left an allowlist
covering almost everything, which is the same defect wearing a different hat.

**Decision, taken with the owner on 2026-08-16: the guard is removed rather than re-anchored.** It
measured a scheduled finish date, and the work is no longer scheduled. A subject is chosen, this
catalogue and the predecessor's documentation are read as research, and what the attribute is for is
settled in that conversation. Under that process **an attribute nothing reads yet is the expected
state**, not a defect, and a check firing on it reports a fault that is not one.

**What is now unattended.** Fifty attribute-and-row pairs carry a forecast that nothing will ever
make anybody revisit:

| Forecast row | Attributes naming it |
|---|---|
| `B11` | `distinguishedName`, `groupType`, `member`, `memberOf`, `primaryGroupID` |
| `B12` | `objectSid`, `sAMAccountName`, `sIDHistory` |
| `B20` | `distinguishedName`, `gPCFileSysPath`, `gPCMachineExtensionNames`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-GroupMSAMembership`, `nTSecurityDescriptor`, `objectCategory`, `objectClass`, `objectGUID` |
| `D3` | `appliesTo`, `attributeSecurityGUID`, `cn`, `displayName`, `isSingleValued`, `lDAPDisplayName`, `rightsGuid`, `schemaIDGUID`, `searchFlags`, `systemFlags`, `validAccesses` |
| `E19` | `adminCount`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-AllowedToDelegateTo`, `msDS-GroupMSAMembership`, `msDS-KeyCredentialLink`, `msDS-SupportedEncryptionTypes`, `pwdLastSet`, `sAMAccountName`, `servicePrincipalName`, `sIDHistory`, `userAccountControl` |
| `E20` | `groupType` |
| `E21` | `displayName`, `flags`, `gPLink`, `gPOptions`, `versionNumber` |
| `J33` | `nTSecurityDescriptor`, `rightsGuid`, `schemaIDGUID`, `userAccountControl` |

Most are probably read already — `objectSid` and `nTSecurityDescriptor` would be surprising
omissions. *Probably* is the finding. Each needs checking against the code, and that is the
catalogue session's work, not this one's.

**The larger gap, named here so it is not mistaken for this one.** The guard removed above policed
one direction: *does every attribute we capture have a consumer?* That catches waste. Nothing
policies the opposite: *does everything that needs an attribute find it captured?* That catches an
audit that is silently incomplete, and it cannot be repaired after a run — a bundle captured without
an attribute cannot gain it. It is owed by row `E16`, recorded as `F-S7-24`, and `F-S44-2` is it
having already happened: three sound test suites agreeing with each other while fifteen attributes
the predecessor captured were absent.

**That direction is the one worth building next, and it is worth more than the fifty rows above.**
Its anchor cannot be this catalogue or the area files, because both are internal; it has to be what
the predecessor actually captured, which is what
[`WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md) exists to hold.
