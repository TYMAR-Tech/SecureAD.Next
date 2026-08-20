# S-32 — The files behind the policies

## The state of the tree

Green at 852 tests. `S-31` is closed and committed at `04fb7cf6`; its slice document is
[`S-31`](../../history/S-31-the-group-that-is-too-big.md) and it is worth reading for `D3` and `F-S31-5`, both
of which bear on this session.

**Read [`0042`](../../decisions/0042-dns-zones-and-records-are-out-of-scope.md) first.** It was
written at the end of `S-31` and it is the closest precedent for what this session has to decide: a
part of the directory the product does not read, why, and how the evidence says so.

## What this session is for

Six rules in the catalogue — SEC-064, SEC-065, SEC-066, SEC-082, SEC-083, SEC-093 — have no possible
source of evidence, because Group Policy settings live in files on the SYSVOL share and nothing
reads them. That is `F-S23-5`, and roughly a tenth of the catalogue is inert because of it. A
customer whose Group Policy grants `SeDebugPrivilege` to Domain Users gets no finding and no
statement that nothing was looked for.

Ledger rows **B14** (SYSVOL & Group Policy capture), **B15** (the file-access seam) and **B16** (the
parsers).

## What the owner has already decided

Taken 2026-08-13, in discussion. **These are answers, not proposals.**

1. **A SYSVOL failure does not fail the run.** The reasoning is the owner's and it is a fact about
   deployments rather than about code: SYSVOL is a file share, and permission problems on it are far
   more likely than on LDAP. A run that dies because one GPO folder out of four hundred could not be
   read would be unusable in the field.
2. **Alternate credentials are not supported.** The predecessor's `SmbSysvolFileReader` establishes
   an authenticated share connection with `WNetAddConnection2` and holds a `NetworkCredential` in
   memory. All of that comes out. The run uses the token it has, consistent with
   [`0039`](../../decisions/0039-one-way-to-start-a-capture.md).
3. **How much of a GPO's DACL to capture is not settled**, and the owner has said explicitly that it
   wants a deeper discussion. **Do not decide it and do not build to a guess.** The predecessor reads
   the GPO root folder's descriptor and nothing below it; that is a starting point for the
   conversation, not an answer.

## The consequence of decision 1, which nobody has stated yet

**This is the first exception to fail-fast, and it should be raised before anything is built.**

[`0003`](../../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md) makes capture
fail-fast, and `S-31`'s `D3` established what follows from that: a bundle exists only when
everything was read, so the run-level verdict is `Full` in every bundle a reader can open, and
`RunCoverage.AllDeclaredUnitsAreComplete` is an internal consistency check rather than a measurement.
`UnreadOutcomeIsUnreachableTests` holds that invariant.

A SYSVOL read that fails without failing the run means **a sealed bundle can now be missing evidence
it tried to collect** — which is the state `D3` proved unreachable, arriving through a different
door.

That is not a reason to reverse the owner's decision, which is well founded. It is a reason to be
precise about three things before writing code:

- **Whether the invariant `D3` established still holds.** It is about naming contexts and domains,
  and SYSVOL is neither, so it probably survives untouched. **Check it rather than assume it**, and
  say which.
- **How a partial SYSVOL read is recorded**, so that a reader can tell "this GPO's settings are not
  in the bundle" from "this GPO has no settings" — the distinction
  [`0002`](../../decisions/0002-absent-view-means-degraded-run.md) exists to protect, and the same
  one `F-S31-5` was raised about. `unread_partition` is the nearest precedent for the shape.
- **Whether this needs a decision record.** It is an exception to `0003` in spirit if not in letter,
  and `0003` does not currently admit one. A record here would be short and would stop a later
  session reading the exception as a bug.

## What ports, and what does not

Verified by reading the predecessor in `S-31`, not assumed.

**Ports nearly as-is — the bulk of it.** Four parsers, pure functions over bytes, with no directory,
database or network dependency, carrying roughly 840 lines of tests:

- `src/SecureAD.Core/GroupPolicy/RegistryPolicyParser.cs` — `Registry.pol`
- `src/SecureAD.Core/GroupPolicy/SecurityTemplateParser.cs` — `GptTmpl.inf`
- `src/SecureAD.Core/GroupPolicy/GroupPolicyPreferenceParser.cs` — the cpassword scan, which
  **does** have a consumer: SEC-083, and SEC-126 mentions it
- `src/SecureAD.Core/GroupPolicy/GpoClientSideExtensions.cs` — reads `gPCMachineExtensionNames` so
  only the GPOs worth fetching are fetched

**Already done.** The new catalogue reads `gPCFileSysPath` and `gPCMachineExtensionNames` for
`groupPolicyContainer` objects, so the LDAP half of finding a GPO's files is built and tested.

**Ports with the credential mechanism removed.** `SmbSysvolFileReader` and the `ISysvolFileReader`
seam. The seam is good and its value is proven: it is what lets the capture module be tested without
a network. Keep it.

**Does not port — new work against the new conventions:**

- **The writers.** `SysvolSettingWriter` and `SysvolAceWriter` target `dim_gpo_setting` and
  `fact_sysvol_ace`, which do not exist here, and they take a raw `SqliteConnection` and run their
  own transactions. This product has one write path, `BundleWriter`.
- **The coverage record.** The predecessor produces coverage per module per domain.
  [`0035`](../../decisions/0035-coverage-is-recorded-once-per-capture-unit.md) records coverage once
  per capture unit — one naming context on one controller — and **SYSVOL is not a naming context.**
  Where its coverage lives is an open question governed by `0035`, and it is the same question
  `F-S31-5` answered for unread partitions.
- **The failure behaviour**, per the owner's decision above.

## The trap this session is most likely to fall into

`S-30` proposed a completeness member that could only ever say one thing, and `S-31` reintroduced a
value nothing wrote within an hour of removing two of them. Both were caught by the same test:
**does the thing have a reachable state in which it says the other answer, and is there a test that
reaches it?**

Apply it to every value this session adds, and in particular to the SYSVOL coverage record. A record
that says "read" in every bundle is worth nothing, and **this is the one place in the product where
partial coverage is genuinely expected**, so it is the one place the record can be made to matter.

## Out of scope

The GPO DACL depth question, until the owner has had the discussion he asked for. The read side
(`C16`–`C28`) and the GUI, which follow this session. Certificate services. The unresolved-reference
classifier (`F-S30-2`). Diagnostics and the three remaining `B20` observations, which are waiting on
logging wanted for its own reasons.

## Conventions

- Decisions are stated once, in `docs/decisions/`. Rows and comments cite; they do not paraphrase.
- Mutation-test every new or changed guard in both directions and record which were observed.
- A ledger row is edited with `next/tools/Replace-InventoryRow.ps1`, never by hand.
- After any scripted edit, check `git diff --numstat` — the shell strips a UTF-8 BOM.
- Long PowerShell goes in a script file under `$env:TEMP`, invoked with a short command.
- The full suite is minutes, not tens of minutes. A run going well past that has hung; cancel it and
  say so rather than treating it as evidence.

## Finish by

- The four parsers ported with their tests, and the seam with the credential mechanism removed
- SYSVOL settings and the GPO folder DACL written through `BundleWriter` into tables designed under
  `0035`, not carried over from the predecessor's schema
- A SYSVOL coverage record with a reachable failed state and a test that reaches it
- The fail-fast exception either shown not to conflict with `D3`'s invariant, or recorded as a
  decision
- The six inert rules named, with what the product should say when Group Policy was not assessed —
  `F-S23-5` records that wording as owed to this row
- A slice document, `docs/next/S-32-the-files-behind-the-policies.md`

## Housekeeping

Untracked and deliberately not committed: `next/ad.lab-20260815-010309/` (a captured bundle),
`tmp-bundle-query/`, `next/tools/row-a7.txt`, `next/tools/row-a9.txt`, and
`next/tools/Read-Bundle.ps1` — the last of which is a tool from `S-30` that nobody has run or
reviewed. Either exercise it and commit it, or delete it; a verification tool nobody has run is the
thing `S-31` spent an afternoon on.
