# S-31 — The group that is too big

## The state of the tree

Green at 837 tests. **No product code changed in `S-30`** — it was an investigation session, and
its output is [`S-30`](../../history/S-30-coverage-that-measures.md), the slice document to read first. It
carries six findings, a built design for `F-S29-3`, and an answer to `F-S29-6`.

**A lab group of 2,000 members now exists.** `tools\New-LabOversizedGroup.ps1` was run against
`badc.ba.ad.lab` on 2026-08-12, creating `OU=RangeLab,DC=ba,DC=ad,DC=lab` and
`CN=RangeLab-Oversized,OU=RangeLab,DC=ba,DC=ad,DC=lab`. **Verified at exactly 2,000 members** by
reading the group back from the directory. That is the case range retrieval has never met, and it
took a forest to produce. **It is the reason task one comes first.**

That verification also discharges a guard the comparison would otherwise need. The directory side of
`tools\Compare-BundleGroupMembership.ps1` reads membership with `Get-ADGroup -Properties member`,
and had *that* truncated at `MaxValRange` too, the script would be comparing two truncations and
passing. It returned 2,000, so the Active Directory module performs its own range retrieval and the
live side of the comparison is trustworthy. **Do not replace it with a raw `System.DirectoryServices`
search without re-establishing that**, because two silently truncating sides agreeing with each
other is exactly the check-that-cannot-fail this tree keeps producing.

## Before anything: read the records

`S-30` stopped short of building for a stated reason. The five decision records that govern
coverage — [`0002`](../../decisions/0002-absent-view-means-degraded-run.md),
[`0003`](../../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md),
[`0017`](../../decisions/0017-capture-reads-the-whole-forest.md),
[`0027`](../../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) and
[`0035`](../../decisions/0035-coverage-is-recorded-once-per-capture-unit.md) — were read only
through the `S-30` brief's summaries of them. [`README.md`](../README.md) is explicit that a
document summarising a decision is discussion rather than authority.

**Read all five before touching coverage.** If any of them contradicts `S-30`'s design, that is a
finding and the design changes, not the record.

## Task one: what the big group proves

**Costs one command and changes what everything else is worth.** If range retrieval truncates, that
is the highest-severity defect in the product and coverage work waits.

1. **Confirm the lab case is still there.** It was verified at 2,000 on 2026-08-12, but a lab is a
   mutable thing and the OU may have been torn down between sessions:

   ```powershell
   (Get-ADGroup -Server badc.ba.ad.lab `
       -Identity 'CN=RangeLab-Oversized,OU=RangeLab,DC=ba,DC=ad,DC=lab' `
       -Properties member).member.Count
   ```

   Anything at or below 1,500 means the group has been changed or removed, and the whole task is
   measuring nothing. Rebuild it with `tools\New-LabOversizedGroup.ps1 -Confirm:$false` before going
   on.

2. **Capture the forest.**

   ```
   securead --library C:\SecureAD-Runs --controller addc.ad.lab
   ```

3. **Compare the stored membership against the directory's own**, exactly:

   ```powershell
   pwsh tools\Compare-BundleGroupMembership.ps1 `
       -BundlePath C:\SecureAD-Runs\<run directory> `
       -GroupDistinguishedName 'CN=RangeLab-Oversized,OU=RangeLab,DC=ba,DC=ad,DC=lab' `
       -DomainController badc.ba.ad.lab
   ```

**The two ways this task can pass while measuring nothing, and both have precedent in this tree:**

- **A match proves nothing unless the ranged path ran.** Check
  `SELECT naming_context_dn, attribute_blocks_fetched FROM partition_coverage` and require a
  non-zero count on `DC=ba,DC=ad,DC=lab`. Zero means the group came back in one response and range
  retrieval is still unexercised — in which case find out why, because 2,000 exceeds every default.
- **A count comparison is not a comparison.** The script compares distinguished names as sets for
  this reason; do not "simplify" it to a count if it needs editing. `S-30` records that the
  predecessor's range loop had four separate ways to return a prefix of a membership while leaving
  every count consistent.

**Whatever the outcome, this is where the `B20` observations get recorded** — the wire spelling of a
ranged attribute name (`F-S7-37`), whether a controller tolerates a base-scope search between two
pages (`F-S7-39`, on which `S-30` has new evidence from the predecessor), what a client sees when a
paging bookmark is evicted (`F-S7-40`), the credential child-object measurement (`F-S7-26`), and a
controller declining a rung. They have been owed since `S-7` and this is the first run that can
answer them.

## Task two: `F-S30-1`, the false statement

**Do this before the coverage work, not after.** It is the one open finding in the category that is
never deferred: the product tells a customer something that is not true.

`BundleWriter.ResolveParentGuids` derives an object's parent by splitting the distinguished name on
its first comma, in SQL, with no awareness of RFC 2253 escaping. Two consequences, described in full
in [`S-30`](../../history/S-30-coverage-that-measures.md#f-s30-1):

- every forest whose root domain DN has two or more components produces one false
  `unresolved_reference` naming a domain that does not exist
- every object whose name contains a comma — `CN=Smith\, John` — gets a garbage parent, a null
  `parent_guid`, and the same false row, **and is detached from the containment tree**, so control
  over its container produces no edge to it

The fix: use `DnHelper.GetParentDn`, which already exists at
`next/src/SecureAD.Kernel/Naming/DnHelper.cs`, is already correct, and already handles the escaped
form — it was carried over from the predecessor and then not called. Exclude partition roots against
`partition_coverage.naming_context_dn` rather than against the presence of a comma, so the property
the original comment was reaching for actually holds.

**The lab cannot show you this defect.** It has zero objects with a comma in the name, which is why
6,359 objects across five partitions produced no sign of it. A test needs an object named with an
escaped comma, and if you find yourself unable to write one that fails before the fix, say so rather
than declaring the fix verified.

**One consequence to state rather than leave implied:** this removes the only rows anything
currently writes to `unresolved_reference`. `F-S30-2` records that the table's four-value reason
vocabulary has one producer and no classifier, so after this fix the table can never have a row.
Say that plainly in the slice document. Do not add a classifier in this session to avoid the
awkwardness.

## Task three: `F-S29-3`, coverage that measures

**The owner's decision of 2026-08-10 is the authority** and is recorded on the finding in
[`S-29`](../../history/S-29-finishing-the-entry-point.md). `S-30` proposes how, as `D1`, `D2` and `D3`. They
are proposals and not decisions.

- **`D1`** — `PartitionCoverage.IsComplete` becomes `ContinuationReferencesAreComplete`, same value,
  and the column follows. Gate 4 gains one vouch shape, `*AreComplete`, **with its own scanner
  self-test**; `README.md` § Gates requires it and `S-29` found two gates that passed while
  measuring nothing.
- **`D2`** — `EvidenceObject.IsComplete` becomes `Completeness`, an enum derived from the connection
  rung. Today that member reports *cannot say* for every domain object in every bundle — 2,972 of
  6,359 in the lab capture.
- **`D3`** — `RunCoverage` derived from recorded rows rather than asserted, **and three-state**
  following the predecessor's `Full` / `Partial` / `Unknown`. `Unknown` gates identically to
  `Partial` and is named separately because the remedy differs — fix discovery, rather than capture
  more.

**All three are settled and none of them needs re-opening.** `D3`'s three-state extension was
ratified by the owner on 2026-08-12 and carries a `Decision:` line; `D1` is an engineering decision
taken in `S-30`; `D2` is accepted and is flagged there as the weakest of the three, because it is
the one that changes what the evidence says. Build them.

**The trap, restated because it is the whole difficulty.** `PartitionCoverage` is only ever
constructed after a successful read, so any completeness flag defined as *everything it tried to
read, it read* is **true in every bundle forever**. `D2` exists to route around this by measuring
something that genuinely varies — the connection rung, where `Signed` is reachable with no
declaration. If, on building it, that turns out not to vary either, **that is the finding**: say so,
and reopen whether the member should exist, rather than inventing a way to make it look meaningful.

Do not add a check refusing to seal when the derived answer disagrees with the plan. `RunCoverage.Of`
and `CaptureRun` already refuse both directions; `S-29` records a third as deliberately not done and
that still holds.

## Task four: `F-S30-3`, the model that tests the wrong world

`ControllerModel.SupportedControls` advertises paged results and nothing else, so it never suppresses
referrals, so `CaptureRunEndToEndTests` asserts `is_complete=1` on a domain partition while every
real capture produces `0`. The model should advertise the domain-scope control
`1.2.840.113556.1.4.1339`.

**Expect the end-to-end assertion to change value, and treat that as the finding confirmed rather
than as a test to repair.** This is the model range retrieval has also been tested against, so do
task one first and let a real controller tell you what else the model is wrong about.

## What governs it

- [`0002`](../../decisions/0002-absent-view-means-degraded-run.md) — unavailable output is never
  rendered as an empty result and never phrased as a statement about the directory. `F-S30-1` is a
  violation of it and `D3`'s third state exists because of it.
- [`0035`](../../decisions/0035-coverage-is-recorded-once-per-capture-unit.md) — coverage is
  recorded once per capture unit, and everything else is derived from those rows.
- [`0027`](../../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) — the
  only ways coverage varies.
- [`0017`](../../decisions/0017-capture-reads-the-whole-forest.md) — a part of the directory a run
  could not reach is a coverage failure that is stated.
- [`0003`](../../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md) — capture is
  fail-fast, which is what makes the trap above a trap.

## Out of scope

Controller failover (`0040`) and parallel capture (`0041`) — decided, deliberately unbuilt, and the
reason `D3` derives rather than asserts. A classifier for `unresolved_reference.reason` (`F-S30-2`).
Taint propagation from incomplete coverage to results (`F-S30-5`) — it belongs to the read side and
wants a ledger row, not an implementation here. Detecting under-privilege (`F-S30-6`). The read side
(`D`, `E`). The run library catalogue (`F12`–`F16`). A GUI.

## Conventions

- Decisions are stated once, in `docs/decisions/`. Rows and comments cite; they do not paraphrase.
- Mutation-test every new or changed guard in both directions and record which were observed.
- A ledger row is edited with `next/tools/Replace-InventoryRow.ps1`, never by hand.
- After any scripted edit, check `git diff --numstat` — the shell strips a UTF-8 BOM.
- Long PowerShell goes in a script file under `$env:TEMP`, invoked with a short command. Reading a
  bundle needs `e_sqlite3.dll` pre-loaded with `NativeLibrary::Load` before `Batteries_V2.Init()`,
  under `pwsh` rather than Windows PowerShell 5.1. `tools\Compare-BundleGroupMembership.ps1` does
  this already and can be copied from.
- The full suite is minutes, not tens of minutes. A run going well past that has hung; cancel it and
  say so rather than treating it as evidence.

## Housekeeping

Still uncommitted in the working tree from `S-29` and `S-30`:
`next/ad.lab-20260815-010309/`, `next/tools/Read-Bundle.ps1`, `next/tools/row-a7.txt`,
`next/tools/row-a9.txt`, `tmp-bundle-query/`. Move, delete or ignore them. A new bundle from task
one will join them.

The lab OU is torn down with `tools\Remove-LabOuSubtree.ps1` against
`OU=RangeLab,DC=ba,DC=ad,DC=lab` — **but not until task one has produced its answer**, and probably
not at all while range retrieval remains the least-exercised path in the product.

## Finish by

- `F-S29-4` closed against the real 2,000-member group, with the stored membership compared against
  the directory's exactly and `attribute_blocks_fetched` shown to be non-zero — or escalated, if the
  comparison fails
- The `B20` observations recorded in the slice document for this session
- `F-S30-1` closed, with a test that fails before the fix on an object whose name contains an
  escaped comma
- `F-S29-3` closed via `D1`, `D2` and `D3`, each guard mutation-tested in both directions
- `F-S30-3` closed, with the changed end-to-end assertion explained rather than quietly updated
- A slice document, `docs/next/S-31-the-group-that-is-too-big.md`
