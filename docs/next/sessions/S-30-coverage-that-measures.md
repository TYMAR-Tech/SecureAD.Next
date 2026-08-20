# S-30 — Coverage that measures, and the group that is too big

## The state of the tree

Green at 837 tests. [`S-29`](../../history/S-29-finishing-the-entry-point.md) is the slice document to read
first; it carries six findings and three are still open.

**What now exists and works.** An operator names one controller and a run library root and gets a
sealed bundle:

```
securead --library C:\SecureAD-Runs --controller addc.ad.lab [--validate]
```

Verified against a live forest on 2026-08-10 — one empty root domain and two children, 6,359
objects, 12,551 access control entries, 362 distinct descriptors, five partitions, five seconds,
every one read over `SignedAndSealed`. Ledger rows `A7` and `A9` are `Done`.

**Read `S-29`'s section "The pattern this session is really about" before anything else.** Four of
its six findings are the same shape — a check that cannot fail, in a world containing no failing
case — and three of those were invisible until the product met a real directory. This session's two
tasks are both in that family.

## Task one: `F-S29-3`, coverage that measures rather than asserts

**Decided by the owner on 2026-08-10 and recorded as a `Decision:` line on the finding.** The
decision is the authority; this is a summary and does not restate it.

Today a bundle answers "was `ba.ad.lab` fully read?" twice and differently. `domain_coverage` says
`Read` and `bundle.coverage_is_complete` is 1; `partition_coverage.is_complete` says 0, for all
three domains. Neither row is false. They mean different things and nothing says which.

Two parts to build:

1. **`PartitionCoverage.IsComplete` stops meaning `!ReferralsSuppressed`.** Referral suppression is
   a deliberate setting, not a completeness question, and it is always on for a domain partition —
   so that flag reads 0 for every domain in every capture that will ever run. The suppression itself
   stays on the row, because an empty continuation-reference list means *nothing lies below* only
   when referrals were not suppressed.
2. **`RunCoverage` is derived from what capture recorded, never asserted.** `CaptureRun` currently
   marks every declared domain `Read` on the reasoning that fail-fast means a failure never reaches
   the seal. That is a belief about control flow rather than a measurement, and
   [`0040`](../../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md) and
   [`0041`](../../decisions/0041-capture-reads-domains-in-parallel.md) are both decided, unbuilt,
   and each introduces the case the belief cannot survive.

**The trap, and it is the whole difficulty of this task.** `PartitionCoverage` is only ever
constructed when a partition was read successfully. Redefine completeness carelessly and the flag
becomes **true in every bundle forever** — a flag that is always false replaced by one that is
always true, which is not a fix. **Whatever the new definition is, there must be a reachable state
in which it is false, and a test that reaches it.** If no such state exists, that is the finding:
say so, and consider whether the flag should exist at all rather than inventing a way to make it
look meaningful.

Do not add a third check refusing to seal on disagreement. `RunCoverage.Of` already refuses a
declared domain with no outcome and `CaptureRun` already refuses a plan that does not cover the
declaration; a third could not fire. `S-29` records that as deliberately not done.

## Task two: `F-S29-4`, the group that is too big

**This is the highest-value item outstanding, and it is the last place in capture where the product
can be quietly wrong rather than loudly wrong.**

Range retrieval has never run. Not against the model, not against a directory. The lab's largest
group has eight members, so `attribute_blocks_fetched` was 0 on all five partitions of the real
capture. `AttributeRange`, `LdapEntryReader.Continue` and the whole ranged path are exercised only
by tests built from Microsoft's articles.

If that path is wrong, a group larger than the controller's `MaxValRange` — 1,500 by default — has a
**prefix of its membership stored as its membership**. Nothing downstream can tell. A privileged
group whose dangerous members fall outside the first block is a finding this product silently fails
to report.

What is needed:

1. **A script that builds the case**: enough accounts in the lab and a group holding more than 1,500
   of them. The owner runs it; hand him the exact commands. Two thousand is a better number than
   1,501, because it proves a second block and a final one rather than only a boundary.
2. **A capture against it.**
3. **A comparison that would fail if the membership were truncated** — the stored member list
   against the directory's own, exactly, not by count alone. A count check passes against a
   truncation that happens to land on a round number, and this repository has enough checks that
   cannot fail.

Five observations are owed against `B20` and become reachable here: the wire spelling of a ranged
attribute name (`F-S7-37`), whether a controller tolerates a base-scope search between two pages
(`F-S7-39`), what a client sees when a paging bookmark is evicted (`F-S7-40`), the credential
child-object measurement (`F-S7-26`), and a controller declining a rung.

## Task three, small: `F-S29-6`

The real capture produced exactly one `unresolved_reference` with reason `DomainNotCaptured`, in a
forest where all three declared domains were read in full. Either something references a principal
outside the forest — a foreign security principal or a trust, which would make the row correct — or
the reason is being attributed wrongly, in which case a real gap is labelled as an expected one. One
query settles it. **Do not guess which.**

## What governs it

- [`0002`](../../decisions/0002-absent-view-means-degraded-run.md) — unavailable output is never
  rendered as an empty result and never phrased as a statement about the directory. Both of this
  session's `S-29` predecessors violated it.
- [`0035`](../../decisions/0035-coverage-is-recorded-once-per-capture-unit.md) — coverage is
  recorded once per capture unit.
- [`0027`](../../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) — the
  only ways coverage varies.
- [`0017`](../../decisions/0017-capture-reads-the-whole-forest.md) — a part of the directory a run
  could not reach is a coverage failure that is stated.
- [`0003`](../../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md) — capture is
  fail-fast.

## Out of scope

Controller failover (`0040`) and parallel capture (`0041`) — both decided, both deliberately
unbuilt. The read side (`D`, `E`). The run library catalogue (`F12`–`F16`). A GUI. The configuration
file that would pin a controller per domain, which the owner deferred until a graphical surface can
generate one.

## A caution about the model

`ControllerModel` now serves attribute values as bytes, because a lab run proved it had been
serving a shape no directory sends and every test in the tree had inherited the guess. **That is one
correction, not a general defence.** The model is still built from articles rather than from a
controller, and every remaining behaviour it asserts — paging, bookmarks, range markers, referral
suppression — is documentation until a real controller says otherwise. Task two is the largest of
those still outstanding, and it is not the last.

## Rules that still bite

- Decisions are stated once, in `docs/decisions/`. Rows and comments cite; they do not paraphrase.
  A finding carrying a `Decision:` line is the other authority — `F-S29-3` has one.
- Mutation-test any new or changed guard in both directions and say which were observed.
- A ledger row is edited with `next/tools/Replace-InventoryRow.ps1`, never by hand.
- After any scripted edit, check `git diff --numstat` — the shell strips a UTF-8 BOM.
- Long PowerShell goes in a script file under `$env:TEMP`, invoked with a short command. PowerShell 7
  (`pwsh`) is now installed and can load the product's .NET 8 assemblies; Windows PowerShell 5.1
  cannot. Reading a bundle needs the native `e_sqlite3.dll` pre-loaded with
  `[System.Runtime.InteropServices.NativeLibrary]::Load(...)` before `Batteries_V2.Init()`.
- A capture bundle left in the working tree is not committed. One is sitting at
  `next/ad.lab-20260815-010309/` and should be moved, deleted or ignored.

## Finish by

- `F-S29-3` closed, with a test that reaches the state where completeness is false — or a finding
  saying no such state exists and what follows from that
- `F-S29-4` closed against a real group of more than 1,500 members, with the stored membership
  compared against the directory's exactly
- `F-S29-6` answered rather than assumed
- The observations owed against `B20` recorded in the slice document for this session
