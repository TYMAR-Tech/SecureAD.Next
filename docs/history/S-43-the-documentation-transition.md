# S-43 — The documentation transition

> **This records session S-43 as of 2026-08-16. Nothing here states current behaviour.**  
> It is kept for the reasoning it carries, not as documentation. See [`docs/history/README.md`](README.md).

The outcome of [the S-43 brief](../next/sessions/S-43-the-documentation-transition.md). It records
what was changed, what was found, and what was deliberately left.

**Where the current answer lives.** What the product has, and what is still open, is in
[`docs/areas/`](../areas/README.md) and the records in `docs/decisions/`. Not here.

---

## What the session was for

The documentation contradicted itself in the places that steer the work, and the owner's account was
that sessions spent their time re-arguing what was decided. The fix was not to reconcile the
documents once — [`S-26`](S-26-reconciling-the-documentation.md) did that and it did not hold —
but to move documentation maintenance out of *"a thing done at the end, from discipline"* and into
*"a thing the build stops for, in the middle"*.

---

## What changed

**The instructions file no longer sends a session to the ledger.** `§ Orient before proposing
anything` previously said to start from `WHAT-THE-OLD-APP-HAD.md` and then read the session documents — a
direct instruction to do the thing that produced the preflight wizard. It now says to read the one
area file, whole, and stop at its *"What has not been discussed"* section. Two demotions were added
below it, so the old habit has something standing in its way rather than merely being absent. The
mis-headed *"Database Schema Guidelines"* section, which held the product's identity and no schema
guidance, was renamed; the duplicated *"Document Authority"* section was removed.

**Four gates were added**, each mutation-tested in both directions with the directions recorded
below.

| Gate | Fails the build when |
|---|---|
| [`AreaFileGateTests`](../../next/tests/SecureAD.Next.Tests/Architecture/AreaFileGateTests.cs) | an area file lacks one of its three sections; a link out of one does not resolve; a capability names a test that does not exist; two areas claim the same test; the index and the directory disagree |
| [`DocumentationLinkGateTests`](../../next/tests/SecureAD.Next.Tests/Architecture/DocumentationLinkGateTests.cs) | any relative link under `docs/` points at something that is not there |
| [`InventoryAreaTagTests`](../../next/tests/SecureAD.Next.Tests/Architecture/InventoryAreaTagTests.cs) | a ledger row names an area that does not exist, carries no area, or the count of unjudged rows changes |
| `OldAppInventory.InventoryColumns` | *(existing)* the ledger gains a column without that being a decision |

**Six area files exist**, and an [index](../areas/README.md) naming all nineteen with their state.
The other thirteen are written as we come to them: a *"What has not been discussed"* section written
months before the work is a guess, and a guess there is worse than an empty section, because a later
session reads it as the complete list of what is open.

**Ten session documents were stamped and moved here**, chosen because nothing enforced them and no
production code cited them. The other thirteen stayed in `docs/next/`, because each is bound to the
code by a passing test — moving them into a folder headed *"nothing here is current"* would have
either broken fifteen test files or left the build enforcing documents declared untrue.

**Every ledger row carries an area.** All 256, covering all nineteen areas, with none left over.

---

## What was found

**The binding practice stopped at `S-28`.** Thirteen of twenty-three session documents in
`docs/next/` are held to the code by a test; the other ten are `S-28` or later. The newest half of
the product — entry point, coverage, preflight, discovery, the shell, the New Audit wizard — is
documented with the least protection. Recorded in
[`DOCUMENT-COVERAGE.md`](../next/DOCUMENT-COVERAGE.md).

**A binding is strong about structure and silent about prose.** `S-14`'s test compares the ladder
table element by element against the code, and also asserts the document exceeds 6,000 characters —
a floor on the prose, not a check of it. The failure this folder's README records, `S-15` claiming
capture *takes a destination* for days after [`0025`](../decisions/0025-the-run-library-is-a-managed-root.md)
decided otherwise, was prose. No test in the tree would have caught it.

**Five citations were broken before this session began**, found by a link check written to verify the
move had broken nothing. One was an Accepted decision record — [`0048`](../decisions/0048-preflight-proves-a-controller-before-a-run-commits.md) —
citing a session document under a name it never had. Two were component documents pointing at source
files that had changed project months earlier. None had ever failed anything, because nothing had
ever looked.

**`0049`'s attested exclusion has no code, no test and no screen.** Found by the overlap check: every
capability first drafted for [`domains-we-skip`](../areas/domains-we-skip.md) already belonged to
another area, borrowed to make the page look furnished. What exists is the product *coping* with a
domain it could not reach, which is not an operator choosing to leave a reachable one out.

**Twenty-five ledger rows are decided against** — all twenty-one `H` rows plus `C26`, `J43`, `J44`
and `K9`, removed by [`0008`](../decisions/0008-live-verification-is-removed.md) — and had been
reading as outstanding work.

**The gate caught the agent twice while drafting area files**: once citing six tests against the
wrong class, once furnishing an area with five capabilities belonging to other areas. Both would
have shipped under the previous way of working.

---

## What was left

- **Step 5**, the surface register keyed to areas, needs all nineteen areas and so needs the owner's
  answers. **Step 7**, demoting the ledger, comes after it.
- **The thirteen bound documents** keep their names and their tests until their areas are written.
- **`C27`**, *low-signal OU recommendation query*, is the one ledger row not judged.
  [`0052`](../decisions/0052-the-domain-is-the-only-unit-of-scope.md) appears to remove its premise,
  but that is the owner's call and marked `?` rather than guessed.
- **The `docs/history/README.md` signpost still sends readers to the port ledger** for what is built
  and what is left. That row belongs to step 7.

## A mistake made during the session

A mutation-testing script died between applying a mutation and reverting it, and the next script
then read the mutated file as its original and restored the mutation. For a few minutes the ledger
carried a wrong area name in eight rows. It was caught and restored, and every later script wraps its
revert in a `finally` block. The lesson is the one the instructions already carry — always revert
before running anything long — and it failed because the revert was not made unconditional.
