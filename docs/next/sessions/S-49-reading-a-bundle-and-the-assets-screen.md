# S-49 — Reading a bundle, and the Assets screen

**Status: brief. Nothing here is built.**

This is the next session's work, agreed with the owner on 2026-08-11 at the end of `S-48`. It is
the first work in the judgement half of the product.

---

## Why this, and why now

The capture half works: the product finds its forest, plans a run, reads every domain, and writes
sealed evidence. **It can then tell the operator nothing about what it collected.** Three area files
say so in as many words — *"Nothing in this area is built."* Sixty-two rule cards exist in
`docs/rules/` and none of them run.

The owner chose the **Assets screen** as the way in, over building a finding first, on the grounds
that it is *"literally reading facts from the bundle"* — permissions, SPNs, and a navigation tree
that is an offline rebuild of the directory tree, used to filter what is shown.

That choice is sound for a reason beyond preference: **reading a bundle is a prerequisite for both
paths.** A rule cannot judge objects nothing can read back. Findings are not being deferred so much
as sequenced behind the thing they need.

[`0064`](../../decisions/0064-an-attribute-is-justified-by-a-rule-or-the-object-view.md) already
decided that an attribute is justified by a rule **or the object view**. Part of what capture
collects is justified by this screen, so building it discharges a promise already made.

---

## What exists

| | |
|---|---|
| `BundleWriter`, `BundleLayout`, `BundleSealing` | writing, laying out and sealing a bundle |
| `EvidenceObject`, `EvidenceAttribute`, `EvidenceValue` | what an object and its attributes are, text or bytes |
| `RunLibrary`, `RunListing`, `RunStateReader` | listing runs and saying what became of each |
| **no reader of any kind** | **the whole of the gap** |

A bundle is `evidence.db`, sealed by `evidence.db.seal`, beside `annotations.db`,
`run-outcome.json` and `preflight.json`.

---

## Decided already — do not re-open

**A bundle that does not verify is not opened.** `SealVerdict.MayBeOpened` returns true for
`SealState.Intact` and nothing else. The reader honours this; it does not get a lenient mode.

**The three outcomes are worded differently, because their remedies differ.** `Unreadable` means the
seal is missing or damaged — *copy it again*. `Mismatch` means the evidence changed after the run
declared itself finished — *this is no longer the evidence*. An interrupted run is a third thing
again and is [`0068`](../../decisions/0068-a-finished-run-reports-with-its-gaps-shown.md), which
says an unfinished run reports not at all. Collapsing these into one apology would throw away what
an operator needs to act.

**The seal is not a signature and is not called one.** There is no key in this product, so it proves
accident — a truncated copy between the build machine and the lab, disk corruption — and not a
determined attacker. Say that plainly if the screen ever explains itself.

**Analysis does not run while a capture runs** —
[`0072`](../../decisions/0072-analysis-and-capture-do-not-run-at-the-same-time.md). This is where
that constraint first bites, and it needs capture state to be visible outside the wizard that
starts it. That seam does not exist yet.

**There is no Risk column.** The predecessor's Assets grid had one, reading `High` on every row.
Nothing in this product computes a finding, and
[`0002`](../../decisions/0002-absent-view-means-degraded-run.md) and
[`0045`](../../decisions/0045-the-shell-is-built-before-the-judgement-half.md) both forbid rendering
an unasked question as an answer. **A Risk column an administrator reads as a security judgement,
filled by nothing, is the worst thing this screen could do.** It arrives with findings.

---

## The owner's answers, 2026-08-11

- **Where the grid starts:** the root of the forest.
- **Which detail section first:** Overview.
- **How much of the old design to keep:** *"the screenshots are just a way to show all the info I
  showed before but I'm not locked into the old design if we can come up with something better."*
  **This is an invitation to design, not to port.** The predecessor's inspector had Overview,
  Permissions, Groups, Kerberos, Delegated Permissions, SPNs, and a set of analysis tools. Treat
  that as an inventory of what an administrator wanted to see, not as a layout to reproduce.

---

## Steps

1. **The reader.** Open `evidence.db`, verify the seal, refuse anything not intact, and report which
   state it hit. No screen; the evidence is tests.
2. **The tree.** Built from the distinguished names already stored — a pure function of what is on
   disk, needing no capture change.
3. **The grid.** Rooted at the forest, filtered by the tree selection.
4. **The overview**, for one selected object.

**Each step is looked at on a running window before the next begins.** Step 1 is the exception and
is proved by tests.

---

## How to work on the screens

`docs/areas/how-the-app-looks.md` opens with **How to work in this area** — nine lessons that cost
two sessions to learn. Read it before changing anything visual. The two that matter most here:

- **Bump the build marker in `ShellWindow.xaml` with every change.** The product is built on one
  machine and run on another. Four rounds went into a rail that was never broken because a
  screenshot could not say which build it showed.
- **Use `next/tools/SecureAD.Gallery`.** Assets will want vocabulary the product does not have — the
  predecessor's screens show severity chips, count pills and a tree. Judge those once, on one page,
  rather than per screen. The gallery is deleted when the styling work is finished.

---

## What this session leaves behind

**Open, and not blocking:**

- `F-0056-6` — an empty table looks like one that loaded and found nothing.
- `F-0071-8` — the review screen is a wall of text with nothing grouping it.
- The tick box and the scrollbar are still Windows' own — the last of `F-0056-2`.
- A test fixture that produces a warning is owed, so that `F-0071-7` can be guarded. It is
  deliberately unguarded rather than guarded by a test that would pass either way.
- The layout of Home and Runs, deferred on purpose: both screens change when findings arrive, and
  polishing a layout about to be rebuilt is work done twice.
