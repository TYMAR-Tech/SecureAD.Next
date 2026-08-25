# Handoff: the documentation rewrite

**Read this first in a new session** — but read it as *history*, not as law.

> **The authority is [`docs/next/README.md`](next/README.md) §*When a document counts as
> documentation*, and [`.github/copilot-instructions.md`](../.github/copilot-instructions.md).**
> Where this file disagrees with either, they win and this file is wrong.
>
> **This file has been wrong three times in ways a session acted on**: *copy, not a move* (the gate
> required no such thing), *Evidence is closed* (it was 14 of 44), and the `P-7`/`F-4` adjudication
> (contradicted by the code). It is a narrative written by the sessions it describes. Treat every
> claim in it as needing re-measurement before use.

---

## The goal

**Fewer files.** Replace the sprawling documentation with **one layer document per code folder,
written from the code**, and **delete the sprawl as it is consumed**.

**The end state is zero files in `docs/areas/`.** Not trimmed, not stubbed — gone. An area file is an
input being consumed, not a fixture to maintain.

**A pass that adds documents without removing any has not consolidated anything.** Measure a pass by
files removed, not by documents written. The Kernel/GroupPolicy pass added three files and removed
none, which is why it is recorded below as *not finished*.

### Route every fact to exactly one destination

| Kind of fact | Goes to |
|---|---|
| What the code does | the layer document for that folder |
| Work that may need doing | [`PUNCH-LIST.md`](PUNCH-LIST.md) |
| A product position | a record in `docs/decisions/` |
| What blocks the rewrite itself | [`PUNCH-LIST.md`](PUNCH-LIST.md), *Documentation rewrite* |
| Anything else | deleted |

**This is a documentation rewrite, not a product audit.** Gaps found along the way go to the punch
list and are left alone. Fixing them is separate work.

### The non-negotiables

1. **Move, do not copy.** Delete content from its old home in the same turn you write it into the
   new one. Leaving both doubles what the next session reads.
2. **Do not test the shape of prose.** No gate on headings, identifiers, status lines, or whether a
   section exists. Read `docs/next/README.md` §*When a document counts as documentation* before
   writing any gate. A live violation is `P-51` in `PUNCH-LIST.md`.
3. **Prove every gate failing.** Point it at a document that does not carry its subject; confirm it
   fails naming what it cannot find; record which checks failed **and which passed**, because the
   passing ones are decoration.
4. **Check the register before scoping a pass.** [`SURFACE-REGISTER.md`](next/SURFACE-REGISTER.md)
   maps types to governing documents. An area file's scope is a *subject* and can span assemblies; a
   pass's scope is a *folder*. They are not the same and assuming so reports an area finished when
   it is two-thirds done.
5. **Say what you opened.** A count you did not read is not a measurement, and a truncated search
   result is not an answer.

### What to do next

**[`PUNCH-LIST.md`](PUNCH-LIST.md), the *Documentation rewrite* section**, in order. `P-51` and
`P-52` are test code and neither is large.

**The first four area files have been deleted** — `how-compare-works`, `who-is-who`,
`what-the-run-covered`, `running-a-capture` — which had not happened once in six previous passes. The
gate that made it impossible (the surface register requiring every type to name a live area file) was
widened to accept layer documents, and proven failing before it was trusted.

---

## State

**Measure a pass by files removed.** `docs/areas` is down from 20 files to 16, the first deletions in
the rewrite.

| Subsystem | Documents | Consumed | Commit |
|---|---|---|---|
| Kernel/Security | 4 in `docs/layers/kernel/` | 3 slice documents | `f1d49f6` |
| Audit/Capture | 4 in `docs/layers/audit/` | 6 slice documents | `ee63b7f` |
| Audit/Connect | 4 in `docs/layers/connect/` | `S-14` | `f7e0747` |
| Evidence | 5 in `docs/layers/evidence/` | `S-18` | `53bb5c6` |
| Kernel/Schema | 1 in `docs/layers/schema/` | `S-3` | `d966416` |
| Kernel/Naming | 1 in `docs/layers/kernel/` | `S-2` | `88886ae` |
| Kernel/GroupPolicy | 2 in `docs/layers/kernel/` | **nothing — area file still 16/23** | uncommitted |

**`docs/next/S-*.md` are all gone.** `S-2` was the last. A reference to one describes history.

**Coverage: 144 of 200 types, 72%** — excluding findings and rules, which are **out of scope** (the
rules engine is scaffolding; `docs/rules/` and `SecureAD.Evidence/Findings/` are consolidated when
the feature is built, not before — see `.github/copilot-instructions.md`). Remaining in-scope debt,
carried and needing re-measurement: `Evidence/` root 14 of 44, `Audit/Sysvol` 0 of 5, and a 112-file
archive backlog that is a separate later pass. All of it is in [`PUNCH-LIST.md`](PUNCH-LIST.md).

**Four more area files govern no types because their feature is unbuilt** — `domains-we-skip`,
`how-privilege-escalates`, `reports-and-export` and `accepting-a-finding`. They are specifications,
not consolidation debt, and deleting them would lose the specification.

**The pass narratives were deleted from this file** on the grounds that git holds them — the commits
above are named — and every open item they cited is in [`PUNCH-LIST.md`](PUNCH-LIST.md), verified by
searching for each identifier rather than by recall. This file was 834 lines and went unread, which
is the failure the rewrite exists to fix.

---

## The cycle

One subsystem per pass. Do not start the next until the current one is committed green.

1. **Find the governing document in [`SURFACE-REGISTER.md`](next/SURFACE-REGISTER.md) and read it
   whole.** It maps every public type to the document that governs it. **Do not assume your folder is
   the whole of what that document governs** — `group-policy.md` governs 23 types across three
   assemblies while the folder holds 16. Where the governing document is still an area file, that
   file is an input to consume and delete, and its
   that govern the area; its *What is built* table names the test proving each capability; its
   *Open findings* section holds live defects that must be carried into the punch list before the
   file is trimmed.
2. **Read every source file in the code folder, in full.** Not the summaries. See the traps below.
3. **Write the document from definitions** — the enum, the writer, the query actually sent.
4. **Move the capability table across verbatim**, in operator voice, with its test names and lab
   dates, **and delete the rows from the area file in the same turn**. It is a **move, not a copy**.
   The rewrite exists to shrink what a later session has to read, and a row living in two places
   doubles that instead. `AreaFileGateTests.EveryAreaFileCarriesTheThreeSections` requires only the
   *What is built* **heading**, not any rows under it, and it enumerates `docs/areas/*.md`
   dynamically — so it never required an area file to exist permanently either. The sentence that
   stood here said *copy, not a move* and read the gate's requirement as a rule about content; it
   was wrong on both halves. Do not verify the test
   names by hand:
   `docs/layers/connect` and `docs/layers/evidence` against the test assembly. **Write the table under
   `## What is built`, or under `## What an operator can do` if the subsystem already uses that** —
   kernel does, the rest do not, and the gate matches both openers.
5. **Retarget the gates** that bind the old document. Retarget, do not retire.
6. **Repoint inbound references** — search for the old filename across `*.cs` and `*.md` first.
7a. **Shrink the area file as you consume it, and delete it when nothing is left.** An area file is
   an input being consumed, not a fixture. Every pass removes what it moved — capability rows,
   findings, decided rows whose subject has gone — so the file gets shorter each time and the final
   deletion is the moment the last content leaves it. **An area file may govern more types than the
   folder a pass covers**, and `docs/next/SURFACE-REGISTER.md` is where you check: it maps every
   public type to its governing document. Delete the file only when every type it governs is
   described somewhere else, or the register's links break and those types silently lose their
   governing document.

7. **Delete the old documents, and correct the solution's document items in both directions**
   remove what was deleted *and add what was written*. Every rewritten layer document is a solution
   folder item; the Evidence pass added none, so its new document was invisible in the IDE while the
   stub it replaced was still listed. The word *prune* stood here and was read as delete-only.
   **`LayerDocumentGateTests` now enforces both halves** — every link out of a layer document
   resolves, so a deletion that left its inbound references behind goes red, and every layer document
   is listed in the solution. This was the only step of the cycle no gate covered, which is why it
   was skipped twice without anything noticing.
8. **Run the whole suite. Commit only when green.**

---

## Traps

Every one of these was paid for. They are kept because they are operational — things that will
happen again this week — rather than history.

**Evidence and claims**

- **A claim that something is *not built* is the least-verified sentence in this repository.** Check
  it against the code before writing it.
- **A finding is not open because a document says so.** A later document may have adjudicated it, and
  that adjudication may itself be wrong. Read the code the claim is about.
- **Read the rule, then read the code that enforces it.** Every false claim here has come from
  believing a rule's wording instead of opening the check. *Copy, not a move* is the latest.
- **XML doc comments are never authoritative.** Reason from data, not from comments.
- **Sampling a file and calling it read.** Files read at 12–20% produced drafts that inherited the
  gaps. Say the fraction you read.
- **Say what you opened**, not "I checked". A proxy for the thing treated as the thing is the shape
  of every mistake made on 2026-08-20.

**Tools that lie quietly**

- **A truncated tool result read as a complete one.** A search backing a completeness claim must
  return something countable, and **the count must be read**. This cost a surviving citation in
  `DnHelper.cs` after a deletion.
- **`Measure-Object -Line` undercounts.** Use `(Get-Content x).Count`.
- **PowerShell's text cmdlets rewrite what they touch.** `Set-Content -Encoding utf8` round-tripped
  every em-dash through ANSI and corrupted the file it was trimming. **Use the .NET file APIs for any
  edit to a document with non-ASCII in it**, which is all of them, and check the BOM before and
  after.
- **`replace_string_in_file` cannot reach `next/SecureAD.Next.sln`.** Use
  `[System.IO.File]::ReadAllLines` with an **absolute** path.
- **PowerShell here-strings hang the terminal.** `@' ... '@` sent as a single line never terminates.

**Gates**

- **A retarget or a new gate is only real if it is observed failing.** Point it at a document that
  does not carry the subject; confirm it fails **naming what it cannot find**; record which checks
  failed **and which passed**, because the passing ones are decoration.
- **Ask what a check is anchored to, and whether it is narrower than its own name.** This is the
  repository's most repeated failure — `P-19`, at least six times — and it has appeared in both
  directions, too narrow and too broad.
- **When a rule is applied to a list, check every entry.** Not whether the list still compiles.

**Scope and process**

- **Delete by section, not by file.** Documents span subsystems: cut the consumed part, leave the
  rest.
- **Retarget and cut in the same turn as the draft.** Deferring the deletion leaves a half-done state
  that looks finished, which is worse than an obviously unfinished one.
- **A convention is not a constraint — check which one you are enforcing.** The documentation-only
  rule is a convention for keeping diffs reviewable, and it was twice used to decline work the owner
  wanted done.
- **Do not hand engineering decisions to the owner.** Tooling, test structure and document shape are
  the session's. What the product does, stores, or refuses is not.
- **Summarising from memory at the end of a long pass.** A session once reported a document drafted
  that was not and an edit applied that had silently failed. **Write the closing summary from tool
  output in the same turn, or not at all.** Fabricated detail late in a pass is the signal to end the
  session.

---

## Files that carry state between sessions

| File | Holds |
|---|---|
| [`docs/next/README.md`](next/README.md) | **the authority.** §*When a document counts as docu
| [`../.github/copilot-instructions.md`](../.github/copilot-instructions.md) | **the authority.** The goal, the routing table, how to orient |
| [`PUNCH-LIST.md`](PUNCH-LIST.md) | open work, one line each; *Documentation rewrite* holds what blocks the consolidation |
| [`PUNCH-LIST.md`](PUNCH-LIST.md) | open work, one line each |
| [`docs/next/SURFACE-REGISTER.md`](next/SURFACE-REGISTER.md) | every public type and the document that governs it — **read before scoping a pass** |
| [`_COVERAGE.md`](_COVERAGE.md) | every archive file, subsystem, lines read, consumed or not |
| [`_DRIFT.md`](_DRIFT.md) | places the documentation and the code disagree |
| [`planned/effective-access.md`](planned/effective-access.md) | the specification for the two unbuilt layers |

These are the memory. A new session reads them and continues; it does not need this one's context.
**This file is not among the authorities** — it is a summary, and it has been wrong three times.

---

