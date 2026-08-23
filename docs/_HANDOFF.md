# Handoff: the documentation rewrite

**Read this first in a new session.** It replaces reconstructing the plan from conversation.

---

## The goal

Replace the sprawling documentation — 120+ files across `docs/areas`, `docs/next` and
`docs/decisions` — with one document per code folder, written from the code, bound by the existing
gates, with the old documents deleted as they are consumed.

**This is a documentation rewrite, not a product audit.** Gaps found along the way are recorded in
[`PUNCH-LIST.md`](PUNCH-LIST.md) and left alone. Fixing them is separate work.

---

## State

**Done — Kernel/Security.** Commit `f1d49f6`. Four documents in `docs/kernel/`, three slice documents
deleted (1,632 lines), all gates retargeted, 2,159 tests green.

**Done — Audit/Capture.** Commit `ee63b7f`. Four documents in `docs/audit/` — the attribute
catalogue, the search capture issues, how a controller's answer is read, and what a controller's
limits oblige. Six slice documents deleted (1,856 lines), six gate suites retargeted, one unsound
gate widened and fixed, 2,160 tests green.

**Two things about that pass are worth carrying forward.**

*The gate that widened.* `EveryPublicTypeInTheCaptureProjectIsNamedByACaptureSliceDocument` scanned
four types while its name and failure message claimed nineteen, and had been green for months. The
fault arrived **by repair**: S-24 moved the catalogue into another assembly, the check failed loudly,
and the fix pointed the scan at the catalogue's new neighbours rather than at the component the test
is named for. Widened during the pass; it immediately named twelve types no document mentioned. It
is `P-19`. **When a check fails after a move, ask what its new subject is — not only whether it
passes again.**

*The archive backlog was not read, and that is correct.* The documents were written from the code,
the tests, the slice documents bound to them and the governing area files — the complete code-first
input set. The 27 archive files under `audit-capture` belong to a **separate later pass**, described
at the top of `_COVERAGE.md`. **Audit/Capture is closed.**

The rule that previously said otherwise — *nothing is drafted until every archive file is consumed* —
was written while the rewrite was archive-first and was left stale when it became code-first. It is
retired. An unread archive backlog is work not yet started, not a defect in a finished pass.

**Why this is not `F-S44-2`.** That fault was a catalogue *reassembled* and then checked against rules
*derived from the same catalogue* — a closed circle with nothing outside it, in which wrong values
survived. A document derived from the code and checked against the code is also a circle, but the
code is the artefact that ships and the document's job is to describe it. What such a document cannot
tell you is whether the code is *right*; that is the audit, and it is deliberately a separate
exercise.

The residual exposure is real but narrow: a **refusal** argued once and never restated, which a
future session could reverse without knowing. Those are found by searching the archive for
decision-shaped language — *decided, refused, must not, rejected, instead of* — not by reading whole
files.

**Done — Audit/Connect.** Four documents in `docs/connect/` — the connection ladder, how a connection
is opened, how the forest is found, and what preflight proves. `S-14-the-connection.md` deleted
(225 lines), `ConnectionDocumentationTests` retargeted, `which-controller-we-read.md` trimmed to its
decision index, `F-S40-1` carried to the punch list.

**Punch-list `#17` was adjudicated during that pass, and the line recording it was wrong.** It said
the ladder treats LDAP 91 as proof of *refused protection*; it does not — 91 maps to
`ProtectedChannelFailed`, which is correct. The fault is that `ProvesTheControllerAnswered` counts
`ProtectedChannelFailed` as an answer, and that list is the gate `0018`'s amendment put in front of
the forest finding. A broken LDAPS certificate on 636 plus a firewall on 389 therefore reaches
*"a controller accepting nothing signed…"*. Microsoft defines 0x5b as *"Cannot establish the
connection"* — the client's own failure, not a response. **Recorded, not fixed**, with the remedy
written out; the branch stays documentation-only.

**How it survived is the transferable part.** `0018`'s amendment has three cases and there is a test
for each — 81, 49, unclassified. The fourth entry in the same list was carried over without being
re-asked. That is `P-19` from the other side: **when a rule is applied to a list, ask whether it was
applied to every entry, not whether the list still compiles.**

**Not started — Kernel/Schema, Kernel/GroupPolicy, Kernel/Naming, Evidence, Cli, Shell.**

**Evidence is the natural next pass.** `S-16-the-bundle.md` and `S-18-run-identity-and-comparability.md`
are its slice documents and both are untouched. Two punch-list items are evidence-side, `P-2` and
`P-3`.

---

## The cycle

One subsystem per pass. Do not start the next until the current one is committed green.

1. **Read the area file whole** — `docs/areas/`. Required by `.github/copilot-instructions.md`, and
   skipping it is how settled questions get reopened. Its *What is decided* table links the records
   that govern the area; its *What is built* table names the test proving each capability; its
   *Open findings* section holds live defects that must be carried into the punch list before the
   file is trimmed.
2. **Read every source file in the code folder, in full.** Not the summaries. See the traps below.
3. **Write the document from definitions** — the enum, the writer, the query actually sent.
4. **Carry the capability table across verbatim**, in operator voice, with its test names and lab
   dates. Verify every test name exists.
5. **Retarget the gates** that bind the old document. Retarget, do not retire.
6. **Repoint inbound references** — search for the old filename across `*.cs` and `*.md` first.
7. **Delete the old documents**, and prune the solution's document items.
8. **Run the whole suite. Commit only when green.**

---

## Rules learned the hard way

**Route every fact to one destination as you read it.**

| Kind of fact | Goes to |
|---|---|
| How it works, why it is this way, do-not-change | the layer document |
| Open work | `PUNCH-LIST.md`, one table row |
| Verified already fixed | nowhere — git and the archive hold it |
| A claim the code contradicts | `_DRIFT.md` |

Writing findings into the punch list as narrative made it 724 lines — larger than the documentation
it supported. It is now 147 and must stay readable in one sitting.

**Delete by section, not by file.** Documents span subsystems. Cut the consumed part, leave the rest,
and note in the header what was taken and where it went.

**A finding is not open because a document says so.** A later document may have adjudicated it — and
that adjudication may itself be wrong. Two archived documents flatly contradict each other on GPO
link precedence; both are recorded and neither is trusted.

**Ask what a check is anchored to.** Two gates required strings from an inventory archived months
ago, and passed. A sound check pointed at a dead reference measures nothing.

**Do not hand engineering decisions to the owner.** Tooling, test structure, document shape and
naming are yours. Decide, then say what you decided and what it cost. Reserve questions for what the
product should do, what an administrator would expect, and what to prioritise.

---

## Traps

**Reasoning from comments rather than data.** XML doc comments are *never authoritative* — see the
instructions. They are argument, and they go stale: `ParsedSecurityDescriptor` still documents three
DACL states where the enum has four. Verify against the definition.

**Sampling a file and calling it read.** Large files were read at 12–20% and the drafts inherited
whatever the summaries claimed. `_COVERAGE.md` records lines read against total for this reason;
state the fraction when claiming a file is read.

**Summarising from memory at the end of a long pass.** The Audit/Capture session finished green and
then reported four document filenames that do not exist, and a deletion count 200 lines out. Both
were wrong only in the summary — the gates and the commit were correct throughout — but a reader
would have gone looking for files by those names. **At the end of a pass, read the directory and ask
`git` for the numbers rather than recalling them.** The wrongness was confident and fluent, which is
what makes it worth a line here: it is the same failure as a well-argued paragraph mistaken for a
conclusion, arriving from the other direction.

**This is also the signal to end a session.** Fabricated detail late in a pass means the useful
context is spent. Commit, update this file, and start fresh rather than pushing into the next
subsystem.

**`Measure-Object -Line` undercounts, and the Audit/Connect pass trusted it.** It reported the
Connect folder as 4,113 lines when it is 4,943 — a 17% understatement that went straight into
`_COVERAGE.md` as a coverage claim, and it named the deleted `S-14` at 175 lines when git says 225.
It appears to drop blank lines. **Use `@(Get-Content $f).Count`, or `git diff --numstat` for anything
git already knows.** Worth its own line because the previous trap says *ask `git` for the numbers
rather than recalling them* and this pass did ask a tool — the tool was wrong, and a wrong number
from a command reads as more trustworthy than a wrong number from memory.

**Capture gaps cannot be worked around later, but are not urgent.** There are no bundles in the field
— the owner is the only user. A missing capture input is ordinary backlog, found naturally when a
rule needs it. Do not argue for urgency on the grounds of re-capturing a customer forest.

**The archive is outside the repository** at `C:\Users\jistrand\Downloads\SecureAD Archive\docs`.
Delete consumed sections from it as well; a second backup exists. Nothing in the repository may cite
it — a citation nobody can follow is worse than none.

---

## Files that carry state between sessions

| File | Holds |
|---|---|
| [`PUNCH-LIST.md`](PUNCH-LIST.md) | open work, one line each |
| [`_COVERAGE.md`](_COVERAGE.md) | every archive file, subsystem, lines read, consumed or not |
| [`_DRIFT.md`](_DRIFT.md) | places the documentation and the code disagree |
| [`planned/effective-access.md`](planned/effective-access.md) | the specification for the two unbuilt layers |

These are the memory. A new session reads them and continues; it does not need this one's context.

---

## The single highest-priority open item

**P-7 / `F-4`.** A lab bundle shows the `ace` table and a re-parse of the same descriptor disagreeing
by one entry — 57 against 56 — while the descriptor reports `dacl_completeness=Complete`. The
mechanism is almost certainly that the DACL walk is bounded by the declared entry count rather than
by the ACL's own `AclSize`.

By the owner's own instructions this is the category that is never deferred: an operator would read
an entry count that is short, and a permission may not be listed.
