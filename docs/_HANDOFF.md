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

**In progress — Evidence.** One document of five is written and bound; the pass is **not** finished
and the branch is deliberately left mid-pass rather than pushed to a fluent-looking end.

*Done.* `docs/evidence/what-a-bundle-holds.md` (408 lines) — the schema, the table list, descriptor
deduplication, the three ways to produce no entries, the writing order, and what is refused against
what is recorded. `BundleDocumentationTests` and `HistoricalRecordDocumentationTests` retargeted onto
it; `docs/next/README.md` repointed; `S-16` cut from 415 lines to 111.

*Done — second sitting.* `docs/evidence/the-bundle-on-disk.md` (223 lines) — the six files a bundle
directory holds, the rename that stops a half-written one being read, the seal and its four
outcomes, and the six run states with the procedure that observes each. Bound by
`BundleOnDiskDocumentationTests`, fifteen checks, every table two-directional. **`S-16` is deleted**
(111 lines), inbound references repointed, and the solution's document items corrected in both
directions — including four `docs/kernel` documents the Kernel pass never added, which is the same
defect recorded against Evidence one subsystem later. 2,174 tests green.

**The `STATES` table moved with it, so the S-18 gate is already half split.** Run states are observed
from files on disk, so they belong beside the file names rather than beside the comparability
verdict; `RunComparabilityDocumentationTests` lost its three state checks and gained one asserting
S-18 does **not** carry a `STATES` table, so a second copy cannot come back. `RunState`,
`RunStateNames`, `RunStateObservation`, `RunStateReader`, `RunOutcome`, `RunOutcomeContents` and
`RunOutcomeFile` left its component list. **The `OUTCOMES` half is still in S-18** and moves when
`whether-two-runs-compare.md` is written.

*Owed, in this order.* `how-a-bundle-is-read.md`, then `run-identity-and-coverage.md` and
`whether-two-runs-compare.md` (which together finish consuming `S-18`, now 332 lines). Reading state
is in `_COVERAGE.md` under `evidence-bundle`.

**Three punch-list adjudications came out of the pass and are recorded in full.** `P-2` verified
correct against the code. `P-3` decided — the mechanism is real, no bundle today carries a wrong
value, and what it costs is the column's independence rather than the number. `P-7`/`F-4` demoted,
which is the one worth reading first.

**Two open findings were live in area files and absent from the punch list**, and are now carried:
`F-0079-6` and `F-0056-1`.

**Retarget and cut in the same turn as the draft.** This pass did not, for one document, and left
the repository holding two descriptions of one schema with a gate pointing at the older. The owner
caught it, not the session. Deferring deletion to a tidy-up step at the end is the same batching
failure as deferring progress updates, and it is worse here because the half-done state looks
finished.

**Not started — Kernel/Schema, Kernel/GroupPolicy, Kernel/Naming, Cli, Shell.**

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
7. **Delete the old documents, and correct the solution's document items in both directions** —
   remove what was deleted *and add what was written*. Every rewritten layer document is a solution
   folder item; the Evidence pass added none, so its new document was invisible in the IDE while the
   stub it replaced was still listed. The word *prune* stood here and was read as delete-only.
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

**A retarget is only real if the old target now fails.** When a table moves between documents,
repoint the gate and then *prove the repoint*: point it at the document the table left and confirm it
goes red. Done for the on-disk split — the misdirected gate failed ten checks naming *has no FILES
table*, *has no SEAL table*, *has no STATES table*, rather than passing against an empty scan. A gate
that parses a marker block it cannot find must throw, never return nothing; `TableRows` asserts on
the marker for that reason, and both Evidence gates carry an `AMissingTableIsAFailureRatherThanAnEmptyScan`
self-test. Two gates in this repository have already passed for months while measuring nothing.

**A claim that something is *not built* is the least-verified sentence in this repository.** The
gates check that every name in a document exists in the code. Nothing checks the reverse claim — that
a capability is absent — because there is no name to look up. So *What is owed* sections rot
invisibly while the paragraphs around them stay bound and true. S-18's was checked during the second
Evidence sitting: **two of its three claims were false**, and one of them was what the surface
register recorded against F6. Both described seams built after the section was written and never
re-read. **Read the code for every unbuilt-work claim before carrying it into a successor document**,
and expect roughly half of them to be stale. This is `P-27`.

**PowerShell here-strings hang the terminal.** `@' ... '@` sent as a single line never terminates:
the closing `'@` only counts at the start of a line, so the shell waits for input that is not coming
and the session has to be killed. It looks exactly like a slow command. **Write document content
with the file-editing tools and keep the terminal to commands that return** — and if a terminal call
has to be cancelled, ask whether it hung before assuming the cancellation was a judgement on the
content. One was misread that way.

**Traps of the same family, one layer down.** `Measure-Object -Line` undercounts, and the
Audit/Connect pass trusted it. It reported the
`_COVERAGE.md` as a coverage claim, and it named the deleted `S-14` at 175 lines when git says 225.
It appears to drop blank lines. **Use `@(Get-Content $f).Count`, or `git diff --numstat` for anything
git already knows.** Worth its own line because the previous trap says *ask `git` for the numbers
rather than recalling them* and this pass did ask a tool — the tool was wrong, and a wrong number
from a command reads as more trustworthy than a wrong number from memory.

**Capture gaps cannot be worked around later, but are not urgent.**
— the owner is the only user. A missing capture input is ordinary backlog, found naturally when a
rule needs it. Do not argue for urgency on the grounds of re-capturing a customer forest.

**The archive is outside the repository** at `C:\Users\jistrand\Downloads\SecureAD Archive\docs`.
Delete consumed sections from it as well; a second backup exists. Nothing in the repository may cite
it — a citation nobody can follow is worse than none.

**PowerShell's text cmdlets rewrite what they touch.** `Set-Content -Encoding utf8` was used to trim
`S-16` and round-tripped every em-dash through ANSI, corrupting the file it was cutting. Caught,
restored from git, redone with `[System.IO.File]::WriteAllLines` and an explicit no-BOM
`UTF8Encoding`. Same family as the `Measure-Object` trap above and worth its own line for the same
reason: a cmdlet that reads as *write these lines back* quietly did something else, and the damage
was invisible in the diff summary. **Use the .NET file APIs for any edit to a document with
non-ASCII characters in it**, which is all of them.

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

**There is not one, and the item that used to be named here has been demoted.** Read this before
picking work off the punch list, because the demotion is more useful than the item was.

`P-7` / `F-4` stood here: a lab bundle shows the `ace` table and a re-parse of the same descriptor
disagreeing by one entry — 57 against 56 — while the descriptor reports `dacl_completeness=Complete`,
with the mechanism given as a DACL walk bounded by the declared entry count rather than by the ACL's
own `AclSize`. It was never deferred on the grounds that *an operator would read an entry count that
is short, and a permission may not be listed.*

**The Evidence pass read the descriptor half of the schema back out of a bundle for the first time,
and neither half of that consequence survives.**

- The entry list an operator sees is `ObjectPermissions.Entries`, a fresh parse of `raw_bytes` with
  nothing deduplicated and nothing reordered. No permission is withheld from a screen.
- `captured_object.ace_count` is written by `BundleWriter.CountEntriesPerObject` and **read by no
  production code in the repository**. There is no reader for a short count to mislead.

**And the disagreement itself is probably designed behaviour.** The `ace` table is not a second walk
of the same DACL; it is the canonical projection, and `AceNormalizer.Normalize` deduplicates it. The
read side deliberately does not — *"a DACL carrying the same grant twice is what the directory holds
and a reader deciding it meant once is editing evidence."* `ObjectPermissions` carries the
measurement: lab bundle `ad.lab-20260819-232425`, 12,603 stored against 12,600 projected. A
one-entry disagreement on one organisational unit is one duplicated entry, and `Complete` is correct
beside it.

**One query decides it**, and it is left for a cleanup pass. Deduplication guarantees `ace` ≤
re-parse, so if the re-parse saw 57 there is no defect; if the `ace` table really saw 57 there is a
projection larger than the bytes it came from, which nothing here explains and which would be worse
than what was recorded. The punch list does not say which way round the numbers were.

**`P-7` itself stands and is ordinary backlog.** The walk really does read `AceCount` and never
`AclSize` or `AclRevision`. What it lost is its corroboration and its priority.

**The transferable part is the third instance of one shape.** An adjudication was written into the
punch list, promoted to the top of this file, and carried through three passes, and the code
contradicts it. The rule was already here — *a finding is not open because a document says so, and
that adjudication may itself be wrong* — and it applies to this file as much as to the archive.
Nothing had read the code the claim was about until the pass that owned it came round.

---

