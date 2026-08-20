# S-43 - The documentation transition

Produces: `docs/next/S-43-the-documentation-transition.md`. Governing records: `0056`, `0057`, and
whatever this session decides about where the product's state is written down.

This session makes permanent the way of working that was tried on one area during `S-42`, and
retires the one that produced fourteen months of contradictions.

**Taken at the owner's decision after the trial.** His words: *"I think it works so how do we
transition to this completely."*

## Why this session exists

**The documentation contradicts itself, and it does so in the places that steer the work.**

The owner's account, and it is the reason this session was called: *"I got really frustrated with
you constantly going back and forth over what's decided, what's blocked, because the documents
contradicted each other."*

Three concrete instances, all found on 2026-08-16 without looking for them:

- **`.github/copilot-instructions.md` said the product has live LDAP browsing.**
  [`0008`](../../decisions/0008-live-verification-is-removed.md), Accepted thirteen months earlier,
  says the Inspect view and the directory tree are not part of the product. The instructions file is
  read at the start of every session and is not on the list of documents that count as
  authoritative, so it won every time.
- **`README.md` § Gates and `SURFACE-REGISTER.md` both state that gate 5b is blocked because
  `next/` has no entry point.** It has had one since the shell shipped.
- **Ledger row `A10`, "Discovery UI", reads *Deferred to phase 3*.** The owner watched it run that
  afternoon.

None of these is a mistake anyone made. Each is a fact restated in prose, in more than one place,
with nothing tying the copies together. When reality moved, every copy became false at once and none
of them knew.

## What the trial established, and what it did not

`S-42` wrote two area files - [`which-controller-we-read`](../../areas/which-controller-we-read.md)
and [`how-the-app-looks`](../../areas/how-the-app-looks.md) - and ran one turn of the loop for real.

**It caught three things a session working the old way would have missed.**

- Writing `0056` before any code forced a dependency into the open: the record required a run-level
  count of unestablished facts, and `RunCoverage` structurally cannot supply one at the moment the
  screen needs it. That became `F-0056-1` instead of being discovered halfway through writing XAML.
- The owner's rule about quiet gaps was corrected after the record was accepted, at a cost of one
  markdown edit. Under a styling session it would have surfaced at the fourth screen.
- The **"What has not been discussed"** section stopped an inference. That section is the whole
  mechanism: it is where "we have not had this conversation" lives, so a session stops and asks
  rather than reading a ledger row as an instruction - which is exactly how the preflight wizard
  went wrong.

**It did not establish that an area file stays true.** Both are hours old. Every document in this
repository was accurate on the day it was written; that has never been the problem. **The gate is
the difference between this and [`S-26`](S-26-reconciling-the-documentation.md)**, which reconciled
the documentation once and did not hold, because nothing enforced the result.

## The shape being adopted

**Four artefacts per unit of work, and only two are authoritative.**

| | Written by | Kept honest by | Authoritative |
|---|---|---|---|
| The area file | owner and agent, in discussion | small enough to read whole | no - it is the working surface |
| A decision record | written once, never edited | superseded by a later record | **yes** |
| The code and its tests | | the suite | **yes** |
| A capability entry | one line at build time | the build fails if its named test is missing | **yes** |
| The reference inventory (today's ledger) | edited only when a row is settled | nothing - it is reference | no |

**The loop.** Read the one area file, and stop at its "not discussed" section. Discuss. The owner
decides. The decision becomes a record. **Then** code. The recording happens as a condition of the
build going green, not as a write-up afterwards.

**The principle behind the mechanism.** Do not build a workflow that depends on the agent
remembering to update documentation. It starts each session with no memory of the last, it is
oriented toward finishing the code, and a document nothing forces it to open is a document it will
reason from without checking. What reaches it is the build failing. So documentation maintenance
moves out of "a thing done at the end, from discipline" and into "a thing the build stops for, in
the middle".

## Scope

**In, in this order. The order is not negotiable: the first two make everything after them
durable.**

**1. Fix `.github/copilot-instructions.md`.** Half an hour, and the highest-leverage change here.
§ *Orient before proposing anything* currently instructs the agent to start from `WHAT-THE-OLD-APP-HAD.md`
and then read the session documents - a direct instruction to do the thing that produced the
preflight wizard. It becomes: read the one area file, and stop at its "not discussed" section.

Also owed in that file, found while reading it whole on 2026-08-16:

- The section headed **"Database Schema Guidelines" contains no database schema guidance** - it
  holds the product's identity, what was removed and when, and what deliberately survives. The most
  load-bearing content in the file, under a heading nobody would look under.
- **"Document Authority" duplicates "What counts as settled"** almost exactly. Two statements of one
  rule, in one file, is a small instance of the problem the rule is about.

**2. Build the area gate.** The check run by hand against the sample, made a build failure: every
decision link resolves, every named test exists and passes, no capability cites a class where it
should cite a test, every area file carries the three sections. **With its own scanner self-test** -
a gate that passes by finding no area files is the failure this repository has committed four times,
and `README.md` § Gates is explicit about why.

**3. Write the remaining areas.** Nineteen in total, two written. The list below is the owner's,
edited from a draft; live inspection was struck out because
[`0008`](../../decisions/0008-live-verification-is-removed.md) had already removed it.

*Getting the data* - which controller we read and whether we can (**written**); what we capture;
running a capture; what the run did and did not cover; domains we deliberately skip.

*Keeping it* - how a run is stored; how the run library stores and lists runs; how compare works.

*Making sense of it* - who is who; what a permission means; how privilege escalates; Group Policy;
what we call a finding; accepting a finding.

*Showing it* - what goes into the new audit wizard; how results are shown; reports and export; how
the app looks (**written**); how failures are reported.

**The agent drafts each; the owner writes the "not discussed" section.** That section is the list of
things the agent must not guess at, and the agent is the wrong one to say what it does not know.

**4. Tag every ledger row with its area.** 229 rows, each becoming **ported**, **decided against**
(naming the record) or **not yet discussed**. This is where it becomes clear whether nineteen areas
cover the product. An untagged row is a row that still reads as an obligation.

**5. Replace `SURFACE-REGISTER.md` with a generated code map keyed to areas.** The one step with
teeth. `SurfaceRegisterTests` binds register entries to ledger rows, so **the build depends on the
ledger today** - moving that binding onto areas is what frees the ledger to stop being a plan. Every
type claimed by exactly one area; an unclaimed type fails the build. A type serving no area is
either dead surface or a capability nobody wrote down, which is the failure that produced the old
application's six unreachable grids.

**6. Stamp and retire the session documents.** Fifty-two files get an enforced header saying what
they are - *"This records session S-nn as of «date». Nothing here states current behaviour"* - and
move to `docs/history/`. They stop being things anyone reads to find out where the product stands.

**7. Demote the ledger.** Rename it for what it is - an inventory of the predecessor - and drop the
four columns that make a row read as owed: Disposition, Lands in, Status, Docs. By this point
nothing in the build depends on it and the edit is mechanical. **It only looks like the hard part.**

**Out, deliberately.**

- Any product change. This session moves and enforces documentation; it decides nothing about what
  the product does.
- Reconstructing the untracked work of the days before `S-42`. The owner drew the line: the register
  starts from what is in the code now and is verified forward by running it. Reconstructed history
  is the least true part of any record.
- The layout work `S-42` left open - `F-0056-3` through `F-0056-6`. That is its own session and it
  needs the owner in front of a running window.
- Gate 5b, the reachability trace. Now unblocked, because `App.xaml.cs` is an entry point, and still
  its own session: a reachability gate written carelessly is a check that passes while measuring
  nothing.

## Where this starts

Two commits from `S-42` are in: `83752d94` sealed the shell so it exports nothing, and `74bed59e`
built the visual language. The suite is at **1,140 passing**.

Read, in this order:

- [`docs/areas/which-controller-we-read.md`](../../areas/which-controller-we-read.md) - the
  retrospective sample, documenting work already done.
- [`docs/areas/how-the-app-looks.md`](../../areas/how-the-app-looks.md) - the prospective one, which
  ran the full loop: nothing decided, then a record, then code, then a review against a real forest
  that produced four findings.
- [`0056`](../../decisions/0056-the-visual-language-encodes-three-states.md) - amended twice on the
  day it was accepted, once by the owner and once by the agent. That is the loop working, and the
  amendments are visible rather than smoothed over.
- `docs/next/README.md` §§ `Tests`, `Gates`, `When a document counts as documentation`.
- [`S-26`](S-26-reconciling-the-documentation.md) - the previous attempt at this, for what happens
  when a reconciliation is not enforced.

**A note on searching this repository.** `git grep` and `git ls-files` are the only searches to
trust here; the built-in file search returns empty results for tracked files under `docs/`.

## Rules

- §§ `Tests` and `Gates` of `docs/next/README.md` bind this session, including the scanner self-test
  every gate carries.
- **No product behaviour changes.** If something is found to be wrong, it is a finding with a
  severity. A documentation session is where a quiet behaviour change hides best.
- **Nothing is deleted.** A superseded document is stamped and moved, never removed. The history of
  how a decision was reached is the part that stops it being re-argued.
- **The owner writes every "not discussed" section.** The agent may draft the rest.
- **A capability is written in operator language**, not in type names: *"an operator can tell a fact
  the run did not measure from one it measured and found wanting"*, not *"FactState has four
  members"*. If a capability cannot be written that way, that is a signal about the code, not about
  the sentence.
- Mutation-test the area gate in both directions and record which directions were observed.

## Finish by

- The solution builds and the whole `SecureAD.Next.sln` suite passes.
- The instructions file no longer points a session at the ledger, and no longer contradicts an
  accepted record.
- The area gate fails the build for a broken link, a missing test and a missing section, carrying
  its scanner self-test, mutation-tested in both directions with the directions recorded.
- Nineteen area files exist, each with three sections, each with a "not discussed" section the owner
  wrote.
- Every ledger row is tagged, and the ledger is renamed for what it is.
- No document outside `docs/decisions/` asserts the status of a gate, a row or a component. Citing
  is allowed; asserting is not.
- **The owner can answer "what has this product got, and what is still open" from the area files
  alone, without reading a session document.** That is the only acceptance test this session has
  that matters.
