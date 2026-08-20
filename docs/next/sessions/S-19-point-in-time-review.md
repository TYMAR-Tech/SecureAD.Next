# S-19 — The point-in-time review

## Scope

This session produces the point-in-time review recorded as owed in
[`docs/next/README.md`](../README.md), in the section headed *Owed: a point-in-time review* — which
this session removed on finishing, because the review is no longer owed. Work in `next/`, and build
and test with `next/SecureAD.Next.sln`.

**It writes no production code.** No ledger row is built. If the cross-reading turns up something
that ought to be built, it is recorded and left.

**It is not a summarising exercise.** A document that restates the decision records would be worse
than nothing, because it would look like a check while being one. The value is entirely in the
cross-reading that produces it.

## Why this session exists

The gates catch drift between a document and the code it names. **Nothing checks that the decision
records agree with each other, or that they still agree with the code.**

On 2026-08-12 two records written the previous day were found to rest on a mechanism another record
had removed eight days earlier. Four states of a drift card described situations no run could reach,
and a document binding them would have passed while asserting the impossible. Nothing caught it — not
a test, not a review, not the index, which was itself missing two records. It was found by accident,
by a session reading `0017` for an unrelated reason. That is the gap this session closes.

There are twenty-nine records now, written across a period in which the product's identity changed
twice. The only thing currently holding them consistent is that somebody remembers.

## Read first

In order:

- [`docs/next/README.md`](../README.md) — §`Gates`, §`How to continue this work`, and
  §`Status`. This last reference read *Owed: a point-in-time review* when the prompt was
  written; that section was removed by this session, per its own `## Finish by`, because the review
  is no longer owed. Repointed rather than deleted so the prompt still names where the work landed.
- [`docs/next/sessions/README.md`](README.md) — how a prompt is written and what binds it
- [`docs/decisions/README.md`](../../decisions/README.md), and then every record in
  `docs/decisions/`, including the superseded ones
- [`docs/next/WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md) — statuses only on a first pass, not the notes
- The `S-*` slice documents in `docs/next/`, for what each session found

Do not read `docs/review/` except [`docs/review/SESSION-LOG.md`](../../review/SESSION-LOG.md). The
rest governs the old codebase, and a session that reads it starts proposing repairs to code that is
being deleted.

## The work

Three passes, and the order matters.

**Read every accepted decision against every other, and look for contradiction rather than
overlap.** Two records that cover the same ground and agree are fine. Two that cannot both be true
are a finding, and a finding of that kind stops the work.

**For every load-bearing claim, read the code rather than a summary.** `docs/map/` and the slice
documents were written by other sessions at other times. Three claims taken from them on 2026-08-12
were contradicted by the code, and two had already been built on before anyone checked.

**For every decision, ask what is built against it, and whether what is built still matches.** A
decision with nothing built against it is not a problem; a decision contradicted by what was built
is.

## Deliverable

**A document in `docs/next/` the owner can read in one sitting.** Plain language. Any term that
cannot be avoided is defined where it is used. It says what the product does today, what each
accepted decision decided in one line, which decisions have been overtaken and by what, and what is
built against what is only decided. It is written to be disagreed with, not to reassure.

**Bound by a test**, per §`When a document counts as documentation`. In both directions at minimum:
every record in `docs/decisions/` has exactly one line in the document, and no line names a record
that does not exist. That check alone would have caught the index silently missing `0025` and `0026`.
Consider also binding the supersession column against each record's own `Status` line, which is what
would have caught `0019`'s stranded rename rule.

## Rules

- Product decisions are the owner's. Present them with options and costs, and wait. Engineering
  decisions are yours: decide, then say what it cost.
- **A contradiction between two accepted records is not yours to resolve.** One of them has to be
  reversed and which one is a product question. Present it with what each reversal would cost, and
  wait.
- Where a decision rests on what the old implementation did, read the old implementation. The map
  names the file; it is not the evidence.
- Record each finding when you make it, not at the end. If you defer, say so plainly.
- Mutation-test every new guard in both directions and record which directions were observed.
- Rows in `WHAT-THE-OLD-APP-HAD.md` are replaced whole by
  [`next/tools/Replace-InventoryRow.ps1`](../../../next/tools/Replace-InventoryRow.ps1), never edited in
  part. See `F-S17-6`.
- `src/SecureAD.*` and `tests/SecureAD.*` are frozen.
- Scratch files are written to `$env:TEMP`, never inside the repository. Four were committed by
  accident on 2026-08-12 because `git add -A` ran against a file list that was counted rather than
  read.

## Finish by

- Writing `docs/next/S-19-[slug].md` in the [`docs/review/TEMPLATE.md`](../../review/TEMPLATE.md)
  shape, recording what the cross-reading found
- Naming both documents in [`docs/next/README.md`](../README.md) §`Status`, which
  `RebuildStatusDocumentationTests` requires
- Removing the section headed *Owed: a point-in-time review* from
  [`docs/next/README.md`](../README.md), since it
  will no longer be owed
- Appending one entry to [`docs/review/SESSION-LOG.md`](../../review/SESSION-LOG.md), in plain
  language
- Running `dotnet build next/SecureAD.Next.sln` and the full test suite
- **Reading** `git status --porcelain` over the whole repository — reading the list, not counting it
  — and `git diff --numstat` before committing
- Committing, with the message written to a file outside the repository rather than a here-string
