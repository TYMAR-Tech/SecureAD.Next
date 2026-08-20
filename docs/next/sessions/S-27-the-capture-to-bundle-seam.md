# S-27 — The capture-to-bundle seam

## Scope

This session builds **the entry point that runs a capture into a bundle** — ledger row **C15** —
and settles what rows **B9** and **B10** still owe. Work in `next/`, and build and test with
`next/SecureAD.Next.sln`.

**Read the three rows before believing their status.** They read `Decided, rebuilding after review`,
and the reading that produced this prompt suggests that is no longer accurate: `BundleWriter`
already exposes `WriteCoverage`, `WriteObject`, `WriteSecurityDescriptor`,
`WriteUnreadableSecurityDescriptor`, `WriteUnresolvedReference` and `Complete`, and
`BundleWriterTests` exercises them. If B9 and B10 are in substance built, say so and replace the
rows. If they are not, say what is missing. **Do not take this paragraph as the answer** — it is
one reading, and [`0033`](../../decisions/0033-nothing-inherited-is-definitive.md) applies to
prompts as much as to anything else.

**What is certainly missing is the join.** Nothing in `next/src` calls `BundleWriter` — only tests
do. Connect is done, capture is done, the schema is done, run identity is done, and **the product
has never run end to end**. This session is the first code that takes what capture reads and puts
it where storage expects it.

**Why now.** Two sessions of decisions have landed in the parser and the schema —
[`0037`](../../decisions/0037-an-unreadable-dacl-says-so.md) and
[`0038`](../../decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md), and with them
`DaclState.Unreadable`, `DaclCompleteness`, `dacl_was_canonical` and the `ace_type` fallback. Every
one is tested against fixtures and **none has ever been exercised on a path that starts at a
directory**. A seam is where fixture-shaped assumptions meet each other.

**Out of scope.** Group membership (**B11**), principal resolution (**B12**), anything in branch E,
view definitions (**C2**), the suppression sidecar (**C5**), and the run library (**F13**–**F16**,
deferred to phase 3). If the seam cannot be built without one of those, that is a finding and a
handover, not a reason to start it.

## Read first

In order:

- [`docs/next/README.md`](../README.md) — §`Tests`, §`Gates`, §`The ledger`,
  §`How to continue this work` and §`Status`. §`Tests` governs this session for the reason under
  **The danger** below
- [`docs/next/WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md) — rows **B9**, **B10** and **C15** in full, and
  **B20**, which holds five findings handed forward for *the row that produces a run*. This is
  plausibly that row; decide whether it is
- [`docs/next/S-15-storage-dispositions.md`](../../history/S-15-storage-dispositions.md) — where all three rows
  were decided in full on 2026-08-12, including the ruling that there is **one** way to run a
  capture and it is a command
- [`docs/next/S-16-the-bundle.md`](../S-16-the-bundle.md) — what a bundle holds, what each table is
  for, and the two sections added on 2026-08-13 about an unreadable DACL and about `ace_type`
- [`docs/next/S-12-the-capture-passes.md`](../S-12-the-capture-passes.md) and
  [`docs/next/S-9-the-capture-unit.md`](../S-9-the-capture-unit.md) — what capture produces and in
  what order
- [`docs/decisions/0029-a-run-that-ends-badly-says-so.md`](../../decisions/0029-a-run-that-ends-badly-says-so.md)
  — because the interesting half of this seam is what happens when capture stops partway
- [`docs/decisions/0035-coverage-is-recorded-once-per-capture-unit.md`](../../decisions/0035-coverage-is-recorded-once-per-capture-unit.md)
  — coverage is written per capture unit, and this is the code that writes it
- [`docs/decisions/0020-the-seal-detects-corruption-not-tampering.md`](../../decisions/0020-the-seal-detects-corruption-not-tampering.md)
  — what the seal claims, which decides when it may be written

**The shape already built, which this session wires rather than designs.** `BundleWriter.Create`
writes to `evidence.db.partial` and `Complete` promotes it; `BundleSealing.Seal` writes the seal;
`RunOutcomeFile.Write` records how a run ended; `BundleLayout` owns every file name.
`SecureAD.Audit` already references `SecureAD.Evidence`, so the seam has somewhere to live.

## The danger this session carries, which the last one did not

**There is no oracle here.** `S-21` could read the parser against `[MS-DTYP]` because a published
specification says what the bytes mean. `GoldenAceHashTests` could prove the port changed nothing
because the predecessor's hashes were recorded before it. **Nothing says what a correct bundle looks
like for a given capture.** The tests for this seam will be invented, and an invented test agrees
with the code by construction — it encodes what the author believed while writing both.

Two guards, and they are the reason §`Tests` is named above:

- **Test the seam against the two sides' own rules, not against itself.** A written object must
  satisfy what `S-16` says the tables mean; a run that stopped must satisfy what `0029` says a run
  says about itself. Those are independent of whatever this session writes.
- **Prefer a test that would fail if the seam did nothing at all.** A test that passes against an
  empty implementation is measuring the fixture.

## Rules

- Product decisions are the owner's. Present them with options and costs, and wait. Engineering
  decisions are yours: decide, then say what it cost. **A brief saying "decide X" is not delegation
  of a product decision.**
- **Nothing inherited is definitive**, per [`0033`](../../decisions/0033-nothing-inherited-is-definitive.md).
  That includes this prompt's reading of B9 and B10, and it includes `S-15`, which decided these
  rows six days ago against a schema that has since changed.
- **A golden value that needs editing is a finding, not a fix.** See §`Tests`.
- **When a decision is made, sweep what it invalidates in the same breath** — every document, ledger
  row, comment and test that repeated the old claim. Not at the end of the session. Two records have
  now been corrected the same day they were written for want of this.
- Records are corrected in place per
  [`0032`](../../decisions/0032-a-decision-record-is-corrected-in-place.md), Context sections
  excepted. The test is: *would a grep hit on this line, with no surrounding context, mislead
  someone?*
- **Mutation-test every new guard in both directions and record which directions were observed.**
  Force a non-incremental build between mutating and reverting, verify the mutation actually
  applied before trusting a pass, revert from a baseline held outside the repository, and verify the
  revert by an anchored match. A stale build and a silently unapplied mutation have each produced a
  false result in the last two sessions.
- Rows in `WHAT-THE-OLD-APP-HAD.md` are replaced whole by
  [`next/tools/Replace-InventoryRow.ps1`](../../../next/tools/Replace-InventoryRow.ps1), never edited in
  part. See `F-S17-6`.
- `src/SecureAD.*` and `tests/SecureAD.*` are frozen.
- Scratch files are written to `$env:TEMP`, never inside the repository. Do not stage with
  `git add -A`; name the files.
- No multi-line here-strings in PowerShell. Write long text to a file and read it.
- **Scripted edits to a source file use `UTF8Encoding($false)`.** PowerShell's `-Encoding UTF8`
  adds a byte-order mark and re-encodes existing punctuation, which has corrupted files in this
  repository twice.

## Finish by

- Writing `docs/next/S-27-[slug].md` in the [`docs/review/TEMPLATE.md`](../../review/TEMPLATE.md)
  shape, with a status on every finding and a **verified-safe** section that is not empty
- **Answering what a run produces when capture stops partway** — which files exist, what the run
  outcome says, whether the evidence is promoted or left partial, and whether the seal is written.
  A bundle that cannot say how it ended is the failure [`0029`](../../decisions/0029-a-run-that-ends-badly-says-so.md)
  exists to prevent
- **Saying whether the first three new schema fields survive contact with a real path** —
  `dacl_state = Unreadable`, `dacl_completeness` and `dacl_was_canonical` are written by
  `BundleWriter` and produced by `SecurityDescriptorParser`, and nothing has yet carried a value
  from one to the other
- Replacing rows **B9**, **B10** and **C15**, and any other row this session's findings change
- Deciding whether **B20**'s five handed-forward findings are owed to this row, and recording the
  answer either way
- Adding any new public type to [`SURFACE-REGISTER.md`](../SURFACE-REGISTER.md) and
  [`CONCEPT-REGISTRY.md`](../CONCEPT-REGISTRY.md) where it owns a question
- Naming the slice document in [`docs/next/README.md`](../README.md) §`Status`, which
  `RebuildStatusDocumentationTests` requires
- Adding the new documents to `next/SecureAD.Next.sln` so they appear in Solution Explorer,
  preserving the file's byte-order mark
- Appending one entry to [`docs/review/SESSION-LOG.md`](../../review/SESSION-LOG.md), in plain
  language
- Running `dotnet build next/SecureAD.Next.sln` and the full test suite
- **Reading** `git status --porcelain` over the whole repository — reading the list, not counting it
  — and `git diff --numstat` before committing
- Committing, with the message written to a file outside the repository rather than a here-string
