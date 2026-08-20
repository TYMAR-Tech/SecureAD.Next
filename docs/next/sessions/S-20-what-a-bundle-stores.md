# S-20 — What a bundle stores

## Scope

This session rebuilds **C1, the evidence schema** — the tables a run writes its findings about a
forest into. Work in `next/`, and build and test with `next/SecureAD.Next.sln`.

It covers the schema and nothing else. **The writers that fill it are B9, B10 and C15 and are not in
scope**, nor is the seal at C11, nor the sidecar at C5. One row, or a small group, per session.

**The code being replaced is already in the tree.** `next/src/SecureAD.Evidence/BundleSchema.cs` and
`EvidenceObject.cs` were written on 2026-08-12 and superseded by review the following day. They store
an object's attributes as name/value rows, which
[`0022`](../../decisions/0022-objects-are-stored-as-typed-columns.md) replaced with typed columns.
**Deciding what survives from that code is part of this session**, not a tidy-up afterwards — the
bundle layout and the guards are worth keeping and the storage shape is not.

## Why this session is next

**Nothing runs end to end, and this is the first of the things that stop it.** A connection can be
opened, a partition can be read, and there is nowhere correct to put what comes back. Capture's
types and the bundle's do not meet, and the row that joins them is B20, which cannot be written
against a schema that contradicts three accepted decisions.

Gate 5b — every public type reachable from something that runs — has been blocked three times and
its trigger has moved twice. It is the gate `docs/next/README.md` says gets more expensive every
week it is deferred. This session does not unblock it, but nothing can until storage is right.

## Read first

In order:

- [`docs/next/README.md`](../README.md) — §`Gates`, §`Tests`, §`How to continue this work`, and
  §`Status`. The block headed *The code in `SecureAD.Evidence` does not match the decisions* is the
  one that governs this session
- [`docs/next/POINT-IN-TIME-REVIEW.md`](../../history/POINT-IN-TIME-REVIEW.md) — what the product does today and
  what every decision decided, in one sitting
- [`docs/decisions/README.md`](../../decisions/README.md), then
  [`0022`](../../decisions/0022-objects-are-stored-as-typed-columns.md),
  [`0002`](../../decisions/0002-absent-view-means-degraded-run.md),
  [`0013`](../../decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md),
  [`0001`](../../decisions/0001-no-backward-compatibility.md),
  [`0017`](../../decisions/0017-capture-reads-the-whole-forest.md),
  [`0020`](../../decisions/0020-the-seal-detects-corruption-not-tampering.md),
  [`0023`](../../decisions/0023-a-finding-has-a-stable-identity.md),
  [`0027`](../../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md),
  [`0030`](../../decisions/0030-the-product-produces-sealed-evidence-never-signed.md),
  [`0032`](../../decisions/0032-a-decision-record-is-corrected-in-place.md) and
  [`0033`](../../decisions/0033-nothing-inherited-is-definitive.md)
- [`docs/next/WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md) — row C1, which carries the decided shape, and the
  rows around it
- [`docs/next/S-16-the-bundle.md`](../S-16-the-bundle.md) — the document this session must bring back
  into agreement with the code, and [`S-15`](../../history/S-15-storage-dispositions.md) for why each
  disposition was chosen
- [`docs/next/CONCEPT-REGISTRY.md`](../CONCEPT-REGISTRY.md) and
  [`SURFACE-REGISTER.md`](../SURFACE-REGISTER.md) — both gain entries when a public type does

Read the old implementation where a decision rests on what it did. `docs/map/` names the file; per
[`0033`](../../decisions/0033-nothing-inherited-is-definitive.md) it is not the evidence.

## The work

**Decide what survives from the superseded code before writing anything.** The bundle layout, the
partial-file mechanism and the guards were judged worth keeping; the name/value storage was not.
Say which, and why, in the slice document.

**Build the schema `0022` specifies.** An object is one row of typed columns keyed on `objectGUID`.
Single-valued attributes are columns; multi-valued attributes get their own tables. There is no
per-attribute record of what did not arrive.

**Make a missing row unambiguous.** This is the part that matters and the reason C1 is not a
mechanical translation. An object with no permission rows either had no permissions or was never
read, and those are opposite findings that look identical. Coverage is recorded **positively, as
rows**, never inferred from absence. A security descriptor that failed to parse stores its errors,
because zero ACEs with no errors means *this object grants nothing* and zero ACEs with errors means
*nobody knows what this object grants*.

**Record what was never captured by reference.** A group member, a permission trustee, a parent
container or a primary group that something pointed at and nothing ever saw, each carrying why.

**Adopt from the predecessor what earned its place**, having read it rather than the map's summary
of it: `dn_reversed` so a subtree query is an indexed prefix scan, `parent_guid`, per-row capture
time, the domain on the object, a deleted flag, per-object entry counts, and somewhere to record a
trustee that could not be resolved and why. `AddColumnIfMissing` does not come across — it is a
migration engine in a product that does not migrate.

## Rules

- Product decisions are the owner's. Present them with options and costs, and wait. Engineering
  decisions are yours: decide, then say what it cost. **A brief saying "decide X" is not delegation
  of a product decision.**
- **When a decision is made, sweep what it invalidates in the same breath** — every document, ledger
  row, comment and test that repeated the old claim. Not at the end of the session. On 2026-08-12
  two records were found wrong within hours of being written, because the ground moved and the sweep
  waited.
- Records are corrected in place per [`0032`](../../decisions/0032-a-decision-record-is-corrected-in-place.md),
  Context sections excepted. The test is: *would a grep hit on this line, with no surrounding
  context, mislead someone?*
- Nothing inherited is definitive, per [`0033`](../../decisions/0033-nothing-inherited-is-definitive.md).
- A golden value that needs editing is a finding, not a fix. See §`Tests`.
- Mutation-test every new guard in both directions and record which directions were observed. Revert
  from a baseline held outside the repository, and verify the revert by an anchored match rather than
  a substring — a revert check that passed while measuring nothing cost a session an hour on
  2026-08-12.
- Rows in `WHAT-THE-OLD-APP-HAD.md` are replaced whole by
  [`next/tools/Replace-InventoryRow.ps1`](../../../next/tools/Replace-InventoryRow.ps1), never edited in
  part. See `F-S17-6`.
- `src/SecureAD.*` and `tests/SecureAD.*` are frozen.
- Scratch files are written to `$env:TEMP`, never inside the repository. Do not stage with
  `git add -A`; name the files.
- No multi-line here-strings in PowerShell. Write long text to a file and read it.

## Finish by

- Bringing [`S-16`](../S-16-the-bundle.md) back into agreement with the code, bound in both
  directions against the tables SQLite reports in a real database rather than against a list in the
  code
- Adding any new public type to [`SURFACE-REGISTER.md`](../SURFACE-REGISTER.md) with the ledger row
  expected to consume it, and to [`CONCEPT-REGISTRY.md`](../CONCEPT-REGISTRY.md) where it owns a
  question
- Replacing row C1 in [`WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md), and any other row this session's
  decisions change
- Writing `docs/next/S-20-[slug].md` in the [`docs/review/TEMPLATE.md`](../../review/TEMPLATE.md)
  shape, with a status on every finding
- Naming the slice document in [`docs/next/README.md`](../README.md) §`Status`, which
  `RebuildStatusDocumentationTests` requires
- Adding the new documents to `next/SecureAD.Next.sln` so they appear in Solution Explorer
- Appending one entry to [`docs/review/SESSION-LOG.md`](../../review/SESSION-LOG.md), in plain
  language
- Running `dotnet build next/SecureAD.Next.sln` and the full test suite
- **Reading** `git status --porcelain` over the whole repository — reading the list, not counting it
  — and `git diff --numstat` before committing
- Committing, with the message written to a file outside the repository rather than a here-string
