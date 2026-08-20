# S-24 — The audit database schema (ledger row C1)

## Scope

This session builds **the schema a bundle holds**: the tables and indexes of `evidence.db`, and the
types that write them.

Capture is finished — B2, B4, B6, B7 and B8 are all `Done` — and it has nowhere to put what it
reads. Nothing downstream of capture can begin until this exists: not the membership graph at B11,
not principal resolution at B12, not a single rule at branch E. This is the row the tree is waiting
on.

It is also the largest **untrue** thing in the tree. `next/src/SecureAD.Evidence/` holds a schema and
writers built on 2026-08-12 and superseded by review the following day. Four decisions contradict
that code, `docs/next/README.md` carries a warning box telling readers not to trust it, and five
ledger rows have read `rebuilding after review` since. A warning box works until somebody skims past
it.

**Produces:** the schema in code, [`S-16`](../S-16-the-bundle.md) revised to match, a test binding
the two in both directions, and `docs/next/S-24-[slug].md` recording what was found.

**Out of scope:** view definitions (**C2**); the bundle's layout and lifecycle on disk (**C10**); the
seal (**C11**); the write-path entry points (**C15**); the suppression sidecar (**C5**). Those are
the other `rebuilding after review` rows and they are separate sessions. Also out of scope: the rule
catalogue, and anything that reads a bundle.

## Read first

In order:

- [`docs/next/README.md`](../README.md) — §`Tests`, §`Gates`, §`The ledger`,
  §`How to continue this work`, §`When a document counts as documentation` and §`Status`. The
  warning box about `SecureAD.Evidence` sits inside §`How to continue this work` and is about the
  code this session replaces
- [`docs/next/S-16-the-bundle.md`](../S-16-the-bundle.md) — the design as it stands, and the document
  this session revises. **Read its table list against `0022` before believing either**
- [`docs/next/S-23-what-capture-must-read.md`](../S-23-what-capture-must-read.md) — what capture
  actually reads, derived from all sixty-two rules. **This is C1's input**, and it is the reason this
  session comes after that one: a schema of typed columns has to name every attribute, so it cannot
  be written until the list of attributes is settled
- [`docs/next/S-20-what-a-bundle-stores.md`](../../history/S-20-what-a-bundle-stores.md) — the measurements, and
  `F-S20-14`, which is the defect that made the case for challenging the inherited shape at all
- [`docs/next/S-15-storage-dispositions.md`](../../history/S-15-storage-dispositions.md) — the dispositions, and
  `F-S15-9`, which is three claims taken from the map and contradicted by the code
- The decisions that govern this row, all of them:
  [`0001`](../../decisions/0001-no-backward-compatibility.md),
  [`0002`](../../decisions/0002-absent-view-means-degraded-run.md),
  [`0013`](../../decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md),
  [`0015`](../../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md),
  [`0020`](../../decisions/0020-the-seal-detects-corruption-not-tampering.md),
  [`0021`](../../decisions/0021-re-analysis-produces-a-new-bundle.md),
  [`0022`](../../decisions/0022-objects-are-stored-as-typed-columns.md),
  [`0031`](../../decisions/0031-there-is-no-assessment-mode.md),
  [`0032`](../../decisions/0032-a-decision-record-is-corrected-in-place.md) and
  [`0033`](../../decisions/0033-nothing-inherited-is-definitive.md)
- [`docs/next/WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md) — row **C1**, and rows **C2**, **C5**, **C10**,
  **C11**, **C15**, which are the sessions this one must not absorb
- The code being replaced: [`next/src/SecureAD.Evidence/`](../../../next/src/SecureAD.Evidence) —
  `BundleSchema.cs`, `BundleWriter.cs` and `EvidenceObject.cs` are built to the shape `0022`
  replaced. `BundleLayout.cs`, `BundleSealing.cs` and everything under `Run/` may not be

## The work

**1. Two governing documents contradict each other. Settle that before writing any code.**
[`S-16`](../S-16-the-bundle.md), under its heading *The tables*, lists `captured_attribute` and
`attribute_value` — one row per object per attribute, with completeness recorded per attribute
because *"withheld and unset
are the same emptiness"*. [`0022`](../../decisions/0022-objects-are-stored-as-typed-columns.md)
**replaced exactly that**, with one row per object and typed columns. A session that builds to both
builds neither. Say which is authoritative, correct the other in place per
[`0032`](../../decisions/0032-a-decision-record-is-corrected-in-place.md), and say plainly that the
two disagreed — because the next reader will find the same contradiction and needs to know it was
seen rather than missed.

**2. `0022`'s stated reason has been withdrawn, and the conclusion may still be right. Separate
them.** `0022` justifies dropping the withheld-versus-unset distinction like this: *"per Microsoft's
own account a base schema attribute cannot be marked confidential at all — which covers the
attributes this product captures."* Both halves now fail.

- **The general claim was withdrawn on 2026-08-11.** [`S-8`](../S-8-captured-attribute-catalogue.md)
  §*Absence is answered from the forest's own schema* records that Microsoft ships
  `msFVE-RecoveryPassword` with `systemFlags` `0x10` **and** a `searchFlags` with bit 128 set, which
  the one-line rule says cannot happen. The interpretation is owed to B8 as `F-S7-27`.
- **The coverage claim failed on 2026-08-13.** S-23 added `ms-Mcs-AdmPwdExpirationTime` and
  `msLAPS-PasswordExpirationTime`, which are **schema extensions, not base schema**, and are exactly
  the kind that can be marked confidential and withheld without an error.

**What that costs a customer, concretely.** If the distinction is not stored, a computer whose LAPS
timestamp capture was refused is indistinguishable from a computer with no LAPS at all — and SEC-091
reports **LAPS missing** on a machine that is correctly protected. A false finding, on a rule fixed
the day before. It needs an answer for at least those two attributes. **Whether to store the
distinction for all attributes, for the schema extensions only, or not at all is a product decision:
present the options with their costs and wait.**

**3. Build the schema, and make the count of attributes derived rather than typed.** Typed columns
means the schema names every single-valued attribute as a column and gives every multi-valued one a
table. That list is `CapturedAttributeCatalog`, and it must be **read from it**, not copied beside
it — a hand-kept second list agrees on the day it is written and stops agreeing silently, which is
the defect gate 2 exists for and which `RangeLiable` already avoids. `0022` says *"capture collects
45 attributes per object"*; do not carry that number forward. Write the command that produces it.

**4. Decide what survives in `next/src/SecureAD.Evidence/`, deliberately.**
[`docs/next/README.md`](../README.md) says outright that this is part of this session and not a
tidy-up: the bundle layout, the partial-file mechanism and the guards were judged to survive, and
the schema, the writer and the object type were not. Check that judgement rather than inherit it —
[`0033`](../../decisions/0033-nothing-inherited-is-definitive.md) applies to work this rebuild did
last week as much as to the predecessor. Anything deleted is named, with what it did.

**5. Bind the schema to the document in both directions**, as row C1 owes: a table named in
[`S-16`](../S-16-the-bundle.md) and absent from the code fails the build, **and** a table in the code
and absent from the document fails it. Carry a scanner self-test, because a check that parses an
empty schema against an empty table list reports a clean result and measures nothing — the failure
this repository has committed three times. Mutation-test in both directions and record which
directions were observed.

**Specific questions this session should answer:**

- **Which of `S-16` and `0022` is authoritative, and what did the other get wrong?** Not *which is
  newer* — which is right, and why.
- **Can a captured attribute be withheld, and does the bundle need to say so?** Answered per
  attribute from the forest's own schema rather than from a list, per
  [`0014`](../../decisions/0014-capture-reads-the-schema-partition.md), because `searchFlags` and
  `systemFlags` are already captured for exactly this.
- **What does an unseen object look like in the schema?** `0022` says the real risk is not an
  attribute that did not arrive but **an object nobody could see**, absent from a search with no row
  and no error, taking its permissions with it. `S-16` answers this with `partition_coverage`.
  Confirm the two answers are the same answer.
- **Does the schema record what was pointed at and never seen?** `0022` requires it — a group
  member, a permission trustee, a parent container, a primary group — each with a reason. Check that
  `S-16`'s `trustee` table is that mechanism, or that something else is.
- **Which of the ten tables in `S-16` does no consumer need?** The reverse of what S-23 asked of
  capture, and the same discipline: a table nobody reads is a table somebody will fill.

## Rules

- Product decisions are the owner's. Present them with options and costs, and wait. Engineering
  decisions are yours: decide, then say what it cost. **A brief saying "decide X" is not delegation
  of a product decision.**
- **A new rule must state what it looks for and what an organisation running this audit can thereby
  mitigate.** The owner's standing instruction of 2026-08-13. It does not arise in this session, but
  it binds anything at branch E that this schema is shaped for.
- **Say whether a claim was read or searched.** A `git grep` count is not a reading. When a claim is
  load-bearing, open the file. This session's whole first work item exists because a decision was
  written from a summary of Microsoft's documentation rather than from the page.
- **Do not type a count into a finding. Write the command that produces it**, next to the number, and
  **run the command as written**.
- `src/SecureAD.*` and `tests/SecureAD.*` are frozen. `next/` is where work happens.
- Scratch files go to `$env:TEMP`, never inside the repository. Do not stage with `git add -A`; name
  the files.
- **Never revert a mutation with `git checkout` on a file that also holds uncommitted work** — it
  discards both. Put the original substring back instead. S-23 lost an hour of edits this way.
- **Do not write a document back with `Set-Content -Encoding utf8`.** Windows PowerShell 5.1 adds a
  BOM and re-encodes; S-23 corrupted a file this way. Read and write bytes through
  `[IO.File]::ReadAllBytes` and `WriteAllBytes`, and check `git diff --numstat` after any scripted
  edit.
- **Run a mutation one per command.** A cancelled multi-mutation script left one applied and
  unreverted in S-23, and again in the session that built B2. It was found by reading the file back,
  not by any check.

## Finish by

- Writing `docs/next/S-24-[slug].md` in the [`docs/review/TEMPLATE.md`](../../review/TEMPLATE.md)
  shape, with a status on every finding and a **verified-safe** section that is not empty
- **Answering the five specific questions above**, or saying plainly which could not be answered
- Correcting whichever of [`S-16`](../S-16-the-bundle.md) and
  [`0022`](../../decisions/0022-objects-are-stored-as-typed-columns.md) is wrong, **in place**, and
  saying that they disagreed
- Recording against `0022` that its confidential-attribute reasoning was withdrawn, and against
  **B8** what the withheld-versus-unset answer turned out to be
- Naming what was deleted from `next/src/SecureAD.Evidence/` and what it did
- Updating ledger row **C1**, and any of **C10**, **C11**, **C15** whose status this changes
- Naming the slice document in [`docs/next/README.md`](../README.md) §`Status`, which
  `RebuildStatusDocumentationTests` requires, and removing the warning box if it is no longer true
- Adding the new documents to `next/SecureAD.Next.sln`
- Appending one entry to [`docs/review/SESSION-LOG.md`](../../review/SESSION-LOG.md), in plain
  language
- Running `dotnet build next/SecureAD.Next.sln` and the full test suite
- **Reading** `git status --porcelain` over the whole repository — reading the list, not counting it
  — and `git diff --numstat` before committing
- Committing, with the message written to a file outside the repository rather than a here-string
