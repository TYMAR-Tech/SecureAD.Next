# S-25 — Finishing the audit database schema (ledger row C1)

## Scope

This session takes **row C1 to `Done`**. It is the only row in the tree reading
`Decided, rebuilding after review`, and the build is red.

`S-24` rebuilt half of it. An object is now one row with typed columns derived from the attribute
catalogue, per [`0022`](../../decisions/0022-objects-are-stored-as-typed-columns.md), and
[`S-16`](../S-16-the-bundle.md) describes the shape the code creates. **The security-descriptor half
was not touched**, so `BundleSchema.cs` currently holds current and superseded work side by side with
nothing marking the boundary — which is how the missing descriptor deduplication survived a full day
of work inside that file.

**Ten things are owed.** Six are C1 instructions never built, three are findings `S-24` raised and
did not repair, and one is a decision made after `S-24` began:

1. **Deduplicate security descriptors** — one row per distinct descriptor keyed on SHA-256 of its
   bytes with the length beside it, objects referencing it, carrying owner, group, DACL state,
   protected flag, entry-set hash and parse errors. Measured 4.81 GB down to 1.24 GB per 100k
   objects, and removes three quarters of the parsing and inserting.
2. **Store entry sets once per descriptor** rather than once per object.
3. **Store the raw descriptor bytes** — about 13% on top of the parsed entries, so a parser defect is
   recoverable by re-analysis rather than by recapturing a customer's forest.
4. **A row for a descriptor that could not be read at all**, per object and as a run total. A
   production domain returned 19,927 of 100,000 objects with no readable descriptor and nothing
   distinguished them from objects that grant nothing.
5. **Record what was never captured by reference** — a group member, permission trustee, parent
   container or primary group that something pointed at and nothing ever saw, each carrying why, from
   the closed set in `0022` with no free text beside it.
6. **Adopt from the predecessor**: `dn_reversed` so a subtree query is an indexed prefix scan,
   `parent_guid`, per-row capture time, the domain on the object, per-object entry counts, and
   somewhere to record a trustee that could not be resolved and why.
7. **Set `page_size` with the schema** — it cannot be changed after the first table exists, and
   production descriptors average 31,742 bytes against a 4 KB default page.
8. **`EvidenceObject` carries the coverage it was read under** — the owner's decision on `F-S24-7`.
   This is what turns the build green: gate 4 fires today because removing the object's completeness
   left the type unable to say whether it looked.
9. **Record the connection security level each controller was read over** — `F-S24-1` option C, so a
   run that read a partition unencrypted says so rather than letting a reader assume coverage.
10. **One partition-coverage type**, per [`0035`](../../decisions/0035-coverage-is-recorded-once-per-capture-unit.md).
    `PartitionCoverage` and `PartitionCoverageRecord` are twins with identical fields defined in two
    projects. Collapse them into one, defined in `SecureAD.Evidence`, and give the configuration and
    schema partitions somewhere that is not domain-shaped.

**Produces:** the finished schema and writer, `S-16` revised again if the shape moves,
`docs/next/S-25-[slug].md` recording what was found, and row C1 reading `Done`.

**Out of scope, and this matters more than usual for this session.** The capture-to-bundle seam
(**B9**, **B10**, **C15**) — that is the next session and this one must not absorb it. View
definitions (**C2**). The suppression sidecar (**C5**). The noise list and comprehensive switch from
[`0034`](../../decisions/0034-capture-excludes-a-shipped-noise-list.md) (**B2**, **B6**).
`CapturedObject.Completeness`, which is `F-S24-9` and belongs with the seam. Anything in branch A.

## Read first

In order, and **row C1 before any code**:

- [`docs/next/WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md) — row **C1**, in full. It is several thousand words
  and it carries the measurements, the reasoning and the instructions this session exists to build.
  `S-24` worked from `S-16` and `0022` without opening it, which is the whole reason ten things are
  still owed. Also rows **C2**, **C5**, **C10**, **C11**, **C15**, which this session must not absorb
- [`docs/next/S-24-the-audit-database-schema.md`](../../history/S-24-the-audit-database-schema.md) — what the
  previous session found, repaired and got wrong. `F-S24-10` is the descriptor gap, `F-S24-7` is the
  red build, `F-S24-1` is the connection-security obligation. Note `F-S24-5`, which was raised in
  detail and **withdrawn as false** — a reminder to check what calls a thing before reasoning about it
- [`docs/next/READING-ORDER.md`](../READING-ORDER.md) — the path an object takes through the code, if
  the writer and the schema are not already familiar
- [`docs/next/S-16-the-bundle.md`](../S-16-the-bundle.md) — the document bound to this schema in both
  directions by `BundleDocumentationTests`. Every new table needs a row **and an honest statement of
  what its absence means**
- [`docs/next/S-20-what-a-bundle-stores.md`](../../history/S-20-what-a-bundle-stores.md) — the measurements
  behind instructions 1 to 4, and `F-S20-14`, `F-S20-16`, `F-S20-17`
- [`docs/next/README.md`](../README.md) — §`Tests`, §`Gates`, §`The ledger`,
  §`How to continue this work`, §`When a document counts as documentation` and §`Status`
- The decisions that govern this row:
  [`0001`](../../decisions/0001-no-backward-compatibility.md),
  [`0002`](../../decisions/0002-absent-view-means-degraded-run.md),
  [`0013`](../../decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md),
  [`0015`](../../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md),
  [`0022`](../../decisions/0022-objects-are-stored-as-typed-columns.md),
  [`0027`](../../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md),
  [`0032`](../../decisions/0032-a-decision-record-is-corrected-in-place.md),
  [`0033`](../../decisions/0033-nothing-inherited-is-definitive.md) and
  [`0035`](../../decisions/0035-coverage-is-recorded-once-per-capture-unit.md)
- The code: [`next/src/SecureAD.Evidence/`](../../../next/src/SecureAD.Evidence) —
  `BundleSchema.cs` and `BundleWriter.cs` are half rebuilt. `EvidenceObject.cs` was rebuilt and needs
  the coverage reference. `BundleLayout.cs`, `BundleSealing.cs` and everything under `Run/` are not
  this row's

## Rules

- **One row. Do not widen.** Anything discovered that is not C1 is recorded as a finding in the slice
  document and **not acted on**. The previous session was individually justified at every step and
  finished nothing.
- **A document is not the truth unless it says it decided something.** Only `docs/decisions/` with
  `Status: Accepted`, or a finding carrying an explicit **Decision:**, states the product's position.
  Everything else is argument.
- **Check who calls a thing before proposing to remove or change it.** Four findings in `S-24` were
  wrong because a type's shape was read as its purpose.
- **Every new table needs its emptiness interpreted** in `S-16`, per `0002`. A table whose absence
  nobody has explained fails `BundleDocumentationTests`.
- **Mutation-test every new guard in both directions**, record which directions were observed, and
  revert before running anything long.
- **The descriptor hash is cryptographic**, because a collision silently misattributes one object's
  permissions to another.
- Do not delete `F-S24-5`. A withdrawn finding is evidence of how an error entered.

## Finish by

- Row **C1** reads `Done` in the ledger, with the Docs column naming what binds it
- The build is green — all 871 tests, including gate 4
- `BundleSchema.cs` holds no pre-review work, and nothing in the tree still says half of it is awaiting rebuild
- Two objects sharing a descriptor produce **one** stored descriptor and **one** stored entry set, asserted by a test
- An object whose descriptor could not be read is distinguishable from one that grants nothing, asserted by a test
- `S-16` names every table the schema creates, in both directions
- The warning box in [`docs/next/README.md`](../README.md) no longer names the schema
- `docs/next/S-25-[slug].md` exists, recording what was found and what was got wrong
