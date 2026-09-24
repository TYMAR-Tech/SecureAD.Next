# P-280 — the occurrence rows, and the name written on each of them three times

**Status: open, nothing built.** This says what the change must do and what must be
measured before its scope can be chosen. The before-measurement already exists in
`next/artifacts/p279-after`; no new run is needed to start.

## What is wrong, and what is not

After `P-279` a judgement is almost entirely one table. On the measured synthetic
bundle, `permission_classification_entry` holds **17,164,866 rows in a 7,189,590,016
byte store** — about **419 bytes per row** — while `permission_entry`, which P-279
fixed, holds 24,098.

**These rows are not duplicates, and nothing here may delete one.** Each is the
distinct fact *this object, at this position, carries that entry*. An object with 521
permissions needs 521 of them. Dropping any is losing a permission the product is
required to report, which is the one thing an audit tool must never do.

What repeats is the **attribution**. The object's distinguished name is written
**three times per occurrence**:

1. in the row, as `target TEXT`
2. in the primary key, `PRIMARY KEY(target, position)`
3. in the unique index, `UNIQUE(target, ordinal)`

## The size, on the owner's own forest

From `securead-cli --describe` against the production capture
`ad.ssa.gov-20260924-020431`, taken 2026-09-24:

| | |
|---|---|
| Objects captured | 940,067 |
| Objects with unreadable permissions | 280,871 |
| **Objects carrying readable permissions** | **659,196** |
| Distinct descriptors | 271,901 |
| Entry positions across all descriptors | 141,739,074 |
| Distinct entries | 522,807 |
| Sealed evidence | 18.67 GB |

659,196 objects at 521 entries each is **about 344 million occurrence rows**, and at
419 bytes each that is **~134 GB of judgement against 18.67 GB of evidence**.

**That figure is a floor, not an estimate.** The synthetic the 419 bytes came from
derived no control edges at all — `control_ace`, `full_control_source_entry` and
`shared_proof_value` were all empty when queried. A real forest adds that whole phase
on top of every byte above.

**The 344 million is `entries × average reuse`**, which is exact only if a
descriptor's entry count and its reuse count are unrelated across the forest. That
cannot be checked from a summary, and on a real directory they are plausibly related:
descriptors high in the tree are both the most reused and the ones carrying the
deepest inherited lists. Treat it as approximate until measured.

## Size is the run time here, not only the disk

The owner abandoned a production judging after eight hours with 27 GB written and
still growing. That is roughly **one twentieth** of the write rate measured on the
bench, so the cost is not linear in rows — index maintenance on a file past the
machine's memory dominates. **The file getting smaller is what makes the run finish
at all**, which is why this is not merely a tidiness concern.

## What must be measured before the scope is chosen

**The average distinguished-name length, which nobody has measured.** It decides
whether an integer identifier alone is enough:

| Average DN | Three copies cost | Row drops to | The owner's forest |
|---|---|---|---|
| ~90 characters | ~270 of 419 bytes | ~150 bytes | **~48 GB** |
| ~50 characters | ~150 of 419 bytes | ~270 bytes | **~87 GB** |

At the top of that range the integer identifier is a real fix. At the bottom it is
not, and the 32-byte `fingerprint` — **about 11 GB across 344 million rows** — has to
be addressed in the same change rather than the next one.

**Getting this wrong costs the owner a day.** He works only inside the production
environment and cannot export a bundle, so every build carried over is a trip, and a
scope chosen by guesswork is a trip spent learning the guess was wrong.

### So the first step is a forecast, not a schema change

A read-only mode in `SecureAD.Measure`, beside `--descriptor-redundancy`, which is
already the precedent for this shape: it opens a sealed bundle read-only, writes
nothing, and reports both JSON and a readable summary. `SecureAD.Measure.exe` is
already in the published build the owner carries.

It must report:

- the **exact** occurrence count — the sum over objects of their own descriptor's
  entry count — which replaces the approximate 344 million above
- the **distinguished-name lengths**, total and average, across those objects
- the **projected judgement size** as it stands, and with the name replaced by an
  integer, so the operator knows what a run will produce **before** starting it

It must not open the bundle immutable. `--descriptor-redundancy` explains why: that
flag asserts the file cannot be changing underneath, which is a claim only a verified
seal earns. Read-only writes nothing either way.

## The shape of the change itself

An integer object identifier, with the distinguished name stored once.
`permission_classification_object` already keys on `target` and is the natural place
to hang it.

## What must not break

- **Every occurrence keeps its exact binding.** The link row's `fingerprint` covers
  the complete `(target, generation, entry)` triple including the ordinal, and is
  recomputed on every read. If the target becomes an integer, the fingerprint is
  still computed over the *distinguished name*, because it is what the occurrence is
  a fact about — an identifier local to one store proves nothing about a directory.
- **The ordinal stays on the occurrence row.** `P-272` and `P-279` both record why:
  the same entry sits at different positions in different lists, and Windows
  evaluates a DACL in stored order, adding a deny only for rights not already granted
  ([MS-ADTS] 5.1.3.3.2).
- **`PermissionClassificationStorage.Complete` counts occurrences per object** and
  refuses a product whose counts disagree. It reads `target`; it will need the
  identifier, and it must keep refusing.
- **Zero backward compatibility, as everywhere in this store.** Bump
  `JudgementSchema.Version` (43 after P-279) and add a `ControlEdgeLayoutTests`
  checkpoint. Never replace a historical layout value.

## What this does not settle

Whether ~48 GB, or whatever the measurement says, is *acceptable* — that is the
owner's call, against a customer laptop. If the answer is still no after this change,
the remaining candidates in order of size are the 32-byte fingerprint, the two
indexes on the occurrence table, and whether `position` and `ordinal` both need
storing when one is derivable from the other on most objects. None of those should be
guessed at either.
