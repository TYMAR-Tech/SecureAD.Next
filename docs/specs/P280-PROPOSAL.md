# P-280 — the judgement is mostly a copy of itself

**A proposal for review. Frozen 2026-09-24; not maintained.**

> **REVIEWED 2026-09-24, AND IT DID NOT SURVIVE UNCHANGED. Do not build from this page.**
> The narrow classification claim in §5(a) held. The **sharing unit did not**:
> `permission_entry` already carries target-dependent trustee presentation, so sharing
> one by descriptor would display one object's name while reading another. The
> fingerprint scheme in §8 needs three explicit bindings rather than one, and the
> schema sketch in §7.1 defeats its own argument by taking the object-to-descriptor link
> from the judgement rather than from verified evidence. The 1.3% agreement in §6 was
> cancellation, not confirmation; the ~3.5 GB in §7.2 is unsupported by any implemented
> model. See *The review came back* in
> [`P280-JUDGEMENT-OCCURRENCE-ROWS.md`](P280-JUDGEMENT-OCCURRENCE-ROWS.md), which is
> authoritative.

The living specification is
[`P280-JUDGEMENT-OCCURRENCE-ROWS.md`](P280-JUDGEMENT-OCCURRENCE-ROWS.md) in this
folder. Where the two disagree, that one wins and this one is out of date. This
document exists to be read once, by a reviewer, and then to stop being read.

**What review is wanted on** is at the end. The short version: one design question is
genuinely open and is the reason this is being reviewed rather than built.

---

## 1. What is being decided

A judging run of the owner's production forest would write a **138 GB** result
describing **18.67 GB** of evidence. Roughly 72% of it is one object name, copied three
times, 331 million times over.

The proposal restructures one table so the same run writes **6.9 GB**, modelled, or
**3.5 GB** with three further changes that are free only while it is being rebuilt.

No entry is dropped. No permission stops being reported. The change is entirely one of
storage shape.

## 2. Background a reviewer needs

**SecureAD captures an Active Directory forest and judges it against security rules.**
A run produces two files with different lifetimes, and the distinction decides most of
what follows:

| File | Contains | Lifetime |
|---|---|---|
| `evidence.db` | what the directory said | **sealed**, hash-verified, captured once |
| `judgement.db` | what the product worked out | **disposable**, rebuilt on every judging |

`BundleLayout` states the rule: *"A judgement is rebuilt from scratch every time a
bundle is judged."* Changing the judgement costs a re-judge. Changing evidence costs a
re-capture of nine domains, because `P-274` makes a bundle written by an older schema
refused by name.

**The table in question** is `permission_classification_entry`
(`next/src/SecureAD.Judgement/PermissionClassificationStorage.cs`). It holds one row
per *permission occurrence* — the fact that **this object, at this position in its
access control list, carries that entry**. An object with 521 permissions needs 521 of
them. None may be dropped; losing one is losing a permission the product is required to
report, which is the one thing an audit tool must never do.

## 3. How we got here

This is the third round of the same disease, and it is worth seeing the pattern before
the proposal.

**`P-272`, evidence, done 2026-09-23.** `BundleWriter` hashed the whole binary
descriptor, so two objects shared storage only if their permission lists were identical
end to end. Under deep inheritance no two ever are, so every inherited entry was written
again per descendant. Fixed by storing each distinct entry once in `access_entry` and
linking through `descriptor_entry`, which carries the ordinal. Measured on a synthetic
at the production shape: **7,081,432 stored rows became 24,098**, and the file fell from
1.73 GB to 592 MB — 66.5%.

**`P-279`, judgement, done 2026-09-24.** The same defect, one floor up: the
classification row named the object it was found on and deduplicated only within that
object, so an entry inherited by a thousand objects was written a thousand times. Fixed
the same way — `permission_entry` holds each distinct entry once. 24,098 distinct
entries had been stored 17,164,866 times.

**`P-280`, this document.** After `P-279` the judgement is almost entirely one table:
`permission_classification_entry` holds 17,164,866 rows in a 7,189,590,016-byte store —
419 bytes per row — while `permission_entry`, which `P-279` fixed, holds 24,098.

**The relevant operational fact:** the owner abandoned a production judging after eight
hours with 27 GB written and still growing. That is roughly one twentieth of the write
rate measured on the bench. The cost is not linear in rows — index maintenance on a file
past the machine's memory dominates — so **the file getting smaller is what makes the
run finish at all.**

## 4. The measurement

A read-only mode, `SecureAD.Measure --judgement-forecast`
(`next/tools/SecureAD.Measure/JudgementForecast.cs`), was built first and run against
the production capture `ad.ssa.gov-20260924-020431` on 2026-09-24.

### It counts what judging writes, not what is convenient

**This is the one place the tool could have been silently wrong.** `descriptor_entry`
and `captured_object.ace_count` are one cheap column away, and both hold the canonical
projection — sorted and **deduplicated by `ace_hash`** by `AceNormalizer`. Judging
writes one row per entry re-parsed from `security_descriptor.raw_bytes`
(`ObjectPermissions.EntriesOf`), where nothing is dropped and nothing is reordered; a
lab bundle measured 12,603 stored against 12,600 projected.

A forecast reading the cheap column would have agreed with itself, reported a plausible
figure, and been short by exactly what deduplication removed. The tool parses the stored
bytes instead, once per distinct descriptor.

### It is checked against a real judgement

On `next/artifacts/p279-after`, which holds a finished judgement, the forecast counted
**17,164,866 occurrences against that judgement's actual 17,164,866 rows.** Exact.
Without that check the projection would be a calculation nobody could contradict.

### Production figures

| | |
|---|---|
| Objects captured | 940,067 |
| Objects carrying readable permissions | 659,196 |
| Descriptors stored / used by an object | 271,901 / 267,550 |
| **Permission occurrences** | **330,856,576** |
| Distinct entries | 522,807 |
| Average name, per object | **106.1 bytes** |
| Average name, per occurrence | 106.9 bytes |
| Occurrences carrying an object type | 238,118,809 (72%) |
| Occurrences carrying an inherited object type | 205,792,883 (62%) |
| Sealed evidence | 18.67 GB |

Two figures the estimate had wrong. The count is **3.8% below** the ~344 million
estimated, because the `entries × reuse` independence assumption fails in the helpful
direction — the most-reused descriptors carry shorter lists. And names are 106.1 bytes,
past the top of the range the specification had tabulated.

## 5. The diagnosis

Three separate duplications, in one table.

**(a) The table is keyed per object when the classification is per entry.** 659,196
objects share 267,550 descriptors. The classification of an entry depends *only* on the
entry: `PermissionClassification.CreateObjectResult` takes the mask, the GUIDs and the
inheritance flags, and reads nothing about the object.
`DangerousPermissionClassifier` states the principle outright — *"one entry cannot say
where it sits; the per-container assessment decides."* So two objects with the same
descriptor produce byte-identical rows, and both are written.

**This is `P-272`'s defect again.** Keyed per descriptor the table holds **141,693,937**
rows against 330,856,576 — and on the `p279-after` bench the same shape lands on exactly
**7,081,432**, the identical figure `P-272` collapsed in the evidence layer.

**(b) The name is stored three times per row** — in the row as `target TEXT`, in
`PRIMARY KEY(target, position)`, and in `UNIQUE(target, ordinal)`. At 106.9 bytes
occurrence-weighted that is **99 GB**.

**(c) Five columns are functions of the entry and are copied onto every occurrence of
it.** `fingerprint` (32 bytes), `object_schema` and `inherited_schema` (GUIDs stored
**as text**, 36 bytes each), `right_count` and `reading_id`. The two GUID columns alone
are **14.9 GB**; the fingerprint is another 10.6 GB. There are 522,807 distinct entries.

## 6. What each shape costs

Modelled from SQLite's record format. **These price the occurrence table and its two
indexes only** — not page fill, not the other tables.

| | Shape | Rows | Occurrence table |
|---|---|---|---|
| A | As it stands | 330,856,576 | **136.5 GB** |
| B | Integer identifier for the name | 330,856,576 | 41.4 GB |
| C | Keyed per descriptor | 141,693,937 | 17.7 GB |
| **D** | **C + classification moved onto the entries** | **141,693,937** | **6.9 GB** |

**A is confirmed by two independent routes.** The record-format model says
146,523,677,387 bytes; calibrating against `p279-after`'s observed size says
148,409,111,579. A 1.3% disagreement between methods, neither derived from the other.

**The model is checked and comes in under.** On `p279-after` it reports 365 bytes per
row against 418.9 observed — under, which is the only acceptable direction, since the
observed figure carries the other tables and free pages too. The tool says outright that
if it ever comes in *over*, none of A–D may be believed.

**One caveat the reviewer should weigh.** The bench synthetic carries **zero**
object-type GUIDs, so the term pricing the largest single item on the owner's forest has
never been validated against a real judgement — only against unit tests. Expect roughly
15% on top of all four for page fill, and more on production where
`permission_classification_object` holds 940,067 JSON rows against the bench's 46,985.
**Call D 8–10 GB in practice.**

## 7. The proposal

Shape **D**, plus three things that are free only while this table is being rebuilt.

### 7.1 Sketch of the schema

Illustrative, not final — the column set is exactly what review is wanted on.

```sql
-- One row per descriptor the run classified. Everything here is a property of the
-- descriptor: owner, DACL state, completeness, canonical order, protected flag, errors.
CREATE TABLE permission_classification_descriptor (
    descriptor_id  INTEGER PRIMARY KEY,
    descriptor     TEXT    NOT NULL,
    entry_count    INTEGER NOT NULL CHECK(entry_count >= 0));

-- One row per captured object, including the 280,871 whose permissions were unreadable.
-- descriptor_id is NULL for those: unreadable is not the same as grants nothing.
CREATE TABLE permission_classification_object (
    target            TEXT    PRIMARY KEY COLLATE NOCASE REFERENCES control_object(target),
    descriptor_id     INTEGER NULL REFERENCES permission_classification_descriptor(descriptor_id),
    availability      TEXT    NOT NULL,
    unreadable_reason TEXT    NULL);

-- One row per (descriptor, ordinal). This is the table the whole proposal is about.
CREATE TABLE permission_classification_entry (
    descriptor_id INTEGER NOT NULL REFERENCES permission_classification_descriptor(descriptor_id),
    ordinal       INTEGER NOT NULL CHECK(ordinal >= 0),
    entry_id      INTEGER NOT NULL REFERENCES permission_entry(id),
    PRIMARY KEY(descriptor_id, ordinal)) WITHOUT ROWID;

-- One row per distinct entry: the classification, which depends only on the entry.
CREATE TABLE permission_classification_result (
    entry_id         INTEGER PRIMARY KEY REFERENCES permission_entry(id),
    right_count      INTEGER NOT NULL CHECK(right_count >= 0),
    reading_id       INTEGER NOT NULL REFERENCES permission_classification_reading(id),
    object_schema    TEXT    NULL REFERENCES permission_classification_schema(guid),
    inherited_schema TEXT    NULL REFERENCES permission_classification_schema(guid));
```

An object's permissions are read by joining object → descriptor → its entries →
their classification.

### 7.2 The three extras

**`position` is dropped.** It is only ever the rank within the list ordered by
`ordinal`, so it is derivable at read time. Ordinals *can* have gaps — `ParseAcl`
advances its counter past an ACE that fails to parse, which is exactly when
`DaclCompleteness` is `Incomplete` — and rank-at-read is correct either way. Dropping it
removes a column **and an entire index**.

**`WITHOUT ROWID`.** With a small row and a natural key the primary-key b-tree *is* the
table: no rowid, no separate index. With the previous item this takes the key from three
stored copies and two indexes to **one copy and none** — modelled at 6.9 GB → **~3.5 GB**.

**The object row loses its descriptor-level JSON.** Today
`permission_classification_object.descriptor` holds owner, DACL state, completeness,
canonical order, protected flag and errors — every one a property of the descriptor,
repeated across 940,067 objects where 267,550 would do. It also stores the distinguished
name twice, once as `target` and once inside the JSON.

## 8. The open question — and the reason for this review

**Where does the fingerprint go?**

`SharedPermissionStorage` is explicit that it is load-bearing:

> *"Every link row carries a fingerprint over the complete `(target, generation, entry)`
> triple including that ordinal, written when the link is written and recomputed on every
> read, so each occurrence still proves which object carried which entry at which
> position. **That fingerprint is the binding**; this row is only the value it points at."*

`P-279` removed `target` from `permission_entry` and the fingerprint is what made that
safe. This proposal removes the per-occurrence row itself, so there is nowhere to put a
per-occurrence fingerprint — and keeping one would defeat the change entirely.

Three options, and the second is the one being proposed:

**(i) Keep it per occurrence.** Costs 10.6 GB and reinstates 331 million rows. Defeats
the proposal.

**(ii) Fingerprint `(descriptor_id, generation, ordinal, entry)` and let the seal carry
the rest.** The object→descriptor binding lives in `object_security_descriptor`, in
**sealed evidence**, which is hash-verified on open. The chain becomes: *sealed evidence
says object X was read with descriptor D* + *the judgement says D at ordinal N carries
entry E, fingerprinted* → *object X at ordinal N carries entry E*. Arguably this is a
**stronger** guarantee than today's, because half of it is protected by the evidence seal
rather than by a judgement-side hash the judgement writes about itself.

**(iii) Drop it and rely on foreign keys.** Loses a real integrity check written at
write time.

**Why this is not mine to decide.** The living specification currently says the
fingerprint must be computed over the *distinguished name*, because *"an identifier
local to one store proves nothing about a directory."* Option (ii) changes what the
fingerprint is about, and the argument that the evidence seal covers the missing half is
reasoning, not measurement. If it is wrong, occurrences become unattributable — which is
precisely the failure the whole descriptor half of this schema exists to prevent.

## 9. What must not break

- **Every occurrence keeps its exact binding.** See §8. This is the piece to build and
  mutation-test first, before anything depends on it.
- **The ordinal survives, and is now the key.** Windows evaluates a DACL in stored
  order, adding a deny only for rights not already granted ([MS-ADTS] 5.1.3.3.2). The
  same entry sits at different positions in different lists.
- **`PermissionClassificationStorage.Complete` must keep refusing.** It counts
  occurrences per object and rejects a product whose counts disagree. It becomes a join.
  Mutation-test that a deliberately wrong count is still refused.
- **Unreadable is not empty.** 280,871 of 940,067 objects have no readable descriptor.
  They keep an object row with no entries, distinct from an object that grants nothing.
- **Zero backward compatibility.** Bump `JudgementSchema.Version` (43 after `P-279`) and
  add a `ControlEdgeLayoutTests` checkpoint. Never replace a historical layout value.

## 10. Alternatives rejected

**An integer object identifier alone** — the original `P-280` proposal. Worth 41.4 GB
where the shape is worth 6.9. It is the wrong end of the problem: it makes the name
cheap without addressing the fact that the row should not exist 331 million times.
Superseded rather than wrong.

**Compressing `security_descriptor.raw_bytes`** — 7.73 GB of evidence, and a real
opportunity. Deliberately **not** in this change: `raw_bytes` is in *sealed evidence*, so
touching it bumps `BundleSchema.Version`, and `P-274` then makes the owner's 18.67 GB
production capture unreadable by the build meant to be tested against it. He would have
to re-capture nine domains before measuring whether any of this worked. It is also worth
roughly a twentieth as much. `--descriptor-redundancy` can price it read-only, on the
capture already in hand, whenever wanted.

**Sampling rather than parsing every descriptor in the forecast** — rejected because the
specification asked for an exact count and a scope chosen by guesswork costs a day.

## 11. Risks and what is unmeasured

**Control edges are not in any figure here.** The `p279-after` bundle the per-row cost
was calibrated on derived **none** — `control_ace`, `full_control_source_entry` and
`shared_proof_value` were all empty. Every number above is therefore a floor. On a real
forest that phase produces rows and nobody knows how many. It cannot be forecast cheaply
because forecasting it means running the derivation; the answer arrives with the first
production judging that finishes, which is what this change is for.

**The GUID term has never been checked against a real judgement**, only unit tests,
because the bench synthetic has no object-type GUIDs. It is the largest single item on
the owner's forest.

**Read paths change shape.** Everything that reads a judgement goes through a join. The
repository's standing constraint is that bounded paging must not eagerly reconstruct
whole objects; a per-descriptor key makes an object's rows one contiguous indexed range,
which should help rather than hurt, but it is a change and it is unmeasured.

**The 3.5 GB figure is modelled, not measured.** It should be checked against the first
real run, and the model's own output is reported beside the observed figure for exactly
that purpose.

## 12. What review is wanted on

1. **§8, the fingerprint.** Is option (ii) sound? Does composing a judgement-side
   fingerprint with a seal-protected evidence link preserve the guarantee that each
   occurrence proves which object carried which entry at which position?
2. **§7.1, the column set.** Is anything in `permission_classification_entry` still
   object-dependent that has been assumed to be entry-dependent? The claim rests on
   `PermissionClassification.CreateObjectResult` and everything it calls.
3. **§7.2, dropping `position`.** Is rank-at-read equivalent in every case, including a
   DACL with gaps in its ordinals?
4. **§10.** Is excluding `raw_bytes` right, or should the re-capture be accepted to do
   both at once?
5. **Anything in §11** that should be measured before building rather than after.
