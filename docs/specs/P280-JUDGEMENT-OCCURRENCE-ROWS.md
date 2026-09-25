# P-280 — the occurrence rows, and the name written on each of them three times

**Status: open. The forecast is built; the change itself is not.** This says what the
change must do and what must be measured before its scope can be chosen. The
before-measurement already exists in `next/artifacts/p279-after`; no new run is needed
to start.

**A standalone proposal for an outside reviewer is frozen at
[`P280-PROPOSAL.md`](P280-PROPOSAL.md), dated 2026-09-24.** It covers the same ground
self-contained, and names the fingerprint question as the one thing review is wanted on.
It is deliberately not maintained: where the two disagree, this page wins and the
proposal is out of date.

## The review came back, and the proposal does not survive it unchanged

**Reviewed 2026-09-24. The narrow classification claim held; the sharing unit did not.**
Read this section before building anything from the proposal.

### The design as proposed would attribute a permission to the wrong object

**`permission_entry` already contains target-dependent data.** `ObjectPermissions.ReadAt`
resolves trustees against the target's distinguished name, and for `S-1-5-10` -
`PrincipalSelf` - `WellKnownTrustee` produces `This object (Alice)` against
`This object (Bob)`. `SharedPermissionStorage` writes that resolved name into
`permission_entry.name` **and into the identity hash that decides sharing**.

So two objects with byte-identical descriptors do *not* produce identical saved entries.
Sharing one `(descriptor_id, ordinal) -> entry_id` row between them makes the second
object display the first object's name: *"This object (Alice)"* when reading Bob. The
completed-result screen reads the saved classification, so separately-read evidence does
not correct it.

**This is the failure an audit tool cannot have**, and it is not hypothetical or future -
it is in the code today.

**But nothing shipped is misattributing anything, and the reason matters.**
`SharedPermissionStorage.ContentKey` serialises the *whole* `PermissionEntry`, trustee
name included, so Alice's SELF entry and Bob's hash differently and never share a row.
`P-279` is safe as written. The comment above that method nevertheless stated the
opposite invariant - *"The target never enters it and the ordinal is normalised away, so
two objects share a row exactly when this agrees"* - and the target **does** enter it,
through `Trustee.Name`. The proposal was built on that stated contract rather than on
the code, which is how a design that would misattribute a permission got as far as
review. **The comment was corrected 2026-09-25**; the code was already right.

**The same cause has a live cost, and it is now measured: 20,454,613.** Because the name
is in the identity, a SELF entry **never deduplicates**: every object carrying one gets its
own `permission_entry` row. `S-1-5-10` appears in the default access control list of
essentially every user and computer object, and `--shape-profile` counted 20,454,613
occurrences of it on the production capture - 6.2% of all 330,856,576. `P-279` took that
table from 17,164,866 rows to 24,098 on the bench; on a real forest `SELF` alone would put
up to twenty million straight back into it. **That is the figure the new sharing unit has
to be chosen against**, and it means `P-285` is not a tidy-up but the question of whether
`P-279` worked at all outside the laboratory.

**The correction is to separate the raw ACE from trustee presentation.** `SELF` stays
`SELF` in the shared value; the displayed object name is resolved from the verified
object being read. That is presentation, not replaying a judgement. The same applies to
the descriptor JSON, whose `owner` is a resolved `PermissionTrustee` rather than an
owner SID.

### Three bindings are required, and none may be inferred from the others

The fingerprint composition is sound **only** with all three made explicit:

1. **object -> descriptor**, taken from *verified evidence*, not from a judgement-side
   pointer. The proposal's own `permission_classification_object.descriptor_id` defeats
   the argument it was built on: if the judgement records X->D2 where evidence says
   X->D1, and the two descriptors have equal entry counts, every fingerprint validates
   and D2's permissions are attributed to X.
2. **descriptor/ordinal -> raw entry**, persisted. Computing `H(target, generation,
   entry)` at read time is not verification unless it is compared with an independently
   established expected value; otherwise it hashes the association the reader already
   chose.
3. **entry -> saved interpretation.** This one is a gap *today*: an occurrence's
   `reading_id` can be repointed at another valid reading and every fingerprint still
   matches. An allow `WRITE_DAC` can be made to read as *"A deny entry grants no
   access"* - dangerous reported as harmless. The whole-judgement seal catches an
   ordinary post-publication edit, but not a wrong association written before sealing.
   **Normalisation makes this worse**, because one wrong association would then affect
   every occurrence of that entry.

### Figures withdrawn

- **The "two independent routes agreeing within 1.3%" claim is withdrawn.** It was
  cancellation, not confirmation. The calibration is `K + 128N`; the model is
  `K + 74N + 36G`; the difference is `54N - 36G = 1,885,434,192` bytes, which is exactly
  the gap between the two forecasts. The calibration omits the production GUID term and
  the model omits the calibration's residual, and the two omissions nearly cancel.
- **The ~3.5 GB figure is withdrawn.** No implemented model produces it.
  `RowModel.Normalised` still prices `position`, three key copies and two indexes. And
  under option (ii) the persisted fingerprint alone is 141,693,937 x 32 =
  **4,534,205,984 bytes**, which already exceeds the retracted figure.
- **The 522,807 distinct entries is the wrong reference.** It counts `access_entry`,
  which holds *canonical* entries - `AceNormalizer` expands generic rights before
  hashing, so `GENERIC_ALL` and its expansion collapse into one, while the judgement
  deliberately keeps those readings apart. A correct count of the wrong representation,
  which is `F-S44-2` exactly.
- **The blanket "floor" and "add roughly 15%" claims are withdrawn** until the costs are
  separated. The synthetic residual mixes model omissions, page occupancy and unrelated
  tables and cannot be transplanted onto a different layout.
- **Units were mixed.** 136.5, 6.9 and 14.9 were GiB; the 10.6 fingerprint figure was
  decimal GB.

### Upheld

- **The narrow classification claim survives.** `Rights`, `Scope`, `right_count`,
  `reading_id` and both schema columns take the raw mask, ACE type, GUIDs, inheritance
  and propagation flags and the run's catalogue, and nothing about the target. The
  reviewer followed the tempting contextual cases - computer creation on the Domain
  Controllers OU, `WRITE_OWNER` against `OWNER RIGHTS`, replication combinations,
  callback and inherit-only entries, property sets - and found no target-property path.
  The correct statement is **entry plus interpretation context, shared within the bound
  generation**, not "entry alone".
- **Dropping `position` is safe.** Validation requires strictly increasing, non-negative
  ordinals and writing assigns position from the list index, so position is exactly
  zero-based rank by ordinal. Ordinals `[0, 2, 7]` give positions `[0, 1, 2]`. Keep the
  original ordinal; do not infer completeness from contiguity, because a truncated tail
  leaves a contiguous prefix.
- **`WITHOUT ROWID` remains a good candidate**, even for a fingerprint-bearing row, which
  stays well under SQLite's ~200-byte guidance for 4 KiB pages.
- **Excluding `raw_bytes` was right.**
- **Control edges can be bounded more cheaply than a full derivation** - count candidate
  holders and relevant entries per descriptor and weight by reuse. The multiplier is
  evidence *links*: `H` holders x `M` relevant entries, not `M`.

### Also found: a defect in the forecast itself

`ObjectsWithReadablePermissions` counts every descriptor link and then takes `.DaclAces`,
discarding parse state, completeness and errors. A stored-but-unparseable descriptor
therefore contributes *one object with readable permissions, zero occurrences*, and a
partially parsed one contributes an unqualified count of its survivors. Descriptor
presence, unreadability and partial parsing must be reported separately.

**Fixed 2026-09-25 as step 1 below.** Nine counts now: presence, readable, unreadable,
partly parsed and error-reporting, each at the object and the descriptor level, because
one malformed descriptor inherited by fifty thousand objects and fifty thousand malformed
descriptors are the same object count and different problems. Readable is derived by
subtraction so it cannot drift from presence; partly parsed stays *readable*, because
`DaclState.Unreadable` means a DACL declared entries and yielded none, and striking such an
object off would discard permissions the product did read. **The declared count is still
never substituted for the parsed one.** The occurrence total on `p279-after` is unchanged
at 17,164,866 and still agrees with that judgement's own row count.

**And the bench could not have found it**, which is the argument for step 2 in miniature:
`p279-after` holds zero unreadable and zero partly parsed descriptors, so every one of the
new counts reads zero there. The fixtures that exercise them had to be crafted by hand.

## The order the work is being done in

Settled with the owner 2026-09-24, after the review. Each is a bounded session.

1. ~~**Make the measurement honest.**~~ **Done 2026-09-25.** The `ContentKey` comment now
   says the target *does* enter the key through `Trustee.Name`, that this is why `P-279` is
   safe, and that a SELF entry therefore never deduplicates (`P-285`); the `entry_hash`
   paragraph points at it, so *"NOR IS THE TARGET"* cannot be read as *the target is
   nowhere in this row*. `P-284` is closed. The inflation `P-285` costs is still
   unmeasured, and still has to be measured before step 5 chooses a sharing unit.
2. **Build a bench that can disagree with us.** The synthetic was generated by this
   codebase, so it could only contain assumptions the code already held - no
   object-type GUIDs, no `SELF` variation, no control edges. Add a shape-profile mode
   reporting distributions and counts only, with no names and no SIDs, so it can leave
   the production environment; teach the generator to match one. **Everything after this
   needs an anchor that is the owner's forest rather than our own beliefs** (`F-S44-2`).

   **2a done 2026-09-25: `--shape-profile` exists.** Read-only, 6,599 bytes of output on
   the bench, and it carries no distinguished name, no domain SID, no trustee that is not
   well-known in every Active Directory, no schema GUID outside the catalogue shipped with
   the product, and no file path. What may be named is decided in one place,
   `ShapeProfile.Publishable`, and asked of `SchemaGuidCatalog.Embedded` rather than of the
   bundle's own captured schema - the captured layer re-reads the base schema too, so
   asking it would let a forest's own extension out on the grounds that the forest had
   heard of it. A GUID or SID that cannot be named is **counted**, because refusing to
   name a thing and refusing to count it are different acts and only the first is
   required. The owner approved the contents on 2026-09-25.

   **2b outstanding: teach the generator to match a profile.**

### What the bench actually looks like, measured 2026-09-25

The first profile was of `next/artifacts/p279-after`, and the second was of the production
capture the same day. The pair is the argument for the mode rather than merely a test of
it. **The production profile and its full reading are at
[`next/artifacts/p280-shape-profile/`](../../next/artifacts/p280-shape-profile/README.md).**

| | Bench | Production, measured |
|---|---|---|
| Entries per descriptor, p50 / p99 / max | **521 / 521 / 521** | 533 / 681 / **1,278** |
| Name bytes, p50 / p99 / max | **97 / 97 / 97** | 105 / 158 / 250 |
| Objects per descriptor, p50 / p99 / max | **1 / 3 / 3** | **1** / 25 / **4,568** |
| Domains | **1** | 9 |
| Occurrences carrying an object type | **0** | 238,118,809 (72%) |
| Occurrences carrying `S-1-5-10` | **0** | **20,454,613** |
| Occurrences with a well-known trustee | **0** | 73,028,129 (22%) |
| Descriptors unreadable or partly parsed | **0** | **0** |
| Occurrences inherited rather than set directly | - | 322,433,893 (**97.5%**) |

**Every descriptor is the same length and every name is the same length.** A forest
where the p50, the p99 and the maximum agree to the unit is not a forest; it is a
constant. The two figures `P-280`'s largest claim rests on - that 72% of occurrences
carry an object-type GUID and that moving five entry-derived columns off the occurrence
row saves three times what per-descriptor keying alone saves - have never been checked
against anything, because the bench has none of them.

**Three things the production profile settled.**

- **The occurrence count is confirmed by two independent routes.** 330,856,576, identical
  to `--judgement-forecast`'s figure of 2026-09-24, from a separately written pass. This
  is a real confirmation, unlike the withdrawn "two routes agreeing within 1.3%" claim
  above, which was cancellation.
- **Reuse is far more skewed than the mean of 2.46 suggests.** The median descriptor is
  carried by **one** object and the largest by **4,568**. Shape C still cuts 330 million
  rows to 141 million, but the saving comes from a small number of enormously shared
  descriptors rather than from a broad average. Anything designed around *"descriptors are
  shared about twice"* will be wrong about half the table.
- **`P-285` costs 20,454,613 occurrences**, which is what the sharing unit has to be chosen
  against. See below.

**So the profile's own first outputs are the finding.** Nothing that follows should be
believed on the bench's authority until the generator has been taught to match the
production shape, which is step 2b.

   normalising on top of a binding that lets a `reading_id` be repointed would make one
   wrong association affect every occurrence of that entry.
4. **Separate the raw ACE from trustee presentation** (`P-285`). `SELF` stays `SELF` in
   the shared value and the displayed name is resolved from the object being read. Also
   a correctness prerequisite, and it sizes the new sharing unit by revealing how much
   the current identity was suppressing.
5. **`P-280` proper.** Per-descriptor keying, the entry-derived columns onto distinct
   entries, all three bindings explicit, object-to-descriptor taken from verified
   evidence, `WITHOUT ROWID`, `position` dropped. Bump `JudgementSchema.Version` and add
   the `ControlEdgeLayoutTests` checkpoint.

Then re-judge the production capture and measure what control edges actually cost, which
is the figure every number on this page is a floor because of.

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

**It is also built on the wrong count, and low by an unmeasured margin.** The 141,739,074
entry positions `--describe` reports are rows in `descriptor_entry`, which
`AceNormalizer` writes **sorted and deduplicated by `ace_hash`**. Judging writes one row
per entry read back out of `security_descriptor.raw_bytes`, where nothing is dropped and
nothing is reordered, because a DACL carrying the same grant twice is what the directory
holds and a reader deciding it meant once is editing evidence. Lab bundle
`ad.lab-20260819-232425` measured 12,603 stored against 12,600 projected. Anything
forecasting this table must parse the stored bytes; the cheap column would agree with
itself and be short by exactly what deduplication removed.

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

## Measured, 2026-09-24, on `ad.ssa.gov-20260924-020431`

**It is past the top of that range, so the integer identifier is a real fix.** The
owner ran `--judgement-forecast` against the production capture; these are that run's
figures, not projections from a laboratory.

| | |
|---|---|
| Objects captured | 940,067 |
| Objects carrying readable permissions | 659,196 |
| Descriptors stored / used by an object | 271,901 / 267,550 |
| **Permission occurrences, exact** | **330,856,576** |
| **Average name, per object** | **106.1 bytes** |
| Average name, per occurrence | 106.9 bytes |
| Longest name | 250 bytes |
| Judgement as it stands | 138 GB |
| **With an integer identifier** | **43 GB** |

**The name, three times, is 99 GB of the 138 — just under 72%.** Removing it is the
single largest thing available anywhere in this store.

Four things the measurement settled that guesswork had got wrong:

- **The count is 330,856,576, not ~344 million** — 3.8% below the estimate above, which
  is the `entries × reuse` independence assumption failing in the *helpful* direction:
  the most-reused descriptors carry shorter entry lists, not longer. The average object
  carries 502 stored entries, not 521.
- **Names are 106.1 bytes, past the 90-character row of the table above.** The
  projection for that row was ~48 GB and the measurement says 43 GB, so the table was
  sound and the forest simply sits beyond it.
- **The name-length correlation is real but negligible**: 106.9 bytes per occurrence
  against 106.1 per object, so objects with longer names carry 0.7% more entries. The
  worry was worth measuring and is not worth designing around.
- ~~**Every name is ASCII**~~ — **withdrawn 2026-09-25, and it was never measured.** The
  claim was concluded from the byte mean and the character mean both reading 106.1, and
  they agree because a handful of accented names cannot move a mean across 659,196
  objects. `--shape-profile` compares the two lengths **per object** and answers
  `EveryNameIsAscii: false`. Nothing rests on it, because the code already pays in bytes —
  but a figure that looked checked was not, which is the shape this page keeps recording.

**What it does not settle is whether 43 GB is acceptable**, and that remains the
owner's call. It is still 2.3 times the 18.67 GB of evidence, and still larger than the
27 GB at which he abandoned a production judging after eight hours. The next candidates
are sized in *What this does not settle* below.

## The shape is the fix, not the identifier — measured 2026-09-24

The identifier was the wrong end of the problem. A second run, against the same
capture, priced four shapes the occurrence table could take. **These figures are the
occurrence table and its two indexes only**, modelled from SQLite's record format;
neither page fill nor the other tables are in them.

| | Shape | Rows | Occurrence table |
|---|---|---|---|
| A | As it stands | 330,856,576 | **136.5 GB** |
| B | Integer identifier | 330,856,576 | 41.4 GB |
| C | Keyed per descriptor | 141,693,937 | 17.7 GB |
| **D** | **Per descriptor, classification moved out** | **141,693,937** | **6.9 GB** |

**A is confirmed by two independent routes.** The model says 146,523,677,387 bytes and
the calibration against `p279-after` says 148,409,111,579 — a 1.3% disagreement between
a figure derived from SQLite's record format and one derived from a real judgement's
observed size. Neither method was used to produce the other.

### Why C works: the judgement re-expands what the evidence collapsed

659,196 objects share 267,550 descriptors, and the classification of an entry depends
only on the entry — `PermissionClassification.CreateObjectResult` takes the entry's
mask, GUIDs and inheritance flags and nothing about the object it sits on.
`DangerousPermissionClassifier` says so outright: *"one entry cannot say where it sits;
the per-container assessment decides."* So two objects with the same descriptor get
byte-identical rows, and both are written.

**This is `P-272`'s defect one floor up.** Keyed per descriptor the table holds
141,693,937 rows against 330,856,576 — and on the `p279-after` bench the same shape
lands on exactly **7,081,432** rows, which is the identical figure `P-272` collapsed in
the evidence layer.

### Why D is worth three times C: the GUIDs are text

| | Occurrences | Share |
|---|---|---|
| Carrying an object type | 238,118,809 | 72% |
| Carrying an inherited object type | 205,792,883 | 62% |

`object_schema` and `inherited_schema` hold a GUID **as text**, 36 bytes, and both are
functions of the entry alone. 443,911,692 GUIDs at 36 bytes is **14.9 GB of duplicated
text**, and the 32-byte `fingerprint` is another 10.6 GB. Five columns - the
fingerprint, both GUIDs, `right_count` and `reading_id` - are all determined by the
entry, and there are **522,807 distinct entries** in the forest. Stored once each
instead of once per occurrence, they stop being 25 GB and become a rounding error.

**The bench could not have found this.** Its synthetic descriptors carry no object-type
GUIDs at all - both counts are zero - so the part of the model that prices them has
never been checked against a real judgement, only against unit tests. It is the largest
single term on the owner's forest and does not exist on the laboratory's.

### What these figures are not

They price the occurrence table and its two indexes. On `p279-after` the same model
came in at 6,265,176,090 against an observed whole-judgement 7,189,590,016, so expect
roughly **15% on top** for page fill and the other tables - and rather more than that
on production, where `permission_classification_object` holds 940,067 rows carrying a
JSON descriptor each against the bench's 46,985. **Call D 8-10 GB in practice**, still
below the 18.67 GB of evidence it is derived from and a quarter of the 27 GB at which a
judging was abandoned.

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

### Built as `--judgement-forecast`, and checked against a real judgement

It reports all three, and where the bundle already holds a finished judgement it reads
that too and states the two counts side by side. On `next/artifacts/p279-after` it
forecast **17,164,866** occurrences against that judgement's actual **17,164,866** rows,
and 46,985 object rows against 46,985 captured objects. Without that check the
projection would be a calculation nobody could contradict.

Two things that measurement fixed in the figures above. The observed cost is **418.9**
bytes per occurrence of which **127.9** is not the name, so on that bundle the three
copies are **69%** of the row - the table on this page assumed roughly that and can now
stop assuming it. And every name in that synthetic is exactly 97 bytes, so it calibrates
the fixed cost and says nothing whatever about how long real names are, which remains
the open question and the reason the owner has to run it.

The report says `Opened read-only` rather than `nothing was written`, because a forecast
of that bundle left both databases byte for byte identical and both `-shm` files
carrying a new timestamp. The distinction is small and an audit tool is not the thing
that rounds a claim up.

## The shape of the change itself

**Decided by the owner, 2026-09-24, after the measurement above: shape D, plus three
things that must not be a second schema bump.** An integer object identifier alone was
the original proposal and is superseded — it is the wrong end of the problem, worth
41.4 GB where the shape is worth 6.9.

### The occurrence table is keyed per descriptor, not per object

The classification of an entry depends only on the entry. So the table records *this
descriptor, at this ordinal, carries that entry*, and objects reach their own rows
through `object_security_descriptor`, which already exists and already has exactly the
659,196 rows needed. This is `P-272` applied one floor up, and it is the whole of the
2.3-to-1 row reduction.

### The five entry-derived columns move onto the distinct entries

`fingerprint`, `right_count`, `reading_id`, `object_schema` and `inherited_schema` are
all functions of the entry alone. There are 522,807 distinct entries against
330,856,576 occurrences. The two GUIDs are stored **as text** and account for 14.9 GB
by themselves; the fingerprint is another 10.6 GB.

### Three more, because they are free only while this table is being rebuilt

- **`position` is not information and goes.** It is only ever the rank within the list
  ordered by `ordinal`, so it is derivable at read time. Ordinals *can* have gaps —
  `ParseAcl` advances its counter past an ACE that fails to parse — which is exactly
  when `DaclCompleteness` is `Incomplete`, and rank-at-read is correct either way.
  Dropping it removes a column and an entire index.
- **`WITHOUT ROWID`, keyed `(descriptor_id, ordinal)`.** With a small row and a natural
  key the primary-key b-tree *is* the table: no rowid, no separate index. Together with
  the previous item this takes the key from three stored copies and two indexes to one
  copy and none, which the model puts at roughly **6.9 GB → ~3.5 GB**. That figure is
  modelled and is the one the first real run should be checked against.
- **`permission_classification_object` carries the same duplication.** Its `descriptor`
  JSON holds owner, DACL state, completeness, canonical order, protected flag and
  errors — every one a property of the descriptor, repeated across 940,067 objects
  where 267,550 would do. It also stores the distinguished name twice, once as `target`
  and once inside the JSON.

### Deliberately not in this change

**`security_descriptor.raw_bytes` stays exactly as it is.** Not because it is not worth
compressing — it is 7.73 GB — but because it lives in *sealed evidence*. Touching it
bumps `BundleSchema.Version`, and `P-274` makes a bundle written by an older schema
refused by name, so the owner's 18.67 GB production capture would become unreadable by
the build meant to be tested against it. He would have to re-capture nine domains
before he could measure whether any of this worked. It is also worth about a twentieth
of what this change is worth. `--descriptor-redundancy` can price it read-only, on the
capture he already has, whenever it is wanted.

## What must not break

- **Every occurrence keeps its exact binding.** The `fingerprint` covers the complete
  `(target, generation, entry)` triple including the ordinal, and is recomputed on
  every read. It must still be computed over the **distinguished name**, because that
  is what the occurrence is a fact about — an identifier local to one store proves
  nothing about a directory. A per-descriptor row has no name on it, so the fingerprint
  is computed at read time from the object's name and the entry. **This is the hardest
  part of the change and the one to get right first.**
- **The ordinal stays on the occurrence row.** `P-272` and `P-279` both record why:
  the same entry sits at different positions in different lists, and Windows
  evaluates a DACL in stored order, adding a deny only for rights not already granted
  ([MS-ADTS] 5.1.3.3.2). It is now the key rather than a payload column, which
  strengthens rather than weakens this.
- **`PermissionClassificationStorage.Complete` counts occurrences per object** and
  refuses a product whose counts disagree. It reads `target`; it becomes a join through
  `object_security_descriptor`, and **it must keep refusing**. Mutation-test that it
  still does.
- **An object with no readable descriptor still gets an object row and no occurrences.**
  280,871 of the 940,067 are in that state and the distinction between *unreadable* and
  *grants nothing* is the one this half of the schema exists to keep.
- **Zero backward compatibility, as everywhere in this store.** Bump
  `JudgementSchema.Version` (43 after P-279) and add a `ControlEdgeLayoutTests`
  checkpoint. Never replace a historical layout value.

## What this does not settle

Whether **43 GB** is *acceptable* — that is the owner's call, against a customer
laptop. It is 2.3 times the evidence it was derived from, and larger than the 27 GB at
which a production judging was abandoned after eight hours, so the answer is not
obviously yes.

If it is no, the remaining candidates are now sized against the measured 330,856,576
occurrences rather than guessed:

| Candidate | Worth | Of the 43 GB |
|---|---|---|
| The 32-byte `fingerprint` | **9.9 GB** | 23% |
| The two indexes on the occurrence table | unmeasured | — |
| `position` and `ordinal` both stored, when one is derivable on most objects | unmeasured | — |

The fingerprint is now the largest single remaining item and is nearly a quarter of
what is left, which is a different proposition from the 11 GB of 134 it was before.
Neither of the other two has been measured, and neither should be guessed at.

## The one thing still unmeasured, and it could be large

**Control edges.** Every figure on this page is labelled a floor for one reason: the
`p279-after` bundle the per-row cost was calibrated on derived **none**. `control_ace`,
`full_control_source_entry` and `shared_proof_value` were all empty when queried. On a
real forest that phase produces rows and nobody knows how many.

It cannot be forecast cheaply, because forecasting it means running the derivation. The
answer arrives with the first production judging that actually finishes — which is what
this change is for.


