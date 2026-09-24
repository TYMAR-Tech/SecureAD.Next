# P-279 before-measurement: what judging costs today

Taken 2026-09-24 on the owner's development machine, against a synthetic bundle
written at the production forest's shape by the real capture writer. Preserved so
the fix can be measured against it rather than against a memory of it.

## What was judged

`next/tools/SecureAD.Measure --permission-storage <out> 0.05`, then
`securead-cli --derive`, then `securead-cli --judge`. Shape in
`verified-shape.json`:

| | |
|---|---|
| Objects | 46,985 |
| Descriptors | 13,592 |
| Entry positions in the evidence | 7,081,432 |
| **Distinct entries** | **24,098** |
| Sealed evidence | 620,806,144 bytes (592 MB) |

## What judging produced

| | |
|---|---|
| Judgement store | **14,265,016,320 bytes (13.3 GB)** |
| Entries written to `permission_entry` | **17,164,866** |
| Times each distinct entry was stored | **712** |
| Judgement against its own evidence | **23x larger** |
| Wall clock | 634 s |

## Where the time went

From `run.log`, the per-phase accounting written at the end of the object pass.
**This is the measurement two earlier storage redesigns were built without**, per
the remark in `JudgingRun` on the verdicts-and-storage split.

| Part | ms | Share of the pass |
|---|---|---|
| **store-permissions** | **345,252** | **64%** |
| commit | 55,420 | 10% |
| rules | 53,577 | 10% |
| read-permissions | 48,887 | 9% |
| complete-permissions | 27,830 | 5% |
| store-control-edges | 4,227 | 0.8% |
| **classify-permissions** | **3,721** | **0.7%** |
| tier0-scan | 567 | 0.1% |
| derive-control-edges | 103 | |
| store-laps | 77 | |
| membership-scan | 14 | |

Pass total 541,902 ms, of which 539,679 ms measured and 2,222 ms unaccounted.

**Reaching a verdict is 0.7% of the pass. Storing it is 64%.** A ratio of 93:1,
which is the answer to the question `P-249` twice guessed at.

## Inside store-permissions

| Part | ms |
|---|---|
| **shared-entry** (writing `permission_entry`) | **202,935** |
| **entry-row** (the classification link) | **114,698** |
| validate | 21,429 |
| shared-load | 3,163 |
| object-row | 1,146 |
| schema-support | 489 |

Total 345,221 ms, of which 343,862 ms measured.

## What this says the defect is

`permission_entry` stores one row per access control entry per object, with the
object's full distinguished name as text on every row, the trustee SID as text,
and a 32-byte binding. `SharedPermissionStorage.Write` deduplicates on a key that
includes the target, so it only skips repeats *within a single object*; the same
entry on a thousand objects writes a thousand rows.

That is the same defect `P-272` removed from the evidence side, where it took a
bundle of this shape from 1.73 GB to 592 MB.

## Caveats, stated because they bound what may be concluded

- **Synthetic, not a customer forest.** It models the production capture's
  permission shape - 521 entries per descriptor over a shared inheritance block -
  and nothing else. The owner's real run shows the same disease (19 GB evidence,
  27 GB judgement and still growing when abandoned) but not the same ratio.
- **Nine of seventeen rules did not complete and six examined no objects.** A
  synthetic bundle has permissions without realistic object classes, so those
  zeros are an artefact of the fixture. They must never be read as findings.
- **The periodic accounting did not fire.** `AccountingEvery` is 100,000 objects
  and this bundle holds 46,985, so these figures come from the end-of-pass
  accounting. On the owner's 939,700-object forest it would fire nine times; a
  fix that also reports on elapsed time would make it work at any size.
