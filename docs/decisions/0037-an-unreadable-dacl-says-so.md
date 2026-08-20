# 0037 - A DACL the run could not read says so, and every descriptor records how many entries it should have

Date: 2026-08-13
Status: Accepted. The clause requiring a stored *entry count* was corrected below, the same day and
before anything shipped: gate 4 refused a bare count and was right, so completeness is recorded as a
closed set of outcomes instead. The decision itself is unchanged.

## Context

`DaclState` had three members. `Present` means there are entries. `Null` means there is no DACL at
all, which in Windows grants **everyone full control**. `Empty` means there is a DACL and it lists
nothing, which grants **nobody anything**. Keeping those two apart is the whole reason the type
exists - [`S-1`](../next/S-1-security-descriptor-parsing.md) says so, and `AceSetHash`'s own remarks
lean on it: whether an empty set means *this object grants nothing* or *this object grants everyone
everything* "is not this value's question - that is what the DACL state beside it answers."

`S-21` found that the state beside it cannot always
answer, because there are **three** ways to end up holding no entries and the type distinguishes
two. A DACL whose header declares entries that then fail to parse also produced `Empty`. Confirmed
against the live parser: a header declaring two ACEs whose bytes are malformed returned
`DaclState = Empty`, zero entries and two errors - identical in that field to a genuinely empty
DACL, which returned `Empty`, zero entries and no errors.

So an object whose permissions the product **could not read** was reported as the most locked-down
object it is possible to be. An auditor scanning for dangerous permissions skips it. It propagates:
`AceNormalizer` returns early for any state other than `Present`, so the object also gets an
`ace_set_hash` over an empty set and groups, under
[`0015`](0015-a-bundle-names-a-pattern-it-never-explains-one-away.md), with genuinely locked-down
objects as one repeated pattern.

**The partial case is worse and was nearly missed.** A DACL declaring three entries of which one
parses returns `Present` with one entry - and that is *true*. Nothing is unreadable; the object
simply looks complete while silently under-reporting. A missing allow entry there is a permission
the product never reports, which is the failure the `S-21` brief named. A fourth state does not fix
this, because the state is not wrong.

This is the failure gate 4 exists to prevent - *found nothing* and *could not compute* rendering
identically - and it is the same shape [`0004`](0004-unknown-counts-name-the-failed-phase.md) already
decided one layer up for report counts. The principle is not new here; it was applied to summaries
and not to the descriptors underneath them.

The timing settles the cost. `C1` is finished and **no bundle has ever been written**, because the
capture-to-bundle seam at `B9`, `B10` and `C15` is not built. A `CHECK` constraint and two columns
are free today and are a migration from the first customer run onwards.

## Decision

**`DaclState` gains `Unreadable`.** It is set when the DACL header declares at least one entry and
none of them parsed, **and when the header itself cannot be read**, which is the same ignorance
arriving one step earlier. It is never inferred from the presence of errors alone, because a
descriptor can carry an error and still have read every entry it declared.

**Every descriptor records the entry count its own header declared**, alongside the entries that
actually parsed. Completeness is then a comparison rather than a judgement: a descriptor is complete
when the declared count equals the number of entries stored against it, and any shortfall is
visible in one query without re-parsing anything.

**— Corrected the same day, before anything shipped.** What is recorded is a **closed set of
outcomes** — `Complete`, `Incomplete`, `Unknown` — and not the count. Gate 4 refused the count on
sight, and the refusal was correct: a number on its own cannot say whether it was measured, so a
header declaring zero entries and a header too truncated to read would both have reached a caller
as `0`. **That is this record's own defect, one field over**, and the first draft of the change
really did reintroduce it — a truncated ACL header came out as `Empty`, which is the exact reading
this record exists to abolish. The gate caught it in the same session that wrote the rule it
breaks.

The exact numbers are not stored. A bundle keeps the descriptor's raw bytes, so *three of five* is
recoverable by re-parsing, which is the division of labour
[`0038`](0038-a-descriptor-records-whether-its-dacl-was-canonical.md) settles on for the same
reason: the cheap question is queryable over a whole forest, and the exact one is answered from the
evidence when something needs it.

**`Unreadable` is not `Empty` and is not `Null`.** It makes no claim about what the object grants.
It says the product does not know, which is the only honest answer and the one the type could not
previously give.

**A consumer may not treat `Unreadable` as safe.** Any surface that reports permissions must render
it as unknown rather than omitting the object, per the same reasoning `0004` gives for counts: the
word occupies the slot the answer would have taken, so its absence is visible to someone skimming.

## Consequences

**An object the product could not read stops looking like the safest object in the estate.** That is
the entire point, and it will make some runs look worse than they did. Every one of those runs was
already worse.

**Two objects with no entries no longer necessarily group together.** An unreadable DACL still
produces an `ace_set_hash` over an empty set, because the normaliser has no entries to hash - the
state beside it is what separates them, exactly as `AceSetHash` says. Any grouping surface must read
both.

**Completeness catches what a fourth state cannot.** A partially read DACL keeps `Present`, which is
true, and the shortfall shows as `Incomplete`. This is deliberate: adding a state for *partially
read* would put a judgement in a field that should hold a fact.

**The schema carries two more columns per descriptor** - the completeness outcome and the state
widening by one permitted value. Descriptors are deduplicated on a hash of their bytes, so this is
paid once per distinct descriptor rather than once per object.

**Consumers must handle a fourth state.** `DaclState` is used in one place in production today, so
the compiler will find them all now and would not have later.
