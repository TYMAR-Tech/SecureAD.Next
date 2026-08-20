# 0044 - SYSVOL coverage is recorded beside the capture units, and a SYSVOL failure does not fail the run

Date: 2026-08-13
Status: Accepted

Taken by the owner in discussion on 2026-08-13, during `S-32`. Widens
[`0035`](0035-coverage-is-recorded-once-per-capture-unit.md) on a stated condition, and records the
first exception to fail-fast capture. Companion to
[`0043`](0043-a-gpos-file-permissions-are-read-below-the-root-folder.md), which settles how deep the
SYSVOL read goes; this settles what the bundle says about it. Governs ledger row `B14`.

## Context

Group Policy settings live in files on the SYSVOL share, and the product is beginning to read them.
The owner decided that **a SYSVOL read failure must not fail the run**, and the reasoning is about
deployments rather than about code: SYSVOL is a file share, permission problems on it are far more
likely than on LDAP, and a run that dies because one policy folder out of four hundred could not be
read would be unusable in the field.

That decision collides with three accepted positions, and the collision is the reason this record
exists rather than a note in a slice document.

**[`0003`](0003-refuse-to-reanalyse-an-incomplete-capture.md) makes capture fail-fast**, and `D3` of
`F-S29-3` drew the consequence: a failed unit returns before the seal, so a bundle exists only when
everything was read. `RunCoverage.AllDeclaredUnitsAreComplete` is therefore an internal consistency
check rather than a measurement, and `UnreadOutcomeIsUnreachableTests` holds that.

**[`0035`](0035-coverage-is-recorded-once-per-capture-unit.md) says a capture unit - one naming
context on one controller - is the only thing that records coverage directly.** SYSVOL is a file
share. It is not a naming context, so under `0035` as written it may not record coverage at all,
while the owner's decision requires that it must: a failure nothing records is a silent hole, which
is what [`0002`](0002-absent-view-means-degraded-run.md) exists to forbid.

**[`0027`](0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) refuses a run that did
not read every domain** as a baseline and as a comparison partner.

The tempting shortcut is to reuse `DomainCoverage.PartiallyRead` for a domain whose SYSVOL read was
incomplete. **It is wrong, and the type's own reasoning says why.** `DomainCoverage` records that a
partly read domain counts as an outright failure because

> A domain read in part is a hole of unknown shape. Nothing downstream can see its edges, so a later
> comparison against it reports fewer changes than really happened while looking exactly like a
> comparison that found nothing.

Taking that route would mean one unreadable policy folder marks its domain incomplete, which under
`0027` makes the whole forest audit unusable as a baseline and uncomparable. That is not "the run
does not fail"; it is the run failing one step later, in a place the operator cannot connect to the
cause.

## Decision

**SYSVOL coverage is recorded, in its own type, held beside the capture units rather than among
them.** The same arrangement `ForestPartitionCoverage` already has and for a related reason: a thing
that is not a domain has failed on its own terms rather than turned a domain into one with a
problem.

**`0035` is widened by exactly one condition, and the condition is what stops this becoming a
general licence.** A thing other than a capture unit may record coverage directly **only where its
incompleteness has knowable edges** - where the record can name what was missed, not merely report
that something was. Anything that cannot meet that test records no coverage, and the reason is
`DomainCoverage`'s: a hole whose shape is unknown cannot be reasoned about downstream and is
therefore a failure of the whole unit, not a partial result.

**SYSVOL meets the condition, and that is why it qualifies.** The GPO list comes from LDAP before
any file is opened, so a run that cannot read three policy folders out of four hundred knows which
three, by name and GUID. The record carries the counts and names the failures, so a report can say
*397 of 400 policies were examined, and these three were not* rather than a bare *partial*.

**`RunCoverage.AllDeclaredUnitsAreComplete` does not consider SYSVOL**, and this is deliberate
rather than an oversight to be tidied later. It stays what `F-S29-3` established: an internal
consistency check over the declared directory units, true in every bundle a reader can open, whose
value is that it enforces `0027` against a future writer. SYSVOL coverage is the opposite kind of
value - one that genuinely varies and is meant to be read. **Merging them would convert an
always-true invariant into a customer-facing verdict, which is precisely the defect `F-S29-3` was
raised about.** They are kept apart on purpose and a future session proposing to unify them should
read this paragraph first.

**`D3`'s invariant is therefore untouched.** Nothing records a capture *unit* as unread, because
SYSVOL is not one. `UnreadOutcomeIsUnreachableTests` continues to hold, on its own terms and without
widening. **Its remarks are corrected**, because they state that a bundle exists only when
everything was read, and after this record that sentence is no longer true of the bundle as a whole
even though it remains true of every capture unit in it. A correct test carrying a wrong explanation
is how the next session is misled.

**The SYSVOL record is required, not optional.** `RunCoverage` takes it with no overload that omits
it, for the reason already written for the forest partitions: a default of *none reported* would let
a run that never attempted SYSVOL pass as though it had nothing to report.

**A run whose SYSVOL read failed entirely is still sealed, still a valid baseline, and still
comparable.** What it is not is silent: the record says what was not read and why, in words an
operator can act on, and the six Group Policy rules state that they were not assessed rather than
reporting nothing found.

## Consequences

**A bundle can now be missing evidence the run tried to collect.** This is a real change and it is
the point of the record. `0003` is unchanged for every capture unit; SYSVOL is the single stated
exception, and it is an exception because the owner judged a fatal SYSVOL failure worse for a
customer than a partial one honestly reported.

**Every future proposal to record coverage for something that is not a capture unit has a test to
pass.** Knowable edges. That test is met by SYSVOL because the denominator comes from the directory;
it would not be met by, say, a partial read of an arbitrary file tree with no independent inventory.

**The counts must have a reachable state in which they disagree**, and a test must reach it. A
SYSVOL record that reports everything read in every bundle would be worth nothing, and this is the
one place in the product where partial coverage is genuinely expected - so it is the one place the
record can be made to matter. `S-30` and `S-31` each shipped a value that could only ever say one
thing; this is the same trap and it is named here so the session cannot walk into it a third time.

**`RunCoverage.Of` changes signature**, so every construction site is updated. The compiler finds
them, and the change is contained to capture and its tests.

**If SYSVOL is ever read for something other than Group Policy**, this record covers the coverage
shape but not the scope, and `0043` covers the depth but not the purpose. A new purpose needs its
own argument.
