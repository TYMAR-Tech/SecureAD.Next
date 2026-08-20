# 0040 - A failed domain is read again from another controller, and leaves nothing behind

Date: 2026-08-14
Status: Accepted

## Context

Ledger row `A6` - routing and failover - was disposed **Delete** in
`S-13`, and the reasoning still holds for
the thing that row described. It was a session-wide routing table answering *"which controller am I
using for domain X right now"*, with a negative cache, a per-domain lock and re-discovery rules. Its
fatal property was that it could change controller **during** a partition, leaving the bundle
holding two views of a replicating directory with nothing recording the join.

What that disposition did not consider is the cost of the failure it declined to insure against.
Capture is fail-fast per [`0003`](0003-refuse-to-reanalyse-an-incomplete-capture.md): a domain that
cannot be read ends the run and no bundle is produced. In a forest of several domains read over
several hours, a single domain controller losing power at hour two therefore discards every domain
that had already completed. The next run starts from nothing.

`S-13` also recorded that failover was machinery for an unobserved event, because no capture of the
predecessor is known to have failed in production - finding `F-S7-35`. That remains true and is a
fair argument about priority. It is not an argument that the run should throw away four hours of
completed work when the event does occur.

The distinction this record turns on was raised by the owner on 2026-08-14, during
`S-28`: a complete restart of one domain is not the same
thing as routing around a failure. Nothing is stitched, because nothing of the failed attempt is
kept.

## Decision

**A domain that fails is read again from the beginning, on the next controller listed for it.** The
retries already decided in [`S-10`](../next/S-10-politeness.md) run first - three attempts at the
request, then one restart of the domain on a fresh connection to the same controller. When those are
exhausted, the domain is attempted on the next controller in its candidate list rather than ending
the run.

**Everything the failed attempt wrote is discarded.** Not merged, not retained, not marked. When the
domain is read again, the bundle contains one continuous read of it from one controller and no trace
of the attempt that died. This is what distinguishes this record from row `A6`: there is no seam,
because there are never two partial reads of one domain in a bundle.

**The mechanism is deliberately not specified here.** What is decided is the outcome - nothing of a
failed attempt survives into the bundle. Naming a mechanism would be a mistake, because
[`0041`](0041-capture-reads-domains-in-parallel.md) makes domains write into the bundle interleaved,
and the obvious single-threaded mechanism does not survive that.

**A controller is never changed during an attempt.** One attempt reads one domain from one
controller for the whole of that attempt, and the check in `PartitionCapture` that refuses a
connection pointing anywhere else stays exactly as it is. A second attempt is a **new** pairing of
domain and controller rather than the same one mutated, so a failure still names one domain on one
machine unambiguously - which is what [`S-9`](../next/S-9-the-capture-unit.md) required and what row
`A6` would have broken.

**The bundle says what happened.** Which controller read each domain, and that an earlier controller
was attempted and failed. A run that quietly succeeded on the second controller would be a run whose
evidence gives no sign that a customer's domain controller went down mid-audit, which is itself
worth knowing.

**The candidate list is finite and its exhaustion ends the run.** When no controller listed for a
domain can read it, the run ends per [`0003`](0003-refuse-to-reanalyse-an-incomplete-capture.md).
There is no discovery of further controllers at the moment of failure and no unbounded search: a
forest with a genuinely broken domain must fail in bounded time rather than grinding through
candidates for hours.

**What stays deleted.** The routing table, the negative cache, the per-domain lock, re-discovery on
a timer, and any change of controller within an attempt. Row `A6` is not reinstated. What this
record uses is the per-domain candidate list, which `S-13` explicitly recorded as **not** lost.

## Consequences

What is saved is not the failed domain's hours - those are paid again in full - but every other
domain's. In a three-domain forest failing at hour two of three, that is the difference between
re-reading one domain and re-reading the forest.

A domain's controller is no longer fixed for the life of a run, only for the life of an attempt.
Anything that assumed one controller per domain per run - rather than per attempt - is wrong and
must be found rather than left to be discovered by a bundle.

This is also the answer to what a failed run leaves behind. The owner's position, taken the same
day, is that a run which cannot finish should leave a log and not partial evidence. Discarding a
failed attempt's writes is that position applied at the level of a single domain, and the two agree
rather than needing to be reconciled.

Nothing may restate this record. Rows, comments and notes cite `0040`.
