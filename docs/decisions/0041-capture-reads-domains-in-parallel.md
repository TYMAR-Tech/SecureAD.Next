# 0041 - Capture reads domains in parallel, one request per controller

Date: 2026-08-14
Status: Accepted

## Context

Capture is sequential today: `CaptureRun` walks the plan one unit at a time and awaits each before
starting the next. Nothing decided that. It is what the first run driver happened to be, written
when there was one controller and no reason to consider a second.

[`S-10`](../audit/limits-and-failures.md) settled the constraint that governs this, and it is narrower
than it first appears:

> Requests are never pipelined. This product places one request at a time on a domain controller.

That is a **correctness** rule rather than a courtesy. The state a controller keeps between the pages
of a paged search comes out of one per-controller budget, `MaxResultSetSize`, and when the budget
fills the controller discards the **oldest** intermediate results. Two paged searches running at once
against one controller can therefore truncate each other silently, and only on forests large enough
that somebody wanted the concurrency - finding `F-S7-12`.

The rule is about one controller, not about the run, and `S-10` says so: *running several naming
contexts at once is expected and safe*, with a mutation recorded specifically to prove the guard
permits it rather than forbidding it by accident.

The guard that holds the rule - `SerializedDirectoryAccessGateTests` - is deliberately broader than
the rule, failing the build on any fan-out shape anywhere in the capture project, with an empty
allowlist. `S-10` also recorded what to do when something legitimately wants concurrency: **narrow
the guard to the code that touches a directory**, never exempt a file.

Decided by the owner on 2026-08-14 during `S-28`, on the
grounds that a forest's domains live on different controllers and reading them one after another
spends a customer's night for no reason.

## Decision

**Domains are read in parallel.** A forest of several domains is read in roughly the time of its
largest domain rather than the sum of all of them.

**Never two requests in flight to one controller.** Unchanged, and it is the rule the parallelism is
arranged around rather than an exception to it. Where two domains are listed against the same
controller, those two are read one after the other with respect to each other.

**Configuration and schema are read first, and complete before any domain starts.** They are already
ordered first because everything else is interpreted against them - a permission naming a schema GUID
means nothing until the schema partition is in hand, per
[`0014`](0014-capture-reads-the-schema-partition.md). Parallelism does not change that; it applies to
the domains that follow.

**Writes into the bundle are serialised.** `BundleWriter` holds one SQLite connection inside one
transaction and is not thread-safe. Parallel reads funnel through a single writer, and a second
writer is not the answer.

**There is no switch.** One behaviour. An operator setting labelled as gentler on production would
be the same failure `S-10` refused for a request rate limit: a number that reads as a lever, whose
relationship to what a server actually experiences is loose enough that an operator choosing it is
worse off than one with no choice.

**The guard is narrowed, never exempted.** Whatever replaces the current fan-out scan must still fail
the build on two concurrent requests to one controller. A guard that permits the new shape by
allowlisting a file would pass while measuring nothing, which is the failure this repository has
shipped more than once.

## Consequences

Wall-clock time falls to roughly the largest domain. Nothing else about the run changes: the same
requests are sent, the same page sizes, the same limits, and each controller experiences exactly what
it experienced before.

Rewriting the guard is the risk in this decision, not the concurrency. The present guard is crude and
correct; a precise one is easy to write and easy to get subtly wrong, and it must be mutation-tested
in both directions before it is believed.

This rules out the obvious mechanism for discarding a failed domain's partial read under
[`0040`](0040-a-failed-domain-is-read-again-from-another-controller.md). A SQLite savepoint is a
stack, so once domains write interleaved there is no way to unwind one domain's work without also
unwinding whatever was written after it. Discarding a failed attempt must therefore be keyed on that
attempt's own coverage handle, which every object already carries.

Nothing may restate this record. Rows, comments and notes cite `0041`.
