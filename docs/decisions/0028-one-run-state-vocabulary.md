# 0028 - One run state vocabulary, and every state is observed rather than assumed

Date: 2026-08-12
Status: Accepted

## Context

The product has to answer one question about a run - *did it finish, and can I use it* - and the
implementation being replaced answered it in four vocabularies with no two sharing members.
`RunState` had seven, `RunStateNames` persisted five, `RunLifecycleState` presented five, and
`RunCoverage` and `AnalysisHealth` sat beside them as further axes. Three of `RunState`'s members
were never persisted, `Cancelled` collapsed into `Failed` on read, and `Interrupted` was reachable
only from one fallback branch.

Two failures came out of that. A renamed constant changed what was written without changing what
was read, and the library funnelled the unrecognised value into `InProgress` - so a sealed run
degraded silently and vanished from every picker filtering on sealed. And `RunDatabaseInspector`
caught every exception and returned one sentinel, so a corrupt file and a file that was never a run
bundle read identically; the operator was told *required run metadata is missing* for both.

A vocabulary is only worth having if each of its words can be arrived at from evidence. As the
bundle stands - four files, per `0019` and
[`0029`](0029-a-run-that-ends-badly-says-so.md) - a run that failed, a run the operator cancelled,
a run killed by a reboot and a run still capturing all leave the same thing behind: an
`evidence.db.partial` and no `evidence.db`. Four words for one observation is how the predecessor
came to have four vocabularies, and declaring states that nothing can produce is worse than
declaring fewer.

## Decision

**One vocabulary, used by the writer, the reader and the display.**

| State | Meaning | May be a baseline |
|---|---|---|
| In progress | Capture or analysis is still running | No |
| Sealed | Finished and sealed | Yes, if every domain was read |
| Failed | Ended in an error the product recorded | No |
| Cancelled | The operator stopped it | No |
| Interrupted | The run stopped without recording why | No |
| Damaged | The bundle exists but its evidence cannot be opened | No |

**Every state is reached by observation, in this order.** The procedure is part of the decision
rather than an implementation detail, because it is what makes the six words honest:

1. `evidence.db` present, seal intact, and it opens - **Sealed**.
2. `evidence.db` present and either check fails - **Damaged**.
3. No `evidence.db`, but a run-outcome file recording a failure - **Failed**, with its reason.
4. No `evidence.db`, but a run-outcome file recording a cancellation - **Cancelled**.
5. No `evidence.db` and no outcome file, and something still holds the partial file open -
   **In progress**.
6. No `evidence.db` and no outcome file, and nothing holds the partial file - **Interrupted**.

The outcome file and the liveness test are decided in
[`0029`](0029-a-run-that-ends-badly-says-so.md). Without them, steps 3 to 6 collapse into one
observation and this table cannot be justified.

**Failed, Cancelled and Interrupted are kept apart**, on the argument
[`0026`](0026-one-answer-to-whether-runs-may-be-compared.md) already accepted for its first three
states: they share a consequence and not a cause, and only the causes are actionable. *Cancelled*
needs no investigation. *Failed* has a recorded reason to read. *Interrupted* means something
outside the product stopped it, and is the only one of the three that sends the operator to look
outside the product.

**Damaged is separate from Interrupted.** An interrupted run stopped; a damaged one cannot be read.
One is re-run, the other is restored or discarded.

**An unrecognised persisted state is a failure, never a default.** Reading a state this version does
not know about yields an `AuditError`, because the plausible cause is a bundle written by a later
version and the honest answer is that this one cannot read it. Defaulting is what made a rename
silently hide every sealed run.

## Consequences

**This vocabulary is about explaining, not about correctness.** All of In progress, Failed,
Cancelled and Interrupted mean *did not complete*, and `0027` refuses a comparison against any of
them identically. The distinction is what the run library can tell an operator deciding what to
delete and what to re-run. A product that reported only *Sealed*, *Damaged* and *Unfinished* would
be equally correct and would say less.

Adding a state costs an entry, a persisted name and a documented row, and the compiler finds the
places that must handle it. Renaming a persisted name is a compile error rather than a silent change
in meaning - the one property the predecessor's `RunStateNames` was extracted to buy, and the only
one of its four vocabularies that earned its existence.

A run killed hard enough to prevent the outcome file being written reports as **Interrupted** even
if the operator had just cancelled it. That is a true statement about what is known, and it is the
limit of what the evidence supports.

This vocabulary covers lifecycle only. How much of the forest a run saw is coverage and is decided
by `0027`; whether derived analysis succeeded is a further axis. The predecessor's mistake was not
having three axes - it was persisting one and reconstructing the others.
