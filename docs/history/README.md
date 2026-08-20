# History

**Nothing in this folder is current. Do not read it to find out what is true.**

These are session narratives and design notes: what somebody found on a particular day, and the
reading that led to a decision. They are dated, they are written once, and they are never corrected
— which is exactly why they must not be consulted as documentation. A document that is never
corrected and contains a present-tense claim is permanently stale the moment that claim changes.

That is not hypothetical. `S-15-storage-dispositions.md` states that the capture entry point *takes
a destination*. Two days later [`0025`](../decisions/0025-the-run-library-is-a-managed-root.md)
decided the opposite — the tool owns a configured root and capture to an arbitrary path is not
offered — and `S-15` went on saying it, as did the ledger row and a class comment that had copied it.
That cost real time on 2026-08-14, and it is the reason this folder exists.

## Where to look instead

| Question | Where |
|---|---|
| What has this product decided, and is it still current? | [`docs/DECISIONS.md`](../DECISIONS.md), generated from the records |
| Why was it decided that way? | the decision record itself, in [`docs/decisions/`](../decisions) |
| What does this component do? | the live document in [`docs/next/`](../next), named for the thing it describes |
| What is built and what is left? | [`docs/next/WHAT-THE-OLD-APP-HAD.md`](../next/WHAT-THE-OLD-APP-HAD.md) |

## Why these are kept at all

Per [`0032`](../decisions/0032-a-decision-record-is-corrected-in-place.md), the reasoning that
produced an error is worth more than the correction alone. A record of what somebody believed on a
Tuesday, including where they were wrong, is how the next person understands why the product is
shaped as it is. Deleting these would keep the conclusions and throw away the argument.

They are also evidence. Several contain findings that were handed forward and have not all been
discharged.

## What decided the split

A document named for a **thing** — the bundle, the connection, the capture unit — describes
something that exists and is held to the code by a test. Those stayed in `docs/next/`.

A document named for a **session or an activity** — dispositions, reviews, reconciliations —
describes what happened during a piece of work. Those are here. Not one of them was bound by any
test, and every documentation contradiction found on 2026-08-14 came from this group.
