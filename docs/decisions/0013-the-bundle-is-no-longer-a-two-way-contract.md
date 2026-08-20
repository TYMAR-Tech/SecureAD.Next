# 0013 - The bundle is no longer a two-way contract

Date: 2026-08-10
Status: Accepted

## Context

`0009` made the `audit.db` bundle the seam
between the old implementation and the rebuild, so that each stage could be replaced independently
and a working product existed throughout. That was one clause carrying two separate promises: the
rebuild can read a bundle the old pipeline wrote, and the rebuild must write a bundle the old
application can open.

Only the second constrains anything. It is why `0009` also states that the bundle schema cannot be
improved opportunistically, and defers every improvement to a single migration after the old
projects are gone. No such improvement is currently named or blocked, but the constraint applies to
every storage row not yet started, and nothing in the rebuild reads or writes a bundle yet - so the
cost of dropping it is at its lowest today and rises with every row.

The owner has accepted a period with no end-to-end product in exchange for a free hand on the
schema. [`0001`](0001-no-backward-compatibility.md) already establishes that nothing on disk needs
preserving; this is about the two live halves, not about the past.

## Decision

The rebuild owes the old application nothing. It writes whatever schema it needs, from now, and
schema improvements are made when they are wanted rather than deferred.

`docs/DATA-MODEL.md` specifies the old bundle only. The rebuild writes its own data model, written
fresh and bound by a test per [`0011`](0011-rebuild-documentation-is-written-fresh-and-bound-by-tests.md).

The rebuild may read bundles the old pipeline wrote, in **test tooling only**. No reader of the old
format ships in the product, per `0001`. What is preserved is the captured forest data, not the
file format, so a reader is expected to be replaced by a one-off extraction once the schemas
diverge.

Captures are taken from the lab forest and frozen as test assets before the old capture code is
deleted, because it is the only thing that can produce them. The concluded half of such a bundle -
control edges, escalation paths, findings - is an answer key to be explained against, not a
specification to be reproduced.

## Consequences

The product does not run end-to-end until connect, capture and storage are rebuilt. That is
accepted, and it is the largest cost of this decision.

Fixing a wrong schema now costs only the code change, which is the reason for making it.

Frozen lab captures give the rebuild real Active Directory semantics and a real multi-domain
topology - an empty root and two child domains - which is where a forest-wide audit tool
misattributes objects. They do not give scale. The order-of-magnitude errors this product has
already made were found at production size, so scale remains an open problem with no answer here.

Comparing new output against a frozen bundle's conclusions will produce differences, and each is a
defect in one implementation or the other. A difference is a conversation, never an edit to the
frozen side.
