# 0009 - The rebuild happens in this repository, with the bundle as the seam

Date: 2026-08-09
Status: Accepted as to the rebuild happening in this repository. Three parts have been replaced and
are corrected below: the two-way seam by [0013](0013-the-bundle-is-no-longer-a-two-way-contract.md),
the location and solution by [0012](0012-the-rebuild-lives-outside-src-with-its-own-solution.md),
and the word *signed* in the identity sentence by
[0030](0030-the-product-produces-sealed-evidence-never-signed.md).

## Context

The product's identity settled after most of its code was written. `docs/review/00a-product-identity.md`
states it in one sentence — a forest-wide security audit producing signed, point-in-time evidence —
and names the earlier identities it replaced. **— The word is now *sealed*, per `0030`: there is no
key in this product and nothing it produces is signed.** The code predates that sentence and its
structure records the older product: a capture mode that no longer exists, a live surface now
removed, a presentation layer with no navigation model in which every screen is alive from process
start.

The component-level map in `docs/map/` establishes that the layering is already correct and
mechanically enforced, that the storage schema and the rule catalogue are sound, and that the
accumulated damage is concentrated in surfaces that should not be ported at all. It also
establishes, in four independent places, that a correct mechanism built without a boundary obliging
its use is never adopted.

Rewriting in a separate repository would sever every `file:line` reference in roughly thirty
thousand lines of documentation from the code it describes, at the moment it is most valuable.

## Decision

The new implementation is built in this repository, beside the existing one. It lives at `next/`,
holding `next/src/` and `next/tests/`, and builds from `next/SecureAD.Next.sln`; the old projects
keep `SecureAD.sln`, and neither solution references the other. That location and split are decided
by [0012](0012-the-rebuild-lives-outside-src-with-its-own-solution.md), which replaced the original
`src/next/` placement and the shared solution.

The bundle is **not** a contract between the two implementations. The rebuild writes whatever schema
it needs and the old application is not expected to open it, per
[0013](0013-the-bundle-is-no-longer-a-two-way-contract.md), which replaced this record's two-way
seam and with it the deferral of every schema improvement. `docs/DATA-MODEL.md` specifies the old
bundle only; the rebuild writes its own data model, bound by a test. The consequence 0013 accepted
is that there is no working product end to end until connect, capture and storage are rebuilt.

The five cross-cutting contracts the map found unadopted — a result type carrying a structured
error, progress and cancellation as required rather than optional dependencies, one classification
of a dangerous right, counts that distinguish zero from could-not-compute, and artefacts that state
their provenance — are written before the product code that would need to adopt them later.

## Consequences

The repository contains two implementations of the same product for as long as the rebuild takes.
That cost is paid deliberately: it keeps the map and the review usable as navigation rather than as
history, and it keeps every `file:line` reference in the documentation pointing at the code it
describes. It does **not** buy a working product throughout, which this record originally claimed —
`0013` traded that away for a free hand on the schema.

The bundle schema is improved when an improvement is wanted, per `0013`. This record originally
deferred every improvement to a single migration after the old projects were gone; that deferral is
gone with the two-way seam.

`docs/map/` is not maintained against the new code. It describes what was built and why it would be
built differently; it is not a description of `next/`.
