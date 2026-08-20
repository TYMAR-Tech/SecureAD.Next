# 0012 - The rebuild lives outside src/ and builds from its own solution

Date: 2026-08-09
Status: Accepted

Supersedes the location and solution given in
[`0009`](0009-greenfield-in-place-with-the-bundle-as-seam.md). Everything else in that record stands:
the rebuild remains in this repository, and the bundle remains the seam.

## Context

The rebuild was placed at `src/next/` so that the whole-product invariant scan, which resolves `src/`
and recurses it, covered the new tree from the moment it existed. That worked, and it was the wrong
reason to choose a location.

Four architecture test files resolve `src/` the same way, and two of them assert the *old* design
rather than a product invariant: read connections must come from the old connection factory, and
connection strings must not be built from literals. The new storage project will trip both as soon as
it opens a connection, for a design that is deliberately different. One of those tests asserts that
its scan root ends in `src`, so the scoping is a decision rather than an accident.

Sharing one solution had its own cost, paid during setup. The editor recreated a project on disk
after it was removed from the solution, held file locks that blocked a rename, and prompted to reload
on every change made outside it. Building the rebuild meant building the old tree, and its several
hundred analyser warnings, first.

Inheriting the product's central promise by accident of folder placement was fragile even while it
worked.

## Decision

The rebuild lives at `next/`, holding `next/src/` and `next/tests/`, and builds from
`next/SecureAD.Next.sln`.

`SecureAD.sln` keeps the original projects and nothing else. Neither solution references the other.
Both build from the command line, which is all the conformance harness and any automation require.

The invariants in `docs/INVARIANTS.md` are asserted explicitly against the rebuild rather than
inherited, so moving the tree again cannot silently drop them.

## Consequences

The repository has two solutions, and a session must be opened against the one it intends to change.
That is stated in `docs/next/README.md` and in the session prompt.

The invariant guards are duplicated, and the duplicates can drift from the originals. This is
accepted: the alternative was carrying the old tree's design assertions into new code, and a
duplicate that is visible in its own project is easier to reconcile than an inherited rule nobody
can see.

Extracting `next/` into a separate repository later remains a `git subtree split`, so this does not
foreclose that.
