# 0033 - Nothing inherited is definitive: the map, the old code and the old documentation are evidence, not answers

Date: 2026-08-12
Status: Accepted

## Context

This rule already existed in three places and was recorded in none of them as a decision.
[`docs/next/README.md`](../next/README.md) says the map *"names the file to open; it is not the
evidence."* [`0011`](0011-rebuild-documentation-is-written-fresh-and-bound-by-tests.md) says old
documents are source material and are not promoted by being moved. The repository instructions warn
that the map is not always right.

Three statements of the same rule, none citable, and the rule has been broken repeatedly:

- **Three claims taken from the map on 2026-08-12 were contradicted by the code**, and two had
  already been built on before anyone checked. Recorded as `F-S15-9`.
- **[`0021`](0021-re-analysis-produces-a-new-bundle.md) exists because re-analysis was deleted on the
  strength of a summary.** The summary said re-analysis re-sealed the bundle, so a re-analysed
  capture could no longer prove what it was. The implementation copies the source into a new bundle
  and never touches the original. The feature was removed for a reason that reading the code would
  have disproved in minutes.
- **[`0016`](0016-the-filtered-set-replication-route-is-a-product-judgement.md) exists because a
  finding said *documented* about something Microsoft does not document.** The finding asked to be
  confirmed rather than believed, and the row that inherited it read it as settled.
- **[`0014`](0014-capture-reads-the-schema-partition.md) exists because
  [`0008`](0008-live-verification-is-removed.md) asserted capture reads the schema partition.** It
  did not and never had.

Each was a claim that was true when written, or was never true, and travelled without its caveat.

## Decision

**The map, the old code and the old documentation are evidence to be weighed, never answers to be
adopted.** A claim from any of them is a lead. It is confirmed against the thing it describes before
anything is built on it, and the confirmation is recorded.

**Where a decision rests on what the old implementation did, the old implementation is read.** The
map names the file; opening it is the work.

**Where a claim is about Active Directory rather than about this codebase, it is checked against
Microsoft's own documentation**, and the citation is carried with it. A claim that cannot be sourced
is marked as a product judgement and says so - which is what `0016` did with the filtered-set route.

**A claim that could not be confirmed is recorded as unconfirmed rather than dropped or believed.**
The failure mode `0016` names is the one to avoid: the caveat survived in the original and the claim
travelled without it.

**The method is: approach the problem, research it, decide, and iterate until it is done.** Not:
find what the predecessor did and reproduce it.

## Consequences

Every component costs more, and this is the second record to say so -
[`0011`](0011-rebuild-documentation-is-written-fresh-and-bound-by-tests.md) already priced fresh
documentation at a fifth to a third again. The same reasoning applies to fresh confirmation, and it
is accepted for the same reason: the alternative is inheriting errors nobody decided to inherit.

**The frozen oracles are the deliberate exception**, and they are not an exception to this rule so
much as an application of it. The classifier fixtures and golden hashes are copied byte for byte
precisely because they are *evidence of what the old system produced*, not claims about what is
correct. A golden value that needs editing is a finding rather than a fix, per
`docs/next/README.md`.

**This does not license rewriting working behaviour.** Confirming a claim often confirms it. `K15`
is the map's one unqualified keep and it was ported unchanged, and `0010` found the rule catalogue
sound. The rule is about what may be *assumed*, not about what must be changed.

A session that cannot confirm a load-bearing claim within its scope records that it could not, and
says plainly what was assumed instead. Silent assumption is the thing this forbids.
