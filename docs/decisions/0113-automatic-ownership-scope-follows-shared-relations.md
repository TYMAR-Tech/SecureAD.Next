# 0113 - Automatic ownership scope follows shared relations

Date: 2026-09-08
Status: Accepted.

After completion of the shared foundation, the owner explicitly approved the selector-and-tests
slice, including partial results on cancellation and no audit-loop, UI or production-budget changes.

## Decision

The automatic ownership selector consumes the shared classifications and source-bound relations
introduced under [0112](0112-shared-tier-0-classification-and-ownership-contracts.md). It defines no
new Tier-0 list. Established shared classifications are its starting points: core identities and
already-qualified controllers such as supported effective members. Inclusion of further controllers
is an assessment reason, never promotion of their Tier-0 classification.

Walk incoming relationships towards those starting points, not outgoing relationships to everything
an administrator manages. Preserve conditional ownership candidates and independent source grants.
A disproven source relationship cannot establish inclusion through that relationship; other grants
remain independently usable. Unsupported dependencies and unresolved identities/resource contexts
remain explicit incomplete scope, not a reason to guess or assess the whole forest.

The selector processes supplied captured relationships only. It does not discover memberships,
contact a directory or enumerate all possible paths. Each selected target is visited once; cycles
terminate, while the retained relation graph preserves alternative explanations. Source, target,
policy and audit-generation mismatches are not silently merged. Ambiguous captured identities are
not used to propagate selection.

Cancellation returns discovered inclusions with an explicit cancelled/incomplete outcome and retained
source reasons. Unvisited, absent or unresolved objects cannot read as outside a complete automatic
scope. Input coverage, supported analysis and processing completion remain independent. No result
from this library call authorizes publication of a partial audit.

## Implementation boundary

This approval covers the offline selector, immutable result/progress contracts and synthetic tests.
There is no production processing limit, inherited membership budget, audit activation, new persisted
format, ownership evaluator change, object command or UI edit. Callers must verify source stores and
provide their coverage; the current partial classification producers cannot establish a complete
forest scope merely because the selector finishes its traversal.

The later audit integration must preserve existing-owner findings, primitive permissions, full-control
supports, group-held counts, rule-pass behavior and immutable publication guarantees. UI wording and
layout retain their separate approval boundary. No new measurement harness, frozen benchmark change,
live access, recapture, commit or push is authorized by this slice.
