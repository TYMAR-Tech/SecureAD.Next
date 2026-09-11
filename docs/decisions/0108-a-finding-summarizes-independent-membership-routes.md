# 0108 - A finding summarizes independent membership routes

Date: 2026-09-05
Status: Accepted.

Settles the reporting choice in `P-146`. Revises the single-nearest-root reporting choice in
[`0106`](0106-a-membership-is-reported-under-the-nearest-root.md), without removing its requirements
for deterministic answers or for keeping a direct catalogue claim distinct from membership.

## Context

An account directly in two privileged groups needs both memberships considered. Naming only the
nearest group and breaking ties deterministically makes the answer repeatable, not complete.
Reporting every equally nearest group still misses an independent route that happens to be longer.

Conversely, several outer groups reached through the same initial membership do not necessarily
require separate removals. Reporting a row for each outer group would multiply the screen by nesting
depth, which is the volume failure `0097` is intended to avoid.

Source inspection found that the current protected-principal derivation stores one selected basis
and one path per principal. The earlier claim that alternative paths were already stored and shown
was false. The underlying nesting is retained, but deriving and presenting alternatives is new work.

## Decision

**Use one finding to summarize independent membership routes, including longer routes, rather than
naming only the nearest root or only equally near roots.** The owner selected option 3 of the three
choices recorded in [WHAT-THE-PRODUCT-IS.md](../WHAT-THE-PRODUCT-IS.md).

A membership route is a chain of group memberships leading from the account to a privileged group.
The initial membership is the group the account directly belongs to. Routes sharing that initial
membership are grouped, rather than represented as separate removal instructions merely because
more outer groups can be reached through it.

The finding can say: *Alice has two membership routes to privileged groups. Review both.* Its
supporting detail names the routes and the initial memberships, so an operator can see what is
actually present and which memberships can be changed. Longer independent routes must not disappear
because a shorter route exists elsewhere.

This changes the membership explanation, not the counted permission edge. `0097` still counts a
group-held permission at the group; it must not be multiplied by the number of members, paths or
outer groups appearing in this explanation.

## Boundaries

- This is not a promise that removing the listed memberships makes an account safe. Other forms of
  control may remain. Proving that every route is removed belongs to the later remediation stage.
- This is not a promise to find the minimum set of removals. Routes may share links beyond their
  initial membership, and changing a shared group can affect other accounts.
- A partial expansion must be labelled partial, with its stopping reason, under `0102`. A partial
  count cannot be presented as the total number of membership routes.
- Protection by AdminSDHolder is not itself proof of membership-based authorization. The separate
  derived answers remain separate; this reporting change must not conflate them.
- Owner acceptance remains its independent answer under `0107`; it must not be reconstructed from
  a selected root, or from the presentation's route summary.
- Answers and their ordering must remain deterministic. A principal protected in its own right
  retains that direct catalogue basis rather than being relabelled as protected through membership.

## Alternatives not selected

**Name all equally nearest roots in one finding.** Less derivation and presentation work, but the
same failure remains when the second independent route is longer.

**Name one nearest root and count the other equally near roots.** A shorter headline, but still
requires deriving the alternatives, hides their names behind another click, and has the same
longer-route limitation.

## Implementation status

**Implemented by P-146.** `MembershipRouteDeriver` derives supporting chains grouped by initial
membership, including longer independent routes to the same root. Derivation schema 10 persists
their scoped identities, captured names, primary links, separate authorization/protection statements
and explicit completeness. The selected protection basis and independent owner acceptance remain
separate. Older single-path stores are refused, not presented as complete route answers.

SEC-021 version 2 carries the summary in one finding, first persisted in judgement schema 14 and exposed
on both existing finding surfaces. Partial evidence retains known findings and names its limits;
the wording makes no minimum-removal or all-privilege-eliminated claim. These are representative
supporting chains, not an exhaustive enumeration of all paths through nesting. Tests cover independent
equal/unequal routes, shared initial memberships, cycles, scope, primary links, stable ordering,
partial expansion, both stores and both screen bindings; regression mutations were observed failing
and restored. P-149's independent layout checkpoint and disabled-refusal control preceded the layout
change. Verification details and the unchanged ad.lab ownership result are in the product document.

At the completion of P-146, stage 6 had not started. The ownership measurement exposed 1,778 misleading Schema Admins
findings, recorded as `P-147` and subsequently corrected by scoped acceptance under `0109`.
The owner explicitly permitted a stopping point with the measurement reported and this decision
recorded rather than a half-built control-edge implementation.

The initial control-edge slice was implemented afterwards, including P-150's catalogue-2 scope
correction. Its current boundary and remaining acceptance gates are recorded in
the judgement store.
That later work does not change this decision's membership-evidence requirements.
