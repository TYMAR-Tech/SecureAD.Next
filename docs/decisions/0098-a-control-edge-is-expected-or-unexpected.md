# 0098 - A control edge is expected or unexpected, and the screen defaults to unexpected

Date: 2026-09-05
Status: Accepted.

Settles `P-73`. This is the decision that gives stage 6 a target rather than a backlog.

## Context

**The predecessor reported 111,627 control edges and 0 escalation paths on `ba.ad.lab`**, a lab
forest of about eight thousand objects. That is not an answer an administrator can act on. It is a
number he learns to scroll past, and once he does, the real one hides inside it.

Almost all of that volume is *dangerous but expected*: Domain Admins can take over a user account,
and that is what Domain Admins are for. Reporting it is true and useless. Not reporting it at all
would mean a genuinely compromised control-plane group produces silence.

[0006](0006-tier-0-and-expected-admin-are-separate-sets.md) keeps Tier 0 and
expected-administrator as separate sets, and what an operator sees where the two meet was undrawn.

## Decision

**Every edge is stored. Each carries a tag: expected or unexpected. The screen defaults to
unexpected, and states how many it is hiding.**

The headline an operator reads: *42 unexpected control edges (111,585 expected, hidden)*.

Four conditions.

1. **Nothing is discarded.** Every edge is computed, stored, exported and countable. Expectedness is
   a tag on an edge and a default filter over it, which is precisely the distinction
   [0092](0092-a-view-filter-is-not-a-change-to-the-catalogue.md) permits: it changes what is shown
   now, never what the product concluded.
2. **The suppressed count is always on screen.** A hidden number that is not stated is a hidden
   number nobody knows to open. This is the same commitment the dashboard makes about coverage:
   stated every time, including when it is zero.
3. **A broad principal is never expected.** `Everyone`, `Authenticated Users`, `Domain Users` and
   the rest of `BroadPrincipalCatalogue` always surface, whatever they hold and wherever they hold
   it. There is no organisation in which everyone is the expected administrator of anything.
4. **Expected means the holder is part of the control plane that already controls the object.**
   Which groups those are is `P-85`, and it is not settled by this record. **Answering `P-85` too
   generously is a wrong answer and not a safe one**: every group added to the control plane
   silently converts unexpected edges into expected ones and hides them by default. That is the
   failure mode this record exists to prevent, arriving through the back door.

## Consequences

**Stage 6 has a target.** The figure it must make small is the unexpected count, not the total, and
a healthy forest should produce a short list.

**`P-85` now gates stage 6.** Condition 4 cannot be implemented without it. It was a candidate
before this record and is a gate after it.

**An expected edge is still a path.** Expectedness affects the default view. It does not remove an
edge from a chain: a route that runs through an expected edge to reach an unexpected one is still a
route, and the chain is reported.
