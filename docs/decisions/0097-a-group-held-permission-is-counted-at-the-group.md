# 0097 - A group-held permission is counted at the group and expands to its members

Date: 2026-09-05
Status: Accepted.

Settles `P-72`, which the row states plainly affects every count an operator reads.

## Context

A permission is granted to a group and held by everyone inside it, directly or transitively. Three
attributions are possible and they produce wildly different numbers on the same forest: name the
group, name every effective member, or name both.

**The predecessor is the evidence against naming every member.** Its dashboard reported 111,627
control edges on `ba.ad.lab`, a lab of about eight thousand objects. Most of that volume is this
shape - one access control entry granting one group, multiplied by its membership - and the remedy
for all of them is still the single entry.

**What the code already does.** `BroadPrincipalCanTakeOverObject` names the broad principal it
reached and records the route it took as `PathFromRoot`, keyed on the broad principal so that two
routes to the same principal on one object are one finding. The route is already carried; only what
is counted was undecided.

## Decision

**Both are stored. The group edge is what is counted; members expand from it on request.**

An operator's headline reads *Helpdesk (400 members) can take over OU=Finance*, and one click lists
the 400.

Three conditions.

1. **The counted edge names the principal the access control entry names**, because that is the
   thing an administrator changes. A count an operator cannot act on is a number he learns to scroll
   past.
2. **The member expansion is stored, not recomputed at display time.** A view that recalculates
   membership would disagree with the edge that produced it the moment a walk stopped early.
3. **The route travels with the edge**, as `PathFromRoot` already does for `SEC-060`, and the
   completeness voucher travels with it. A membership walk that stopped at a budget makes the
   expansion incomplete, and the expansion must say so rather than appear short.

## Consequences

**A 400-member group and a 2-member group produce the same count of one.** The membership size is on
the row, so the difference in exposure is visible without being multiplied into the total.

**Which root a membership is attributed to is a separate defect**, recorded as `P-105`: `Walk`
reports the last established root processed rather than the nearest, so three accounts directly in
Enterprise Admins on `ad.lab` are each reported under `BUILTIN\Administrators`. An edge that names
the wrong root sends an operator to remove the wrong membership. That is fixed before stage 6
consumes `Walk`, not inside it.
