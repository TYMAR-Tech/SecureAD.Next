# 0105 - Domain controller edges are grouped, never suppressed

Date: 2026-09-06
Status: Accepted.

Settles what the screen does about domain controller computer accounts, which
[0099](0099-the-tier-0-control-plane-catalogue.md) placed outside the control plane.

## Context

`0099` holds that a domain controller computer account is a Tier 0 **asset** and not a control-plane
**entry**, following the settled ruling that a group of domain controllers is not a domain
controller. Its edges therefore surface.

The consequence is that every domain controller in the forest produces visible replication edges on
the first run. On a large forest that reads as hundreds of unrelated replication defects, which is
how an operator learns to distrust a screen.

**The wrong fix is to conclude from the count alone that this is noise and hide it.** Microsoft
describes replication as occurring between domain controllers and identifies each controller through
its server and NTDS Settings objects - which supports the conclusion that DC replication activity is
legitimate, and does **not** establish that every right a DC computer account holds should be hidden.

## Decision

**Domain controller computer accounts stay outside the expected principal catalogue. What changes is
presentation, not expectedness.**

1. **Visible replication edges are grouped by holder and naming context.**
2. **The holder is labelled as a domain controller asset** where that classification is established -
   and where it is not established, it is not asserted.
3. **Replication capabilities are presented separately** from anomalous `DirectoryControl`,
   `CredentialExposure` or `MembershipEscalation` capabilities held by the same account. A surprising
   capability must not be buried inside a block of routine ones.
4. **No edge is suppressed**, and the stored set is unchanged. This is a view under
   [0092](0092-a-view-filter-is-not-a-change-to-the-catalogue.md), not a change to what the product
   concluded.
5. **Primitive replication rights forming one compound capability are counted once**, not separately,
   so the number reflects what an administrator would change.

**No *expected DC replication* exception is added**, and it is not added until stage 6 can tell apart:

- a replication capability required for ordinary domain controller operation,
- a surprising capability held by a DC account,
- a replication right granted outside the normal DC authorisation structure,
- a stale computer account still holding rights after demotion or replacement.

**Until those are distinguishable, visible and clearly grouped is safer than hidden.** The last of
them - a demoted controller's account still holding replication rights - is precisely the finding an
audit tool exists to produce, and an expectedness exception would hide it.

## Consequences

- **The first screen is readable without anything being suppressed**, which is the outcome `0098`
  wants and the mechanism it permits.
- **The grouping is measured, not assumed.** `P-145`'s gate reports counts attributable to each
  domain controller computer account, so whether this presentation works is a number rather than an
  opinion.
