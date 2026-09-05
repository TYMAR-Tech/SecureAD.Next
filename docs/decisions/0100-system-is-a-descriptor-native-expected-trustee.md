# 0100 - SYSTEM is a descriptor-native expected trustee, not a catalogue administrator

Date: 2026-09-06
Status: Accepted.

Settles `P-141`, which [0099](0099-the-tier-0-control-plane-catalogue.md) left open as the one thing
that could spoil stage 6 before it computed anything.

## Context

`0099` entered SYSTEM (`S-1-5-18`) as restricted and did not say restricted to what. Under `AC-S6-14`
an entry that does not declare an unrestricted capability scope does not get one - and `S-1-5-18`
carries full control in the default security descriptor of very nearly every class in Active
Directory. Left as it was, every one of those became an unexpected edge and the default screen showed
a number in the tens of thousands: **the 111,627 failure arriving as the conservative choice**, with
the pressure then to widen the catalogue under duress.

**The distinction that resolves it.** Microsoft documents LocalSystem as having unrestricted access to
AD DS *when running on a domain controller*, and separately documents that on an ordinary domain
member LocalSystem presents the **computer's** credentials on the network and receives only what that
computer account or its groups are granted. So two different things share one name:

- `S-1-5-18` **named directly in an Active Directory security descriptor** - a platform authorisation
  the object itself encodes.
- **A service running as LocalSystem** on a member server, which authenticates as the computer
  account and is not `S-1-5-18` remotely at all.

Merging them is what would produce either the enormous count or, worse, a rule that suppresses edges
belonging to machine accounts.

## Decision

**`NT AUTHORITY\SYSTEM` (`S-1-5-18`) is an expected platform identity for capabilities directly
established by applicable ACEs naming SYSTEM. Its authority scope is derived from the ACE and its
valid inheritance scope, never assigned globally. Its capability scope is unrestricted within that
evidenced scope.**

This is **not** an ordinary control-plane entry and the data model keeps the difference visible. The
reason code is `ExpectedPlatformIdentityDirectAce`, distinct from `ExpectedSameDomainControlPlane`
and `ExpectedForestControlPlane`, because SYSTEM is expected *because the descriptor says so*, not
because a catalogue named it an administrator of anything.

**What it never does.**

- **SYSTEM expectedness never transfers to another principal** - not to a computer account, not to
  the Domain Controllers group, not to Enterprise Domain Controllers, not to anything.
- **A service running as LocalSystem on a member server is never modelled as using `S-1-5-18`
  remotely.** It acts as the computer account, which is a different principal with its own edges.
- **Missing, unread or incompletely parsed descriptor evidence produces `Unknown`, never `Expected`.**
  A descriptor nobody could read is not a permission anybody verified.

## Acceptance criteria this adds

| Id | Criterion |
|---|---|
| `AC-S6-16` | A directly applicable SYSTEM ACE may produce an `Expected` edge for each capability it effectively establishes. |
| `AC-S6-17` | SYSTEM receives no `Expected` capability that is not established by the target's effective descriptor. |
| `AC-S6-18` | SYSTEM expectedness does not transfer to a computer account or to any group. |
| `AC-S6-19` | A service running as LocalSystem on a member server is not modelled as using `S-1-5-18` remotely. |
| `AC-S6-20` | Inherited SYSTEM rights are `Expected` only where inheritance evaluation establishes that the ACE applies to the target. |
| `AC-S6-21` | An unread or incompletely parsed descriptor never produces an `Expected` SYSTEM edge. |

## Consequences

- **The structural platform ACEs stop dominating the screen** without anyone widening the control
  plane to achieve it.
- **`EffectiveAccessCalculator` and `EntryReachReader` supply the answer**, since expectedness for
  SYSTEM is now a question about whether an ACE applies - which is already computed, already consults
  `INHERIT_ONLY_ACE`, and was already the subject of `F-S45-1`.
- **Enterprise Domain Controllers (`S-1-5-9`) is a different question and stays restricted under
  `0099`.** It is a group, not a descriptor-native platform identity, and it is small enough to look
  at directly.
