# 0095 - Ownership is a control edge where the owner is not an administrator

Date: 2026-09-05
Status: Accepted.

Settles `P-70`, which stage 6 (control edges) cannot be built without. Narrows the row as written:
the row's premise was false and is corrected below.

## Context

**`P-70` said the product "reports the owner without saying what owning it grants". That was already
untrue when this was decided**, and the correction matters more than the row did.

Opened 2026-09-05:

- `next/src/SecureAD.Judgement/ObjectOwnershipRules.cs` implements `SEC-031` (an ordinary object
  owned by a principal that is not administrative, `Low`) and `SEC-032` (the same for objects
  `AdminSDHolder` protects, `High`). Both are registered in `RuleCatalogue.All`, so both run.
- `next/src/SecureAD.Evidence/Findings/ObjectOwnershipEvidence.cs` carries the owner SID and name,
  the object class, an `IsComplete` voucher over the membership walk, and a two-state standing:
  the owner exists, or the owner was deleted and the object is orphaned.
- `next/src/SecureAD.Judgement/BroadPrincipalCanTakeOverObject.cs` (`SEC-060`) already treats
  `WriteOwner` as takeover-class only where an owner's implicit rights survive, consulting both an
  `OWNER RIGHTS` (`S-1-3-4`) entry on the object and the forest's `BlockOwnerImplicitRights`
  setting, and refusing to answer where that setting was never read.

So the product does judge ownership. What was genuinely undecided is narrower: whether being the
owner is itself an **edge** - a stored statement that a principal can take over an object, which a
screen counts and a chain walks - or only a finding.

**Why it cannot wait for stage 6.** An owner implicitly holds Modify Permissions and can grant
himself full control. If ownership is not an edge, the graph is missing the most direct takeover
route there is, and every chain that runs through an owned container stops short.

## Decision

**Ownership is a control edge, and only where the owner is not an administrative principal** - the
same set `SEC-031` and `SEC-032` already report. The owner's words: the graph gains the direct
takeover route without eight thousand uninteresting edges.

Three conditions.

1. **The set is the one the existing rules already decide.** Stage 6 reuses
   `ObjectOwnershipReading` rather than restating what "administrative" means. Two definitions that
   must agree is the shape that has already cost this repository three defects.
2. **An ownership edge is claimed only where an owner's implicit rights survive.** The check is
   `SEC-060`'s and is not duplicated: an `OWNER RIGHTS` entry on the object, or the forest's
   `BlockOwnerImplicitRights` setting, removes them. Where the forest setting was never read, no
   edge is claimed in either direction - the absence of an edge must not read as safety.
3. **An ownership edge carries the same completeness voucher as the finding.** Where the membership
   walk behind "not administrative" stopped early, the edge says so.

## Consequences

**An object owned by Domain Admins produces no edge.** That is deliberate and it is the point:
those are the roughly eight thousand edges that made the predecessor's number unreadable. It is also
consistent with [0098](0098-a-control-edge-is-expected-or-unexpected.md), which would have marked
them expected and hidden them anyway.

**An orphaned object - owner deleted - produces no edge either**, because no principal can act on
it. It remains a `SEC-031`/`SEC-032` finding, which is where the remedy lives.

**This does not settle how the edge is displayed.** See
[0096](0096-effective-permissions-are-shown-object-first-and-principal-first.md).
