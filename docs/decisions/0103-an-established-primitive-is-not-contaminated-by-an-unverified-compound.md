# 0103 - An established primitive is not contaminated by an unverified compound

Date: 2026-09-06
Status: Accepted.

Settles `Q7` of `SPEC-stage-6-control-edges.md` - what confidence `CanSetOwner` carries, and what
happens to the takeover route built on top of it.

## Context

Microsoft states that a holder of `WRITE_OWNER` *"can set any valid user or group SID as the owner of
an object"*, and the `TOKEN_OWNER` constraint governs the default owner for newly created objects
rather than this operation. An earlier draft of the specification claimed the documentation was split
on this and was wrong to.

What is genuinely unverified is whether AD DS adds server-side constraints of its own, because the
product audits AD DS rather than an abstract securable object. The temptation was to hold the whole
route at `Unknown` until a lab observation settled it.

## Decision

**Three claims, kept separate, each carrying its own confidence.**

1. **The holder has `WRITE_OWNER`** - `Established` from the descriptor, by effective access.
   `CanSetOwner` is `Established` whenever effective access establishes `WRITE_OWNER`.
2. **AD DS permits the holder to name a controlled takeover SID** - `CanSetTakeoverOwnerSid` stays
   `Unknown` until the AD DS lab gate in section 13.1 is recorded.
3. **The resulting owner can rewrite the DACL** - follows the owner-implicit-rights decision tree,
   which already consults `OWNER RIGHTS` and `BlockOwnerImplicitRights` under all three MS-ADTS
   6.1.3.4 conditions (`F-S45-2`).

**`CanBecomeOwnerAndRewriteDacl` is `Unknown` unless every precondition is `Established`.**

**Confidence never flows backwards.** `CanSetOwner` is not reduced because the compound route above
it is unverified - that would contaminate an established primitive with uncertainty belonging to a
later step, and it would make the product quieter about something it can actually prove.

## Consequences

- **The screen can say what is proven and what is not, in the same chain**, rather than collapsing to
  the weakest link and reporting less than the evidence supports.
- **The lab gate retires exactly one `Unknown`**, and its absence blocks nothing else.
- **This is the general shape** for any compound capability the product later assembles: the compound
  inherits the weakest precondition, and no precondition inherits anything from the compound.
