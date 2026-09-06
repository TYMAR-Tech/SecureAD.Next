# 0109 - Schema Admins ownership is accepted only in the schema

Date: 2026-09-05
Status: Accepted.

Settles `P-147`. Extends the separate owner-acceptance answer established by `0107` without widening
its unrestricted owner list.

## Decision

**Accept the forest-root Schema Admins group and its members as owners only within that forest's
schema partition, including the partition root itself.** The owner explicitly selected the group
and its members, not the group alone.

Ownership elsewhere remains reportable unless the principal independently qualifies through another
accepted owner category. An account in both Schema Admins and Domain Admins must retain that broader
acceptance; it must not be narrowed because the stored protection basis happens to name Schema Admins.

Identify Schema Admins by its forest-root security identifier, never its display name or RID 518
under an arbitrary domain. A renamed group still matches; a same-named custom group does not. Match
the target against the schema boundary of the captured forest, not any container called Schema.

Membership-based authorization and AdminSDHolder protection remain different questions. Derive the
owner answer independently rather than reading it from a single protection basis. A distribution
nesting path must not be treated as administrative authority merely because it propagates protection.

A proven schema membership stays accepted inside that schema when another membership path is
incomplete. Outside the schema, incomplete evidence must not be read as proof that the principal
has no broader accepted membership. Missing forest identity cannot authorize a schema exception.

## Evidence and reason

The ad.lab ownership comparison recorded in [WHAT-THE-PRODUCT-IS.md](../WHAT-THE-PRODUCT-IS.md)
produced 1,778 findings calling Schema Admins non-administrative on the schema it administers. This
was present with the five operator groups both accepted and excluded; it was not their volume delta.

Microsoft's [privileged accounts and groups reference](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
places Schema Admins in the forest root and limits its administrative authority to the schema.
[Schema Implementation](https://learn.microsoft.com/windows/win32/ad/schema-implementation) states
that the schema container is CN=Schema,CN=Configuration followed by the forest-root domain's
distinguished name, and that one schema serves the whole forest. Both pages were read in full.

Scoped acceptance matches that boundary. Accepting the group everywhere would hide ownership outside
its authority; accepting only the group itself would keep reporting its administrative members.

## Implementation and verification requirements

- Preserve the separate, persisted owner-acceptance answer and its uncertainty; do not infer it from
  AdminSDHolder protection or merge RID 518 into the unrestricted accepted-owner set.
- Invalidate older derivations when their stored owner semantics no longer answer this question.
- Test the real root group, direct and nested members, mixed accepted memberships, foreign and child
  domain identifiers, renamed principals, the schema root and descendants, similarly named targets,
  escaped DN separators, and incomplete evidence.
- Observe the boundary checks fail before trusting their passing result.
- Re-derive and judge the same sealed ad.lab evidence. Account for every finding removed and retain
  the remaining findings and undecided objects; do not claim a clean forest from a partial verdict.

This decision does not implement `0108`'s membership-route presentation or start stage 6.
