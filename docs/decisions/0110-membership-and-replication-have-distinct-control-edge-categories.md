# 0110 - Membership and replication have distinct control-edge categories

Date: 2026-09-06
Status: Accepted.

Settles Q10 of [the stage-6 specification](../next/SPEC-stage-6-control-edges.md).
The owner accepted the recommendation: "ill take your recommendation".

## Decision

**Add `MembershipEscalation` and `ReplicationControl` as separate capability categories,
without renaming or removing existing categories.** Retain `DirectoryControl`,
`CredentialExposure` and the existing specification's `ConditionalEscalation` vocabulary.
This does not promise that every category has a stage-6 capability.

- **DirectoryControl** describes authority over an object's own security descriptor.
  An established owner-setting right is not an unconditional DACL-takeover claim.
- **CredentialExposure** describes credential-related capabilities, such as password reset.
  A password reset is not described as control of the target's permission list.
- **MembershipEscalation** describes group-membership capabilities. Unrestricted membership
  modification and adding or removing one's own account remain different capabilities.
  The category does not assert that every target group is privileged.
- **ReplicationControl** describes capabilities obtained through directory replication.
  Each capability retains its qualifying rights and target naming context; the category does
  not imply access to every secret or every filtered attribute.

**These are semantic categories, not an ordered risk score.** Category assignment does not
establish severity, expectedness, Tier 0 classification, feasibility or confidence. In particular,
classifying a domain controller's capability as replication does not hide it: `0105` still
requires visible grouping by holder and naming context, apart from its other capabilities.

## Evidence and rationale

The following Microsoft pages were read in full before the recommendation was accepted:

- [Control Access Rights](https://learn.microsoft.com/windows/win32/ad/control-access-rights)
  distinguishes extended rights, property sets and validated writes. It specifically says
  Self-Membership permits the caller's account, but no other account, to be added or removed.
- [Self-Membership](https://learn.microsoft.com/windows/win32/adschema/r-self-membership)
  identifies the validated write and its group target.
- [User-Force-Change-Password](https://learn.microsoft.com/windows/win32/adschema/r-user-force-change-password)
  defines password resetting, not security-descriptor modification.
- [DS-Replication-Get-Changes-All](https://learn.microsoft.com/windows/win32/adschema/r-ds-replication-get-changes-all)
  describes replication of secret domain data.

**The category names are SecureAD vocabulary, not a Microsoft taxonomy.** The sources establish
why the operations must not be described interchangeably; the owner accepted how SecureAD groups
them. Separating them also supports `0105`'s already-accepted presentation boundary.

## Consequences and limits

- Persistence, the capability catalogue and presentation must use the same category values.
  Future export must preserve them as well; this decision does not start the export stage.
- Counting remains governed by `0097`: membership expansion and supporting routes do not
  multiply the counted group-held edge. Primitive evidence survives beneath aggregates.
- Expectedness remains governed by `0098` through `0101`, not by these category names.
  Owner acceptance remains separate under `0107` and `0109`.
- `0103`'s owner-transition laboratory gate remains. An established `CanSetOwner` is not
  weakened by an unknown compound, and the unknown compound is not promoted by its category.
- The stage-6 specification's group-held Self-Membership verification gate remains in place.
  These references and this category decision are not a record that its controlled cases ran.
- This accepts Q10 only, not the rest of the proposal. It does not implement control edges,
  clear P-145 or establish that stage 6 is complete.
