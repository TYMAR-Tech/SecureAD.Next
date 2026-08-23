# 0016 - The filtered-set replication route is a product judgement, not a documented fact

Date: 2026-08-08
Status: Accepted

## Context

Finding `F-S3-6`, recorded in the schema-GUID catalogue's slice document and since carried into
[`what-a-schema-guid-means.md`](../schema/what-a-schema-guid-means.md), states that
`DS-Replication-Get-Changes` held together with `DS-Replication-Get-Changes-In-Filtered-Set` at the
domain head is "a documented route to replicating that set, LAPS passwords among them, **without a
single ACE on any computer object.**"

That finding was written with unusual care about its own provenance - it says the mechanics "come
from published research rather than from anything in this repository" and asks to be confirmed
rather than believed. One word in it is nevertheless wrong, and it is the load-bearing one.
**Microsoft does not document this.**

Verification against Microsoft Learn, recorded in full in
[`permission-classification.md`](../kernel/permission-classification.md):

- The Learn page for
  [`DS-Replication-Get-Changes-In-Filtered-Set`](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-in-filtered-set)
  carries **no description whatsoever**. It publishes a CN, a display name, a rights GUID and an
  applies-to list, and says nothing about what the right permits. Its two siblings both carry a
  description sentence; this one does not.
- [`DS-Replication-Get-Changes-All`](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all)
  is described as "Control access right that allows the replication of secret domain data."
- Microsoft's own definition of DCSync, in the Defender for Identity posture assessment
  [Remove non-admin accounts with DCSync permissions](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts),
  names exactly two permissions to remove: Replicating Directory Changes and Replicating Directory
  Changes All. The filtered-set right is not mentioned.

The premise underneath the finding fares better, but only half of it:

- `msLAPS-Password` is documented with `SearchFlags: 904` in the
  [Windows LAPS schema extensions reference](https://learn.microsoft.com/windows-server/identity/laps/laps-technical-reference),
  which Microsoft decomposes as `fRODCFilteredAttribute + fNEVERVALUEAUDIT + fCONFIDENTIAL +
  fPRESERVEONDELETE`. Confidential **and** in the RODC filtered attribute set, stated outright.
- `ms-Mcs-AdmPwd` is a legacy LAPS schema extension and appears nowhere in the AD schema reference.
  Microsoft describes it as a confidential attribute in a
  [Windows Server 2025 troubleshooting article](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/confidential-attributes-unexpected-behavior-using-windows-server-2025-dc),
  and publishes **no `searchFlags` value for it and no statement that it is in the RODC filtered
  set**.

So the mechanism is plausible and its motivating premise is confirmed for the modern attribute:
a right named for the filtered set, and an attribute documented as being in the filtered set. That
is a good reason to suspect the route. It is not a source for it.

Meanwhile the product has already taken a position. [`SEC-002`](../rules/SEC-002.md) specifies the
DCSync rule as firing on any pair from `{GetChanges} x {GetChangesAll, GetChangesInFilteredSet}` and
surfaces `has_get_changes_in_filtered_set` in its context. [`SEC-076`](../rules/SEC-076.md) does the
opposite - it requires the `GetChanges + GetChangesAll` pair and explicitly declines the filtered-set
case - and records the divergence as `[IMP-DCSYNC-FILTERED-SET]`, noting it "requires a
product-level decision".

The two rule specifications disagree with each other, and both are source of truth for their own
rule.

## Decision

The filtered-set replication route is retained as a **product judgement whose provenance is
[`SEC-002`](../rules/SEC-002.md)**, not as a fact about Active Directory. The word "documented" is
withdrawn from `F-S3-6`. No assertion anywhere in the rebuild may cite Microsoft for it.

`F-S3-6` stays open and stays owned by the rules work. It is **not** an obligation on K16.

K16 takes no position on whether the pair is dangerous, because a per-ACE classifier cannot hold a
position on a pair. That is the per-principal question `F-S3-7` identifies, and it is recorded as
owed rather than answered.

The disagreement between `SEC-002` and `SEC-076` is a finding in its own right and is not resolved
here. Nothing in the rebuild should be written that assumes either one has won.

Lab verification - granting a test principal exactly `GetChanges + GetChangesInFilteredSet` in a
forest and attempting the read - remains the evidence that would settle it, and is now worth more
than before, because the citation that was assumed to exist does not.

## Consequences

K16 is unblocked. It was carrying an obligation it could not discharge, on the strength of a
citation that does not exist.

The `ms-Mcs-AdmPwd` `searchFlags` value carried anywhere in the rebuild has no Microsoft source and
must not be presented as though it does. `msLAPS-Password` is safe to assert with a citation.

If the filtered-set route is later confirmed in a lab, `SEC-076` is the specification that is wrong
and `SEC-002` is vindicated. If it is disconfirmed, `SEC-002` is over-reporting and the extra pair
must come out of the rule and out of its `ContextJson`. Either way one specification changes, and
the change is a rule change rather than a classifier change.

A finding that names its own weak provenance is doing its job. `F-S3-6` said it wanted confirming
rather than believing, and was then read as settled by the row that inherited it. That is the
failure mode worth noticing: the caveat survived, and the claim travelled without it.
