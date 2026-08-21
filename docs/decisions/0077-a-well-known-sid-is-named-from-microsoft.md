# 0077 - A well-known SID is named from Microsoft, not from the directory

Date: 2026-08-20
Status: Accepted

## Context

Until this decision the product learned who a SID was in one way: search the objects the run
captured for one whose `objectSid` matches, take its name and the domain it was captured from. That
is the right question for an account or a group, and the wrong one for the SIDs Microsoft defines,
in two ways that a lab bundle showed together.

**It answers confidently for SIDs that are not principals.** Active Directory keeps real objects
under `CN=WellKnown Security Principals,CN=Configuration` — thirty-four of them in the lab forest —
with names like `Self`, `Creator Owner` and `Everyone`. The search therefore succeeded for
`S-1-5-10`, and the screen showed **Self**, with a domain, in a card formatted identically to the
group beside it. The name was correct and the conclusion was not: `PRINCIPAL SELF` is a placeholder
meaning the object the entry sits on, and `CREATOR OWNER` is a template replaced when a child object
is created. Neither holds anything. In bundle `ad.lab-20260819-232425` those two SIDs were named by
**1,394** and **314** access control entries, among them `Write ms-Mcs-AdmPwd` and
`Write msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer object — permissions an operator acts
on, attributed to something that does not exist.

**It answers arbitrarily where several captured objects share a SID.** `S-1-5-11` matched four
objects in that bundle: the well-known principal in the forest root, and `ForeignSecurityPrincipals`
entries in three different domains. `ObjectPermissions` chose between them with
`SELECT … WHERE objectsid = $sid LIMIT 1`, which carries no `ORDER BY`, over a table with no index
on `objectsid`. The answer was therefore whichever row the scan reached first — correct only because
the Configuration partition happened to be captured before the domain partitions. A different
capture order, a resumed run, or an index added for performance would each have changed which domain
an operator saw beside *Authenticated Users*. Nothing in the product or its tests stated which of
the four was right, so nothing would have failed when it changed.

A third consequence sits behind both: with no notion of a well-known SID there was nowhere to record
that `S-1-3-4` — `OWNER RIGHTS` — is not a trustee at all but a qualifier that changes what owning
the object grants. That was finding `F-1` against `S-56`.

## Decision

**A SID is named from Microsoft's table first, and only then from the objects the run captured.**

`WellKnownSidCatalog` holds the values MS-DTYP 2.4.2.4 publishes and is consulted before the
captured-object search. Each entry carries what Microsoft calls it, what an operator should read, and
— the part that does the work — whether a permission naming it is held by somebody: a principal, a
placeholder substituted per object, an owner-rights qualifier, or a logon context.

**A well-known SID is given no domain.** It belongs to none. *Everyone* appeared to be a principal
of `ad.lab` only because the object it was named from lives in that forest's Configuration partition.
A relative identifier such as `Domain Admins` is a different case and is still resolved from the
captured objects, which find the real group and its real domain.

**The values are harvested, not written from memory.** `next/tools/harvest-ms-dtyp-well-known-sids.ps1`
extracts them over plain HTTP; the same section was read independently through the Microsoft Learn
documentation service; `WellKnownSidCatalogMicrosoftAnchorTests` pins every value.

**The predecessor's catalogue is a cross-check and never a source.** It was read in full and found to
carry `S-1-5-17` as *This Organization* where Microsoft publishes `IUSR`, to omit `S-1-5-15`
entirely, and to use `S-1-5-32-581` for Storage Replica Administrators where Microsoft publishes
`S-1-5-32-582` and no 581 at all. Both errors were internally consistent and would have survived any
test written from that file.

## Consequences

**A permission is credited only to something that holds it.** `PermissionTrustee.HoldsThePermission`
is false for a placeholder and for `OWNER RIGHTS`, and true for every ordinary account — including one
this run could not name, because not knowing who somebody is is not the same as their holding
nothing.

**`PRINCIPAL SELF` is resolved and `CREATOR OWNER` is not.** On `BAMS1` the first reads
*This object (BAMS1)*, which turns a grant that looked like it belonged to a group called Self into
what it is: a computer that may write its own delegation attribute. The second is left unresolved on
purpose — it becomes whoever creates a child object in future, and a sealed bundle cannot know who
that will be.

**The `LIMIT 1` ambiguity is dissolved rather than tie-broken.** The SIDs that matched several objects
no longer reach the query. The query and its missing `ORDER BY` remain for ordinary principals, where
a SID identifies one object; if that assumption is ever shown to be false for an account, it is a new
finding and not this one.

**The catalogue is another thing that must be kept correct**, and is exempt from gate 4 on the same
terms as the six catalogues before it: a table compiled into the assembly that reads nothing and
cannot fail. The claim that its contents are right is held by the anchor test and the harvest script,
not by the exemption.

**It does not decide whether the product judges ownership.** `OWNER RIGHTS` is now named and its
presence reported; what an owner is left with is not. Microsoft documents the suppression of implicit
`READ_CONTROL` and `WRITE_DAC` and is silent on `WRITE_OWNER`, and
`docs/areas/what-a-permission-means.md` still records ownership judgement as undiscussed.
