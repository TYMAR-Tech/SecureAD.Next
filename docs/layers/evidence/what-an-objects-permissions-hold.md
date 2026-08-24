# What an object's permissions hold

**Code:** `next/src/SecureAD.Evidence/ObjectPermissions.cs`
**Layer:** Evidence — one object's security descriptor, as the bundle stored it.

[`what-a-bundle-holds.md`](what-a-bundle-holds.md) describes the tables a bundle is made of, and
[`what-an-object-holds.md`](what-an-object-holds.md) is one object's attribute values read back out
of them. This page is the other half of the same object: who may do what to it. It is what the
permissions section of the object window is built from.

The door is `BundleReader.ReadPermissions`, which belongs to
[`how-a-bundle-is-read.md`](how-a-bundle-is-read.md); the reader behind it,
`ObjectPermissionsReader`, is internal and is described here because its behaviour is the only
thing a caller can observe about it.

Naming a right, wording a mask and judging whether a permission is dangerous are not done here.
Those belong to the Kernel — see [`permission-classification.md`](../kernel/permission-classification.md)
and [`security-descriptors.md`](../kernel/security-descriptors.md). This page is about what the
bundle holds, not what it means.

Bound by `ObjectPermissionsDocumentationTests`. The states table below is bound **in both
directions** against the code — an availability state the code declares and this page does not name
fails the build, and so does a row here naming a state that does not exist.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `ObjectPermissions` | One object's security descriptor as the bundle holds it: who owns it, what state its DACL was in, its entries, and what went wrong reading it |
| `PermissionEntry` | One access control entry, as the bundle stored it — the mask and the flags, neither worded nor judged |
| `PermissionTrustee` | The principal an entry names, and what this bundle knows about it |
| `DescriptorAvailability` | Whether this bundle holds the object's descriptor at all |

<!-- TYPES:END -->

This table is the page's claim of ownership, and it is bound in both directions: a public type of
this component missing from it fails the build, and so does a row naming something that is not one.
Other pages name these types in passing — to say where a boundary is, or what a column holds — and
a mention is not a claim.

## Three ways to hold no entries, and only one is about the object

`DescriptorAvailability` exists because an empty permission list has three causes and they mean
opposite things.

<!-- AVAILABILITY:BEGIN -->

| State | What it means |
|---|---|
| `Read` | The descriptor was read and is in this bundle |
| `Unreadable` | The object has a descriptor and this run could not get it |
| `NotAttempted` | Nothing was attempted — no descriptor was read and no failure was recorded |

<!-- AVAILABILITY:END -->

Only `Read` with no entries is a fact about the forest. The other two are the absence of a fact,
and a viewer that does not keep them apart tells a reader an object is safe when nobody knows
whether it is. One production domain returned 19,927 of 100,000 objects with no readable
descriptor, so this is the common case rather than the corner.

This is a different question from `DaclState`. This says whether the descriptor *arrived*; that
says what the descriptor, having arrived, *contained*.

## The entries come from the descriptor's own bytes, not from the `ace` table

`ObjectPermissions.Entries` is produced by re-parsing `security_descriptor.raw_bytes`. The `ace`
table is not read for this, and that is deliberate.

The `ace` table is the **canonical projection**: sorted into evaluation order and deduplicated by
`ace_hash`. That is right for what it is for — `ace_set_hash` is how two runs are compared without
reading every entry of every object — and wrong for showing an operator what the directory holds.
A DACL carrying the same grant twice is what the directory holds, and a reader deciding it meant
once is editing evidence.

**This is measurable, not theoretical.** On lab bundle `ad.lab-20260821-014720`, across all 363
descriptors, the projection holds 12,601 entries and the stored bytes hold 12,604. Three
descriptors account for the whole difference: the two default Group Policy objects in each of the
three domains, each carrying one duplicated `AccessAllowed` entry for that domain's administrators.
Reading the projection would drop those three entries before anybody could see them.

Entries are ordered by the ordinal the canonicalised DACL gave them, and generic rights are
expanded on the way out, so a shorthand *full control* has already become the specific rights it
grants before any caller sees it.

## An entry is stored, not interpreted

`PermissionEntry` carries the mask and the flags as the directory holds them. `AceType` is kept as
stored text rather than parsed into an enum, so an entry of a type this build has no member for
reaches a reader instead of being dropped.

`HasObjectType` and `HasInheritedObjectType` come from the flags the entry actually carried, not
from whether the corresponding GUID is null. Those are different questions, and inferring presence
from nullity is right only by coincidence of the current parser.

## A trustee is a SID first and a name only sometimes

`PermissionTrustee.DistinguishedName` is null far more often than it looks like it should be. A
trustee is a SID, and a SID is only a name if the object holding it was captured by this run.
Well-known identities, principals from another domain, and identifiers left behind by a deleted
object all stay bare. `UnresolvedReason` says why, where the run classified it.

Names are resolved against Microsoft's table first and this run's captured objects second, and
nowhere else. There is no lookup against a live directory: a bundle is read on a machine that may
never have seen the forest, and a name fetched at read time would be the name today rather than the
name the evidence was sealed with.

`HoldsThePermission` is false only for a well-known SID that is not a principal — `CREATOR OWNER`,
or `OWNER RIGHTS`, which sits in a DACL to change what ownership grants rather than to grant
anything itself. It is true for an ordinary account or group this run could not resolve, because a
trustee whose name is unknown still holds the permission and reporting otherwise would understate
who has access.

## Ownership, and the one thing it is allowed to say

An owner ordinarily holds Read Permissions, Modify Permissions and Modify Owner implicitly, and
Modify Permissions is the dangerous one — an owner can write himself full control. An
`OWNER RIGHTS` entry is how an administrator stops that.

`ObjectPermissions.OwnerRightsEntryIsPresent` reports that such an entry is present and applies to
this object. It does **not** report the owner as powerless: Microsoft documents the suppression of
the owner's implicit `READ_CONTROL` and `WRITE_DAC` and is silent on `WRITE_OWNER`. An entry that
applies only to descendants does not count, because it governs the objects beneath a container
while granting nothing on the container itself.

False is also the answer when the DACL could not be read, which is the honest one: nothing was seen
that restricts ownership. `DaclState` and `Errors` are what say whether looking succeeded.

## Errors are what the run recorded plus what re-reading found

`Errors` merges two sources: the messages the capturing run stored against this descriptor, and any
error produced by parsing the sealed bytes again now. Duplicates are dropped.

A fresh error means the parser changed between the build that captured and the build that is
reading. The bytes cannot have changed — the seal covers them — and `canonicalization_version` does
not detect this, because the parser is not the hash. Reporting the fresh error rather than
swallowing it is what stops a descriptor this build cannot re-read from looking like an object that
grants little.

## What a null return means

`ReadPermissions` returns null when the bundle captured no object by that name. That is a different
answer from an object with no entries, and is kept apart from it for the same reason
`DescriptorAvailability` has three states.
