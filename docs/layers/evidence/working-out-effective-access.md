# Working out effective access

**Code:** `next/src/SecureAD.Evidence/EffectiveAccessCalculator.cs`
**Layer:** Evidence — what a permission list actually grants, as opposed to what it says.

[`what-an-objects-permissions-hold.md`](what-an-objects-permissions-hold.md) describes the entries a
bundle stores for one object. This page is the step after: turning that list into the question a rule
actually needs answered, which is *what can this principal do to this object*.

**Those are not the same question, and the gap between them is where a tool tells a customer
something false.** The same trustee can appear on an object several times. Some entries take rights
away rather than grant them. Some entries are sitting on the object only so that they can be copied
onto the objects beneath it, and grant nothing where they sit. Some are limited to a single
attribute. Reading such a list entry by entry and believing each one produces sentences like
*"Everyone can rewrite this object's permissions"* about objects where nobody can.

Naming a right or judging whether it is dangerous is not done here — that belongs to the Kernel, see
[`permission-classification.md`](../kernel/permission-classification.md). This page is about
arithmetic on masks, not meaning.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `EffectiveAccessCalculator` | Turns an object's stored entries into what each trustee effectively holds |
| `EffectiveAccessResult` | What the calculator found, and whether the question could be answered at all |
| `EffectiveAccess` | One trustee's effective mask, and the entry that first granted it |
| `EffectiveAccessOutcome` | Why a list of holders is, or is not, an answer |

<!-- TYPES:END -->

---

## The three things it honours

### An inherit-only entry grants nothing where it sits

`INHERIT_ONLY_ACE` marks an entry that does not control access to the object it is attached to. It is
there to be copied downwards when children are created. MS-ADTS 6.1.3 puts it plainly: the flag
*"identifies an ineffective ACE, which does not control access to the object to which it is
attached"*.

**This is not a rare shape.** Any inheritable entry whose `inheritedObjectType` names a class the
object does not have is stored on that object with the flag set. So an organizational unit
delegation scoped to user objects lands on every computer object beneath it as an inherit-only
entry. Counting one would report a machine as exposed by a delegation that does not touch it.

### Deny entries are applied in stored order

Active Directory gathers granted and denied masks across the whole list, and a deny removes only
rights that have not already been granted by an earlier entry. So **an allow appearing before a deny
survives it**.

This is why [`ObjectPermissions`](what-an-objects-permissions-hold.md) carries `DaclWasCanonical`,
and why `EffectiveAccessResult` carries it forward: a non-canonical list is *more open* than its
entries read, and an operator comparing this product against a directory tool needs to know which
kind of list they are looking at. Sorting the entries before evaluating them — the obvious-looking
simplification — would report such an object as safe when it is not.

### A scoped entry answers only the question it is scoped to

Whether an entry is limited to an object type is read from `ACE_OBJECT_TYPE_PRESENT` and **never**
from whether the GUID happens to be null, because an object entry carrying no GUID narrows nothing.

Asking about the object as a whole is a *narrower* question than asking about a named attribute, not
a wider one. It is answered only by entries that carry no scope, because a delegation over one
attribute confers nothing over the object generally.

---

## Absent, unreadable and clean are three states

An empty list of holders means *nobody holds anything* only when the descriptor was read and its
entries parsed. `EffectiveAccessOutcome` keeps the others apart, because all of them would otherwise
arrive at a caller as the same empty list and print as the same reassuring silence.

| Outcome | What it means | Why it cannot render as empty |
|---|---|---|
| `Computed` | The DACL was read and the holders are the answer | — |
| `DescriptorNotRead` | Nobody read the security descriptor | A production domain returned 19,927 of 100,000 objects with no readable descriptor. Reporting those as granting nothing says an object is safe when nobody knows |
| `GrantsEveryoneEverything` | The DACL pointer was null | The most open state an object can be in. A list of holders cannot express *everyone*, so reported as an empty list it would look like the safest object in the directory |
| `EntriesUnparsed` | The DACL declared entries and none of them parsed | What it grants is unknown, which is not the same as nothing |

`EffectiveAccessResult.IsComplete` is true only for `Computed` **and** a DACL every declared entry of
which arrived. A list that lost entries is a floor rather than the whole truth: a right nobody could
parse may still be granted.

---

## Who uses it

`LapsPasswordReadAccess` (SEC-090) asks it per LAPS password attribute. `SEC-060` and `SEC-031` are
specified against it and not yet built.

**It was private to SEC-090 until 2026-09-05**, and lifting it fixed a defect rather than only
sharing code: the private version never consulted the propagation flags, so an inherit-only entry
counted as a grant. Recorded as `F-S45-1`.
