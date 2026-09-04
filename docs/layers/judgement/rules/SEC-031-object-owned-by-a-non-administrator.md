# SEC-031 — an object is owned by somebody who is not an administrator

> **Status: specified, not built.** This document states what the rule must do and why. Nothing in
> it is authoritative until a decision record says so; read it as argument. Written 2026-09-04.

## For a reviewer

**What this rule says in one sentence.** *This object's owner can rewrite its permissions whenever
they like, and its owner is not an administrator.*

**Why an administrator would not otherwise see it.** Ownership is not in the permission list. An
administrator can review every entry on an object, find nothing wrong, and miss that the owner can
replace the whole list at will. Microsoft is blunt about this: *"No matter what permissions are set
on an object, the owner of the object can always change the permissions on an object."*[^planning]

**Where it comes from.** An object created by a member of the Administrators group is owned by that
group. An object created by anybody else is owned by **that person, personally**, and stays that way
for the life of the object.[^descriptors] So this condition is not usually an attack — it is the
ordinary residue of somebody once having been allowed to create something.

---

## 1. What it finds

One finding per object whose **owner** is not an administrative principal.

Ownership matters because of what it silently confers:

> An object's owner implicitly has **WRITE_DAC** access to the object. This means that the owner can
> modify the object's discretionary access control list (DACL), and thus, **can control access to
> the object**.[^owner]

So the owner is a permission holder who does not appear in the permission list.

## 2. Why this matters, and the honest limit of the anchor

**Microsoft states every fact the conclusion rests on.**

- The owner implicitly holds `WRITE_DAC` and therefore controls access.[^owner]
- *"Administrators are, by default, the owners of most of the AD DS objects in their respective
  domains."*[^appendixg] — so administrative ownership is the norm, not a preference of ours.
- An object created by a non-administrator is owned by that person personally.[^descriptors]

**Microsoft also prescribes the remedy, but in one context.** Defender for Identity's *Edit
misconfigured certificate templates owner (ESC4)* is the only Microsoft assessment about ownership
itself. It describes *"an Active Directory object with an owner, who controls access to the object
and the ability to edit the object"*, warns that an owner which is a built-in unprivileged group
lets an adversary *"escalate privileges, and compromise the entire domain"*, and gives the fix:
**"changing the owner to a privileged and monitored user."**[^esc4]

**The limit, stated plainly rather than glossed.** That assessment is scoped to certificate
templates. Its *reasoning* is not — "an Active Directory object with an owner, who controls access
to the object" is true of every object in the directory — but Microsoft has not written the general
recommendation. **So this rule rests on a Microsoft prescription in one context plus Microsoft
platform facts that are general.** It does not rest on a Microsoft statement that non-admin
ownership is bad practice everywhere, because no such statement was found. Recorded as `P-137`.

**What was checked and found not to help.** The ASD/CISA advisory *Detecting and Mitigating Active
Directory Compromises* was read in full on 2026-09-04. The word *owner* does not appear in it. It
addresses attack techniques and their detection, not permission hygiene, and it is **not** an anchor
for this rule.

## 3. What this rule refuses to claim

- **That the owner did anything wrong.** The commonest cause is that they created the object.
- **That the object matters.** See [§6](#6-severity).
- **That the owner can rewrite the list**, where an `OWNER RIGHTS` entry says otherwise. See
  [§5](#5-the-one-thing-that-would-make-this-rule-lie).

## 4. What counts as an administrative owner

**Expected, and therefore silent:**

| Owner | Why |
|---|---|
| `BUILTIN\Administrators` (`S-1-5-32-544`) | The default owner of most AD DS objects[^appendixg] |
| `Domain Admins` (RID 512) | Owns `AdminSDHolder` **by design** — the documented exception[^attacksurface] |
| `Enterprise Admins` (RID 519) | Forest-wide administration |
| `Administrator` (RID 500) | The built-in account |
| `SYSTEM` (`S-1-5-18`), `Enterprise Domain Controllers` (`S-1-5-9`), `Creator Owner` (`S-1-3-0`) | Platform identities, not people |
| Other `BUILTIN` operator groups (`S-1-5-32-548`…`552`) | Administrative by construction |

**An owner that is administrative only through group membership is also expected, and this is a
correction to the predecessor.** The predecessor's `SEC-031` decided administrativeness from the
identifier alone and recorded its own false positive: *"An owner who is privileged only by
transitive group membership… will still fire a finding."* We have the membership expansion that the
predecessor lacked, so the check consults it. A person inside `Domain Admins` **is** an
administrator, and reporting them is a finding about nothing that would train an operator to ignore
the rule.

## 5. The one thing that would make this rule lie

**`OWNER RIGHTS` (`S-1-3-4`) switches off what this rule is about.** Microsoft:

> The Owner Rights group represents the current owner of the object. When an ACE that carries this
> SID is applied to an object, the system **ignores the implicit READ_CONTROL and WRITE_DAC
> permissions for the object owner**.[^special]

So on an object carrying such an entry, the owner cannot rewrite the permission list, and a finding
saying they can would be **false** — the one category of error an audit tool may never commit.

**The rule therefore checks for it and stays silent where it applies**, and the object is judged
rather than refused: this is knowledge, not ignorance. This must be a negative control, because it
is invisible unless deliberately tested and the rule looks correct without it.

## 6. Severity

**`High` where the owned object is itself protected by `AdminSDHolder`. `Medium` otherwise.**

The reasoning: owning an ordinary user object lets you rewrite that object's permissions; owning a
protected object is a route to privilege. The predecessor rated its narrower rule `High` throughout,
but its scope was admin objects only — with the scope widened to every object, one severity for both
cases would either overstate the ordinary case or understate the privileged one.

**This split uses something that exists.** `ProtectedPrincipalClosure` is built and persisted, so
"is this object protected" is answerable today. It is deliberately **not** the Tier 0 question, which
is stage 7 and must not be pre-empted here.

## 7. Which objects are examined

**Every object whose owner was captured.** Not only privileged ones — the owner's decision of
2026-09-04, with filtering left to the screen.

**Two consequences worth expecting.** In a forest where the *"System objects: Default owner for
objects created by members of the Administrators group"* policy has been changed, creator-ownership
may be the norm estate-wide and this rule will be loud. And `AdminSDHolder` is legitimately owned by
`Domain Admins` rather than `Administrators`, which [§4](#4-what-counts-as-an-administrative-owner)
already admits.

## 8. What the rule reads

| Input | Why |
|---|---|
| The object's `owner_sid` | The subject of the rule; already captured |
| `DescriptorAvailability` | To tell *no owner recorded* from *nobody read it* |
| The object's ACEs | To find an `OWNER RIGHTS` entry |
| `DerivationReader.MembersOf` | To decide whether the owner is administrative by membership |
| `ProtectedPrincipalClosure` | For the severity split |

## 9. When it does not answer

| Situation | Verdict | Why not silence |
|---|---|---|
| The descriptor was never read | could not resolve | Nobody knows who owns it. |
| The descriptor was read but carries **no owner** | could not resolve | **A correction to the predecessor**, whose `SEC-031` silently skipped these (`N6`). A missing owner on a descriptor that was read is not *"the owner is fine"* — it is a fact nobody has, and `0002` forbids treating that silence as an answer. |
| The owner is not in the bundle (`PrincipalNotFound`) | could not resolve | Cannot tell whether they are administrative. |
| The owner's identifier belongs to a domain read **in full** and nothing carries it (`PrincipalDoesNotExist`) | judged, and **reported** | An object owned by a deleted account is a real and durable problem: nobody can be asked to hand ownership over. Note this is the opposite of SEC-060's handling, and deliberately so — there, non-existence means the grant reaches nobody; here, it means the object is orphaned. |
| The membership walk did not finish | could not resolve | The owner might be administrative through a group the walk did not reach. |
| The owner is administrative | judged, nothing reported | A real answer. |

## 10. Tests

Negative controls, each of which must be observed failing:

- an object owned by `BUILTIN\Administrators` — must **not** be reported
- `AdminSDHolder` owned by `Domain Admins` — must **not** be reported
- an object owned by a plain user who is a member of `Domain Admins` — must **not** be reported,
  which is the predecessor's recorded false positive
- an object carrying an `OWNER RIGHTS` entry — must **not** be reported, and must be judged
- an object whose descriptor was read but carries no owner — must **not** report clean
- an object owned by a plain user with no administrative membership — **must** be reported
- a protected object so owned — must be reported at `High`; an ordinary one at `Medium`

## 11. Verified against `ad.lab`

Not yet run. **Expect this one to be noisy in the lab**, and treat a large count as information
about the forest rather than as a defect in the rule until the objects have been looked at.

---

[^owner]: [Owner of a New Object](https://learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object)
[^descriptors]: [How Security Descriptors are Set on New Directory Objects](https://learn.microsoft.com/windows/win32/ad/how-security-descriptors-are-set-on-new-directory-objects)
[^appendixg]: [Appendix G: Securing Administrators Groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-g--securing-administrators-groups-in-active-directory)
[^attacksurface]: [Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface)
[^esc4]: [Security assessment: Certificates — Edit misconfigured certificate templates owner (ESC4)](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates)
[^special]: [Special identity groups — Owner Rights](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-special-identities-groups)
[^planning]: [Security Planning — Securing the server operating system](https://learn.microsoft.com/dynamics-gp/installation/securityplanning)
