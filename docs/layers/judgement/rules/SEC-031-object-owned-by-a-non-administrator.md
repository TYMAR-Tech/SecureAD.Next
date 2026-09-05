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
for the life of the object.[^descriptors]

**This finding reports latent authority. It is not evidence of abuse, and must never be worded as
if it were.** The ordinary sequence is: somebody was allowed to create an object, they created it,
they became its owner, and the object stayed that way for years. Nobody did anything wrong at any
point. What the finding says is that a capability exists which no permission review will show you —
not that it has been used, and not that it was granted in error. An operator who reads this as
evidence of malicious delegation will waste a day and then stop trusting the rule.

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
- **That the owner can rewrite the list**, where an `OWNER RIGHTS` entry or a forest that has
  blocked implicit owner rights says otherwise. See
  [§5](#5-when-the-owner-does-not-actually-keep-the-power-this-rule-reports).

## 4. What counts as an administrative owner

**Expected, and therefore silent:**

| Owner | Why |
|---|---|
| `BUILTIN\Administrators` (`S-1-5-32-544`) | The default owner of most AD DS objects[^appendixg] |
| `Domain Admins` (RID 512) | Owns `AdminSDHolder` **by design** — the documented exception[^attacksurface] |
| `Enterprise Admins` (RID 519) | Forest-wide administration |
| `Administrator` (RID 500) | The built-in account |
| `SYSTEM` (`S-1-5-18`), `Enterprise Domain Controllers` (`S-1-5-9`), `Creator Owner` (`S-1-3-0`) | Platform identities, not people |
| Other `BUILTIN` operator groups (`S-1-5-32-548`…`552`) | **Treated as administrative for the purpose of ownership, which is narrower than calling them administrators.** `Account Operators`, `Backup Operators`, `Print Operators` and `Server Operators` carry very different risk profiles, and plenty of organisations do not regard them as full administrative authorities. What is being said here is only that finding one of them as an owner is not the condition this rule looks for. Whether they should hold that standing at all is a different question and a different rule. |

**An owner that is administrative only through group membership is also expected, and this is a
correction to the predecessor.** The predecessor's `SEC-031` decided administrativeness from the
identifier alone and recorded its own false positive: *"An owner who is privileged only by
transitive group membership… will still fire a finding."* We have the membership expansion that the
predecessor lacked, so the check consults it. A person inside `Domain Admins` **is** an
administrator, and reporting them is a finding about nothing that would train an operator to ignore
the rule.

### A service account owner does fire, and the reason is that the product cannot know otherwise

**The question, raised in review on 2026-09-04:** a service account owns objects it created, holds no
administrative membership, and is itself managed entirely by administrators. Does that fire? **Yes,
and deliberately.**

**Because *administrative principal* and *administratively controlled principal* are different
things, and only the first is decidable from the directory.** Nothing on an object says *this
account is looked after by the platform team*. There is no attribute for it, no group that reliably
means it, and no captured evidence that would settle it. A rule that tried to infer it would be
guessing, and a rule that guessed wrong in the quiet direction would hide real latent authority
behind an assumption nobody could check.

**So the rule answers the question it can answer**: this owner is not an administrative principal.
That statement stays true whoever manages the account. The `Low` severity of
[§6](#6-severity) and the latent-authority framing above are what keep it proportionate, and an
organisation that considers a particular service account's ownership acceptable has the acceptance
mechanism for exactly that, which leaves a record where a silent exclusion would not.

## 5. When the owner does not actually keep the power this rule reports

**The question is not "is there an `OWNER RIGHTS` entry". It is "does this owner still hold
`WRITE_DAC` over this object".** Two different things switch that power off, and an earlier draft of
this document named only the first, calling it *"the one thing that would make this rule lie"*. That
was wrong, and the correction is recorded as `P-138`.

**This matters because it is the one category of error an audit tool may never commit.** A finding
that says an owner can rewrite an object's permissions, on an object where the platform stops them,
is a false statement a customer would act on.

### The first: an `OWNER RIGHTS` entry on the object

Microsoft:

> The Owner Rights group represents the current owner of the object. When an ACE that carries this
> SID is applied to an object, the system **ignores the implicit READ_CONTROL and WRITE_DAC
> permissions for the object owner**.[^special]

So on an object carrying such an entry, the owner cannot rewrite the permission list.

### The second: the forest has blocked implicit owner rights

`BlockOwnerImplicitRights` is character 29 of `dSHeuristics`, introduced with the hardening for
`CVE-2021-42291`. **It does not switch owner rights off across the directory, and reading it that way
would be a worse defect than the one it fixes.** MS-ADTS 6.1.3.4 gives three conditions, and the
implicit rights are blocked only when **all three** hold:[^blocking]

| Condition | Detail |
|---|---|
| The heuristic blocks | Character 29 is `1`. **`2` and `3` do not block** — they are settings of the same heuristic that leave owner rights alone. `0` is the default and does not block, except on Windows 11 version 26H1, which this product cannot detect and therefore does not claim |
| The owner is not a forest or domain administrator | Membership of `Domain Admins` or `Enterprise Admins` **specifically** — narrower than [§4](#4-what-counts-as-an-administrative-owner)'s notion of administrative |
| The object is a computer | `objectClass` is `computer` or derives from it |

**So in a hardened forest this rule stays fully answerable for organizational units, groups, users,
certificate templates and everything else** — which is most of what it is worth having on. Had the
heuristic been read as a general switch, a forest that set it would have gone silent across the
directory and hidden exactly the latent authority this rule exists to surface.

### What the rule does with each

**Where either condition applies, the rule stays silent and the object is judged rather than
refused**: this is knowledge, not ignorance.

**Where the evidence cannot settle it, the object is refused rather than reported.** If
`dSHeuristics` was never read, the forest's setting is unknown, and on a computer object owned by a
non-administrator that unknown is load-bearing — the difference between a real finding and a false
one. `HeuristicReadOutcome` already separates *the forest defaults this* from *nobody looked*, so the
rule can tell.

Both conditions must be negative controls, because each is invisible unless deliberately tested and
the rule looks correct without either.

## 6. Severity

**`Low`, uniformly. One level, because this rule makes one claim.**

**Decision: the owner ruled on 2026-09-05 that the protected-object case becomes a second rule
rather than a second severity, and that this rule keeps one level.** Two reasons were given and the
second is the stronger. Splitting is cheaper — varying severity per finding would change
`RuleDefinition`, which all fourteen rules share, whereas a second card changes nothing. But the
reason to prefer it is what an operator gets: two rules are two things they can sort, filter and
accept independently, where one rule with mixed levels is a single row they must open to understand.

**An earlier draft reached the same shape for a wrong reason, and the correction matters because it
nearly cost a sound design.** That draft held that
[`0066`](../../../decisions/0066-a-finding-is-called-a-finding.md) makes per-finding severity
impossible for any rule. It does not: `0066` forbids **the customer** changing a severity, not a rule
deriving one. The owner confirmed this on 2026-09-04. So the split is a choice made on its merits and
not a constraint obeyed — which means it can be revisited if it turns out to serve an operator badly.

**Why `Low` is the right level for what this rule says.** The commonest cause of this finding is that
somebody created the object, as [§1](#1-what-it-finds) says. Organisational units, service accounts,
application containers and custom application objects routinely carry creator ownership as
operational residue. A forest where that is normal would produce an estate-wide wall of `Medium`, and
a level that describes most of the directory has stopped ranking anything.

`Low` is not *unimportant*: it is a real capability that no permission review will show you, and the
finding is worth having precisely because nothing else reports it.

**The serious case lives in [`SEC-032`](SEC-032-protected-object-owned-by-a-non-administrator.md).**
Owning an object that `AdminSDHolder` protects is a route to privilege rather than latent authority
over one object, and that is a different sentence deserving its own card and `High`. Splitting a rule
when the severity argument splits is the established pattern here: `P-92` collapsed five path rules
into one on that reasoning, and `P-96` proposes splitting `SEC-071` by feasibility for the same
reason.


## 7. Which objects are examined

**Every object whose owner was captured, except those `AdminSDHolder` protects**, which
[`SEC-032`](SEC-032-protected-object-owned-by-a-non-administrator.md) covers instead.

**Decision: not only privileged ones — the owner's decision of 2026-09-04, reaffirmed 2026-09-05.**
Filtering is left to the screen. The owner further ruled on 2026-09-05 that the rule is built at this
scope and the lab count is **looked at together before anything is decided from it**: a large number
is information about the forest rather than evidence that the rule is wrong.

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
| `dSHeuristics` character 29 | To find whether the forest has blocked implicit owner rights, per [§5](#5-when-the-owner-does-not-actually-keep-the-power-this-rule-reports) |
| The object's `objectClass` | Because the block above applies only to computer objects |
| `DerivationReader.MembersOf` | To decide whether the owner is administrative by membership |
| `ProtectedPrincipalClosure` | To stay silent on objects `SEC-032` covers |

**It reads `ProtectedPrincipalClosure` again, and the reason is the split.** An earlier draft dropped
it when the severity split was abandoned. With [`SEC-032`](SEC-032-protected-object-owned-by-a-non-administrator.md)
now covering protected objects, this rule needs it in order to **stay silent on them** — otherwise
both rules report the same object and an operator sees one problem twice, at two severities, and
has to work out that they are the same thing. The two rules cover disjoint sets.

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
- an object owned by a service account with no administrative membership — **must** be reported,
  which pins the decision in [§4](#a-service-account-owner-does-fire-and-the-reason-is-that-the-product-cannot-know-otherwise)
- every finding this rule emits carries `Low` — pinned so that a later edit reintroducing a
  per-finding severity fails rather than quietly contradicting `0066`

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
[^blocking]: [MS-ADTS 6.1.3.4 — Blocking Implicit Owner Rights](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/fb7c101d-ec8b-4fbf-bca8-7d7c2d747d0c), and [MS-ADTS 6.1.1.2.4.1.2 — dSHeuristics](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5) for the character and its values. Both read 2026-09-05.
[^planning]: [Security Planning — Securing the server operating system](https://learn.microsoft.com/dynamics-gp/installation/securityplanning)
