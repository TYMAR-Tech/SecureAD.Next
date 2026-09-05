# SEC-032 — a protected object is owned by somebody who is not an administrator

> **Status: built 2026-09-05.** This document states what the rule does and why. Nothing in it is
> authoritative until a decision record says so; read it as argument.

## For a reviewer

**What this rule says in one sentence.** *Somebody who is not an administrator owns an object the
directory itself protects because that object confers privilege — and an owner can rewrite an
object's permissions whenever they like.*

**Why it is separate from [`SEC-031`](SEC-031-object-owned-by-a-non-administrator.md).** They apply
the same test. They differ in what the answer *means*. Non-administrative ownership of an ordinary
object is latent authority over that object. Non-administrative ownership of an object
`AdminSDHolder` protects is a **route to privilege**: the objects in that set are the ones whose
compromise yields administrative control of the domain, which is precisely why the directory
re-stamps their permissions every hour.

**Decision: two rules rather than one rule with two severities — the owner, 2026-09-05.** Two rules
are two things an operator can sort, filter and accept independently; one rule with mixed levels is
a single row they must open to understand. It is also the cheaper shape, because severity stays
fixed on the rule card and no shared interface changes.

**A correction worth recording, because it nearly cost this design.** An earlier draft held that
[`0066`](../../../decisions/0066-a-finding-is-called-a-finding.md) makes per-finding severity
impossible for any rule, and struck a sound design on that basis. It does not: `0066` forbids **the
customer** changing a severity, not a rule deriving one. The owner confirmed this on 2026-09-04. The
split is therefore a choice made on its merits and can be revisited.

---

## 1. What it finds

One finding per object that **`AdminSDHolder` protects** and whose **owner** is not an
administrative principal.

The two conditions are both necessary, and neither is this rule's own invention:

- **Protected** is answered by `ProtectedPrincipalClosure`, the same derivation `SEC-030` uses. An
  object is protected when it is, or is inside, one of the groups Microsoft lists in *Appendix C:
  Protected Accounts and Groups in Active Directory*.
- **Not administrative** is answered by [`SEC-031` §4](SEC-031-object-owned-by-a-non-administrator.md#4-what-counts-as-an-administrative-owner),
  which this rule shares rather than restates. The decision lives in `ObjectOwnershipReading`,
  written once, because two copies of it would be two chances to get the owner-rights condition
  wrong.

## 2. Why this matters

Microsoft states every fact the conclusion rests on.

> An object's owner implicitly has **WRITE_DAC** access to the object. This means that the owner can
> modify the object's discretionary access control list (DACL), and thus, **can control access to
> the object**.[^owner]

And on the protected set:

> Members of these groups are targets for attackers because of the level of privilege they hold in
> the directory.[^appendixc]

So an owner outside the administrative tier can grant themselves control of an object the directory
protects *because* it confers privilege. `AdminSDHolder` re-stamping the object's permission list
every hour does not help: it rewrites the **DACL**, and it does not change the **owner**, who can
rewrite the DACL again immediately.

**That last point is the whole reason this rule is `High` rather than `Medium`.** An administrator
may reasonably believe a protected object is self-healing. Against a non-administrative owner it is
not.

## 3. What this rule refuses to claim

- **That the owner did anything wrong.** The commonest cause is that they created the object.
- **That the object has been abused.** This is a capability, not an event.
- **That the owner can rewrite the list**, where an `OWNER RIGHTS` entry or the forest's
  owner-rights hardening says otherwise. See
  [`SEC-031` §5](SEC-031-object-owned-by-a-non-administrator.md#5-when-the-owner-does-not-actually-keep-the-power-this-rule-reports),
  which this rule shares.

## 4. Severity

**`High`, uniformly.**

`High` rather than `Critical` because the finding is *a privileged object can be taken over by
somebody outside the administrative tier*, not *the domain is compromised*. Reaching the second
requires the owner to act, and this product reports capability rather than events.

`High` rather than `SEC-031`'s `Low` because the object is one the directory protects. That is not
this product's judgement about which objects matter — it is Microsoft's, expressed in the protected
set, and reading it off the closure is what lets this rule elevate without inventing a definition of
*sensitive* that stage 7 will define properly later.

## 5. Which objects are examined

**Every object the protection closure calls protected**, and no others.

**The two rules cover disjoint sets, and that is enforced rather than intended.** `SEC-031` stays
silent on protected objects and this rule stays silent on everything else. If both reported the same
object an operator would see one problem twice at two severities and have to work out they were the
same thing.

**Where the closure cannot say, neither rule reports.** A partial closure can make a protected object
look unprotected, which would move it from this rule to `SEC-031` and understate it. Both rules
refuse instead.

**An object with no `objectSid` is not protected, and that is an answer rather than a gap.**
`AdminSDHolder` protects principals — accounts and groups — by stamping their descriptors. An
organizational unit or a container is not a principal and cannot be in the protected set. Without
this, every organizational unit in the forest would be refused by both rules and the ownership
question would go unanswered across most of the directory.

## 6. What the rule reads

| Input | Why |
|---|---|
| The object's `owner_sid` | The subject of the rule |
| `DescriptorAvailability` | To tell *no owner recorded* from *nobody read it* |
| The object's ACEs | To find an `OWNER RIGHTS` entry |
| `dSHeuristics` character 29, and the object's `objectClass` | To decide whether the owner keeps implicit rights |
| `ProtectedPrincipalClosure` | Whether the object is protected, and whether the owner is administrative by membership |
| `DerivationReader.MembersOf` | Whether the owning account still exists |

## 7. When it does not answer

| Situation | Verdict | Why not silence |
|---|---|---|
| The descriptor was never read | could not resolve | Nobody knows who owns it |
| The descriptor was read but carries **no owner** | could not resolve | A fact nobody has, and `0002` forbids treating that silence as an answer |
| The protection closure is incomplete | could not resolve | A protected object could look unprotected, and reporting it at `Low` under `SEC-031` would understate it |
| The closure holds no fact about an object that **has** a SID | could not resolve | A gap, not a statement |
| The owner's membership walk did not finish | could not resolve | The owner might be administrative through a group the walk did not reach |
| The owner cannot rewrite the list | judged, nothing reported | Knowledge, not ignorance |
| The owner is administrative | judged, nothing reported | A real answer |

## 8. Tests

Negative controls, each of which must be observed failing:

- a protected object owned by `BUILTIN\Administrators` — must **not** be reported
- a protected object owned by a member of `Domain Admins` — must **not** be reported, because
  administrativeness is decided by membership and not by identifier alone
- an **unprotected** object owned by a non-administrator — must **not** be reported here, and must
  be reported by `SEC-031`
- a protected object whose owner is non-administrative — must be reported **once**, and not also by
  `SEC-031`
- a protected object carrying an `OWNER RIGHTS` entry — must **not** be reported
- an object whose protection could not be determined — must be **refused** by both rules
- an organizational unit with no `objectSid` — must be treated as unprotected rather than refused

## 9. Verified against `ad.lab`

Not yet run.

---

[^owner]: [Owner of a New Object](https://learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object)
[^appendixc]: [Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
