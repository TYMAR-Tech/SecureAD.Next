# SEC-032 — a protected object is owned by somebody who is not an administrator

> **Status: built 2026-09-05. Severity corrected to `Medium` the same day — see `F-S45-7`.** This
> document states what the rule does and why. Nothing in it is authoritative until a decision record
> says so; read it as argument.

## For a reviewer

**What this rule says in one sentence.** *Somebody who is not an administrator owns an object the
directory itself protects — which the directory should have undone within the hour, so either it
just happened or the repair job has stopped running.*

**Read [§2](#2-why-this-matters) before anything else if you knew the earlier version.** This rule
shipped claiming the exposure was durable because `AdminSDHolder` leaves ownership alone. The lab
disproved that within a day. The rule kept its subject and lost its argument, which is why the
severity moved.

**Why it is separate from [`SEC-031`](SEC-031-object-owned-by-a-non-administrator.md).** They apply
the same test. They differ in what the answer *means*. Non-administrative ownership of an ordinary
object is latent authority over that object, and it persists until somebody changes it.
Non-administrative ownership of an object `AdminSDHolder` protects is not supposed to persist at
all, so observing it says something about the directory's own housekeeping rather than only about
the object.

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
protects *because* it confers privilege.

**And then the directory takes it back.** An earlier version of this section argued that
`AdminSDHolder` re-stamping does not help, because SDProp rewrites the DACL and leaves the owner
alone — so the exposure is durable. **That was wrong, and the lab settled it on 2026-09-05.** A
planted protected object's owner was set to an ordinary user, read back correctly, captured as
such, and roughly an hour later read `BA\Domain Admins` with nobody having touched it. SDProp
resets the **owner** as well as the permissions. Microsoft's pages disagree with each other here —
Appendix C and *Reducing the Active Directory Attack Surface* say *permissions*, while the Event
4780 article says the descriptor is made to match the template *"on the binary level"*, and a
descriptor includes the owner field. **The directory settled it in favour of the second reading.**
Recorded as `F-S45-7`.

**The rule survives that correction, but it is now a different claim.** If a protected object has a
non-administrative owner at the moment of capture, exactly one of two things is true:

1. **The ownership changed within roughly the last hour** — you are looking at something in
   progress rather than something stale, which is not obviously less urgent.
2. **SDProp is not running.** It can be disabled, stalled, or broken on the domain controller
   holding the PDC emulator role. If so, *every* privileged object in the domain has been sitting
   unrepaired for as long as that has been true, and nothing else in SecureAD would tell you.

**This rule cannot yet distinguish the two**, and says so in what the operator reads. Detecting a
stopped SDProp directly is a separate question, put to the owner on 2026-09-05 and not yet decided.

> [!IMPORTANT]
> **This is the only finding in the product whose absence from a later run proves nothing.** The
> same object may be reported once and gone the next time with nobody having fixed it. Section 4
> explains why that is tolerated rather than designed out, and
> [§9](#9-verified-against-adlab) records the observation itself.

## 3. What this rule refuses to claim

- **That the owner did anything wrong.** The commonest cause is that they created the object.
- **That the object has been abused.** This is a capability, not an event.
- **That the owner can rewrite the list**, where an `OWNER RIGHTS` entry or the forest's
  owner-rights hardening says otherwise. See
  [`SEC-031` §5](SEC-031-object-owned-by-a-non-administrator.md#5-when-the-owner-does-not-actually-keep-the-power-this-rule-reports),
  which this rule shares.

## 4. Severity

**`Medium`, uniformly. Lowered from `High` on 2026-09-05.**

**Decision: `Medium` — the owner, 2026-09-05.** The rule shipped at `High` on the durability
argument [§2](#2-why-this-matters) now retracts. With that argument gone the exposure is
self-healing within the hour, which does not support `High`.

`Medium` rather than `Low` because of what the owner expects to see in practice: *essentially never*
in a healthy domain. A condition that should be impossible to observe, observed, is worth reporting
loudly even when it repairs itself — and the case where it does **not** repair itself is a
domain-wide failure of a control nobody is watching.

`Medium` rather than `High` because the product reports capability rather than events, and this
capability expires. An operator who treats every one of these as a live compromise will burn time on
findings the directory has already fixed.

**Why not one rule with a derived severity.** Tempting now that severity turns on a timing question,
but the rule cannot answer that question — it does not know when the change happened or whether
SDProp is running. A derived severity would have to guess, and a guessed severity is worse than a
fixed one an operator can learn to read.

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

**Run 2026-09-05 against a planted positive. 8,379 objects judged, 4 refused, 1 finding.**

`Set-LabOwnershipAndTakeover.ps1` plants `SecureADProtObject`, a member of `Backup Operators` — which
Appendix C lists as protected — owned by `SecureADPlainOwner`, an ordinary user. The rule reports it
with the expected wording, and **`SEC-031` does not**, which proves the disjointness against a real
directory rather than only in a fixture. The finding was recorded at `High`; the severity was
lowered to `Medium` later the same day for the reason [§4](#4-severity) gives.

**Planting it is what found `F-S45-6`, and nothing else would have.** Before the plant this rule had
returned zero and looked correct. It could not fire at all: it read `objectSid` as text where the
directory stores bytes, so every object in the forest looked like it carried no identifier and was
treated as unprotected. The planted object was reported by `SEC-031` at `Low` — the right claim at
the wrong severity, on exactly the objects where severity matters. `SEC-031` fell from 9 findings to
8 and this rule rose from 0 to 1 when it was fixed, which is the same object moving to the rule that
owns it.

**The run also disproved [§2](#2-why-this-matters), and the plant is what disproved it.** Left
alone, the planted object's owner returned to `BA\Domain Admins` within the hour with nobody
touching it — `adminCount` still 1, still in `Backup Operators`. That is SDProp restoring ownership,
which the rule document said it would not do. **A rule that had only ever been tested against
fixtures would have carried the wrong claim to a customer at the wrong severity**, because a fixture
has no SDProp in it to contradict the argument. Settled as `F-S45-7`.

---

[^owner]: [Owner of a New Object](https://learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object)
[^appendixc]: [Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
