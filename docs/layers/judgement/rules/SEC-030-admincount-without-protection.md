# SEC-030 — an object carries `adminCount=1` that AdminSDHolder does not protect

**Status:** specification, not yet implemented.
**Severity:** Medium.
**Rule identifier:** `SEC-030`.

---

## For a reviewer

**This document is written to be checked by somebody who cannot see this repository.** Every claim
about Active Directory below cites a Microsoft source, and every case is stated in terms of the
directory rather than of this product's code. If a claim cannot be checked against the source beside
it, that is a defect in this document.

**What would be most useful to hear:** any exclusion that should not be one, any case that would fire
or not fire against a real forest differently from what is stated here, and any Microsoft source that
contradicts something below. A disagreement is a reason to re-read the source rather than to change
the rule, and it is worth raising either way.

**This rule replaces one from a previous product.** That rule had three defects, named in
[§7](#7-what-the-previous-product-got-wrong-and-why) with the source that proves each. If the
reasoning there is wrong, the corrections are wrong too.

---

## 1. What it finds

An object whose `adminCount` attribute is `1`, which is **not** one of the accounts or groups
AdminSDHolder protects, and which is **not** a member — directly or through nesting — of any of them.

In plain terms: *this object was privileged once, is not privileged now, and is carrying the leftovers.*

## 2. Why it matters, in Microsoft's words

The consequence is documented rather than inferred.
[Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory):

> When an account is removed from a protected group, it is no longer considered a protected account,
> but its adminCount attribute remains set to 1 if it is not manually changed. The result of this
> configuration is that the object's ACLs are no longer updated by SDProp, but the object still does
> not inherit permissions from its parent object. Therefore, the object may reside in an
> organizational unit (OU) to which permissions have been delegated, but the formerly protected
> object will not inherit these delegated permissions.

So the object sits in a state nobody chose: **no longer maintained by SDProp, and still not
inheriting from where it lives.** Its access control list is a snapshot of whatever AdminSDHolder
held on the day it was last stamped, frozen and unmaintained.

Microsoft's own troubleshooting guidance treats this as a fault to find and fix, calling such objects
*orphaned* — [Troubleshoot insufficient access rights error](https://learn.microsoft.com/entra/identity/app-provisioning/insufficient-access-rights-error-troubleshooting#resolution).

## 3. The protected set

Fifteen accounts and groups, per
[Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory):

| # | Name | Identifier |
|---|---|---|
| 1 | Account Operators | `S-1-5-32-548` |
| 2 | Administrator | RID 500 |
| 3 | Administrators | `S-1-5-32-544` |
| 4 | Backup Operators | `S-1-5-32-551` |
| 5 | Domain Admins | RID 512 |
| 6 | Domain Controllers | RID 516 |
| 7 | Enterprise Admins | RID 519 |
| 8 | Enterprise Key Admins | RID 527 |
| 9 | Key Admins | RID 526 |
| 10 | Krbtgt | RID 502 |
| 11 | Print Operators | `S-1-5-32-550` |
| 12 | Read-only Domain Controllers | RID 521 |
| 13 | Replicator | `S-1-5-32-552` |
| 14 | Schema Admins | RID 518 |
| 15 | Server Operators | `S-1-5-32-549` |

**Group Policy Creator Owners (RID 520) is not on this list**, and is not protected. See
[§7](#7-what-the-previous-product-got-wrong-and-why).

**Cert Publishers is not on this list either.** It was protected between Windows 2000 SP4 and
Windows Server 2003 and removed afterwards, per the version table in
[Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory).

## 4. Membership is transitive, and that is why this rule needs more than one object

[Admin-Count attribute](https://learn.microsoft.com/windows/win32/adschema/a-admincount) states the
attribute:

> Indicates that a given object has had its ACLs changed to a more secure value by the system because
> it was a member of one of the administrative groups (**directly or transitively**).

So a user three groups deep beneath Domain Admins carries `adminCount=1` legitimately. Checking
direct membership alone would report every such user as stale, which is a false positive on any
forest that nests its administrative groups — that is to say, most of them.

The check must be the **transitive closure**.

## 5. When it fires

| # | The forest holds | Fires | Why |
|---|---|---|---|
| P1 | A user with `adminCount=1`, in no privileged group at all | **Yes** | The plain case. Privileged once, not now. |
| P2 | A user with `adminCount=1` whose only privileged membership is Group Policy Creator Owners | **Yes** | GPCO is not protected, so nothing is maintaining this object's ACL. |
| P3 | A user with `adminCount=1` nested only under non-protected groups | **Yes** | Nesting does not confer protection unless something protected is above it. |
| P4 | A group with `adminCount=1` that is not protected and not nested under anything protected | **Yes** | The attribute is defined on `group` as well as `user`. |
| P5 | A user with `adminCount=1`, member of Account Operators, **in a forest that has excluded operator groups via `dSHeuristics`** | **Yes** | The forest removed that protection itself. See [§6](#6-the-forest-can-narrow-the-protected-set-itself). |

## 6. When it does not fire

| # | The forest holds | Fires | Why |
|---|---|---|---|
| N1 | Any of the fifteen protected objects, carrying `adminCount=1` | **No** | Expected. SDProp maintains these. |
| N2 | A user directly in Domain Admins with `adminCount=1` | **No** | Correctly protected. |
| N3 | A user nested three deep under Domain Admins with `adminCount=1` | **No** | Transitive membership protects, per §4. |
| N4 | A user in Account Operators with `adminCount=1`, ordinary forest | **No** | Account Operators is protected. The previous product fired here — see §7. |
| N5 | A user in Backup Operators, Print Operators, Server Operators or Replicator with `adminCount=1` | **No** | All four are protected. |
| N6 | An object with no `adminCount`, or `adminCount=0` | **No** | Nothing to be stale. |
| N7 | An object whose SID was not captured | **No finding, and not silence** | It cannot be compared against the protected set. See [§8](#8-what-it-refuses-to-answer). |

## 7. What the previous product got wrong, and why

Three defects, each with the source that settles it. **All three are corrected here.**

### 7.1 It treated Group Policy Creator Owners as protected

The previous rule excluded RID 520 from firing, on the stated grounds that it was an *"expected
protected identity"*.

**GPCO is absent from Appendix C's fifteen.** It is a group that can create Group Policy objects; it
is not maintained by SDProp. An object whose only privileged membership is GPCO is therefore
genuinely stale, and the previous rule suppressed that finding silently.

**Effect: a missed finding.** Case P2 above is the one it lost.

### 7.2 Its membership check omitted the operator groups

The previous rule's transitive check looked only for RIDs 512, 516, 518, 519, 520, 521, 526, 527 and
`S-1-5-32-544`. It did **not** include Account, Server, Print or Backup Operators, or Replicator —
`S-1-5-32-548` through `552`.

All five **are** protected per Appendix C. So a user who is a member of Account Operators, carrying
`adminCount=1` exactly as Microsoft describes, was reported as stale.

The card written against that product noticed the behaviour and guessed at a justification:

> This appears intentional (operator membership is risky in its own right) but is not documented.

It was not intentional. Operator membership *is* risky, but that is a different finding — this rule
is about a stamp nothing maintains, and on those accounts something does.

**Effect: a false positive on any forest that uses operator groups.**

### 7.3 It could not account for a forest narrowing its own protected set

`dSHeuristics` character 16, `dwAdminSDExMask`, removes Account, Server, Print or Backup Operators
from AdminSDHolder's protection forest-wide
([MS-ADTS 6.1.1.2.4.1.2](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5),
bit assignments in [KB 56a70fa8](https://support.microsoft.com/topic/delegated-permissions-are-not-available-and-inheritance-is-automatically-disabled-56a70fa8-6d17-35ac-0f2c-87ec14b61980)).

In a forest that has done so, a member of Account Operators carrying `adminCount=1` **is** stale —
nothing is maintaining it any more. The previous product never read that setting, so it could not
tell the two forests apart.

**Effect: a missed finding in forests that use the exclusion mask.** Case P5 above.

## 8. What it refuses to answer

**An object whose SID was not captured produces no finding and is not counted as clean.** It cannot
be compared against the protected set, and reporting it as *not stale* would state something nobody
established.

**A derivation that could not work out the membership closure makes this rule's answer a floor rather
than a fact.** If the closure is incomplete, an object that appears to be in no protected group may
simply be one whose path was never computed. The rule must say so rather than report a clean result.

**It does not assert why the attribute is set.** `adminCount` is `System-Only: False`
([Admin-Count attribute](https://learn.microsoft.com/windows/win32/adschema/a-admincount)), so an
administrator can set it by hand. A hand-set value is indistinguishable from a stale stamp, and the
finding says what is true — *this object carries the attribute and nothing protects it* — rather than
guessing at history.

## 9. Open questions

Stated rather than hidden. A reviewer's opinion on any of these is welcome.

1. **Severity.** Medium is inherited from the previous product. The consequence is a frozen,
   unmaintained ACL rather than a direct privilege grant, which argues for Medium; but such an object
   can carry stale administrative permissions indefinitely, which argues higher. Not yet settled.

2. **Deleted objects.** A tombstoned object can carry `adminCount=1`. The previous rule did not
   filter them and reported them. Whether a deleted object is worth a finding is unresolved.

3. **Empty protected groups.** The previous product suppressed findings on operator groups with no
   members. Under §7.2 this question mostly dissolves — those groups are protected, so they do not
   fire regardless — but a forest using the exclusion mask brings it back.

4. **Computer accounts.** `adminCount` is documented on `user` and `group`. A computer is a subclass
   of user in the schema, so a computer account can carry it. Whether that should be worded
   differently for an operator is unresolved.

## 10. Sources

| Claim | Source |
|---|---|
| The fifteen protected accounts and groups | [Appendix C](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) |
| What happens when an account leaves a protected group | [Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory) |
| `adminCount` set for direct or transitive membership; `System-Only: False`; classes `user` and `group` | [Admin-Count attribute](https://learn.microsoft.com/windows/win32/adschema/a-admincount) |
| Orphaned objects are a fault to find | [Troubleshoot insufficient access rights error](https://learn.microsoft.com/entra/identity/app-provisioning/insufficient-access-rights-error-troubleshooting#resolution) |
| Cert Publishers protected only 2000 SP4 – Server 2003 | Version table, [Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory) |
| `dwAdminSDExMask` at character 16 | [MS-ADTS 6.1.1.2.4.1.2](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5) |
| Which group each mask bit excludes | [KB 56a70fa8](https://support.microsoft.com/topic/delegated-permissions-are-not-available-and-inheritance-is-automatically-disabled-56a70fa8-6d17-35ac-0f2c-87ec14b61980) |
