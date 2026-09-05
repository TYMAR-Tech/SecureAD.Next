# SEC-060 — a broad principal can take over an object

> **Status: specified, not built.** This document states what the rule must do and why. Nothing in
> it is authoritative until a decision record says so; read it as argument. Written 2026-09-04.

## For a reviewer

**What this rule says in one sentence.** *Everyone can take over this object* — where "take over"
means rewrite its permissions, or become its owner and then rewrite its permissions.

**Why it is worth having.** An administrator can look at an object's permission list and see the
word *Everyone* next to *Write DACL* without registering what it means: that any person who can log
on can grant themselves, or anybody else, full control of that object, and nothing about the object
will look unusual afterwards. The permission list shows what was granted. It does not show what the
grant is *worth*.

**What it deliberately does not do.** It does not say the permission is wrong. This product cannot
know which principals an organisation intended to hold access — the owner's decision recorded as
`P-123` — so the rule reports only that the holder is broad in every organisation, which needs no
local knowledge.

---

## 1. What it finds

One finding per object where a principal that is **broad in every organisation** holds — directly,
or through group nesting — a permission that yields control of that object's access control list.

**"Broad in every organisation"** means the principal is one nobody chooses to be a member of.
`BroadPrincipalCatalogue` holds the set, decides it by identifier rather than by name, and is
verified against Microsoft. It holds six absolute identifiers — `Everyone`, `Anonymous Logon`,
`Authenticated Users`, `BUILTIN\Users`, `BUILTIN\Guests` and `Pre-Windows 2000 Compatible Access` —
and three domain-relative ones: `Domain Users` (513), `Domain Guests` (514) and `Domain Computers`
(515). **An earlier draft of this list omitted the last two and named seven principals rather than
nine**; the catalogue is what decides, and the document was wrong.

**Through nesting matters more than directly.** A delegation naming `LAPS-Readers` looks scoped.
Nothing in the directory tools shows that `Domain Users` sits three groups inside it. Finding that
is what `DerivationReader.MembersOf` is for, and it is the same walk SEC-090 uses.

## 2. Why this matters

Microsoft's Defender for Identity assessment for misconfigured certificate templates states the
consequence plainly, for exactly this combination of principal and right:

> If there's an entry in the ACL that grants a built-in, unprivileged group with permissions that
> allow for template setting changes, an adversary can introduce a template misconfiguration,
> **escalate privileges, and compromise the entire domain**. Examples of built-in, unprivileged
> groups are *Authenticated users*, *Domain users*, or *Everyone*. Examples of permissions that
> allow for template setting changes are *Full control* or *Write DACL*.[^esc4]

And the assessment for sensitive groups gives the mechanism:

> WriteDACL permissions allow an identity to modify an object's access control list. When a non-admin
> identity has this permission over a sensitive group, that identity can **grant itself or another
> identity privileged control**. Attackers often abuse this type of permission to escalate
> privileges in Active Directory environments.[^writedacl]

The joint ASD/CISA advisory makes the same point about the estate as a whole: Active Directory *"is
susceptible to compromise due to its permissive default settings"*, and *"every user in Active
Directory has sufficient permission to enable them to both identify and exploit weaknesses"*.[^asd]

## 3. What this rule refuses to claim

- **That the permission is a mistake.** It may be deliberate. The rule reports breadth, not intent.
- **That the object matters.** Whether this object is important is a Tier 0 question, and Tier 0 is
  stage 7. See [§6](#6-severity).
- **That the list is complete**, where the membership walk did not finish. See
  [§8](#8-when-it-does-not-answer).

## 4. Which rights count, and why each one

**The test is not "a powerful-sounding right". It is: does holding this yield control of the
object's access control list?** Each of the three below does, and the reasoning for each is
Microsoft's.

| Right | Why it is takeover-class |
|---|---|
| `GenericAll` (Full Control) | Includes `WRITE_DAC` outright. **Provable rather than asserted**: MS-ADTS 6.1.3 gives the generic mapping Active Directory uses for every security descriptor operation, and `GENERIC_ALL_MAPPING` lists `RIGHT_WRITE_DAC` and `RIGHT_WRITE_OWNER` among its members.[^mapping] `GenericRightsExpander` already implements that mapping and is verified against it, so this rule reads an expanded mask and does not restate the table. |
| `WriteDacl` | *"Grants the right to modify the DACL in the object security descriptor."*[^rights] The holder rewrites the permission list, including granting itself anything. |
| `WriteOwner` | *"Grants the right to change the owner."*[^rights] The holder makes itself the owner, and an owner *"implicitly has WRITE_DAC access… the owner can modify the object's DACL."*[^owner] So it reaches the same place in two steps rather than one — **except where the platform has switched those implicit rights off**, which is the next paragraph and is not optional. |

**The `WriteOwner` chain is conditional, and stating it unconditionally would make this rule lie.**
Becoming the owner yields `WRITE_DAC` only where the owner's implicit rights survive. Two things
remove them: an `OWNER RIGHTS` (`S-1-3-4`) entry on the object, and the forest setting
`BlockOwnerImplicitRights` — `dSHeuristics` character 29 — under the three conditions MS-ADTS 6.1.3.4
gives together.[^blocking] Those conditions are set out in full in
[`SEC-031` §5](SEC-031-object-owned-by-a-non-administrator.md#5-when-the-owner-does-not-actually-keep-the-power-this-rule-reports)
and are not restated here, because two copies of a three-part condition is how one of them comes to
be wrong. In short: the heuristic must be `1`, the principal must not be a domain or enterprise
administrator, and the object must be a computer.

**So on a computer object in a hardened forest, `WriteOwner` alone is not takeover-class**, and a
finding claiming it is would be false. `WriteDacl` and `GenericAll` are unaffected — they grant the
right directly rather than through ownership. Recorded as `P-138`.

**`GenericWrite` is deliberately excluded, and this is provable rather than a judgement call.**
`GENERIC_WRITE_MAPPING` is `RIGHT_READ_CONTROL`, `RIGHT_DS_WRITE_PROPERTY` and
`RIGHT_DS_WRITE_PROPERTY_EXTENDED` — and nothing else.[^mapping] It does not contain `WRITE_DAC` or
`WRITE_OWNER`, so it cannot yield control of the access control list, which is the test
[§4](#4-which-rights-count-and-why-each-one) applies. It is still genuinely dangerous — on a group it
can add members, on a user it can set a service principal name — but what it yields depends on the
object's class, and a per-class analysis of consequence is what stage 6 exists to build. An earlier
draft called this exclusion a judgement worth stating; the mapping settles it. When control edges
arrive, revisit.

**Effective access is computed, not read off the entries.** A permission list is not a list of what
people can do, and three things about it have to be honoured before a finding is made:

- **An inherit-only entry grants nothing on the object carrying it.** `INHERIT_ONLY_ACE` marks *"an
  ineffective ACE, which does not control access to the object to which it is attached"*.[^mapping]
  An organizational unit that delegates control of everything beneath it must not be reported as
  handing anybody control of the organizational unit itself.
- **Deny entries are applied in stored order.** A deny removes only rights not already granted by an
  earlier entry, so an allow ahead of a deny survives it. The earlier wording here — *"a grant
  cancelled by a preceding deny is not a grant"* — was right about the common case and silent about
  the one that matters: a **non-canonical** list is more open than it reads, and both orderings must
  be tested.
- **An entry scoped to an object type does not confer control of the object.** Read from
  `ACE_OBJECT_TYPE_PRESENT`, never from whether the GUID is null.

All three live in `EffectiveAccessCalculator`, which SEC-090 also uses — see
[`working-out-effective-access.md`](../../evidence/working-out-effective-access.md).

## 5. Which objects are examined

**Every object whose security descriptor was read.** Not only sensitive ones.

**This is the owner's decision of 2026-09-04, and it departs from both the predecessor and
Microsoft.** The predecessor's `SEC-060` reported per control edge and elevated to `Critical` for
Tier 0 targets; Microsoft's own assessment is scoped to sensitive groups and certificate templates.
Reporting on everything is the truthful option and may be a large number of findings in a real
forest. The owner's stated intent is that the screen filters what an operator wants to see rather
than the rule deciding for them.

**The alternative was rejected for a specific reason.** Scoping to "sensitive" objects today means
inventing a definition of sensitive that stage 7 will define properly later, and two definitions
that must agree is the shape that has already cost this repository three defects.

## 6. Severity

**`High`, uniformly.**

The predecessor elevated to `Critical` for Tier 0 targets. **That elevation is not available yet and
must not be faked**: Tier 0 is stage 7 and is not built. A severity that varies by a definition
nobody has written would move when that definition arrives, and `0066` requires severity to be fixed
on the rule card.

`High` rather than `Critical` because the finding is *this object can be taken over*, not *the
domain is compromised*. Where the object taken over is itself privileged, the consequence is far
worse — and that is exactly the elevation that waits for stage 7.

## 7. What the rule reads

| Input | Why |
|---|---|
| The object's security descriptor | The grants themselves |
| `DescriptorAvailability` | To tell *nothing granted* from *nobody read it* |
| `BroadPrincipalCatalogue` | Which principals are broad, by identifier |
| `DerivationReader.MembersOf` | What is nested inside each trustee |
| `dSHeuristics` character 29, and the object's `objectClass` | To decide whether a `WriteOwner` grant actually reaches `WRITE_DAC` through ownership |

Every derived fact it reads is declared, so judging refuses a bundle whose derivation is absent or
belongs to different evidence.

## 8. When it does not answer

**Absent, unreadable and clean are three states, and the rule keeps them apart.**

| Situation | Verdict | Why not silence |
|---|---|---|
| The descriptor was never read (`NotAttempted` or `Unreadable`) | could not resolve | Reporting an object as safe when nobody read its permissions is the one thing an audit tool must not do. A production domain returned 19,927 of 100,000 objects with no readable descriptor. |
| A trustee is not in the bundle (`PrincipalNotFound`) | could not resolve, for that trustee | Not found is not *not broad*. |
| A trustee's identifier belongs to a domain read **in full** and nothing carries it (`PrincipalDoesNotExist`) | judged, nothing reported for that trustee | No such principal exists, so the entry grants nobody anything. `P-134`. |
| The expansion stopped at a budget (`StoppedAtBudget`) | could not resolve, for that trustee | Everything listed is inside; the absence of anything else is not a fact. |
| The descriptor was read and no broad principal holds a takeover right | judged, nothing reported | A real answer. |

**Where an object yields a finding *and* a trustee that could not be expanded, the finding is
reported and carries its own incompleteness.** Returning both on the verdict costs the findings
entirely — judging counts an object with unresolved inputs as not judged and discards what it found,
which turned two real findings into zero against `ad.lab` on 2026-09-03.

## 9. Tests

**This rule has no internal anchor**, so every value below is anchored to Microsoft or to the lab.

Negative controls, each of which must be observed failing:

- an allow entry cancelled by a preceding deny — must **not** be reported
- an allow entry appearing **before** a deny of the same right — must **still** be reported, because
  a non-canonical list is more open than it reads
- an inherit-only entry granting `WriteDacl` to a broad principal — must **not** be reported on the
  object carrying it
- an entry scoped to a single attribute — must **not** be reported as control of the object
- `WriteOwner` alone, on a computer object, in a forest whose `dSHeuristics` character 29 is `1`,
  where the principal is not a domain or enterprise administrator — must **not** be reported
- `WriteOwner` alone, on a **non-computer** object in that same forest — must **still** be reported,
  because the block does not apply there
- `WriteOwner` alone, on an object carrying an `OWNER RIGHTS` entry — must **not** be reported
- a computer object owned by a non-administrator whose forest `dSHeuristics` was never read — must
  be **refused**, not reported and not silent
- `GenericWrite` alone — must **not** be reported, per [§4](#4-which-rights-count-and-why-each-one)
- `ReadProperty` or any read-only right — must **not** be reported
- a narrow, correctly-scoped delegation to a group of named administrators — must be silent
- a broad principal reached at depth six — must be reported **with the full path**
- a truncated expansion finding no broad principal — must **not** report clean
- an object whose descriptor was unreadable — must **not** report clean
- a trustee resolving to a principal that does not exist — must be judged silently, not refused

**Anchored outside itself.** Per `F-S44-2`, a fixture built from the same assumption as the code
proves only that the two agree. The access-mask values are taken from Microsoft's published
constants, and the rule is not considered working until it has run against `ad.lab`.

## 10. Verified against `ad.lab`

**Run 2026-09-05 against a planted positive. 8,383 objects judged, 0 refused, 1 finding.**

`Set-LabOwnershipAndTakeover.ps1` plants a nested path — `SecureADTakeoverOuter` →
`SecureADTakeoverInner` → `Domain Users` — and grants the outer group **both** `WriteDacl` and
`WriteOwner` on an organizational unit. The rule reports:

> Domain Users can rewrite the permission list directly (reached through SecureADTakeoverOuter ->
> SecureADTakeoverInner -> Domain Users).

which is the right object, the right principal, the full two-hop path, and — because both rights
were granted — proof that the **stronger** right is the one reported. A rule that named `WriteOwner`
here would tell an operator that hardening the forest would protect them, which it would not.

**Before the plant this rule returned zero**, and the evidence was queried directly to confirm no
entry in the forest granted a takeover-class right to a broad principal. That was true, and it was
still not verification: `building-a-rule.md` is explicit that a reading which has only ever returned
zero proves nothing, and `F-S45-4` and `F-S45-6` are both defects that a zero was hiding.

**Two earlier runs are the more important record.** The first judged **no objects at all** — all
8,378 counted as *not applicable* — because the rule declares no subject class to mean *every object*
and an empty list matched nothing (`F-S45-4`). The second refused every computer object because the
`dSHeuristics` reader named a table that does not exist and a guard turned the failure into a
plausible silence (`F-S45-5`). 3,139 tests were green throughout.

---

[^esc4]: [Security assessment: Certificates — Edit misconfigured certificate templates ACL (ESC4)](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates)
[^writedacl]: [Accounts security posture assessments — Ensure non-admin identities cannot have WriteDACL permissions on sensitive groups](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts)
[^rights]: [File and Directory Access Rights Constants](https://learn.microsoft.com/windows/win32/wmisdk/file-and-directory-access-rights-constants)
[^owner]: [Owner of a New Object](https://learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object)
[^mapping]: [MS-ADTS 6.1.3 — Security Descriptor Requirements](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a), which gives the generic mapping table, the `INHERIT_ONLY_ACE` meaning and the ACE ordering condition. Read 2026-09-05.
[^blocking]: [MS-ADTS 6.1.3.4 — Blocking Implicit Owner Rights](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/fb7c101d-ec8b-4fbf-bca8-7d7c2d747d0c). Read 2026-09-05.
[^asd]: Australian Signals Directorate, co-sealed by CISA, *Detecting and Mitigating Active Directory Compromises*, September 2024. Read in full 2026-09-04; it addresses attack techniques rather than permission hygiene, and the quoted line is its general framing rather than a control.
