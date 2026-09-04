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

**"Broad in every organisation"** means the principal is one nobody chooses to be a member of:
`Everyone`, `Anonymous Logon`, `Authenticated Users`, `Domain Users`, `BUILTIN\Users`,
`BUILTIN\Guests`, `Pre-Windows 2000 Compatible Access`. `BroadPrincipalCatalogue` already holds this
set, decides it by identifier rather than by name, and is verified against Microsoft.

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
| `GenericAll` (Full Control) | Includes `WRITE_DAC` outright. Named by Microsoft as one of the two rights that allow object settings to be changed.[^esc4] |
| `WriteDacl` | *"Grants the right to modify the DACL in the object security descriptor."*[^rights] The holder rewrites the permission list, including granting itself anything. |
| `WriteOwner` | *"Grants the right to change the owner."*[^rights] The holder makes itself the owner, and *"an object's owner implicitly has WRITE_DAC access… the owner can modify the object's DACL."*[^owner] So it reaches the same place in two steps rather than one. |

**`GenericWrite` is deliberately excluded from this rule, and that is a judgement worth stating.**
It is genuinely dangerous — on a group it can add members, on a user it can set a service principal
name — but what it yields depends on the object's class, and a per-class analysis of consequence is
what stage 6 exists to build. Including it here on the strength of "it sounds bad" would put a
finding in front of a customer that this rule cannot justify. Recorded rather than forgotten:
when control edges arrive, revisit.

**Deny entries are honoured.** A grant cancelled by a preceding deny is not a grant. The effective
grant computation SEC-090 uses already does this, and the same negative control applies here.

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

Not yet run.

---

[^esc4]: [Security assessment: Certificates — Edit misconfigured certificate templates ACL (ESC4)](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates)
[^writedacl]: [Accounts security posture assessments — Ensure non-admin identities cannot have WriteDACL permissions on sensitive groups](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts)
[^rights]: [File and Directory Access Rights Constants](https://learn.microsoft.com/windows/win32/wmisdk/file-and-directory-access-rights-constants)
[^owner]: [Owner of a New Object](https://learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object)
[^asd]: Australian Signals Directorate, co-sealed by CISA, *Detecting and Mitigating Active Directory Compromises*, September 2024. Read in full 2026-09-04; it addresses attack techniques rather than permission hygiene, and the quoted line is its general framing rather than a control.
