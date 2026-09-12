# SEC-091 ΓÇö LAPS missing on a computer

**Status:** specified 2026-09-03. Not yet built. Scope settled by the owner 2026-09-03 ΓÇö see [┬º3](#3-scope-which-computers-are-in-scope).
**Severity:** Medium. See [┬º7](#7-severity).
**Rule identifier:** `SEC-091`.
**Implemented by:** `LapsMissingOnComputer` in `SecureAD.Judgement` (planned).

---

## For a reviewer

**This document is written to be checked by somebody who cannot see this repository.** Every claim
about Active Directory cites a Microsoft source, and every case is stated in terms of the directory
rather than of this product's code.

**It has a card to port from.** `docs/rules/SEC-091.md` is the predecessor's *LAPS Missing on
Computer*. **The card is a source and not an authority** ΓÇö but on the question this document got
wrong, the card's instinct was closer to right than mine was. See
[┬º6](#6-what-is-not-reported-and-why), which records the error rather than quietly repairing it. The
one place this document still departs from the card is how domain controllers are excluded
([┬º5](#5-what-is-excluded-and-why)), and there the card's own backlog agrees with the departure.

**This rule has a sibling.** `SEC-094` reports a modern-capable machine carrying only a legacy
timestamp. The two were split so that an estate running legacy emulation mode can silence one without
silencing the other. `SEC-091` is the narrower and more serious of the two: **nothing at all**.

**The single most important thing in here is [┬º4](#4-the-absence-problem-and-why-it-is-smaller-than-we-thought).**
The starting position written into `ROADMAP.md` on 2026-09-02 assumed the two attributes this rule
reads may be withheld silently as confidential. **Checked against Microsoft's published schema and
then against `ad.lab` itself, that assumption is wrong**: the attributes this rule reads are shipped
non-confidential. The absence problem is real but far narrower, and the check is cheap.

**What would be most useful to hear:** whether Medium is right in [┬º7](#7-severity), given that
`SEC-094` sits beside it and the two need to rank sensibly against each other.

---

## 1. What it finds

A **computer** carrying **neither** LAPS expiration timestamp ΓÇö not Windows LAPS, not legacy
Microsoft LAPS ΓÇö in a forest where LAPS management is possible and where this run could see the
answer.

In plain terms: *nothing is rotating the local administrator password on this machine, so whatever
that password is, it is probably the same password as on every other machine imaged alongside it.*

**A machine carrying only the legacy timestamp is not this rule.** That is `SEC-094`, and
[┬º6](#6-what-is-not-reported-and-why) explains why it is a separate finding rather than a quieter
version of this one.

## 2. Why an unmanaged local administrator password matters

**The exposure is password reuse across machines, not the password itself.** When the local
administrator password is set once ΓÇö by an image, a build script, or a technician ΓÇö every machine
built the same way shares it. One compromised machine yields a credential that works on all of them,
and it works locally, so no domain authentication is involved and nothing is logged centrally.

Microsoft states the purpose of the feature plainly in
[*What is Windows LAPS?*](https://learn.microsoft.com/windows-server/identity/laps/laps-overview):

> "Windows Local Administrator Password Solution (Windows LAPS) is a Windows feature that
> automatically manages and backs up the password of a local administrator account on your Microsoft
> Entra-joined or Windows Server Active Directory-joined devices."

**What the organisation can therefore mitigate:** the lateral-movement step that turns a single
compromised workstation into every workstation. It is the step that makes ransomware spread, and it
does not require any directory privilege at all.

**What this rule does not tell you** is who may *read* the password once LAPS is deployed. A LAPS
deployment that grants a broad group the right to decrypt is a different exposure, and it is
`SEC-093`, which needs the permission graph and belongs after stage 5.

## 3. Scope: which computers are in scope

**All computers except domain controllers.** The owner chose the domain-controller exclusion on
2026-09-02 and settled the remainder on **2026-09-03**: **a computer running a client operating
system is reported exactly as a server is, at the same severity.** There is no client/server split,
no second rule and no separate severity.

**Why the question was asked at all**, since the answer now looks obvious and the reasoning should
not have to be rediscovered:

| Reporting clients too | Reporting servers only |
|---|---|
| LAPS matters **most** on workstations ΓÇö that is the population where one shared local password becomes lateral movement across thousands of machines | An estate that deploys LAPS to servers first, deliberately, gets a finding for every workstation it owns |
| Microsoft's own supported-platform list leads with Windows client | The finding count is the workstation count, which in a real estate is tens of thousands |
| Silence on clients would be the product's most consequential silence | A rule an operator cannot act on is a rule he learns to scroll past |

**The decision went to the left-hand column, and one consequence follows immediately:** on an estate
of any size this rule's finding count is the count of unmanaged machines, which during a rollout is
most of them. That volume is the reason the severity stays **Medium** rather than rising ΓÇö see
[┬º7](#7-severity) ΓÇö and it is the reason the About text has to say plainly what the rule does not
see, particularly the Microsoft Entra ID case in [┬º6](#6-what-is-not-reported-and-why).

**A detail this decision makes harmless, which would have mattered under the other answer.** The only
thing in the captured evidence that distinguishes a client from a server is the `operatingSystem`
string itself. There is no flag for it: `userAccountControl` marks a machine
`WORKSTATION_TRUST_ACCOUNT` whether it is a laptop or a member server, and only a domain controller
differs. Under *servers only*, a machine with no `operatingSystem` value could not have been
classified at all and would have had to be reported as unjudgeable. **Because clients and servers are
treated alike, `operatingSystem` now decides nothing** ΓÇö it is carried in the evidence and shown to
the operator, and the rule never branches on it.

## 4. The absence problem, and why it is smaller than we thought

**The problem, stated.** A LAPS attribute that is absent from a computer object means one of two very
different things: *LAPS is not deployed on this machine*, or *this run was not allowed to see it*. A
confidential attribute is withheld **silently**, with no error ΓÇö the search simply returns without
it. Microsoft describes the mechanism in
[*Mark an attribute as confidential*](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential):

> "Active Directory performs a read access check on an object in the following cases: when you
> evaluate whether the object matches the search filter; when you return attributes of an object that
> match the search filter. By default, only administrators have CONTROL_ACCESS permissions to all
> objects. Therefore, only Administrators can read confidential attributes."

**Reporting a protected estate as unprotected is the failure to avoid**, and it is the one thing an
audit tool must not do, because a customer acts on it.

### The correction: the attributes this rule reads are not confidential

**The starting position assumed they might be. Microsoft's published schema says they are not.**
[*Windows LAPS schema extensions reference*](https://learn.microsoft.com/windows-server/identity/laps/laps-technical-reference)
gives a `SearchFlags` value for each attribute, and the split is deliberate:

| Attribute | `SearchFlags` | Confidential? |
|---|---|---|
| `msLAPS-PasswordExpirationTime` | **0** | No |
| `msLAPS-Password` | 904 | Yes |
| `msLAPS-EncryptedPassword` | 904 | Yes |
| `msLAPS-EncryptedPasswordHistory` | 904 | Yes |
| `msLAPS-EncryptedDSRMPassword` | 904 | Yes |
| `msLAPS-EncryptedDSRMPasswordHistory` | 904 | Yes |
| `msLAPS-CurrentPasswordVersion` | 904 | Yes |

Microsoft decomposes 904 on that same page as `fRODCFilteredAttribute`, `fNEVERVALUEAUDIT`,
**`fCONFIDENTIAL`** and `fPRESERVEONDELETE`. The confidential bit is 128, per
[*Search-Flags attribute*](https://learn.microsoft.com/windows/win32/adschema/a-searchflags):

> "128 (0x00000080) | Mark attribute as confidential. Ignored for base schema attributes
> (systemFlags=0x10)."

**Every attribute that carries the password is confidential. The expiration timestamp is not.** And
the expiration timestamp is the only thing this rule reads. That is a coherent design on Microsoft's
part: *whether* a machine is managed is not a secret, and *what the password is* is.

**Checked against a real forest, not only against the page.** This is the `SEC-021` lesson ΓÇö any
claim a document makes about what Active Directory contains is a claim to check against Active
Directory. Read from the `ad.lab` schema partition on 2026-09-03:

```
lDAPDisplayName               searchFlags systemFlags
---------------               ----------- -----------
ms-Mcs-AdmPwd                         904
msLAPS-Password                       904
ms-Mcs-AdmPwdExpirationTime             0
msLAPS-PasswordExpirationTime           0
```

**Both expiration attributes read 0 in a forest that carries both schema extensions**, and the legacy
`ms-Mcs-AdmPwdExpirationTime` behaves exactly as its Windows LAPS counterpart does. `systemFlags` is
empty on all four, confirming they are schema extensions rather than base-schema attributes ΓÇö so bit
128 **would** be honoured on them if anybody set it, which is why the check below still has to happen.

### So the rule still asks, it just expects a yes

**It is derivable per forest, and `docs/decisions/0002` requires it to be told apart rather than
guessed.** Capture already reads `searchFlags` and `systemFlags` from the schema partition, so the
rule does not assume the default ΓÇö it reads what this forest actually says.

**Three states, and they must never collapse into one another:**

| What the schema says | What it means | What the rule does |
|---|---|---|
| The attribute is **not in the schema at all** | The LAPS schema extension was never applied to this forest. **No computer in it can be managed by that product**, so absence is not evidence about any individual machine | Cannot be a finding *for that product*. If **neither** extension is present, the forest has no LAPS at all ΓÇö see below |
| The attribute is present and **`searchFlags` bit 128 is set** | This forest has marked it confidential. An unprivileged run sees nothing and a privileged run sees everything, and the two are indistinguishable per object | **`CouldNotJudge`**, naming the attribute. Never a finding |
| The attribute is present and **bit 128 is clear** | Absence is a fact about the machine | Absence is reportable |

**Neither extension present is a finding about the forest, not about a machine.** It is the honest
statement, and it is one finding rather than one per computer ΓÇö but this product's rules judge one
object at a time and cannot make a forest-level statement. So in that case the rule reports
**nothing** and says why in its About text. Recorded as a punch-list item rather than smuggled in:
a forest-scoped finding is machinery this product does not have yet, and inventing it inside a rule
would be the wrong place for it.

### How the schema answer reaches the rule

**A rule judges one object and nothing else** ΓÇö no sibling lookup, no second pass. So the rule cannot
read the schema partition itself while it is holding a computer object; the answer has to be handed
to it.

**That means a new `DerivedFactKind`.** `JudgingContext` is the only channel a rule has for anything
beyond the object in hand, and it is declared, so `docs/decisions/0091` refuses a judging whose
derivation is missing rather than reporting an unanswerable question object by object. The shape:

- a Derivation phase that reads the schema partition once and records, per attribute name, whether
  it exists and whether bit 128 is set
- `DerivedFactKind.AttributeVisibility`, declared by this rule
- a run without it is refused for the whole run, exactly as `SEC-021` and `SEC-030` are refused
  without `ProtectedPrincipals`

**Why not just let the rule assume the Microsoft default.** Because that is the shape of mistake this
repository keeps catching: `SEC-021`'s `krbtgt` defect and `F-S44-2` are both a check anchored to a
belief rather than to the thing being measured. The default is *what Microsoft ships*, not *what this
forest is*, and an estate that hardened its schema is exactly the estate that would be reported
wrongly.

## 5. What is excluded, and why

| Excluded | Why |
|---|---|
| **Domain controllers** | The owner's decision of 2026-09-02. See the note below: this is a scope choice, not a technical impossibility |
| **Disabled computer accounts** | The owner's decision of 2026-09-03, taken after the first lab run reported two of them. A disabled account has no running machine behind it, so there is no local administrator password for anything to rotate and the finding's advice cannot be followed. **This departs from `SEC-021`, which reports a disabled user account, and the difference is real**: a disabled user still carries a password and a service name, so re-enabling restores the exposure exactly, while the exposure here lives on a machine's local security database and a stale account has no machine attached. **What it costs**: a machine switched off for a month is genuinely unmanaged and is now silent. Stale accounts are a real finding of a different kind and are `P-120` |
| **Non-computer objects** | LAPS attributes live on the computer class. Microsoft: the `Update-LapsADSchema` cmdlet "adds the schema attributes to the directory and to the `mayContain` list on the computer schema class" |
| **Computers already managed by either product** | An expiration timestamp from either LAPS product means something is rotating the password. Which product is doing it is a migration question, not a security one ΓÇö see [┬º6](#6-what-is-not-reported-and-why) |

### Domain controllers are excluded by `DomainControllerSignals`, not by distinguished name

**The predecessor excluded them with `distinguished_name NOT LIKE '%,OU=Domain Controllers,%'`.** Its
own card records that it arrived there by fixing a different bug, and its own improvement backlog
flags the result as brittle under the tag `[IMP-DC-DETECT]`: *"Brittle if customers move DCs to a
non-default OU."*

**This product already solved this properly and it must not be re-solved badly here.**
`DomainControllerSignals` reads three independent signals ΓÇö the `SERVER_TRUST_ACCOUNT` bit, a
`primaryGroupID` of 516 or 521, and the Domain Controllers container ΓÇö treats **any** of them as
enough, and reports disagreement rather than resolving it. `SEC-010` and `SEC-011` already use it.

**The child-domain trap, and this document was wrong about it until the forest said so.** A child
domain's controller also has a member-server computer account in the parent domain, and this section
claimed that was *"a solved problem in `DomainControllerSignals`"*. **It is not, and it cannot be.**
That type reads the three signals off *the object in hand*, and the parent-domain account carries
none of them: read from `ad.lab` on 2026-09-03, `CN=BADC,CN=Computers,DC=ad,DC=lab` and
`CN=PHDC,CN=Computers,DC=ad,DC=lab` each carry `userAccountControl` 4098 ΓÇö a workstation trust
account ΓÇö with `primaryGroupID` 515, sitting in `CN=Computers`. A rule judging one object cannot know
that those names belong to controllers in another domain.

**What `DomainControllerSignals` does solve** is the *predecessor's* bug, which was a
distinguished-name match: a real controller moved out of the Domain Controllers container is still
caught here by its trust bit or its primary group. That is worth having and this rule uses it. It is
a narrower claim than the one this section made.

**What actually excludes those two objects is that they are disabled** ΓÇö see
[┬º5](#5-what-is-excluded-and-why). Both were reported at Medium by the first `ad.lab` run, advising
an operator to deploy Windows LAPS to machines that no longer exist under those accounts.

**Worth recording, because the exclusion is a choice and not a fact:** domain controllers *can* be
LAPS-managed. Windows LAPS manages the DSRM account password on domain controllers ΓÇö Microsoft:
*"You also can use Windows LAPS to automatically manage and back up the Directory Services Restore
Mode (DSRM) account password on your Windows Server Active Directory domain controllers."* A domain
controller has no ordinary local administrator account to manage, which is why excluding it is right
for **this** rule; an unmanaged DSRM password is a separate question this product does not currently
ask.

## 6. What is **not** reported, and why

### A machine with only a legacy timestamp is `SEC-094`, not silence ΓÇö and this document was wrong about it first

**What this section said before 2026-09-03:** that a modern-capable machine carrying only a legacy
timestamp should produce no finding, because *"its password is being rotated. LAPS is not missing."*

**That premise is false, and the owner's knowledge of the product is what caught it.** The legacy
attribute is **never cleared** when Windows LAPS takes over. Microsoft's migration procedure removes
the legacy *policy* and then the legacy *software*, and touches no directory attribute at any point.
So `ms-Mcs-AdmPwdExpirationTime` persists indefinitely as residue, and its presence proves **nothing
about whether anything is still rotating that password**. It may be a live legacy deployment; it may
equally be a fossil from a policy that stopped applying three years ago.

**I asserted a fact about Active Directory without checking it against Active Directory.** That is
`SEC-021`'s `krbtgt` defect in the same shape, caught one step earlier only because it was written
down before it was built. It is recorded here rather than quietly corrected, because
[┬º4](#4-the-absence-problem-and-why-it-is-smaller-than-we-thought) already carries one instance of
this lesson and this is the second in a single rule.

**Microsoft's own migration guidance is the inverse of the mistake.** Asked how to confirm a
migration succeeded, Microsoft says:

> "When storing passwords in Active Directory, you can look for the appearance of a new or updated
> `msLAPS-PasswordExpirationTime` attribute on the managed device's AD computer object."

**The appearance of the modern timestamp is Microsoft's own success signal.** Its absence on a
machine capable of running Windows LAPS is therefore a real and documented negative, and reporting it
is not a migration nag ΓÇö it is the check Microsoft tells an administrator to perform, run across the
estate instead of one machine at a time.

**So the case is reported, by `SEC-094`, not by this rule.** The split is not cosmetic:

| | `SEC-091` | `SEC-094` |
|---|---|---|
| Fires when | **neither** timestamp is present | modern-capable machine, **legacy present, modern absent** |
| Means | nothing has ever managed this password | the modern policy is not landing, or this is emulation mode |

**Why two rules and not one rule with a state field.** Acceptance is per finding
(`docs/decisions/0080`, `0023`), and suppression in the interface is per rule. An estate running
legacy emulation mode deliberately must be able to silence the second without silencing the first.
One merged rule makes that impossible. This is the same reasoning that kept `SEC-028`, `SEC-029` and
`SEC-033` as three rules rather than one combined finding.

### The trap `SEC-094` carries, and this rule does not

**Windows LAPS legacy emulation mode.** A fully modern machine can be *deliberately* configured so
that Windows LAPS honours the old Group Policy and writes to the **legacy** attributes ΓÇö no modern
timestamp ever appears. Microsoft positions it exactly at organisations mid-migration:

> "You might use emulation mode if you migrate an existing deployment of legacy Microsoft LAPS to
> Windows LAPS."

So `legacy present, modern absent` has two causes that are **identical in the directory**: a Group
Policy that is not processing, and a deliberate emulation-mode configuration. The evidence that
separates them ΓÇö the client-side extension registry key, and event 10023 ΓÇö is on the machine, not in
Active Directory. `SEC-094` therefore states what was observed and names the candidate causes; it
never asserts which one applies. Its own document carries this in full.

**This rule is unaffected by it**, because emulation mode still writes a timestamp, and `SEC-091`
fires only when there is no timestamp of either kind.

### Other boundaries, which belong in the About text

1. **A LAPS deployment that the whole estate can read is not reported.** Whether the finding is
   *nobody is rotating this password* or *everybody can read it* are different rules; the second is
   `SEC-093`.
2. **A stale rotation is not reported.** A machine whose expiration timestamp is present but long
   past is managed as far as this rule is concerned. That is `SEC-092`.
3. **Passwords backed up to Microsoft Entra ID are invisible here.** Microsoft: *"If you are planning
   to only backup passwords to Microsoft Entra ID, you do not need to perform any of these steps,
   including extending the AD schema."* A machine managed that way carries no Active Directory
   attribute and this rule, reading a directory bundle, cannot see it. **This is the most likely
   source of a false finding in a real estate and it must be in the About text**, because the product
   cannot detect it and the operator can.

## 7. Severity

**Medium**, agreeing with the predecessor's card.

- **It is a configuration gap, not an active exposure.** Nothing is being attacked, and no credential
  has been disclosed. Compare `SEC-090`, which reports a password that can actually be read.
- **The consequence is real but conditional.** It matters when a machine is already compromised, as
  the step that turns one machine into many.
- **Volume argues against promoting it.** This rule reports per machine, across the whole computer
  population now that clients are in scope ([┬º3](#3-scope-which-computers-are-in-scope)), and during
  a LAPS rollout it reports the part of the estate not yet reached. A High that fires on half an
  estate teaches an operator to filter the rule out, which costs more than the severity gains.

**The argument for High**, recorded rather than hidden: shared local administrator passwords are the
single commonest lateral-movement mechanism in real intrusions, and an estate with no LAPS at all is
in a materially worse position than the word *hygiene* suggests. The counter is that this rule cannot
distinguish *no LAPS anywhere* from *LAPS everywhere except these three machines*, and those deserve
different urgency. If a forest-scoped finding is ever built (see [┬º4](#4-the-absence-problem-and-why-it-is-smaller-than-we-thought)),
that one has a good claim to High while this one stays Medium.

## 8. What the rule reads

| Input | Why |
|---|---|
| `msLAPS-PasswordExpirationTime` | Whether Windows LAPS is managing this machine |
| `ms-Mcs-AdmPwdExpirationTime` | Whether legacy Microsoft LAPS is managing this machine |
| `operatingSystem` | The OS family ΓÇö whether the name says *Server*. Reported, and half of the capability answer |
| `operatingSystemVersion` | The build number. **New capture work**, see below |
| `objectClass` | The **most derived** class must be `computer`. See the note below |
| `userAccountControl` | Feeds `DomainControllerSignals` |
| `primaryGroupID` | Feeds `DomainControllerSignals` |
| `distinguishedName` | Feeds `DomainControllerSignals`, and names the object |
| `sAMAccountName` | The name shown, falling back to the distinguished name when absent |

**Seven of the eight are already in `CapturedAttributeCatalog`. `operatingSystemVersion` is new**, and
adding it contradicts the `ROADMAP` handoff's claim that this rule needs no capture work. The owner
agreed to it on 2026-09-03.

**Why the version is needed and the name is not enough.** The predecessor classified by matching the
OS *name* ΓÇö `LIKE '%2019%'`, `LIKE '%2016%'` ΓÇö which its own backlog flagged as brittle under
`[IMP-OS-CLASSIFIER]`, and which under-reported twice: it classed Windows 10 as *not applicable*
when Microsoft supports Windows LAPS on it, and classed Server 2012 as *not applicable* when legacy
LAPS runs on it perfectly well. The build number is numeric and locale-independent and has none of
those faults.

**Why the name is still needed as well.** Windows 10 1607 and Windows Server 2016 are **both build
14393**. The build number alone cannot tell a client from a server, so the family comes from the name
and the generation comes from the version. Either attribute alone gives a wrong answer.

**Derived facts: `AttributeVisibility`** ΓÇö new, described in [┬º4](#4-the-absence-problem-and-why-it-is-smaller-than-we-thought).
This rule cannot judge an underived bundle.

**The class test is on the most derived class, and that direction is the opposite of `SEC-021`'s.**
A computer's `objectClass` chain is `top, person, organizationalPerson, user, computer`. `SEC-021`
had to avoid matching computers when it wanted users; this rule has to avoid matching *users* when it
wants computers, and testing *is `computer` in the chain* is safe while testing the chain loosely in
the other direction is not. The fixtures use the real chain for the same reason `SEC-021`'s do.

**Never the password attributes.** `ms-Mcs-AdmPwd`, `msLAPS-Password` and the encrypted forms sit on
the same object and are forbidden by `CredentialAttributeGuardTests`. This rule reads only whether a
password is being managed, never what it is.

## 9. When it does not answer

| Case | What happens |
|---|---|
| No derivation offered | `CouldNotResolve(NotDerived)`. Per `0091` the run is refused before this point, so it should be unreachable |
| Either expiration attribute is confidential in this forest | **`CouldNotJudge`**, naming that attribute. Silence here is not a statement that the machine is unmanaged |
| Neither LAPS schema extension exists in this forest | No finding, and the reason is in the About text. See [┬º4](#4-the-absence-problem-and-why-it-is-smaller-than-we-thought) |
| `operatingSystem` is absent | The rule proceeds and reports the machine with no operating system named. It decides nothing, per [┬º3](#3-scope-which-computers-are-in-scope), so its absence cannot stop a verdict |

**Absent is the ordinary case here and must not be reported as an unread input.** Most computers in a
forest without LAPS carry neither timestamp, and naming a missing attribute against nearly every
object reads as a broken capture. The distinction that matters is the one in
[┬º4](#4-the-absence-problem-and-why-it-is-smaller-than-we-thought): *absent and readable* is a
finding, *absent because withheld* is `CouldNotJudge`, and only the schema can tell them apart.
`SEC-027` ┬º9 is the worked example of getting this wrong.

## 10. Tests

`LapsMissingOnComputerTests`. The negative controls that matter:

- **a computer with Windows LAPS** and **a computer with legacy LAPS** ΓÇö the two managed states
- **a computer with legacy LAPS on a modern server OS** ΓÇö the tier-mismatch case the card reported
  and this rule does not, and the one `ad.lab` actually contains
- **a domain controller with no LAPS attribute** ΓÇö including one **outside** the Domain Controllers
  container, which is the case the predecessor's DN test got wrong
- **a user object** ΓÇö the class exclusion, using the real `objectClass` chain
- **a computer with no LAPS attribute where the schema marks the attribute confidential** ΓÇö must be
  `CouldNotJudge` and must never be a finding. **This is the test that protects a hardened estate**
- **a computer in a forest whose schema carries neither extension** ΓÇö no finding

**The external anchor**, per `F-S44-2` and the *Anchoring* section of `building-a-rule.md`: the
confidential bit this rule tests must be checked against something outside this repository. The
constant is 128 from
[*Search-Flags*](https://learn.microsoft.com/windows/win32/adschema/a-searchflags), and the attribute
names are Microsoft's published LDAP display names. A test asserts the rule's constant against the
published value rather than against another copy of itself.

Each mutated in both directions, **one mutation at a time**.

## 11. Verified against `ad.lab`, 2026-09-03

**The rule was wrong on its first real run, and the forest is what caught it ΓÇö again.** The counts
matched this document's prediction exactly, and the reasoning behind them did not. That is
`F-S44-2` in its plainest form: a prediction right by luck reads exactly like a prediction right by
understanding, and only opening the forest tells them apart.

**What the first run reported:** two findings in `ad.lab`, at Medium, which is what the table below
forecast. The objects were not the two member servers this document expected. Read from `ad.lab`'s
PDC emulator on 2026-09-03:

```
CN=BADC,CN=Computers,DC=ad,DC=lab   userAccountControl=4098  primaryGroupID=515  dNSHostName=BADC.ad.lab
CN=PHDC,CN=Computers,DC=ad,DC=lab   userAccountControl=4098  primaryGroupID=515  dNSHostName=PHDC.ad.lab
```

`4098` is `WORKSTATION_TRUST_ACCOUNT` **with `ACCOUNTDISABLE`**. Both are leftovers of joining a
machine to the parent domain and then promoting it into a child; the machines those names belong to
are now the controllers of `ba.ad.lab` and `ph.ad.lab`, whose real accounts were correctly excluded.
The finding told an operator to deploy Windows LAPS to machines that do not exist under those
accounts ΓÇö the `SEC-021` `krbtgt` shape, one rule later: advice that cannot be followed.

**Two things came out of it, and neither was a quiet repair.** The owner excluded disabled computer
accounts from both rules ([┬º5](#5-what-is-excluded-and-why)), and this document's claim that
`DomainControllerSignals` solves the child-domain trap was corrected ΓÇö it cannot, because it reads
one object and the parent-domain account carries none of its three signals. The stale accounts
themselves are `P-120`.

### After the fix

| Question | How it was answered | Answer |
|---|---|---|
| Was the rule scheduled and did it complete? | `rule_execution` in the judgement store | `Succeeded`, 14 objects judged, **0 not judged, 0 unresolved** |
| Did the new derivation reach it? | the same row ΓÇö an absent `AttributeVisibility` refuses the whole run | it ran, so the phase produced its product against a real forest |
| Does it still report the disabled leftovers? | re-judged the **same sealed evidence** with the fixed rule | **0 findings**, down from 2 |
| Were the domain controllers excluded? | all three appear among the 14 judged and none among the findings | 3 excluded |
| Were the group managed service accounts excluded? | see below | 3 excluded |
| Total findings across the forest | `show-findings.ps1` | 9 before, **7 after** |

**Fourteen objects judged against eleven computers in the forest, and the difference matters.**
`laps-census.ps1` reads the live directory and counts 11 computers; the rule was offered 14. The
three extra are `TestgMSA`, `gMSAlegacy` and `gmsaBlah` in `ba.ad.lab`, whose `objectClass` chain
**contains** `computer`. They are excluded because the rule tests the *most derived* class ΓÇö had it
asked whether `computer` was present, those would have been three more false findings, on objects
with no local administrator password at all.

### What this run did **not** establish

**`SEC-091` now has no positive case in `ad.lab`.** The only two objects it reported were the
disabled leftovers, and every remaining computer in the forest is either LAPS-managed, a domain
controller, or a group managed service account. **Its positive path is exercised by tests and by
nothing in the lab**, and a green run against this forest must not be read as confirming the rule
fires ΓÇö that is the same mistake in a quieter form. Seeing it fire needs a planted enabled machine
with neither timestamp, alongside the planted unmanaged **client** [┬º3](#3-scope-which-computers-are-in-scope)
already needs and which this lab also cannot supply.

**The confidential branch was not exercised either, and never will be here.** Both expiration
attributes read `searchFlags` 0 in this forest, as [┬º4](#4-the-absence-problem-and-why-it-is-smaller-than-we-thought)
records. It is covered by a fixture that sets bit 128, and that check was **observed failing** in
both directions before it was trusted.

### What the forest held, read on 2026-09-03

**Fourteen computer-class objects, eleven of them computers.** The expected result stated below was
written before the rule existed; the *counts* held and the *identities* did not.

| Domain | Machine kind | `operatingSystem` | LAPS state | Expected |
|---|---|---|---|---|
| `ad.lab` | 2 member servers | Windows Server 2022 Datacenter | none | **finding** |
| `ad.lab` | domain controller | Windows Server 2022 Datacenter | none | excluded |
| `ba.ad.lab` | member server | Windows Server 2022 Datacenter | Windows LAPS | quiet |
| `ba.ad.lab` | member server | Windows Server 2016 Datacenter | legacy LAPS | quiet |
| `ba.ad.lab` | client | Windows 11 Enterprise | Windows LAPS | quiet |
| `ba.ad.lab` | domain controller | Windows Server 2022 Datacenter | none | excluded |
| `ph.ad.lab` | member server | Windows Server 2022 Datacenter | **legacy LAPS** | quiet here \u2014 this is **`SEC-094`**, per [┬º6](#6-what-is-not-reported-and-why) |
| `ph.ad.lab` | member server | Windows Server 2016 Datacenter | legacy LAPS | quiet |
| `ph.ad.lab` | client | Windows 11 Enterprise | Windows LAPS | quiet |
| `ph.ad.lab` | domain controller | Windows Server 2022 Datacenter | none | excluded |

**Eleven computers, three of them domain controllers. The expected result is two `SEC-091` findings,
both in `ad.lab`, and one `SEC-094` finding in `ph.ad.lab`.**

**The lab contains a genuine positive for each rule without anything being planted**, which is worth
recording because `SEC-027`'s positive case remains unplantable in a single forest. Nothing here has
to be manufactured, and nothing has to be removed afterwards.

**Note that both client machines in the lab are already LAPS-managed.** The scope decision of
2026-09-03 puts clients in scope on equal terms with servers, so **the lab as it stands cannot
exercise that decision at all** ΓÇö every client in it is quiet for the same reason every managed
server is. A planted unmanaged client is needed to see the rule fire on one. Recording that now,
because a green run against `ad.lab` would otherwise look like it had confirmed something it never
touched ΓÇö which is `F-S44-2` in its most ordinary form.
