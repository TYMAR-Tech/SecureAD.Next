# SEC-090 — a broad principal can read LAPS passwords

**Status:** specified 2026-09-03. Not yet built.
**Severity:** High. Settled by the owner 2026-09-03. See [§7](#7-severity).
**Rule identifier:** `SEC-090`.
**Implemented by:** `LapsPasswordReadAccess` in `SecureAD.Judgement` (planned).

---

## For a reviewer

**This document is written to be checked by somebody who cannot see this repository.** Every claim
about Active Directory cites a Microsoft source, and every case is stated in terms of the directory
rather than of this product's code.

**It departs sharply from its predecessor card, and deliberately.** The old card was titled
*Unexpected Principal can Read LAPS Passwords* and fired on any principal outside a hard-coded list
of administrators. That presumes the product knows which principals an organisation intended, and it
does not and cannot. The owner settled this on 2026-09-03 and it is recorded as `P-123`; [§3](#3-what-this-rule-refuses-to-claim)
is the whole of the reasoning.

**The thing most worth challenging** is [§4](#4-the-two-rights-a-confidential-attribute-needs). This
rule requires *two* access rights where the predecessor required one, which means it reports fewer
principals than the old product did. Whether that is correctness or under-reporting is the judgement
this rule stands on.

**The predecessor's MITRE tag is not carried over.** It was `T1003.003`, which is credential dumping
from the domain database — the NTDS file. Reading a LAPS password is not that: it is an authorised
LDAP read of an attribute, using a permission somebody granted. The tag looks copied rather than
reasoned and is dropped.

---

## 1. What it finds

A **computer object whose LAPS password attributes can be read by a broad principal** — one that is
broad in every organisation: `Everyone`, `Authenticated Users`, `Domain Users`, `Domain Computers`,
`Guests`, `Anonymous Logon`.

The principal need not be named in the access control entry. It counts if it falls out of the **full
expansion** of whichever principal *is* named, however deeply nested, and the finding shows the
membership path that reached it.

In plain terms: *somebody delegated the right to read local administrator passwords, and when you
follow the group memberships all the way down, the delegation reaches everybody.*

## 2. Why this matters

**The password is the machine's local administrator password, in clear text.** Microsoft states the
storage plainly: `msLAPS-Password` "contains a Unicode string that specifies the clear-text version
of the current password", stored as JSON on the computer object.[^schema]

**And the harm of the nesting is Microsoft's own observation**, from *Implementing Least-Privilege
Administrative Models*, section *On Member Servers*:

> "we find membership ranging from a handful of local and domain accounts, to dozens of nested
> groups that, when expanded, reveal hundreds, even thousands, of accounts with local Administrator
> privilege on the servers... without consideration to the fact that any user who can modify the
> memberships of those groups in the domain can gain administrative control of all systems on which
> the group has been nested"

**What the organisation can therefore mitigate:** an unnoticed path by which every authenticated user
in the domain can retrieve the local administrator password of any managed machine, and so obtain
administrative control of it — locally, with no domain authentication and nothing logged centrally.

## 3. What this rule refuses to claim

**It does not decide which principals should hold LAPS read access.** Nothing in the directory says
whether a given delegation is correct. The owner's decision of 2026-09-03 (`P-123`) came from a live
customer whose LAPS decryptor group is deeply nested *and* is also used to delegate attribute read at
the domain root — a configuration that looks alarming and may be entirely deliberate. Only the
organisation running the audit knows.

**So the rule asserts exactly three things and nothing beyond them:**

1. **A broad principal is in the fully expanded effective set.** This needs no local knowledge,
   because it is wrong in every organisation.
2. **The scope the grant is inherited from, stated as a fact and not a verdict.** A grant inherited
   from the domain root is reported as such and is not called an error; a domain-root delegation may
   be intended.
3. **The membership path**, so the operator can act. At depth six, naming the broad principal does
   not tell anybody which link to cut.

**Testing the name of the delegated principal would not work anyway.** Microsoft's security groups
reference gives the built-in `Users` group default members of *Authenticated Users* and *Domain
Users*, so a delegation to `Users` is effectively a delegation to everybody; and
`Pre-Windows 2000 Compatible Access`, which Microsoft says has read access for all users and groups
in the domain, may contain *Everyone* and *Anonymous*. Broadness is decided by SID, by
`BroadPrincipalCatalogue`, and never by name.

**The whole expansion, browsable, is not this rule.** That is the groups screen recorded as `P-126`.
A finding exists only when something fired; an inventory has to exist when nothing did.

## 4. The two rights a confidential attribute needs

**Every Windows LAPS password attribute is marked confidential.** Microsoft's schema reference gives
`msLAPS-Password` a `SearchFlags` value of `904`, and lists the constituent bits — one of which is
`fCONFIDENTIAL`.[^schema]

**Reading a confidential attribute therefore needs two rights, not one.** Microsoft:

> "After Windows Server 2003 SP1 is installed and after Active Directory performs a read access
> check, Active Directory checks for confidential attributes. If confidential attributes exist and if
> READ_PROPERTY permissions are set for these attributes, Active Directory will also require
> CONTROL_ACCESS permissions for the attributes or for their property sets."[^confidential]

**The predecessor tested `CONTROL_ACCESS` alone** — its query was `(access_mask & 256) != 0` and it
never looked at `READ_PROPERTY`. That names principals who cannot in fact read the password, which is
the product telling a customer something false.

**This rule requires both to raise a finding.** Settled by the owner, 2026-09-03.

**A `CONTROL_ACCESS`-only grant is still reported — as a stated fact, not a finding.** It is a
sensitive permission and Microsoft's own tooling hunts for it, but on its own it does not yield the
password, so it is not asserted as an exposure.

## 5. Generic and object-specific entries are different questions

**A generic entry grants the right over everything; an object-specific one grants it only for the
named attribute.** Microsoft:

> "When you use the confidential attributes feature, CONTROL_ACCESS permission is granted by
> assigning a generic access control entry to a user. If CONTROL_ACCESS permission is granted by
> assigning an object-specific access control entry, the user will only have CONTROL_ACCESS
> permission to the confidential attribute."[^confidential]

**Microsoft treats the generic case as the thing to go looking for**, and says why:

> "Some users or groups might have the extended rights permission on the OU of the managed device.
> This situation is problematic, because users who have this permission can read confidential
> attributes, and all the Windows LAPS password attributes are marked as confidential."[^getstarted]

**So the rule must read `HasObjectType`, not `ObjectTypeGuid is null`.** Those are different
questions, and `ObjectPermissions` keeps them apart for exactly this reason: an object entry carrying
no GUID narrows nothing and reaches as far as its plain counterpart, whereas a GUID that is present
names what the entry is scoped to. Reading it wrong reports the wrong population — in one direction a
narrow per-attribute delegation is inflated into control over the object, and in the other a blanket
grant is missed entirely.

## 6. Which attributes count

| Attribute | Product | Holds |
| --- | --- | --- |
| `ms-Mcs-AdmPwd` | legacy Microsoft LAPS | the password, clear text, always |
| `msLAPS-Password` | Windows LAPS | the password, clear text — **only when encryption is off** |
| `msLAPS-EncryptedPassword` | Windows LAPS | the password, encrypted — **written instead when encryption is on** |

**All three are matched.** The reason the third is included is not symmetry. Microsoft says
`ADPasswordEncryptionEnabled` **defaults to True** and separately that it "highly recommends"
enabling it.[^concepts] On a forest following that advice, `msLAPS-Password` is empty on every
machine — so a rule watching only the first two would find nothing and report the estate clean while
a broad group held read access to the attribute that actually carries the secret.

**In the ordinary case the third GUID changes nothing**, because
`Set-LapsADReadPasswordPermission` grants across the LAPS password attributes as a set — Microsoft
describes it as specifying "who can read various password attributes"[^concepts] — so the same
principal already holds an entry on each, and the matches de-duplicate. It only changes the answer
where somebody delegated the encrypted attribute by hand, which is precisely the case that would
otherwise be invisible.

**Reading the encrypted attribute is not the same as reading the password**, and the finding must say
so. Decryption is governed by the `ADPasswordEncryptionPrincipal` policy setting and never by the
ACL: "When a user is granted permission to query a password from Active Directory that doesn't
automatically imply that the user has permission to decrypt an encrypted password."[^getstarted]

**The DSRM and password-history variants are out of scope**, recorded on the punch list. They concern
domain controllers rather than the member-machine population this rule judges, and folding them in
would mix two questions.

## 7. Severity

**High, and fixed.** Settled by the owner 2026-09-03, against `P-124`.

**It does not move with `ADPasswordEncryptionEnabled`.** The argument for making it move is real: a
broad grant reaches ciphertext where encryption is on and the password itself where it is off.
The decision is that the encryption posture is **stated as a plain fact in the finding** and does not
modify the severity. Two reasons:

- **It keeps SEC-090 independent of SEC-093.** A severity that depended on a Group Policy value read
  by another rule would mean SEC-090 answers differently depending on whether an unrelated derivation
  ran, and nothing in the finding would explain why.
- **Ciphertext is not safety.** The encrypted value is still exfiltrable and still attackable
  offline, and if the decryptor principal is itself broadly nested — the live customer configuration
  that prompted `P-123` — the two together are a full compromise. Encryption raises the cost; it does
  not remove the exposure.

## 8. What the rule reads

| Input | Source | Why |
| --- | --- | --- |
| `objectClass` | captured attribute | the class test, most-derived, via `LapsAttributes.IsComputer` |
| `userAccountControl` | captured attribute | the disabled-account exclusion, via `LapsAttributes.IsDisabled` |
| the object's DACL | `JudgingContext.Permissions` | the entries, their masks, and `HasObjectType` |
| the LAPS attribute schema GUIDs | the captured schema layer | to match an object-specific entry to the attribute it names |
| the expansion of each trustee | `JudgingContext.MembersOfPrincipal` | to reach a broad principal through nesting, with the path |

**The schema GUIDs are resolved from the *captured* layer, not the shipped one.** A forest that never
ran `Update-LapsADSchema` has no such attribute at all, and an answer from a shipped table would
claim otherwise. This follows `docs/decisions/0014`, which requires every answer to state which layer
it came from.

**Declared derived fact:** `DerivedFactKind.PrincipalExpansion`. `JudgingRun` refuses the whole
judging where the nesting was not derived, rather than letting the rule report per-object silence —
a group nobody expanded and a group with nothing in it are opposite answers, and being handed the
second when the first is true would report a broad delegation as safe.

## 9. When it does not answer

**Absent, unreadable and clean are three states, and the rule keeps them apart.**

| Situation | Verdict | Why not silence |
| --- | --- | --- |
| The descriptor was never read (`DescriptorAvailability.NotAttempted` or `Unreadable`) | could not resolve | A production domain returned 19,927 of 100,000 objects with no readable descriptor. Reporting those as granting nothing says an object is safe when nobody knows. |
| No LAPS password attribute exists in this forest's schema | judged, nothing reported | No object can carry the value, so nothing is delegated to read. This is a fact about the forest, and reporting the estate for it would be reporting the schema. |
| A trustee is not in the bundle — a principal from a trusted external forest, or one from a domain the run could not read (`PrincipalExpansionOutcome.PrincipalNotFound`) | could not resolve, for that trustee | Not found is not *not broad*. |
| A trustee's identifier belongs to a domain the run read **in full**, and nothing in that domain carries it (`PrincipalExpansionOutcome.PrincipalDoesNotExist`) | judged, nothing reported for that trustee | No such principal exists, so the entry grants the right to nobody. This is knowledge, not ignorance, and refusing on it costs a verdict for nothing. Usually an account deleted while the entries naming it were left behind. |
| The expansion stopped at a budget (`StoppedAtBudget`) | could not resolve, for that trustee | Everything listed is genuinely inside; the absence of anything else is not a fact. `PrincipalExpansion.IsComplete` is what says so. |
| The object is a disabled computer account | judged, nothing reported | Consistent with SEC-091: there is no live machine, so there is no local administrator password to read. |

## 10. Tests

**This rule has no internal anchor.** The predecessor's evaluator exists, but it is wrong in the way
[§4](#4-the-two-rights-a-confidential-attribute-needs) describes, so agreeing with it would be a
defect rather than a check. Every value below is anchored to Microsoft or to the lab.

Negative controls that must each be observed failing:

- an allow entry cancelled by a preceding deny — must **not** be reported
- an entry with `READ_PROPERTY` and no `CONTROL_ACCESS` — must **not** be a finding
- an entry with `CONTROL_ACCESS` and no `READ_PROPERTY` — must be a stated fact, **not** a finding
- an object entry carrying no `ObjectType` (`HasObjectType` false) — must be treated as reaching the
  attribute, not as scoped to nothing
- an object entry naming a *different* attribute's GUID — must **not** be reported
- a narrow, correctly-scoped delegation to a group containing only named administrators — must be
  silent, which is the whole of `P-123` expressed as a test
- a broad principal reached at depth six — must be reported **with the full path**
- a truncated expansion finding no broad principal — must **not** report clean

## 11. Verified against `ad.lab`

**Run 2026-09-04, re-judged after `P-134`.** Judged all 14 LAPS-relevant computers and reported
three findings.

| Finding | Broad principal | Route |
|---|---|---|
| `BAMS1` | `Everyone` (`S-1-1-0`) | named directly in the access control list |
| `BAWK1` | `Everyone` (`S-1-1-0`) | named directly |
| `BAWK1` | `Domain Users` (RID 513) | through a delegated group |

**The run as first judged returned `Indeterminate`, and understanding why is worth more than the
fix.** On one further computer a trustee held both `READ_PROPERTY` and `CONTROL_ACCESS` over a LAPS
password attribute and could not be found in the bundle under any scope. Nothing broad was found
beside it, so there was no finding to carry the incompleteness — and [§9](#9-when-it-does-not-answer)
requires a refusal rather than silence. One unjudged object marked the whole rule.

Measured in the bundle, the unresolvable trustees were ordinary domain principals of `ba.ad.lab`
carrying 18, 12 and 3 such entries between them. The owner confirmed on 2026-09-04 that in that lab
an unresolvable identifier is a deleted account.

**The refusal was correct on the evidence the rule then had, and `P-134` gave it better evidence.**
`ba.ad.lab` is a domain the run read *in full*, and an identifier of the form
`S-1-5-21-a-b-c-RID` names the domain that issued it. So "nothing carries this identifier" in a
fully-read domain is not a gap: no such principal exists, the entry grants nobody anything, and
there is nothing inside it to fear. The derivation now records which domains were read completely,
keyed by domain SID, and answers `PrincipalDoesNotExist` where it can prove all of that — leaving
`PrincipalNotFound` for every case it cannot. Re-judging the same sealed bundle moved the rule to
`Succeeded` with `objects_not_judged` at zero **and the three findings above unchanged**, which is
the result that matters: the fix removed a refusal without moving a single answer.

**What did change is that the three findings no longer carry the sentence "Not every principal
holding this access could be expanded".** That sentence was true and is now false, because the
expansion is complete.

**Do not read this as licence to treat "not found" as "does not exist".** In a customer forest the
same symptom still covers a principal from a trusted external forest, or a domain the run could not
read, and those remain genuinely unknown. A domain read only in part refuses exactly as an
unreachable one does: most of a domain is a hole of unknown shape, not nearly all of an answer.

**What the run confirmed that no fixture could.** An earlier version asked for each trustee only at
the domain the trustee was captured in, so every computer whose list named `SYSTEM` or a domain
group answered `PrincipalNotFound`: the rule reported *Indeterminate* over half the estate and
buried two real findings. `MembersOfTrustee` now asks under each scope a SID could be keyed by. Two
thousand nine hundred and seventy-three green tests did not see it.

**That same shape is why `PrincipalDoesNotExist` does not end the scope walk.** A domain-relative
identifier is keyed under the *empty* scope, so an answer of "no such principal" at the trustee's
own domain says nothing about whether the trustee exists — and stopping there would have been the
same defect in new clothing.


---

[^schema]: [Windows LAPS schema extensions reference](https://learn.microsoft.com/windows-server/identity/laps/laps-technical-reference)
[^confidential]: [Mark an attribute as confidential in Windows Server 2003 Service Pack 1](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential)
[^getstarted]: [Get started with Windows LAPS and Windows Server Active Directory](https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
[^concepts]: [Key concepts in Windows LAPS](https://learn.microsoft.com/windows-server/identity/laps/laps-concepts-overview)
