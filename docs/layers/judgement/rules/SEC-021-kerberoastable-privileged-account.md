# SEC-021 — a privileged account with a service name registered on it

**Status:** specified 2026-09-02. Not yet built.
**Severity:** Critical — the first rule in this product to carry it. See [§6](#6-severity).
**Rule identifier:** `SEC-021`.
**Implemented by:** `KerberoastablePrivilegedAccount` in `SecureAD.Judgement` (planned).

---

## For a reviewer

**This document is written to be checked by somebody who cannot see this repository.** Every claim
about Active Directory cites a Microsoft source, and every case is stated in terms of the directory
rather than of this product's code.

**Unlike `SEC-027`, this one has a card to port from.** `docs/rules/SEC-021.md` is the predecessor's
*Kerberoastable Privileged Account*, and it partitions the problem the way the owner chose on
2026-09-02: `SEC-020` reports every account with a service name, `SEC-021` reports only privileged
ones. `SEC-020` stays unbuilt. **The card is a source and not an authority** — [§5](#5-what-is-excluded-and-why)
departs from it on one exclusion, and says why.

**This is the first stage-4 rule that cannot judge an underived bundle.** It declares
`DerivedFactKind.ProtectedPrincipals`, so `docs/decisions/0091` applies and a judging without a
matching derivation is refused for the whole run rather than per object.

**What would be most useful to hear:** whether Critical is right in [§6](#6-severity), and whether
the disabled-account decision in [§5](#5-what-is-excluded-and-why) is right — it departs from the
predecessor.

---

## 1. What it finds

A **user** account that has at least one `servicePrincipalName` and is a **protected principal** —
that is, one the AdminSDHolder derivation establishes as privileged.

In plain terms: *any member of this domain can ask a domain controller for a ticket encrypted with
this administrator's password, take it away, and attack it offline for as long as they like.*

## 2. What kerberoasting is

A service principal name is how Kerberos names a service so a client can ask for a ticket to it. When
a client asks, the domain controller returns a service ticket **encrypted with the key derived from
the password of the account the name is registered on**.

**The request is not privileged.** Any authenticated member of the domain may ask for a service
ticket for any service name — that is what the protocol is for. Nothing about the request looks
unusual, and the account being attacked is never contacted.

Microsoft, [*Suspected Kerberos SPN exposure*](https://learn.microsoft.com/defender-for-identity/alerts-mdi-classic#credential-access-alerts)
(external ID 2410, rated **High**, MITRE
[Kerberoasting T1558.003](https://attack.mitre.org/techniques/T1558/003/)):

> "Attackers use tools to enumerate service accounts and their respective SPNs (Service principal
> names), request a Kerberos service ticket for the services, capture the Ticket Granting Service
> (TGS) tickets from memory and extract their hashes, and save them for later use in an offline
> brute force attack."

And on the newer detection,
[*Possible Kerberoasting attack*](https://learn.microsoft.com/defender-for-identity/alerts-xdr#credential-access-alerts):

> "an attacker requests Kerberos service tickets for accounts with Service Principal Names (SPNs) in
> the Active Directory. The attacker then extracts and attempts to crack the encrypted tickets
> offline to obtain the plaintext passwords of those accounts. These targeted accounts might have
> been compromised, allowing the attacker to move laterally within the organization, escalate
> privileges, steal data, or set up backdoors."

**Why offline matters.** The attack proceeds at the attacker's own pace, on their own hardware, with
no lockout, no failed-logon events on the account, and no further contact with the directory. The
only thing standing between the attacker and the password is how hard the password is.

## 3. Why *privileged* is the whole rule

**Service names on ordinary accounts are normal and expected.** That is what a service account is.
Microsoft's *Unsecure account attributes* assessment lists *"Remove a Service Principal Name (SPN)"*
as a recommended action and then states the scope plainly:

> "When a user account is configured with an SPN set, it means that the account has been associated
> with one or more SPNs. This typically occurs when a service is installed or registered to run under
> a specific user account… **This recommendation only showed for sensitive accounts.**"

**So Microsoft itself reports this only for sensitive accounts, and this rule follows.** Reporting
every account with a service name would report the normal operation of every application in the
estate.

**What makes the privileged case different in kind, not degree.** The ticket is encrypted with *that
account's* password. If the account is a Domain Admin, then a single ordinary domain member — a
compromised workstation, a contractor's account, anybody — can obtain material that turns into
domain administration by offline guessing. There is no lateral movement to perform and no privilege
to escalate through first.

**What the organisation can therefore mitigate:** a documented, single-step path from *any* domain
account to *administrator*, which is invisible in every log because the request is legitimate.

## 4. The remedy, in Microsoft's words

From the *Security principal reconnaissance (LDAP)* alert page, under **Kerberoasting specific
suggested steps for prevention**:

> - Require use of [long and complex passwords for users with service principal accounts](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/minimum-password-length).
> - [Replace the user account by Group Managed Service Account (gMSA)](https://learn.microsoft.com/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview).

**Both, and in that order of preference, and the finding says so.** A group managed service account
has a 240-byte password the operating system generates and rotates automatically, so there is
nothing worth cracking; a long complex password on the existing account only makes the offline attack
expensive rather than impossible.

**A third remedy the finding must name, which Microsoft's list does not:** *if the account does not
actually run a service, remove the service name.* An administrator account with a stale service name
left over from a test is the common real-world case, and it is the only remedy that removes the
exposure rather than raising its cost.

**What the wording must not say:** that any of the three makes the account safe. Removing the service
name closes this route; it says nothing about the other ways a privileged account can be reached.

## 5. What is excluded, and why

| Excluded | Why |
|---|---|
| **Computer accounts** | The password is generated by the operating system, is 120 characters, and rotates by default every 30 days. There is nothing here an offline attack recovers in useful time. |
| **Group managed service accounts** | Microsoft's own recommended remedy. Its password is machine-generated and rotated automatically, which is exactly the state this rule is asking for. Reporting it would report the fix as the defect. |
| **Accounts with no service name** | Not kerberoastable. There is no ticket to request. |
| **Accounts that are not privileged** | The owner's decision of 2026-09-02, and Microsoft's own scope: *"This recommendation only showed for sensitive accounts."* This is the rule's boundary and belongs in its About text — see [§10](#10-what-is-not-reported-and-why). |

**`krbtgt` needs no special case here.** The predecessor excluded it by relative identifier. It holds
no `servicePrincipalName`, so it never reaches the test — and if a directory ever presented one, that
is something an administrator should be told about rather than something to hide. Same reasoning as
`SEC-022` §5.

### Disabled accounts are reported, departing from the card

**The predecessor excluded them**, stating that the key distribution centre will not issue a ticket
for a disabled account. **This product reports them, because that claim could not be evidenced.**

Microsoft's Kerberos troubleshooting material was searched for a statement that a TGS request naming
a disabled account's service is refused. **None was found.** That is the identical position `SEC-022`
§5 reached about AS-REP for disabled accounts, and it is resolved the same way: an exclusion resting
on an unevidenced belief risks hiding a real exposure, and re-enabling the account would restore it
in full.

**The disabled state travels in the evidence and is named in the finding's wording**, so an operator
can rank it himself rather than having the product decide for him on something it cannot support.
**If a Microsoft source is later found stating the KDC refuses these, this becomes an exclusion and
this section is the record of why it was not one first.**

## 6. Severity

**Critical.** This is the first rule in this product to carry it, and `Severity.Critical` is
documented as *"Severe. Someone should look at this today."*

The reasoning, and it is a judgement rather than a Microsoft position:

- **The attacker needs only an ordinary domain account.** Not administrative access, not a foothold
  on a privileged host — any authenticated member of the domain.
- **What it yields is administration of the domain**, directly. Every other path this product
  reports needs steps in between.
- **It is silent.** The ticket request is legitimate protocol traffic, the attack happens offline,
  and the account being attacked is never touched.

**Microsoft rates its own detection High**, not Critical. That is a rating of an alert about an
attack in progress, and this is the posture that makes the attack a single step against an
administrator — so it does not settle the question either way.

**Consistent with the predecessor**, which also rated `SEC-021` Critical while rating the
all-accounts `SEC-020` lower. That agreement is worth noting precisely because this document departs
from the same card on the disabled-account question.

**The argument against Critical:** if the privileged account's password is genuinely long and random,
the offline attack fails. The counter is that the product cannot see password quality from a
directory reading, and rating on an assumption of good passwords is the same class of mistake as
`P-113` — printing an estimate as a finding.

## 7. What the rule reads

| Input | Why |
|---|---|
| `servicePrincipalName` | Whether the account is kerberoastable at all, and which services are named. |
| `objectSid` | The identity the derivation is asked about. |
| `objectClass` | Decides the exclusion of computers and managed service accounts, and is reported. |
| `userAccountControl` | The disabled state, for the wording. It decides nothing. |
| `sAMAccountName` | The name shown, falling back to the distinguished name when absent. |

**Derived facts: `ProtectedPrincipals`.** The same product `SEC-030` reads, and the reason this rule
cannot judge an underived bundle.

**Why AdminSDHolder protection is the definition of "privileged" here.** It is Microsoft's own
mechanism for designating the accounts that matter — SDProp stamps exactly the members of the groups
Microsoft defines as privileged, directly and through nesting. Using it means the answer to *"is this
account sensitive?"* comes from the directory's own designation rather than a list this product
invented, and it is already derived, already persisted and already bound to the evidence.

## 8. When it does not answer

Follows `SEC-030`, because it consumes the same derived product and the same failures apply:

| Case | What happens |
|---|---|
| No derivation offered | `CouldNotResolve(NotDerived)`. Per `0091` the run is refused before this point, so it should be unreachable. |
| The protected-principal closure is incomplete | `CouldNotResolve`, carrying the derivation's own stated reason. **Checked before the object's own facts**, because no per-object answer can be trusted while the graph behind it is incomplete — a partial closure makes a privileged account look ordinary, which is the direction that loses a finding. |
| The object's SID cannot be read | `CouldNotResolve(IdentityUnreadable)`. The derivation is keyed by SID; without one there is nothing to ask about. |
| The derivation has no entry for this SID | `CouldNotResolve(NotDerived)`. Silence would report a privileged account as ordinary. |
| The derivation says *unknown* | `CouldNotResolve`, carrying its reason rather than flattening it. |
| `servicePrincipalName` absent | **No finding, no unread input.** Most accounts have none and are genuinely not kerberoastable. |
| `servicePrincipalName` present, every value unreadable | `CouldNotJudge`, naming the attribute. The account has service names and none could be read, so the rule cannot say it is clean. |
| `servicePrincipalName` present, **some** values unreadable | **Reported, with the count in the evidence and in the wording.** One readable service name is enough to make the account kerberoastable, so refusing here would lose a true Critical finding over an unreadable sibling. |
| `objectSid` absent | Treated as unreadable, above. |

**The asymmetry is deliberate.** An absent service name is a fact about the account; an absent or
doubtful protection answer is a fact about the run. Only the second is uncertainty.

**The partial-read case was got wrong first and gate 4 caught it.** The rule originally refused any
account with an unreadable service name. That is the same mistake `SEC-027` made and the same gate
found it, by refusing a bare collection from a type that could not say whether it had read
everything. The fix is the same: carry the count, report what is known, and say plainly that the
account may claim to run more than is listed.

## 9. What it rests on

`KerberoastableAccountEvidence`, stored in `finding_kerberoastable_account` with its service names in
a child table:

- the account's `objectSid` — the identity the derivation was asked about
- every `servicePrincipalName` it carries, in the order captured
- the whole `userAccountControl` value, from which `IsDisabled` is derived rather than stored

**Every service name, not just the first.** An operator deciding whether the account really runs
something needs to see what it claims to run; one name would answer a narrower question than the one
he has.

## 10. What is **not** reported, and why

**An account with a service name that is not privileged produces no finding.** That is `SEC-020`, and
it is not built. Stated in the About text and the guidance so an operator reads it, per the About
commitment in `WHAT-THE-PRODUCT-IS.md`.

**Two things follow that an operator should know:**

1. **A service account that is not privileged today can become privileged tomorrow** by being added
   to a group, and this rule will then report it. Its exposure did not change; its consequence did.
2. **Privilege here means AdminSDHolder-protected.** An account that is powerful in practice — it
   owns a critical application, or holds broad rights granted directly on objects — but is in no
   protected group is not reported. Ranking that needs the privilege graph, which is stage 5 and 6
   work. **This is the same boundary `SEC-027` has**, recorded as `P-114`, and it is the second rule
   to hit it.

## 11. Tests

`KerberoastablePrivilegedAccountTests`. The negative controls:

- **a privileged account with no service name** — the commonest privileged account in any forest
- **an unprivileged account with a service name** — every ordinary service account, and the case
  §10 says is not reported
- **a computer and a gMSA, both privileged and both with service names** — the two class exclusions,
  which a rule filtering on the wrong thing would report
- **an unknown or incomplete protection answer** — must not silently become "not privileged"

Each mutated in both directions, **one mutation at a time** — recorded on 2026-09-02 after two
simultaneous mutations masked one another while building `SEC-028`.

**Observed failing on 2026-09-02.** Two mutations, run separately:

| Mutation | What failed | What it said |
|---|---|---|
| `NotProtected` no longer returns silently, so unprivileged accounts are reported | 1 of 9 | `AnOrdinaryAccountWithAServiceNameIsNotReported`, printing a Critical finding against an ordinary service account — which is the rule turning into `SEC-020` and reporting every application in the estate |
| The class test changed from *most derived class is `user`* to *`user` appears anywhere in `objectClass`* | 2 of 9 | `APrivilegedComputerWithAServiceNameIsNotReported` and `APrivilegedGroupManagedServiceAccountIsNotReported`, each printing a finding whose own `ObjectClass` column read `computer` and `msDS-GroupManagedServiceAccount` |

**The second mutation is the one worth keeping.** It is not a hypothetical: a computer's
`objectClass` really is `top, person, organizationalPerson, user, computer`, so the obvious way to
write the test — *is this a user?* — reports **every domain controller in the forest**, each of which
has service names and is a member of a protected group. The finding would have been Critical, on
objects whose passwords are machine-generated at 120 characters and rotated, and it would have been
false. The fixtures use the real class chain rather than a single value for exactly this reason.

## 12. Verifying against `ad.lab`

Not yet run. Plantable, unlike `SEC-027`: a service name is set with `setspn` or by writing
`servicePrincipalName`, and group membership is ordinary administration. The order is the usual one —
establish what the forest holds from sealed evidence first, then plant.

**The negative half is the interesting one here.** `ad.lab` is expected to contain privileged
accounts without service names and service accounts that are not privileged. Both must stay silent,
and confirming that on real data is what distinguishes this rule from one that reports every account
with a service name.
