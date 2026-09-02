# SEC-027 — an account carrying a privileged identifier in its SID history

**Status:** specified 2026-09-02. Not yet built.
**Severity:** High — decided by the owner, 2026-09-02.
**Rule identifier:** `SEC-027`.
**Implemented by:** `PrivilegedSidHistory` in `SecureAD.Judgement` (planned).

---

## For a reviewer

**This document is written to be checked by somebody who cannot see this repository.** Every claim
about Active Directory below cites a Microsoft source, and every case is stated in terms of the
directory rather than of this product's code. If a claim cannot be checked against the source beside
it, that is a defect in this document.

**This rule has no predecessor and no card.** `docs/rules/SEC-123.md` covers who can *grant* SID
history; nothing covered who *has* it. There is therefore nothing internal to anchor it to, which is
the `F-S44-2` situation: a set of internally consistent tests would prove only that this rule agrees
with itself. **The anchor is Microsoft's *Unsecure SID History attributes* assessment and the
MS-DTYP relative identifier table**, and every section below names which.

**What would be most useful to hear:** whether the exclusion in [§6](#6-what-is-not-reported-and-why)
is drawn in the right place. The severity in [§7](#7-severity) was decided by the owner on
2026-09-02 against the argument recorded there, so it is settled rather than open.

---

## 1. What it finds

Any captured security principal — `user`, `computer` or `group` — whose `sIDHistory` attribute
contains a security identifier whose relative identifier is one Microsoft documents as privileged.

In plain terms: *this account is a member of a privileged group that no group membership listing
will show you, because the privilege is carried as an identifier rather than as a membership.*

## 2. What SID history is, and what carrying one does

Every security principal has an identifier, its `objectSid`. It is not portable: the last part of it
identifies the account, and everything before it identifies the domain that issued it. Move the
account to another domain and it must be issued a new one.

[Security identifiers](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers#sids-and-globally-unique-identifiers)
describes what happens to the old one:

> "When a User object moves from one domain to another, a new SID must be generated for the user
> account and stored in the `ObjectSID` property. Before the new value is written to the property,
> the previous value is copied to another property of a User object, `SIDHistory`. This property can
> hold multiple values."

And what that property then does, on the same page:

> "When a user signs in and is successfully authenticated, the domain authentication service queries
> Active Directory for all the SIDs that are associated with the user… All these SIDs are returned
> to the authentication client, and they're included in the user's access token. When the user tries
> to gain access to a resource, **any one of the SIDs in the access token (including one of the SIDs
> in the `SIDHistory` property), can allow or deny the user access**."

So a value in `sIDHistory` is not a historical note. **It is a live entry in the access token,
evaluated on every access check, exactly as a group membership is.**

[Using DsAddSidHistory](https://learn.microsoft.com/windows/win32/ad/using-dsaddsidhistory) states
the consequence directly:

> "Adding SIDs to a security principal's `sIDHistory` is a security-sensitive operation that
> **effectively grants to the destination principal access to all resources accessible to the source
> principal**, provided that trusts exist from applicable resource domains to the destination
> domain."

**Why no group membership listing shows it.** Membership is stored as a link between two objects —
the group's `member` attribute and the account's `memberOf`. A SID in `sIDHistory` creates no such
link. Nothing was added to any group, so listing that group's members, at any depth, will not name
this account. The [SID-History attribute](https://learn.microsoft.com/windows/win32/adschema/a-sidhistory)
schema page confirms the attribute is defined on the `Security-Principal` class — so groups and
computers carry it too, not only users.

## 3. Why it matters, in Microsoft's words

[Defender for Identity, *Unsecure SID History attributes*](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-sid-history-attributes):

> "Accounts configured with an unsecure SID History attribute are windows of opportunities for
> attackers and can expose risks.
>
> For example, **a nonsensitive account in a domain can contain the Enterprise Admin SID in its SID
> History from another domain in the Active Directory forest, thus "elevating" access for the user
> account to an effective Domain Admin in all domains in the forest.** If you have a forest trust
> without SID Filtering enabled (also called Quarantine), it's possible to inject a SID from another
> forest and it will be added to the user token when authenticated and used for access evaluations."

**That example is this rule.** A non-privileged account, holding a privileged identifier from
another domain, effectively privileged, visible in no membership listing.

Microsoft's detection of the act rather than the state is
[*Suspected SID-History injection*](https://learn.microsoft.com/defender-for-identity/alerts-mdi-classic#persistence-and-privilege-escalation-alerts)
(external ID 1106), rated **High**, mapped to MITRE **Privilege Escalation (TA0004)**, technique
**Account Manipulation (T1134)**, sub-technique **SID-History Injection (T1134.005)**. That alert
fires when a SID is *added*. This rule reports the SID that is *there*, which is what a run over
sealed evidence can see.

**What the organisation can therefore mitigate:** a standing privilege escalation that survives
every review of group membership, because it is not a group membership. An administrator auditing
Domain Admins will not find this account, and the account has the access anyway.

## 4. The remedy, in Microsoft's words

The *Unsecure SID History attributes* assessment gives the steps exactly:

> 2.1. Identify the SID in the SIDHistory attribute on the account.
> ```powershell
> Get-ADUser -Identity <account> -Properties SidHistory | Select-Object -ExpandProperty SIDHistory
> ```
> 2.2. Remove the SIDHistory attribute using the SID identified earlier.
> ```powershell
> Set-ADUser -Identity <account> -Remove @{SIDHistory='S-1-5-21-...'}
> ```

**The guidance says that and no more.** It does not promise the change is safe: the value may be the
only reason the account can still reach resources whose permissions were never re-stamped after the
migration, and removing it can take that access away. The guidance states the action and what it may
break, and never that the customer is then secure.

## 5. Which identifiers count as privileged, and why each one

**Microsoft does not publish its filter.** The assessment says only that it "checks for accounts with
SID History attributes which Microsoft Defender for Identity profiles to be risky" — the profile is
Defender's own model and is not documented. So the filter below cannot be attributed to Microsoft;
**what is attributed to Microsoft is what each identifier is**, from the well-known SID tables in
[Security identifiers](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers#well-known-sids)
and MS-DTYP 2.4.2.4. The decision that these identifiers amount to privilege is this product's, and
is stated as such.

Every identifier below is already present in `WellKnownSidCatalog`, harvested from MS-DTYP
2.4.2.4 by `next/tools/harvest-ms-dtyp-well-known-sids.ps1`, read independently through the Microsoft
Learn documentation service, and held by `WellKnownSidCatalogMicrosoftAnchorTests`. **The rule adds
no new catalogue of identifiers and no new values.** It declares which of the catalogue's existing
entries it treats as privileged.

**There are two kinds, and conflating them is a defect this document made first.** Microsoft
defines the domain administration groups as *relative identifiers* — the last value of a SID counted
from an issuing domain — and the built-in groups as *whole well-known SIDs* whose domain identifier
is fixed at 32 on every machine. The two tables in *Security identifiers* are separate for that
reason, and `WellKnownSidCatalog` transcribes them into separate lists.

**Domain-relative — matched on the last value of the SID:**

| RID | Who it is | Microsoft's description, abbreviated |
|---|---|---|
| 500 | Administrator | "A user account for the system administrator… By default, the Administrator account is a member of the Administrators group, and it can't be removed from that group." |
| 502 | krbtgt | "A user account that's used by the Key Distribution Center (KDC) service." |
| 512 | Domain Admins | "A global group with members that are authorized to administer the domain… a member of the Administrators group on all computers that are joined to the domain, including domain controllers." |
| 516 | Domain Controllers | "A global group that includes all domain controllers in the domain." |
| 518 | Schema Admins | "authorized to make schema changes in Active Directory." |
| 519 | Enterprise Admins | "authorized to make changes to the forest infrastructure… a default member of every Domain Admins group in the forest." |
| 520 | Group Policy Creator Owners | "authorized to create new Group Policy Objects in Active Directory." |
| 521 | Read-only Domain Controllers | "A global group that includes all read-only domain controllers." |

**Built-in — matched on the whole SID, never on its last value:**

| SID | Who it is | Microsoft's description, abbreviated |
|---|---|---|
| S-1-5-32-544 | Administrators | "After the initial installation of the operating system, the only member of the group is the Administrator account." |
| S-1-5-32-548 | Account Operators | "have permission to create, modify, and delete accounts for users, groups, and computers in all containers and organizational units (OUs)…" |
| S-1-5-32-549 | Server Operators | "Sign in to a server interactively… Start and stop services. Back up and restore files. Format the hard disk…" |
| S-1-5-32-550 | Print Operators | "can manage printers and document queues." |
| S-1-5-32-551 | Backup Operators | "can back up and restore all files on a computer, **regardless of the permissions that protect those files**." |
| S-1-5-32-552 | Replicators | "supports file replication in a domain… *Don't* add users to this group." |

**Why the second table is not a list of relative identifiers, and how that was found.** This
document first listed all fourteen together as relative identifiers, and the rule was written that
way. Matching 544 on the last value of any SID means `S-1-5-21-<some domain>-544` is reported as the
built-in Administrators group — but that is an ordinary account or group in a domain that issued 544
in the normal course of allocating identifiers, and the product would have been **telling a customer
that an unprivileged object is privileged.** `EveryPrivilegedIdentifierIsOneMicrosoftDocuments`
failed on the first run, naming 544 as an identifier Microsoft's catalogue does not define as
domain-relative. That is the check earning its place: nothing else in the rule would have noticed,
because every positive test still passed.

**Two entries need their reasoning stated, because neither is an administrator.**

- **502, krbtgt** is not a group and grants no access by membership. It is here because a SID
  history value equal to a domain's krbtgt account is not a migration artefact under any documented
  scenario, and an administrator should be told about it. It is the same reasoning `SEC-022` used
  for not special-casing krbtgt: a case that only arises on a tampered directory is a case worth
  reporting rather than hiding.
- **550, Print Operators** is the weakest entry in the table. Microsoft describes it as managing
  printers and queues, which is not administration of the domain. It is included because it is a
  built-in operator group Microsoft groups with the others, and because a benign migration has no
  reason to carry it. **If it proves noisy against a real forest it should be removed, and that is a
  change to this table rather than to the rule's logic.**

**Deliberately not treated as privileged:** 501 (Guest), 513 (Domain Users), 514 (Domain Guests),
515 (Domain Computers), 517 (Cert Publishers), 522, 525, 526, 527, 545, 546, 547, 553, 571, 572.
Each is either an everyone-group whose presence in SID history says nothing, or a role this product
has no Microsoft basis to call privileged. `525` (Protected Users) is a *protection*, and reporting
it would be reporting a defence as a defect.

## 6. What is **not** reported, and why

**An account carrying the identifier of a custom privileged group from the old domain produces no
finding.** This is the rule's boundary and it is stated here, in the guidance, and in the operator's
About text, so that silence is never read as *this account carries nothing*.

Consider a group `ServerAdmins` in a domain that was migrated away from, with relative identifier
`1157`. In its own domain it had been added to the local `Administrators` group on member servers and
granted rights through Group Policy. Every one of those grants is stored as the identifier, not the
name. An account carrying `S-1-5-21-<that domain>-1157` still receives all of it.

**Nothing in the number says so.** `1157` is issued sequentially by the RID master
("the RID for the new SID is taken from the domain controller's allocation of RIDs" — *RID
allocation*, same page) and is indistinguishable from any other account or group in that domain. To
rank it, the product would have to know what that identifier was granted, and:

- **if the old domain no longer exists — the ordinary case after a migration — that information does
  not exist for any tool to read.** No derivation recovers it, because the evidence was never in
  this forest.
- if the old domain is still in the forest, ranking it means evaluating everything that identifier
  is granted across every captured object. That is the privilege graph, which is stage 5 and 6 work,
  not a stage 4 attribute rule.

**So the boundary is drawn where the evidence ends, not where it was convenient.** Recorded as a
punch-list item against stage 5: *rank a SID history value by what it is actually granted in this
forest.*

**What the operator gets instead.** Two things, so the gap is visible rather than silent:

1. `sIDHistory` is already shown on the object detail screen as *Former identifiers*
   (`ObjectSectionCatalog`), independent of any rule. A value nobody can rank is **information**
   about an asset, which is the honest classification for it, and is the same position
   `P-113` took on the account-activity timestamp.
2. When the rule *does* fire, its evidence carries **every** value in the attribute, including the
   ones it could not rank, and the finding's wording says how many there were. An operator is never
   shown a filtered view of the account he is being told about.

## 7. Severity

**High**, decided by the owner on 2026-09-02. This is a judgement made against an absence of
Microsoft guidance rather than against a source. The reasoning he accepted:

- The access is real, standing, and equal to membership of the named group — Microsoft: "effectively
  grants… access to all resources accessible to the source principal."
- It is invisible to the review an administrator would actually perform, which is what makes it
  worse than an equivalent membership.
- Microsoft rates its own *detection* of SID history injection High. That is an alert about an act
  in progress rather than a rating of the posture, so it supports High without settling it.

It would sit level with `SEC-010`, `SEC-011` and `SEC-022`.

**The argument against High**, stated so it is not lost: unlike `SEC-022`, this is not exploitable by
an attacker who holds nothing — somebody must already control the account. A migration that
legitimately carried an administrator's own account across domains produces a true finding that is
not an incident.

**A `computer` or `group` is reported identically to a `user`**, decided by the owner in the same
turn. The mechanism does not differ — the schema puts `sIDHistory` on `Security-Principal` — and no
Microsoft source distinguishes them, so ranking one lower would be this product inventing a
distinction the directory does not make. The object class travels in the evidence and is named in
the finding's wording, so an operator can rank it himself. This is the same shape `SEC-022` used for
the disabled state.

## 8. What the rule reads

| Input | Why |
|---|---|
| `sIDHistory` | The identifiers. Captured multi-valued and **binary** (`CapturedAttributeCatalog`), so each value is decoded with `Sid.ToText` — the same reading `MembershipNestingPass` already uses, so the rule and the derivation cannot disagree about what a value says. |
| `objectSid` | The account's own identifier, to establish which domain issued it, so the finding can say the history value came from a *different* domain. |
| `objectClass` | Reported beside the finding, and decides nothing. |
| `sAMAccountName` | The name shown, falling back to the distinguished name when absent. |

**No derived facts.** `RequiredDerivedFacts` is empty, so this rule is offered no derivation and is
unaffected by the refusal in `docs/decisions/0091`. It can judge a bundle that was never derived,
which is the second rule to show that the Wave 6 seam costs an attribute-only rule nothing.

**How a value is judged privileged.** `PrivilegedSidHistory.PrivilegedName` answers it, and the rule
and the reader both ask it, so stored evidence and live judgement cannot disagree. A built-in SID is
matched whole through `WellKnownSidCatalog.FindBySid`; anything else has its last sub-authority read
by `Sid.RelativeIdentifier` and looked up with `WellKnownSidCatalog.FindByRid`. A SID under the
built-in domain is never read the second way, or one number would carry two meanings. The catalogue
is a transcription of MS-DTYP and carries no opinion about privilege; **the privileged subset belongs
to this rule**, because privilege is a judgement and MS-DTYP does not make it.

## 9. When it does not answer

| Case | What happens |
|---|---|
| `sIDHistory` absent | **No finding, and no unread input.** An account with no SID history is the ordinary case and is genuinely clean, not unknown. This is the one place the rule must not name a missing attribute, or every account in the forest would report an unread input. |
| `sIDHistory` present but a value is not a decodable identifier | No verdict for the object, naming `sIDHistory` in `InputsNotCaptured`. It is not skipped, which would silently report the account as fine on the strength of a value nobody could read. |
| `objectSid` absent or undecodable | The finding is still raised if a privileged identifier is present, and the evidence records that the issuing domain could not be compared. The escalation does not stop being true because the account's own identifier was unreadable. |
| No object GUID | No finding. A finding must be attributable to an object or it cannot be acted on. |

The distinction in the first two rows is the one that matters: **absent means clean, unreadable means
unknown**, and the two must never collapse into the same silence (`0002`, `0086`).

## 10. What it rests on

`PrivilegedSidHistoryEvidence`, stored in `finding_privileged_sid_history`, holding:

- every value in `sIDHistory`, in written form — **including the ones not ranked**, per [§6](#6-what-is-not-reported-and-why)
- which of them matched, and the relative identifier and Microsoft name of each match
- the account's own `objectSid`, so a reader can see the match came from a different domain

The count of unranked values is derived from the list rather than stored beside it, so there is no
second copy to disagree with the first — the same reasoning as `KerberosPreauthenticationEvidence`
and its `IsDisabled`.

## 11. Tests

`PrivilegedSidHistoryTests`. The negative controls carry the weight, and there are four kinds:

- **an account with no `sIDHistory` at all** — the overwhelming majority of a real forest
- **an account whose SID history is a non-privileged identifier** (an ordinary RID such as `1157`,
  and `513` Domain Users) — the case §6 says is not reported, pinned so that widening the rule
  cannot happen silently
- **an account whose `objectSid` is privileged but whose SID history is not** — a Domain Admin is
  not a finding, and reading the wrong attribute would make it one
- **the identifiers either side of each accepted one** (`511`/`513` around 512, `517`/`520` around
  518 and 519, `547`/`553` around the operator block) — which is what catches a mistyped constant

To be reported as required: the rule mutated in **both** directions — a privileged identifier removed
from the accepted set, and a non-privileged one added — with the tests observed failing and what they
said recorded here, as `SEC-022` §11 does.

**Observed failing on 2026-09-02.** Three mutations, all caught:

| Mutation | What failed | What it said |
|---|---|---|
| `519` (Enterprise Admins) replaced with `513` (Domain Users) — both directions at once | 4 of 43 | `AnAccountCarryingEnterpriseAdminsFromAnotherDomainIsReported` and `EveryAcceptedIdentifierIsReported(519)` for the removal; `AnAccountCarryingAnOrdinaryIdentifierIsNotReported(513)` and `AnIdentifierBesideAnAcceptedOneIsNotReported(513)` for the addition, each naming the finding that should not exist |
| The unreadable-value guard forced to never fire | 1 of 43 | `AnUnreadableSidHistoryValueIsNotSilentlySkipped` — the verdict came back complete when a value had not been read. `AnAccountWithNoSidHistoryIsCleanRatherThanUnreadable` correctly kept passing, which is what proves the two cases are distinguished rather than both merely tolerated |
| The built-in groups listed as relative identifiers rather than whole SIDs | 6 of 38, on the first run before the defect was found | `EveryPrivilegedIdentifierIsOneMicrosoftDocuments` naming 544, plus the five `EveryAcceptedIdentifierIsReported` cases. **This one was not a deliberate mutation** — it was the real state of the code, and §5 records what it would have done to a customer |

**The third row is the reason this rule has an anchor test at all.** Every positive test passed while
the rule was wrong, because the rule and the tests shared the mistake. Only the check that goes
outside this repository — to Microsoft's catalogue — disagreed.

**The stored evidence is proven through the grid's own paging path, not only through the rule.**
`FindingsPagingTests.APageCarriesTheEvidenceOfEveryKindOfFinding` now writes a `SEC-027` finding
beside the other two kinds and reads it back. That test exists because of `P-112`, where every paging
test wrote one evidence kind and a defect in the others went unseen; adding a third kind without
adding it there would have repeated exactly that.

**It is the first evidence kind stored across two tables**, so the fixture deliberately carries a
match, an unranked value and an unreadable count. Mutation observed on 2026-09-02: the child-row
reader was changed to keep only the first value, and the test failed naming the value that had gone —
`Expected: ["…-519", "…-1157"], Actual: ["…-519"]`. Without the second value in the fixture the
mutation would have passed.

## 12. Verifying it against `ad.lab`

**Run 2026-09-02, negative half only. The rule reported nothing, and reporting nothing was correct.**

| Question | How it was answered | Answer |
|---|---|---|
| Was the rule scheduled and did it complete? | `rule_execution` in the judgement store | `Succeeded`, **4,239** objects judged, 0 not judged |
| Does the forest hold anything to find? | `list-sid-history.ps1`, reading sealed evidence directly | **0 objects carry any SID history at all** |

**The object count is itself a check.** `SEC-027` judged 4,239 objects where the account-only rules
judged 2,085. The difference is the groups, which is what `SubjectClasses: [user, computer, group]`
should produce — a rule silently judging only users would have shown 2,085 here.

**Still unproven, stated plainly.** `list-sid-history.ps1 -All` returned zero as well, because the
forest holds no SID history whatsoever — so its zero is consistent with a clean forest **and** with a
script that cannot read the table, which is the exact ambiguity the script's own header says it
exists to remove. `count-uac-flag.ps1` does not have this problem: it was seen returning seven rows
for `0x20` in the same session. **`SEC-027` is therefore the least-verified rule built so far** and
must not be written up as standing where `SEC-021`, `SEC-028`, `SEC-029` and `SEC-033` now stand.

A constraint found while writing the lab scripts changes what can be verified in this forest at all,
and it is stated here rather than discovered later.

### What can be verified, and how

| Step | How | What it proves |
|---|---|---|
| 1. The rule is scheduled and reaches a verdict | `run.log` (*Judge started rules=5*) and `rule_execution` in the judgement store | it ran, rather than being silently absent |
| 2. The forest holds no privileged SID history | `next/tools/list-sid-history.ps1`, reading sealed evidence directly | the silence is the forest's, not the rule's |
| 3. That reading script is not itself broken | the same script with `-All` | a script that reports zero is worthless until seen reporting something |
| 4. A real SID history value is captured and correctly **not** reported | `next/tools/Set-LabSidHistoryAccount.ps1`, then capture and judge again | the strongest negative control available: a real object, in a real directory, genuinely carrying SID history, that the rule correctly stays silent about |

**Step 4 is the one worth dwelling on.** `Set-LabSidHistoryAccount.ps1` does not write `sIDHistory`;
it creates an account in one domain and moves it to another, and the domain controller writes the
attribute. That is the mechanism Microsoft's *Security identifiers* article describes — *"an
administrator for the enterprise can move the employee's User object from… Contoso\NoAm to
Contoso\Europe… the previous value is copied to another property of a User object, SIDHistory."* So
the object is real in the way that matters, and an empty forest is not being used to prove anything
it cannot.

### What cannot be verified in this forest, and why

**A positive case — an account carrying a *privileged* identifier — cannot be planted in `ad.lab`.**
Two Microsoft statements close every route:

- [Using DsAddSidHistory](https://learn.microsoft.com/windows/win32/ad/using-dsaddsidhistory#domain-and-trust-requirements),
  *Domain and Trust Requirements*: **"The source and destination domains must not be in the same
  forest. …This inter-forest constraint ensures that duplicate SIDs, whether appearing as primary
  SIDs or `sIDHistory` values, are not created in the same forest."** `ad.lab` is one forest, so the
  supported API refuses by design.
- [MS02-001](https://learn.microsoft.com/security-updates/securitybulletins/2002/ms02-001#frequently-asked-questions):
  **"There are neither system calls nor LDAP APIs that enable SIDHistory data to be modified."** So
  there is no writing the attribute directly either.

And the cross-domain move in step 4 cannot produce one: the value it creates is the account's own
former identifier, which the RID master allocated sequentially, and a privileged relative identifier
cannot be obtained that way at all.

**What this costs, stated plainly:** the rule will have been observed staying correctly silent on
real data, and observed firing only against bundles. **It will not have been observed firing on a
real directory object.** That is a weaker verification than `SEC-022` received, and it should not be
written up as though it were the same thing.

**The options, for the owner to choose between:**

| Option | What it gets | What it costs |
|---|---|---|
| Accept steps 1–4 and record the gap | a real negative control; the positive proven end to end through a bundle the product itself wrote | the rule is never seen firing on a directory object |
| Stand up a second small forest with an external trust | the genuine article — `DsAddSidHistory` or ADMT can then place a privileged SID | a second forest, a trust, and account-management auditing enabled in both domains |
| Defer the positive case until a customer forest is captured | costs nothing now | the first time it fires for real is in front of a customer |

The reading script follows `next/tools/count-uac-flag.ps1`, which is what separates *the forest is
clean* from *the rule is broken*, and it carries its own control for the same reason. The planting
script follows `next/tools/Set-LabNoPreauthAccount.ps1` and runs under Windows PowerShell 5.1.
