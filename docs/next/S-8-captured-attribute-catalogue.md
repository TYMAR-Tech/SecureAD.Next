# S-8 — The captured attribute catalogue

**Type:** slice
**Inventory row:** B2 — Captured attribute catalogue
**Lands in:** `SecureAD.Audit`
**Date:** 2026-08-11

---

## What this is, in one paragraph

Capture asks a domain controller for a named list of attributes. Whatever is not on that list is
not in the bundle, is in no report, and cannot be added afterwards without capturing the forest
again — and nobody can go back and re-read last quarter. So this list is the ceiling on everything
the product will ever be able to say about a customer's directory. This document is the list, and
for each entry, what reads it.

The code is [`CapturedAttributeCatalog`](../../next/src/SecureAD.Kernel/Capture/CapturedAttributeCatalog.cs)
in the namespace `SecureAD.Audit.Capture`, with `CapturedAttribute`, `AttributeCardinality` and
`AttributeStorage` beside it. `CapturedAttributeCatalogDocumentationTests` holds the two to each
other, so an attribute in the code and not in the table below fails the build, and so does a row
below naming an attribute the code does not request.

## The rule this row exists to enforce

> **Every attribute names something that reads it. An attribute that cannot name a consumer does
> not go in.**

"The previous product had it" is not a consumer. The previous catalogue was hand-enumerated and had
reached version 10, and carrying it across wholesale would have imported every unexamined choice in
it under cover of a rebuild.

The consumer named is an inventory row, because no rule code exists in the rebuild yet. That is the same
device [`SURFACE-REGISTER.md`](SURFACE-REGISTER.md) uses for a type awaiting its first caller, and
it has the same property: a forecast with an owner and a date, rather than a silence. `Read by`
cells are checked against the inventory, so a row that does not exist cannot be named, and a promise
that has come due — the named row reaching `Done` while the attribute still has no code consumer —
fails the build.

## Three decisions this row had to make

Each was created by something settled after B2 was first written. Each is answered here, with what
it costs.

### 1. A failed schema read ends the run

B2's inventory row said a failed schema read **degrades** the run rather than ending it. On 2026-08-11
the owner decided fail-fast: a unit that cannot be captured fully ends the run immediately. B4 then
made the schema partition a capture unit like any other, and gave it its own domain controller so
that a failure names one unit unambiguously. Those two statements cannot both stand.

**Fail-fast holds. A forest whose schema partition cannot be read produces no bundle.**

The reason is what the alternative would produce. Without the schema, every GUID in every access
control entry that is not in the shipped catalogue is unnameable — and by
[`0014`](../decisions/0014-capture-reads-the-schema-partition.md) that is exactly the set that
matters, because a locally created attribute's GUID is generated at creation and exists in that
forest and nowhere else. A run that continued would produce a bundle in which an unknown number of
permissions could not be attributed to what they grant, and per
[`0002`](../decisions/0002-absent-view-means-degraded-run.md) that has to be told apart from "we
looked and it was safe" on every finding that touches one. That is not a degraded run; it is a
bundle that has to caveat itself everywhere, which is the shape of evidence nobody can act on.

The second reason is what a failure actually means. Reading the schema partition needs no privilege
beyond reading the directory, and it is a few thousand objects once per forest. There is no
customer who is *allowed* to run this product and *not* allowed to read their own schema. A failure
here is a connectivity or availability fault, and the honest response to one is to say so and stop,
not to produce evidence and hope.

**What it costs.** A forest where the schema partition is briefly unreachable — one controller
down, one preflight choice unlucky — yields nothing rather than yielding most of an audit. The
mitigation is preflight, which B4 already requires: the controller for the configuration and schema
partitions is chosen and validated as serving them *before* the run starts, so this fails in the
first seconds rather than at hour two. This costs a run, and it never costs a customer a wrong
answer.

*Recorded as F-S7-22 in `S-7`, which is the row that carries the
contradiction.*

### 2. One capture filter, and it excludes rather than includes

The previous product put two filter modes on step 2 of the audit wizard as radio buttons: **Known
Security Classes** and **Comprehensive All Objects**.

**The rebuild has one behaviour and no radio button.**

Neither of the old two survives as written, and it is worth being clear about why the *second* one
is not simply deleted. Its own setting did not survive the settings panel — `CaptureFilterMode` was
destroyed by any Apply, silently, while the product reported success (F-S7-21). So as shipped it was
not a feature. But the *reason* someone built it was sound, and deleting it without replacing that
reason would leave a real hole:
under the inclusion list, an object of a class nobody enumerated has **no security descriptor
captured at all**, because the old code shared one filter between object capture and
security-descriptor capture. A vendor application's objects, a locally defined class, an
administrative container from a product nobody remembers installing — a dangerous delegation on any
of those was invisible, and "Comprehensive All Objects" was the only way to see it.

That hole is also flatly at odds with
`0017`, which says capture reads the whole
forest and scope is applied to reading rather than to evidence.

**What the inclusion list was really keeping out — corrected 2026-08-11.** The first version of this
section said the second filter mode's only observed effect was DNS record objects. That was wrong,
and the owner corrected it from memory before the evidence was found. The product's own
customer-facing readme states the reason: capturing every object *"avoids large volumes of
smart-card, credential, vendor, and system objects that can **triple capture size** without
improving the user and group risk picture"*, and promises the advanced mode as future work. The
objects are named in `DirectoryTreeService`, described there as *"credential/SSO metadata objects
nested under user accounts"* — three classes from one customer's single-sign-on product, and beside
them four that are in no way site-specific: `msDS-Device`, `msFVE-RecoveryInformation`,
`msTPM-InformationObject` and `foreignSecurityPrincipal`. A BitLocker recovery object is a child of
the computer object and a computer accumulates them, so the volume problem is not one customer's.
It is every forest that encrypts its disks. See F-S7-26.

So the single behaviour is:

- **Every object** in every naming context capture reads is captured, whatever its class, with the
  universal attributes — identity, class, security identifier, and the security descriptor.
- **The enumerated classes** get extra attributes on top. That list is still enumerated and still
  versioned; there is no capture-everything of *attributes*.
- **Two classes are excluded by name**: `dnsNode` and `dnsZone`, per the DNS scope decision of
  2026-08-11. An exclusion stated by name is something a report can print. An inclusion list that
  happens not to mention DNS is a silence.

An unknown class therefore gets identity and its access control list, and nothing else. That is the
right split: the permissions on an object are what this product assesses, and they are the same
shape on every object regardless of class. What is lost on an unknown class is the class-specific
detail, and gaining that later is a matter of adding a row to this catalogue.

**What it costs — corrected 2026-08-11.** Every vendor and application object in the forest now
appears in the bundle with its access control list, and so does every credential child object
beneath a user or a computer. The one figure anyone has ever put on that is the readme's *triple
capture size*, which appears exactly once in the whole repository and rests on no measurement
recorded anywhere — so it is a recollection rather than a number, and per
[`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md) it is
treated as one. It also means the product will report delegations on objects a customer does not
recognise, which is a support burden and is the correct behaviour.

**Where this stands.** The owner's decision of 2026-08-11 is to **hold at the behaviour above** —
capture everything but DNS — and to settle the volume question with a production capture rather than
an argument, pulling a sample across with the personal data stripped. If the tripling is real,
high-volume credential child classes join the named exclusions and are printed in the report the way
DNS is; that mechanism already exists and needs no redesign. What does **not** depend on the
measurement is BitLocker: the owner has decided that who may read a recovery key is a question this
product answers, so `msFVE-RecoveryInformation` stays in scope whatever the volume turns out to be.
The measurement, and the one question it has to answer, are recorded as F-S7-26.

*Recorded as F-S7-23 in `S-7`, amended 2026-08-11.*

### 3. The binding is split, because only half of it can be honest yet

B2 owes a test in both directions: an attribute nothing reads fails the build, **and** a rule
needing an uncaptured attribute fails the build.

The second direction cannot be built now. There are no rules in the rebuild. A test that walked an
empty set of rules and reported that none of them needed a missing attribute would pass, forever,
while measuring nothing — which is precisely the failure gate 5 fell into and the first thing
`.github/copilot-instructions.md` § When to stop and raise it names. So it is split the way gate 5 was:

- **B2a — built now.** Every attribute the catalogue requests appears in the table below with a
  non-empty `Read by` naming at least one real inventory row; and no named row has reached `Done`
  while the attribute still has no code consumer. The second half is the decay guard, and it is
  what makes the first half more than paperwork: the promise comes due on a date rather than
  standing forever.
- **B2b — owed, and blocked.** A rule that names an attribute the catalogue does not request fails
  the build. This becomes buildable when there are rules to walk, which is inventory row **E16 — Rule
  catalogue**, with E18 to E22 supplying them.

*Recorded as F-S7-24 in `S-7`, named by inventory row E16.*

## Three properties of the catalogue, not special cases

### Range-liable is cardinality, and cardinality is carried

A domain controller returns at most `MaxValRange` values of one attribute on one object — 1,500 by
default, and capped at 5,000 on Windows Server 2008 and later whatever the LDAP policy says
([LDAP administration limits](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/view-set-ldap-policy-using-ntdsutil),
[the hard-coded maximums](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/domain-controller-returns-500-values-ldap-response)).
Past that the remaining values are simply not in the response. There is no error. A reader that does
not ask for the rest with a range specifier reports a group of nine thousand members as a group of
five thousand, and reports it confidently.

This is a property of **every** multi-valued attribute, not of `member`. The previous product knew
about `member` and handled it in a separate pass, which is correct for `member` and is exactly the
shape that breaks when the next large multi-valued attribute is added — `msDS-KeyCredentialLink` and
`sIDHistory` are on this list and both can grow. So `CapturedAttributeCatalog.RangeLiable` is
**derived** from the cardinality of every entry rather than listed, and B8 reads it instead of
testing an attribute name. A second hand-maintained list would agree on the day it was written and
stop agreeing silently, which is the defect gate 2 exists for.

### Absence is answered from the forest's own schema, not guessed

An attribute marked confidential in the schema is not returned to a caller who lacks
`CONTROL_ACCESS` on it, and it is not returned as an error — it is simply absent, exactly as though
it had never been set
([Mark an attribute as confidential](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential),
[Search-Flags](https://learn.microsoft.com/windows/win32/adschema/a-searchflags) bit 128). So every
attribute added here adds a case where absent means either *not set in this forest* or *we were not
permitted to read it*, and [`0002`](../decisions/0002-absent-view-means-degraded-run.md) requires
those to be told apart. That is real work per attribute rather than a free addition.

It is not, however, work that has to be done by hand or by guess. The distinction is a fact about
each forest, recorded in that forest's own schema. Capture already reads the schema partition per
`0014`, so `searchFlags` and `systemFlags` are added to the schema attribute set below and the
question is answered from the directory rather than from a list. The catalogue makes no claim about
which of its entries could be withheld, because such a claim would be a guess dressed as data — the
very mistake
[`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md) records.

**How the two flags combine — corrected 2026-08-11, settled 2026-08-13.** The first version of this
section said the answer was simply derivable, because bit 128 is *"ignored for base-schema
attributes"*, which are the ones carrying `systemFlags` `0x10`. That was then challenged, because
Microsoft ships `msFVE-RecoveryPassword` — the BitLocker recovery key — with `systemFlags` `0x10`
**and** a `searchFlags` of `0x298`, which has bit 128 set
([ms-FVE-RecoveryPassword](https://learn.microsoft.com/windows/win32/adschema/a-msfve-recoverypassword)),
and a published attribute carrying both at once looked like a counter-example.

**It is not one.** *Ignored* is not *absent*: the bit may be stored on a base-schema attribute and
simply has no effect, which is precisely what `msFVE-RecoveryPassword` shows. The two articles agree,
and the rule is one line — **an attribute is effectively confidential when `(searchFlags & 128) != 0`
and `(systemFlags & 0x10) == 0`**. `F-S7-27` was opened on the misreading and is now resolved.

What this row commits to is unchanged by that, and deliberately: **capture records both flags, and
how they are interpreted is decided where absence is interpreted.** The rule above says whether an
attribute *can* be withheld. Whether it *was* is a second question with a second cause — a Windows
Server 2025 controller withholds confidential attributes from an unencrypted connection without
saying so — and that belongs to D3 with the flags, as `F-S24-1`.

Inventory row B8 built the part that can be built without an answer: an attribute that did not come
back is reported as its own state and never as an attribute with no values, so nothing downstream
can read one as the other. Deciding what that state *means* in a given forest needs the schema facts
materialised, which is inventory row D3, and the finding moved there rather than being closed.

### The product never captures a credential

The catalogue reads **permissions on** credential material. It never reads the credential.

This stopped being obvious on 2026-08-11, when the owner decided that who may read a BitLocker
recovery key is a question the product should answer. That answer comes from the access control list
on the `msFVE-RecoveryInformation` object — which is a child of the computer object — and never from
`msFVE-RecoveryPassword`, the 48-digit key sitting on the same object one line away. The reasoning
that puts the object in scope reads, at a glance, like reasoning that puts its attributes in scope.

A bundle is sealed, exportable, and forwarded by customers to auditors and insurers. One holding
recovery keys, password hashes or a key distribution root key is not a degraded audit tool; it is a
different and much worse kind of software, and it would be one careless line away. So this is a
guard rather than a sentence in a document. `CredentialAttributeGuardTests` fails the build if the
catalogue ever names one of thirteen credential-bearing attributes, and separately asserts that the
permissions on such an object **are** still captured — because a guard that could be satisfied by
avoiding the object altogether would quietly undo the decision it exists to protect.

The forbidden list is deliberately wider than anything anyone has proposed capturing. A forbidden
name nobody wanted costs nothing; a missing one costs everything.

## The catalogue

`Read by` names inventory rows **and rules**. A rule is named as its card identifier — `SEC-091`, from
`docs/rules/` — and `CapturedAttributeCatalogDocumentationTests` requires a named rule to be a card
that exists, exactly as it requires a named row to be a real inventory row. **Changed 2026-08-13, at
[`S-23`](S-23-what-capture-must-read.md)**, which re-derived this catalogue against all sixty-two
rule cards; until then only an inventory row counted, which bounded the catalogue by how far the port
had got rather than by what the product needs.

`Cardinality` is `SingleValued` or `MultiValued`, and `MultiValued`
means range-liable. `Storage` is `Text` or `Binary`, and `Binary` means the value is an octet string
that must never be round-tripped through a string.

This catalogue is **version 3**, and every bundle records it, so a bundle read years later can still
say what it was allowed to see. It started at 1 rather than continuing the previous product's
sequence, which had reached 10: per [`0001`](../decisions/0001-no-backward-compatibility.md) there
is no compatibility to preserve, and a continuing number would imply that a bundle stamped 10 and a
bundle stamped 11 hold comparable evidence. They do not. Version 2 is S-23's three computer
attributes. Version 3 is S-51's five: `whenCreated` and `description` on every object, and
`userPrincipalName`, `accountExpires` and `lastLogonTimestamp` on accounts — the difference between
an object view that lists permissions and one that can say who a principal is and whether anybody
still uses it.

**Two attributes were refused at version 3, on one rule.** `lastLogon` and `whenChanged` are both
documented by Microsoft as not replicated, so each controller holds its own value. This product
reads one controller per domain, so either would present one controller's view as a fact about the
domain — and a stale-account finding built on `lastLogon` would be wrong in a way nothing on screen
could reveal, because the account logging on daily to a different controller looks dormant. The
refusals are held in `CapturedAttributeCatalog.NotCaptured` with their reasons, because a refusal
that is not written down is indistinguishable from an oversight and both of these will be proposed
again.

<!-- CATALOGUE:BEGIN -->

### Universal — every object, every class

| Attribute | Cardinality | Storage | Read by | Why |
|---|---|---|---|---|
| distinguishedName | SingleValued | Text | B11, B20 | The object's place in the directory. Every report that says where something is, and every member reference that has to be attributed to a domain, resolves through it |
| objectGUID | SingleValued | Binary | B20 | The only identifier that survives a rename or a move. Access control entries are stored against it, so a comparison between two runs is not confused by an object having been moved |
| objectClass | MultiValued | Text | B20 | What an object is, as the whole chain of classes it derives from — which is why `objectCategory` is carried beside it. It once also forecast B6, on the expectation that the class would choose which extra attributes were requested; B6 requests the whole catalogue on every object instead, so nothing chooses at request time and the reader is the writer |
| objectCategory | SingleValued | Text | B20 | The single-valued, indexed answer to what an object *is*. `objectClass` cannot give a straight answer to that because it holds every class the object derives from |
| objectSid | SingleValued | Binary | B12 | Turns the trustee of a permission into a principal that can be named. Without it a dangerous permission is attributed to a number |
| nTSecurityDescriptor | SingleValued | Binary | B20, J33, SEC-001, SEC-002, SEC-003, SEC-004, SEC-005, SEC-006, SEC-014, SEC-024, SEC-025, SEC-031, SEC-040, SEC-060, SEC-063, SEC-080, SEC-081, SEC-090, SEC-120, SEC-121, SEC-123, SEC-124, SEC-201, SEC-204 | The permissions themselves. This is the product's subject, and the twenty-two rules named are the ones with nothing to say without it. Requested with owner, group and DACL only and no SACL, so capture needs no `SeSecurityPrivilege` and runs as an ordinary authenticated user |
| whenCreated | SingleValued | Text | J34 | When the object came into existence, which is the first question asked of anything unexpected — an account created last Tuesday holding Full Control is a different finding from one that has held it since 2009. Replicated and in the global catalogue, so one controller's answer is the domain's. Its counterpart `whenChanged` is **refused**: Microsoft documents it as not replicated, and this product reads one controller per domain |
| description | MultiValued | Text | J34 | What an administrator wrote about the object, and the only field in the directory that says *why* something exists. Multi-valued in the schema, which most tooling gets wrong by showing the first value only |

### Accounts — `user`, `inetOrgPerson`, `computer`, `msDS-ManagedServiceAccount`, `msDS-GroupManagedServiceAccount`

One set, because these are one kind of thing: something that holds credentials and can act. The
previous product kept four near-identical lists for them and they had drifted apart.

| Attribute | Cardinality | Storage | Read by | Why |
|---|---|---|---|---|
| sAMAccountName | SingleValued | Text | B12, E19 | The name an administrator recognises an account by, and the one a finding has to print for the account to be findable |
| userAccountControl | SingleValued | Text | E19, J33, SEC-010, SEC-011, SEC-012, SEC-022, SEC-023, SEC-032, SEC-067, SEC-077, SEC-101, SEC-126, SEC-131 | Holds whether the account is disabled, whether pre-authentication is off, and whether the account is trusted for delegation. Eleven rules read a flag out of it, which makes it the most consumed attribute after the security descriptor. On K16's list of attributes whose write is dangerous |
| adminCount | SingleValued | Text | E19, SEC-030 | Marks an account that AdminSDHolder protects, or protected once. A set `adminCount` on an account no longer in a privileged group is the residue of past privilege |
| primaryGroupID | SingleValued | Text | B11 | Primary group membership is not in the group's `member` attribute. A membership graph without it is missing edges, and the missing ones are Domain Users and Domain Computers |
| memberOf | MultiValued | Text | B11 | The reverse of `member`. Carried because the forward direction can cross into a domain captured later or not at all, and the two together are how that gap is seen rather than inferred |
| sIDHistory | MultiValued | Binary | B12, E19 | An account carrying another principal's identifier holds that principal's access. It is a documented migration mechanism and a documented escalation route. **No rule among the sixty-two reads it** — S-23, `F-S23-4` |
| servicePrincipalName | MultiValued | Text | E19, SEC-020, SEC-021, SEC-026, SEC-126 | An account with a service principal name can have a service ticket requested for it by anyone, and the ticket is encrypted with the account's key |
| msDS-AllowedToDelegateTo | MultiValued | Text | E19, SEC-010, SEC-011, SEC-012 | Constrained delegation. Names the services this account may impersonate a user to |
| msDS-AllowedToActOnBehalfOfOtherIdentity | SingleValued | Binary | B20, E19, SEC-010, SEC-011, SEC-013, SEC-122 | Resource-based constrained delegation, in the other direction: a security descriptor naming who may impersonate users to *this* account. Write access to it is a takeover of the machine |
| msDS-KeyCredentialLink | MultiValued | Text | E19 | The public keys that can authenticate as this account. Write access to it is authentication as the account without touching its password. **No rule among the sixty-two reads it** — S-23, `F-S23-4`, and that is a gap in the rule catalogue rather than in capture |
| msDS-SupportedEncryptionTypes | SingleValued | Text | E19 | Whether the account still accepts weak Kerberos encryption, which decides whether a requested ticket is worth cracking. **No rule among the sixty-two reads it** — S-23, `F-S23-4` |
| pwdLastSet | SingleValued | Text | E19 | A service account whose password has not changed in years is the account whose key an old captured ticket still opens. **No rule among the sixty-two reads it** — S-23, `F-S23-4` |
| userPrincipalName | SingleValued | Text | J34 | The name an account signs in with, which is frequently not its `sAMAccountName` and is what an administrator will be given when asked to identify a principal |
| accountExpires | SingleValued | Text | J34 | Whether the account has a lifetime at all. An expired account cannot be used and a never-expiring contractor account is the one nobody revoked. Two stored values mean *never* — `0` and `9223372036854775807` — and Microsoft's own page explains why: the maximum on an account never configured to expire, zero on one whose expiry was removed |
| lastLogonTimestamp | SingleValued | Text | J34 | Whether anybody still uses the account. Replicated, unlike `lastLogon`, which is why this is the one captured — but **deliberately coarse**: a controller only updates it when its own value is older than `msDS-LogonTimeSyncInterval`, which defaults to between 9 and 14 days. Anything worded from it says so on the row |

`computer` adds the three that decide whether its local administrator password is managed:

| Attribute | Cardinality | Storage | Read by | Why |
|---|---|---|---|---|
| operatingSystem | SingleValued | Text | SEC-091 | Which LAPS product a machine *should* have. SEC-091 requires Windows LAPS on Server 2019 and later and legacy LAPS on Server 2016, so without this the rule cannot tell a correctly managed machine from an unmanaged one |
| ms-Mcs-AdmPwdExpirationTime | SingleValued | Text | SEC-091, SEC-092 | Legacy LAPS. Its presence is how SEC-091 knows LAPS is deployed, and its value is how SEC-092 knows the password has stopped rotating. Never the password itself, which `CredentialAttributeGuardTests` forbids |
| msLAPS-PasswordExpirationTime | SingleValued | Text | SEC-091, SEC-092 | Windows LAPS, the same two questions. Both are schema extensions rather than base-schema attributes, so either can be marked confidential and withheld — which is why `searchFlags` is read per forest rather than the absence being guessed |

`msDS-GroupManagedServiceAccount` adds one more:

| Attribute | Cardinality | Storage | Read by | Why |
|---|---|---|---|---|
| msDS-GroupMSAMembership | SingleValued | Binary | B20, E19, SEC-102 | A security descriptor naming who may retrieve the account's managed password. It is the account's password, expressed as a permission, and no other account class has one |

### `group`

| Attribute | Cardinality | Storage | Read by | Why |
|---|---|---|---|---|
| sAMAccountName | SingleValued | Text | B12, E19 | As above |
| groupType | SingleValued | Text | B11, E20 | Security or distribution, and the scope. A distribution group grants nothing, and reporting one as though it did is a false finding. **No rule among the sixty-two reads it** — S-23, `F-S23-4` |
| adminCount | SingleValued | Text | E19 | As above |
| member | MultiValued | Text | B11 | Membership. The attribute that motivates range retrieval, and the one where getting it wrong understates a group rather than failing |
| memberOf | MultiValued | Text | B11 | Nested membership upward |
| sIDHistory | MultiValued | Binary | B12, E19 | As above. A group can carry it too |

### `organizationalUnit`

| Attribute | Cardinality | Storage | Read by | Why |
|---|---|---|---|---|
| gPLink | SingleValued | Text | E21 | Which Group Policy objects apply here. A dangerous permission on a policy is only dangerous over the objects the policy reaches |
| gPOptions | SingleValued | Text | E21 | Whether inheritance is blocked, which changes which policies reach the objects below |

### `groupPolicyContainer`

| Attribute | Cardinality | Storage | Read by | Why |
|---|---|---|---|---|
| displayName | SingleValued | Text | E21 | The name an administrator knows the policy by. Its distinguished name is a GUID and is unusable in a report |
| gPCFileSysPath | SingleValued | Text | B20, SEC-064, SEC-065, SEC-066, SEC-082, SEC-083, SEC-093 | Where the policy's files live. `GpoInventory` turns it into the target the SYSVOL read starts from, and the six rules named have nothing to say without those files. A policy returned without one cannot be read at all, and is recorded as unlocatable rather than dropped from the count of what should have been read ([`0044`](../decisions/0044-sysvol-coverage-is-recorded-beside-the-capture-units.md)) |
| flags | SingleValued | Text | E21 | Whether the computer or user half of the policy is disabled, so a setting that is present but never applied is not reported as applied |
| versionNumber | SingleValued | Text | E21 | Whether the directory half and the SYSVOL half of the policy agree. They can disagree, and when they do the policy's effect is not what either half says |
| gPCMachineExtensionNames | MultiValued | Text | B20, SEC-083 | Which kinds of setting the policy declares it contains, read by `GpoClientSideExtensions.ParseCseGuids`. The SYSVOL read does not narrow by it: what a workstation applies is the files on the share, so `S-33` lists those instead. Kept because a policy whose declared extensions and actual files disagree is worth being able to ask about |

### Schema partition — `attributeSchema` and `classSchema` objects

Read once per forest, on every capture, per
[`0014`](../decisions/0014-capture-reads-the-schema-partition.md). A few thousand objects, needing
no privilege beyond reading the directory.

| Attribute | Cardinality | Storage | Read by | Why |
|---|---|---|---|---|
| lDAPDisplayName | SingleValued | Text | D3 | The name of the attribute or class, as everything else in the directory spells it |
| cn | SingleValued | Text | D3 | The other name the same object carries. Kept because the two differ and a reader will meet both |
| schemaIDGUID | SingleValued | Binary | D3, J33 | What an access control entry actually names. A locally created attribute's value is generated at creation and exists in that forest alone, which is the whole reason this partition is read |
| attributeSecurityGUID | SingleValued | Binary | D3 | The join that expands a property-set permission into the attributes it really grants. A property set names no attributes; each attribute points back at the set through this. It is an octet string, and `rightsGuid` on the other side of the join is a 36-character string — the same GUID in two representations, which never match compared as they arrive |
| isSingleValued | SingleValued | Text | D3 | The forest's own answer to the cardinality this catalogue declares. A disagreement is a finding, on the same terms `0014` sets for a `schemaIDGUID` that disagrees with the shipped value: it is either a defect in the reader or something wrong in the forest, and neither is resolved by picking a winner |
| searchFlags | SingleValued | Text | D3 | Bit 128 marks the attribute confidential, which is what makes an absent value possibly a withheld value rather than an unset one |
| systemFlags | SingleValued | Text | D3 | Bit `0x10` marks a base-schema attribute, and bit 128 of `searchFlags` has no effect on one — so the pair decides whether an attribute can be marked confidential at all. Captured because any rule about which attributes can be withheld needs both halves; the combining rule was settled at S-24 when `F-S7-27` was resolved, and applying it is owed to the row that materialises these facts rather than assumed here |

### Extended-rights container — `controlAccessRight` objects

Read once per forest, on every capture, per `0014`. One container read resolves three of the five
things a GUID in an access control entry can mean, so this is not a feature about extended rights:
property sets and validated writes are stored here too, which Microsoft states outright
([Control Access Rights](https://learn.microsoft.com/windows/win32/ad/control-access-rights)).

| Attribute | Cardinality | Storage | Read by | Why |
|---|---|---|---|---|
| cn | SingleValued | Text | D3 | One of the entry's two names — `User-Force-Change-Password` |
| displayName | SingleValued | Text | D3 | The other, and the one an administrator recognises — `Reset Password`. `0014` asks for the friendly one. Both are display text; matching is on the GUID, which is F-S7-5 |
| rightsGuid | SingleValued | Text | D3, J33 | The GUID an access control entry carries. A 36-character string, not an octet string |
| validAccesses | SingleValued | Text | D3 | Which of the three this entry is: 256 an extended right, 48 a property set, 8 a validated write. Without it the three are indistinguishable and a property-set permission cannot be expanded |
| appliesTo | MultiValued | Text | D3 | The classes the right is defined for, as schema GUIDs. What stops a right being reported against an object it cannot apply to |

<!-- CATALOGUE:END -->

## Considered and not carried

Each of these was in the previous product's catalogue. None could name a consumer. They are listed
rather than dropped in silence, because dropping one is not free: a bundle captured without it
cannot gain it, so this is the list an owner reads to say "no, keep that one" while it is still a
one-line change.

**Re-checked 2026-08-13 at [`S-23`](S-23-what-capture-must-read.md)**, against all sixty-two rule
cards rather than against the inventory rows that existed. That is the check this list had never had:
until then "no consumer" meant "no consumer among the handful of rebuild components that are
built", which is a much weaker statement than it reads as. Three entries did not survive it and are
struck through below. The rest did, and the owner confirmed the `whenCreated`/`whenChanged` drop on
the same day.

| Attribute | Why not | What adding it later costs |
|---|---|---|
| `name` | It is the first component of `distinguishedName`, which is already carried, and `DnHelper` extracts it | Nothing. It is derived, not captured |
| `userPrincipalName` | `sAMAccountName` is the identifier findings print. No decided row reads a second one | A full recapture of every account |
| `whenCreated`, `whenChanged` | No decided row reads either. The obvious uses — how old a delegation is, whether an account is new — belong to rules that do not exist. **S-23 confirmed this against all sixty-two cards: none reads either**, and the owner confirmed the drop on 2026-08-13. It is no longer "the drop most likely to be wrong" | A full recapture |
| `isDeleted` | Deleted objects live in a container that needs a control this capture does not send, so the attribute would be present and always false | Nothing changes here; it is a capture-scope question, not a catalogue one |
| `description` | A free-text field. It is not evidence, and it is where customers put things they should not | A full recapture |
| `lastLogonTimestamp`, `accountExpires` | Staleness rules, which do not exist | A full recapture |
| `operatingSystemVersion`, `dNSHostName` | Inventory rather than delegation. `operatingSystem` **was in this row and has been carried since 2026-08-13**: S-23 found that SEC-091 decides which LAPS product a machine should have from it, so "inventory" was wrong about that one | A recapture of every computer |
| `managedBy` | A pointer to a stated owner. The permission that *actually* lets someone change a group is in the access control list, which is captured. This attribute would be a second, weaker answer to the same question | A recapture of the groups |
| ~~`ms-Mcs-AdmPwdExpirationTime`, `msLAPS-PasswordExpirationTime`~~ **Overturned 2026-08-13, and this is the entry to read if you read only one.** The reason given was that these say only that LAPS is in use, and that the real risk is who may read the password, which is a permission and is already captured. Both halves are true and the conclusion did not follow: SEC-091 and SEC-092 do not ask who may read the password. They ask whether LAPS is deployed at all, and whether it has stopped rotating. Neither question has any other source, so without these two both rules report a clean forest whatever the forest looks like. Carried since S-23, timestamps only; the password attributes beside them stay forbidden. The confidential-attribute point stands and is now real work, answered per forest from `searchFlags` | Nothing now. It would have been a recapture of every computer |
| `msDS-ManagedPasswordInterval`, `msDS-ManagedPasswordId`, `msDS-HostServiceAccountBL` | Operational detail of a managed service account. The security question is who may retrieve the password, which is `msDS-GroupMSAMembership`, and that is carried | A recapture of the service accounts |
| The password-policy sets — `minPwdLength`, `maxPwdAge`, `pwdProperties`, `lockout*`, and the eleven `msDS-Password*` and `msDS-Lockout*` attributes on `msDS-PasswordSettings` | No decided row reads them; inventory row B13 is undecided and may not survive. Fine-grained password policy is a different product question from delegation | **Cheap, unusually.** These live on the domain object and on a handful of policy objects — tens of objects, not millions — so adding them later is a small additional pass rather than a forest recapture. That asymmetry is why they are the safest of these to leave out |
| Display specifiers | `0014` notes that friendly attribute labels come from the display-specifier containers, which is a third container this row does not read. Owed to D3 rather than dropped | A read of one more container in the configuration partition, on a later capture |

## The binding was mutation-tested in both directions

A guard is not shown to work by passing. Each check below was made to fail deliberately, the
mutation was confirmed to have reached the file before the result was believed, and every mutation
was reverted. Mutations 1 to 9 were run on 2026-08-11 when the row was built; 10 to 12 the same day,
when the credential guard was added.

| # | Mutation | Expected | Observed |
|---|---|---|---|
| 1 | The `member` row deleted from the document | The code-to-document direction fires | `TheDocumentDescribesEveryAttributeTheCatalogueRequests` fired, and the scanner self-test fired with it |
| 2 | A `whenCreated` row added to the document | The document-to-code direction fires | `TheDocumentDescribesNoAttributeTheCatalogueDoesNotRequest` fired |
| 3 | The `Read by` cell on `member` emptied | The rule this row exists for fires | `EveryAttributeNamesSomethingThatReadsIt` fired |
| 4 | `member` pointed at inventory row `Z99` | A forecast pointing at nothing fires | `EveryReaderNamedIsARealLedgerRow` fired |
| 5 | `member` pointed at B2, which is now `Done` | The decay guard fires | `NoAttributeStillWaitsForALedgerRowThatIsFinished` fired |
| 6 | `member` described as `SingleValued` in the document | The agreement check fires | `TheDocumentAgreesWithTheCodeOnCardinalityAndStorage` fired |
| 7 | `member` made `SingleValued` in the **code** | The same check fires from the other side, and range retrieval loses it | `TheDocumentAgreesWithTheCodeOnCardinalityAndStorage` and `TheKnownLargeAttributesAreRangeLiable` both fired |
| 8 | The table's `BEGIN` marker renamed | The parse refuses rather than silently reading nothing | All seven checks fired, including `TheCheckReadsBothTheCatalogueAndTheDocument` |
| 9 | A `LoadFromSchemaPartition` member added to the catalogue | Gate 4's exemption comes due | `TheCatalogueExemptionsHaveNotComeDue` fired |
| 10 | `msFVE-RecoveryPassword` added to the universal attribute set | The credential guard fires | `TheCatalogueNeverRequestsACredential` fired |
| 11 | The forbidden list emptied | The guard's self-test fires, rather than reporting a clean surface | `TheGuardHasBothACatalogueAndAListToCheckItAgainst` fired, and all four of `TheGuardStillForbidsTheOnesItWasWrittenFor` fired with it |
| 12 | `nTSecurityDescriptor` removed from the universal set | The other half of the BitLocker decision fires — a guard satisfiable by not capturing the object at all is not a guard | `ThePermissionsOnACredentialObjectAreStillCaptured` and `AnUnknownClassStillGetsItsSecurityDescriptor` both fired |

Mutation 8 is the one that matters most, and it is why the markers exist. The document holds a
second table — the twelve attributes deliberately not carried — and a parser that read every table
in the file would have treated those twelve as requested attributes. A parser that lost its markers
and read nothing would have been worse: every check would have passed against an empty set.

**One thing went wrong doing this, and it is worth recording.** The first run of the mutation script
aborted part-way through, leaving mutation 2 applied and unreverted; the second run then took the
mutated file as its baseline and left two phantom rows behind. It was caught by the guard itself
rather than by the person running it — which is the argument for the guard, and also the reason
`git diff --numstat` is not sufficient to check a scripted edit: these files were new and untracked,
so `numstat` reported nothing at all.

## What this document cannot tell you

It can be held to the code, and it is. It cannot tell you whether the reason given in a `Why` cell
is a good reason, whether an attribute that names a consumer is genuinely needed by it, or whether
one of the twelve entries above was dropped in error. Those need a reader who knows what an audit of
Active Directory is for. The test catches drift and omission; it does not catch bad judgement.
