# The captured attribute catalogue

**Code:** `next/src/SecureAD.Kernel/Capture/CapturedAttributeCatalog.cs`, `CapturedAttribute.cs`
**Layer:** Kernel — pure logic, but the ceiling on everything the Audit layer may ask for.

The named list of attributes capture asks a domain controller for, and, for each entry, what reads
it.

---

## The types

<!-- TYPES:BEGIN -->
| Type | What it is |
|---|---|
| `CapturedAttributeCatalog` | The list itself, plus the object classes read, the classes deliberately unread, and the attributes refused with their reasons |
| `CapturedAttribute` | One entry: the attribute's name as the schema spells it, how many values it may hold, how it is stored, and what reads it |
| `AttributeCardinality` | `SingleValued` or `MultiValued` — and `MultiValued` is what makes an attribute range-liable |
| `AttributeStorage` | `Text` or `Binary` — and `Binary` means the value must never be round-tripped through a string |
<!-- TYPES:END -->

Each type carries its own reasoning in its XML documentation. **That is the reference; this page is
the orientation.**

---

## What this is for

Capture asks a domain controller for a named list of attributes. **Whatever is not on that list is
not in the bundle, is in no report, and cannot be added afterwards without capturing the forest
again** — and nobody can go back and re-read last quarter.

So this list is the ceiling on everything the product will ever be able to say about a customer's
directory. It is the one decision in the subsystem that cannot be corrected later.

---

## The rule this exists to enforce

> **Every attribute names something that reads it. An attribute that cannot name a consumer does not
> go in.**

"The previous product had it" is not a consumer. The previous catalogue was hand-enumerated and had
reached version 10, and carrying it across wholesale would have imported every unexamined choice in
it under cover of a rebuild. This is
[`0064`](../decisions/0064-an-attribute-is-justified-by-a-rule-or-the-object-view.md): an attribute
is justified by a rule that reads it, or by a field of the object view it fills, and never
speculatively.

**A consumer is a rule card or an inventory row.** `Read by` cells are checked against both, so a
row that does not exist cannot be named, and a promise that has come due — the named row reaching
`Done` while the attribute still has no code consumer — fails the build.

### The check this rule had, and the anchor it did not

Until 2026-08-13 only an inventory row counted as a consumer. Almost no inventory row was built, so
**the catalogue was bounded by how far the port had got rather than by what the product needs.** Two
shipped rules, SEC-091 and SEC-092, could not be answered at all: a customer with LAPS installed and
silently not rotating for a year would have got a report that said nothing about it. Not *unknown* —
nothing, which is indistinguishable from a clean result.

That is `F-S23-1`, repaired by re-deriving the catalogue against all sixty-two rule cards.

**The deeper fault is `F-S44-2` and it is still open.** Three sound test suites cover this catalogue
— the document matches the code, the code matches the rules, the rules match the document — every
check passing in both directions with negative controls, and **the whole circle anchored to the set
of rules already written.** A rule nobody wrote is an attribute nobody misses. Security descriptor
parsing and the sixty-two rule cards were *ported* and have external anchors; this catalogue was
*reassembled* and has none. Internal-consistency tests cannot supply one however thorough they are.

**Ask what a set of checks is anchored to, not only whether each one is sound.**

---

## Three properties of the catalogue

### One filter, and it excludes rather than includes

The previous product offered two filter modes on the audit wizard as radio buttons. **The rebuild
has one behaviour and no radio button.**

Under the old inclusion list, an object of a class nobody enumerated had **no security descriptor
captured at all**, because one filter was shared between object capture and security-descriptor
capture. A vendor application's objects, a locally defined class, an administrative container from a
product nobody remembers installing — a dangerous delegation on any of those was invisible. That is
also flatly at odds with `0017`, which says capture reads the whole forest.

So the single behaviour is: **every object** in every naming context capture reads, whatever its
class, with identity and its access control list — and **two classes excluded by name**, `dnsNode`
and `dnsZone`, per [`0042`](../decisions/0042-dns-zones-and-records-are-out-of-scope.md).

**An exclusion stated by name is something a report can print. An inclusion list that happens not to
mention DNS is a silence.**

An unknown class gets identity and its access control list and nothing else. That is the right
split: the permissions on an object are what this product assesses, and they are the same shape on
every object regardless of class.

### Range-liable is cardinality, and cardinality is carried

A domain controller returns at most `MaxValRange` values of one attribute on one object. Past that
the remaining values are simply not in the response, with no error.

This is a property of **every** multi-valued attribute, not of `member`. The previous product knew
about `member` and handled it in a separate pass, which is correct for `member` and is exactly the
shape that breaks when the next large multi-valued attribute is added — `msDS-KeyCredentialLink` and
`sIDHistory` are on this list and both can grow. So `CapturedAttributeCatalog.RangeLiable` is
**derived** from the `AttributeCardinality` of every entry rather than listed. A second
hand-maintained list would agree on the day it was written and stop agreeing silently.

### Absence is answered from the forest's own schema, not guessed

Every attribute added here adds a case where absent means either *not set in this forest* or *we
were not permitted to read it*, and
[`0002`](../decisions/0002-absent-view-means-degraded-run.md) requires those to be told apart. That
is real work per attribute rather than a free addition.

It is not work that has to be done by guess. The distinction is a fact about each forest, recorded
in that forest's own schema, and capture already reads the schema partition per
[`0014`](../decisions/0014-capture-reads-the-schema-partition.md) — so `searchFlags` and
`systemFlags` are in the schema set below and the question is answered from the directory.

**The catalogue itself makes no claim about which of its entries could be withheld**, because such a
claim would be a guess dressed as data.

---

## The credential guard

A bundle is sealed, exportable, and forwarded by customers to auditors and insurers. One holding
recovery keys, password hashes or a key distribution root key is not a degraded audit tool; it is a
different and much worse kind of software, and it would be one careless line away.

The risk is not hypothetical and it is not obvious. What puts BitLocker in scope is *who may read a
recovery key* — a permission on the `msFVE-RecoveryInformation` object — and never
`msFVE-RecoveryPassword`, the 48-digit key sitting on the same object one line away. **The reasoning
that puts the object in scope reads, at a glance, like reasoning that puts its attributes in scope.**

So this is a guard rather than a sentence in a document. `CredentialAttributeGuardTests` fails the
build if the catalogue ever names one of thirteen credential-bearing attributes, and separately
asserts that the permissions on such an object **are** still captured — because a guard that could
be satisfied by avoiding the object altogether would quietly undo the decision it exists to protect.

**The forbidden list is deliberately wider than anything anyone has proposed capturing.** A
forbidden name nobody wanted costs nothing; a missing one costs everything.

---

## The catalogue

`Read by` names inventory rows **and rules**. A rule is named as its card identifier — `SEC-091`,
from [`docs/rules/`](../rules/) — and a named rule must be a card that exists.

`Cardinality` is `SingleValued` or `MultiValued`, and `MultiValued` means range-liable. `Storage` is
`Text` or `Binary`, and `Binary` means the value is an octet string that must never be round-tripped
through a string.

This catalogue is **version 3**, and every bundle records it, so a bundle read years later can still
say what it was allowed to see. It started at 1 rather than continuing the previous product's
sequence, which had reached 10: per [`0001`](../decisions/0001-no-backward-compatibility.md) there
is no compatibility to preserve, and a continuing number would imply that a bundle stamped 10 and
one stamped 11 hold comparable evidence.

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

---

## Every attribute, and every rule that consumes it

Re-derived against all sixty-two rule cards rather than against the rebuild's progress. `—` means no
rule among the sixty-two consumes it; the *Consumed by* column then names what does.

**Where this derivation is weak, stated rather than hidden.** The evaluator source for each of the
sixty-two rules was **not** read; the cards were. A card that misdescribes its own evaluator would
carry that error into this table. The cards are verification documents written against the code, so
this is a reasonable basis, but it is second-hand. What was read first-hand is the writer that turns
an attribute into a stored column, which is the half where a silent mismatch would be invisible.

<!-- DERIVATION:BEGIN -->

| Attribute | In catalogue | Rules that consume it | Consumed by, if no rule |
|---|---|---|---|
| distinguishedName | yes | every rule that joins `dim_object`, which is all sixty-two | — |
| objectGUID | yes | all sixty-two, as the join key | — |
| objectClass | yes | SEC-010, SEC-011, SEC-012, SEC-020, SEC-021, SEC-026, SEC-032, SEC-051, SEC-052, SEC-063, SEC-076, SEC-077, SEC-080, SEC-090, SEC-091, SEC-092, SEC-100, SEC-101, SEC-102, SEC-122, SEC-126, SEC-131, SEC-201, SEC-204 | — |
| objectCategory | yes | none directly; it is the single-valued answer `objectClass` cannot give | B20 |
| objectSid | yes | every rule that names a trustee or a member | B12 |
| nTSecurityDescriptor | yes | SEC-001, SEC-002, SEC-003, SEC-004, SEC-005, SEC-006, SEC-014, SEC-024, SEC-025, SEC-031, SEC-040, SEC-060, SEC-063, SEC-080, SEC-081, SEC-090, SEC-120, SEC-121, SEC-123, SEC-124, SEC-201, SEC-204 | — |
| sAMAccountName | yes | none read its value; thirty-three cards print it | B12, E19 |
| userAccountControl | yes | SEC-010, SEC-011, SEC-012, SEC-022, SEC-023, SEC-032, SEC-067, SEC-077, SEC-101, SEC-126, SEC-131 | — |
| adminCount | yes | SEC-030 | — |
| primaryGroupID | yes | none directly; it is an edge of the membership graph every membership rule reads | B11 |
| memberOf | yes | none directly; the reverse edge, carried so a cross-domain gap is seen rather than inferred | B11 |
| member | yes | none directly; the forward edge under SEC-003, SEC-004, SEC-005, SEC-006, SEC-013, SEC-021, SEC-023, SEC-030, SEC-050, SEC-051, SEC-052, SEC-061, SEC-062, SEC-063, SEC-100 | B11 |
| sIDHistory | yes | — | B12, E19 |
| servicePrincipalName | yes | SEC-020, SEC-021, SEC-026, SEC-126 | — |
| msDS-AllowedToDelegateTo | yes | SEC-010, SEC-011, SEC-012 | — |
| msDS-AllowedToActOnBehalfOfOtherIdentity | yes | SEC-010, SEC-011, SEC-013, SEC-122 | — |
| msDS-KeyCredentialLink | yes | — | E19 |
| msDS-SupportedEncryptionTypes | yes | — | E19 |
| pwdLastSet | yes | — | E19 |
| whenCreated | yes (added at S-51) | — | the object view, which asks when anything unexpected came into existence |
| description | yes (added at S-51) | — | the object view; the only field in the directory that says why an object exists |
| userPrincipalName | yes (added at S-51) | — | the object view, which has to name a principal the way an administrator will be given it |
| accountExpires | yes (added at S-51) | — | the object view, for whether the account has a lifetime at all |
| lastLogonTimestamp | yes (added at S-51) | — | the object view, for whether anybody still uses the account. `lastLogon` is refused: it is not replicated |
| msDS-GroupMSAMembership | yes | SEC-102 | — |
| groupType | yes | — | B11, E20 |
| operatingSystem | yes (added here) | SEC-091 | — |
| ms-Mcs-AdmPwdExpirationTime | yes (added here) | SEC-091, SEC-092 | — |
| msLAPS-PasswordExpirationTime | yes (added here) | SEC-091, SEC-092 | — |
| gPLink | yes | — | E21 |
| gPOptions | yes | — | E21 |
| displayName | yes | — | D3, E21 |
| gPCFileSysPath | yes | — | B14 |
| flags | yes | — | E21 |
| versionNumber | yes | — | E21 |
| gPCMachineExtensionNames | yes | — | B14 |
| lDAPDisplayName | yes | — | D3 |
| cn | yes | — | D3 |
| schemaIDGUID | yes | none directly; every rule matching an `object_type_guid` resolves through it | D3, J33 |
| attributeSecurityGUID | yes | none directly; SEC-090, SEC-123 and SEC-124 cannot expand a property set without it | D3 |
| isSingleValued | yes | — | D3 |
| searchFlags | yes | — | D3 |
| systemFlags | yes | — | D3 |
| rightsGuid | yes | none directly; SEC-002 and SEC-040 match extended rights through it | D3, J33 |
| validAccesses | yes | — | D3 |
| appliesTo | yes | — | D3 |

<!-- DERIVATION:END -->

---

## What the union costs, and what the real cost is

**Nothing measurable**, and the reason is worth stating because it is not what anyone expects.

Against a measurement of a production domain of 100,000 objects, where parsed access-control entries
cost **4.81 GB** and deduplicated raw descriptors **0.63 GB**, a forest with fifteen thousand
computers carrying three extra short string attributes adds well under a megabyte. Four orders of
magnitude below the smallest storage choice on the table.

**The general lesson outlives those attributes.** The expensive thing a bundle holds is
`nTSecurityDescriptor`, and it is already captured on every object. An ordinary attribute is
therefore close to free, and **the argument against adding one is not storage.** It is the two real
costs: absence has to be told apart from withholding, and an attribute nobody removes sits in every
bundle forever.

---

## Do not change without reading this

**Do not add an attribute that cannot name a consumer.** And do not accept "the previous product had
it" as one.

**Do not add a credential-bearing attribute.** The guard will stop you. If the guard is what needs
changing, that is a conversation, not a fix.

**Do not turn the class exclusions into an inclusion list.** An unknown class must still yield its
access control list.

**Do not maintain a separate list of range-liable attributes.** It is derived from cardinality for a
reason.

**Do not add `lastLogon` or `whenChanged`.** Both are unreplicated and this product reads one
controller per domain. They are in `NotCaptured` with their reasons precisely because they will be
proposed again.

**Do not bump the catalogue version without changing what a bundle may contain.** The version is how
a bundle read years later says what it was allowed to see.

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.**

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank means
unit-tested but not yet exercised against Active Directory.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain the capture never asks the directory for a credential | `CredentialAttributeGuardTests.TheCatalogueNeverRequestsACredential` |  |
| be certain that guard is checking a real catalogue against a real list, not two empty ones | `CredentialAttributeGuardTests.TheGuardHasBothACatalogueAndAListToCheckItAgainst` |  |
| have the permissions **on** a credential object captured, while its secret is not | `CredentialAttributeGuardTests.ThePermissionsOnACredentialObjectAreStillCaptured` |  |
| have LAPS reported by when it last rotated, never by the password itself | `CredentialAttributeGuardTests.TheCatalogueTakesTheLapsTimestampAndNotTheLapsPassword` |  |
| be certain no attribute is asked for two different ways | `CapturedAttributeCatalogTests.NoAttributeIsDeclaredTwoDifferentWays` |  |
| be certain DNS is the only thing deliberately left out of the catalogue | `CapturedAttributeCatalogTests.TheDnsClassesAreTheOnlyOnesExcluded` |  |
| rely on every attribute the code requests appearing here with a consumer named | `CapturedAttributeCatalogDocumentationTests.TheDocumentDescribesEveryAttributeTheCatalogueRequests` |  |
| be certain this document names no attribute the code does not request | `CapturedAttributeCatalogDocumentationTests.TheDocumentDescribesNoAttributeTheCatalogueDoesNotRequest` |  |
| read which object classes are captured and which are deliberately not | `CapturedAttributeCatalogDocumentationTests.TheDocumentNamesTheObjectClassesAndTheExclusions` |  |
| be certain every part of the capture subsystem is described somewhere a reader will find it | `CapturedAttributeCatalogDocumentationTests.EveryPublicTypeInTheCaptureProjectIsNamedByACaptureDocument` |  |
| be certain the derivation and the catalogue name the same attributes | `CapturedAttributeDerivationDocumentationTests` |  |
