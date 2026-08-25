# The judgement half — how findings are produced

> **This is discussion, not a decision.** Nothing here states the product's position. Only a record
> in `docs/decisions/` with `Status: Accepted`, or a finding carrying an explicit `Decision:` line,
> does that. Read this as an argument for a design, written 2026-08-25 from a full read of the
> predecessor at `C:\Users\jistrand\source\repos\razamus\SecureAD\src`.
>
> **It is an input, not a fixture.** It is consumed and deleted as it is built, the same discipline
> `docs/areas/` is under. A section that has become code belongs in that code's layer document, and
> the section goes. A pass that leaves this file the same length has not built anything.

## What exists today

Capture works. A run connects to a forest, reads every partition, reads Group Policy files from
SYSVOL, and seals a bundle. The shell exists and can start a run.

The judgement half is two rules — `UnconstrainedDelegationOnAccount` (SEC-010) and
`UnconstrainedDelegationOnNonDomainController` (SEC-011) — and **nothing constructs either of
them.** Searched across `next/src` on 2026-08-25: no caller of `IRule.Judge`, no caller of
`BundleWriter.WriteFinding`, no caller of `BundleReader.ReadFindings` outside the test project. A
run today captures a forest and produces zero findings, because no code asks a rule anything.

## The problem with the current shape

`IRule.Judge(EvidenceObject subject)` takes **one object and nothing else**, deliberately, and says
so in its own remarks: a rule "cannot quietly acquire a dependency it never declared", and anything
resting on group membership "needs a wider shape and a decision to go with it".

That decision is this document, and the answer is that the shape does not fit the product.

The predecessor's `IRuleEvaluator.Evaluate` receives a **`SqliteConnection`** — the whole database.
Every one of its 62 rules is a set query. "Find every account where…" is a question about a table,
not a predicate on one object. SEC-010 and SEC-011 fit the per-object shape only because
unconstrained delegation genuinely is one flag on one object; they are the exception.

An earlier reading of this repository counted "10 of 61 rules fit per-object" from the
predecessor's coverage map. **That count was wrong** and is recorded here so it is not repeated: the
coverage map records which *tables* a rule read, not whether it examined one object at a time.

**`IRule` has two consumers. Replacing it now is the cheapest it will ever be.**

## The stages

Three stages over one bundle, in order. This is the predecessor's shape and it is sound; what
changes in the rebuild is honesty about gaps, not the sequence.

```
CAPTURE            DERIVE                              JUDGE
(built)            (not built)                         (2 rules, unreachable)

objects       ->   effective group membership     ->   rules query derived facts
permissions   ->   control edges                  ->   findings written to bundle
SYSVOL        ->   tier classification
                   escalation paths (scope open)
```

**Capture and judgement stay separate acts.** `StoredFindings.DidNotRun` already states this
position: a captured bundle nobody has judged is an ordinary state, not an error — and not a clean
forest. Rules must be re-runnable against an old bundle without returning to the forest.

## Stage 1 — reading a bundle back

**The largest single gap, and it is not the engine.** `BundleWriter.WriteObject(EvidenceObject)`
exists; there is no reverse. `BundleReader` offers `ReadObjectAttributes(dn)` for one distinguished
name and `ReadTree()`, neither of which returns the `EvidenceObject` shape a rule needs.

Required before anything else:

- enumerate objects from a sealed bundle in the `EvidenceObject` shape
- enumerate permissions (`ObjectPermissions`) alongside them
- stream rather than materialise — a forest capture is hours of data, not a list

## Stage 2 — derive

Each phase reads the bundle and earlier phases, and writes derived facts. **Each phase is
independently fault-isolated**: a phase that fails is recorded by name and the run continues
degraded. This matters most for the most expensive phase, which is also the likeliest to fail.

### 2a — Effective group membership

Breadth-first expansion of group nesting, answering "who is *really* in this group".

#### Two closures, because "member" answers two different questions

**This is one closure in an earlier draft and that was wrong.** The two questions have different
answers and running them together produces a confident false positive.

| Closure | Follows | Answers |
|---|---|---|
| **Authorization** | security-enabled groups only | *Does this principal hold this access right now?* |
| **Protected** | security **and distribution** groups | *Is this principal covered by AdminSDHolder and SDProp?* |

The authorization closure is what control edges and Tier 0 reachability rest on. **Distribution
groups must not appear in it.** Microsoft is explicit in
[Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface):
*"accounts that are members of nested distribution groups will not receive the protected group's SID
in their access tokens."* A distribution group is not security-enabled and cannot carry permissions.

The protected closure **must** follow them, from the same source: distribution groups are included
in protected-group enumeration precisely because they can later be converted to security groups.

**The earlier draft applied distribution-group following to the control graph**, which would have
produced:

```
Alice -> member of -> DistributionGroup-A -> member of -> Domain Admins
=> "Alice can reach Tier 0"
```

Alice does not presently receive the Domain Admins SID through that nesting. The finding would have
been false, and it would have been stated confidently. Recorded rather than quietly fixed, because
the citation was already in the document and the wrong conclusion was drawn from it anyway.

#### Latent privilege is a finding in its own right

The nesting above is not nothing — it is a loaded gun with the safety on:

> **Latent privilege.** `DistributionGroup-A` is nested in Domain Admins. Converting it to a
> security group would immediately grant 47 members Domain Admins rights at next logon.

That is genuinely useful and it is honestly labelled. It is **not** current effective control and
must never be counted as one.

#### Membership is a fact. Usability is contextual, and belongs in `2b`

**An earlier draft made membership itself target-dependent** — `IsEffectiveMember(principal, group,
targetDomain)`, with the membership graph projected per object being judged. The concern was right
and the shape was wrong, in a way that would have been expensive.

Alice really *is* transitively a member of a domain-local group in another domain. That is a fact
about Alice and the group, and it does not change depending on which object anyone is looking at:

```
SecurityMembershipClosure(principal, group)      target-independent
```

What varies is whether that group **counts** when checking access to a particular resource, because
group scope decides where a group can grant anything — a domain-local group grants only within its
own domain. That is an **authorization** question, not a membership question, and it is answered in
`2b` where effective access is computed.

**The cost difference is the reason this matters.** Projecting membership per target object is
principals × objects — on the order of 100,000 × 500,000. Keying the context on **domain** instead
makes it principals × domains, which in a three-domain forest is three, not half a million.

Microsoft models it the same way: per MS-KILE, the KDC adds the **resource domain's** domain-local
groups to the authorization data when it issues a service ticket. Domain is the boundary Windows
itself reuses.

#### Everything both closures need

- **SIDHistory**, forward and reverse. An ACE naming an old SID from a migration grants access to
  the current principal. Missing this under-reports.
- cycle detection — AD permits membership loops. **A cycle is also a finding**, not merely a
  traversal guard; the predecessor reported it as SEC-052.

**Expansion runs against a budget, and a partial answer says so.** The predecessor returns
`IsComplete = false` with the specific `PartialGroups` named rather than silently returning a short
list. That is the same discipline `RuleVerdict.InputsNotCaptured` already encodes, and it must
survive into the derived facts — a rule resting on a partial closure has not established anything.

### 2b — Control edges

Convert raw ACEs into semantic capabilities. The predecessor's vocabulary is 25 `ControlType`
values; the ones that carry escalation meaning are:

`GenericAll`, `WriteDacl`, `WriteOwner`, `Owns`, `ResetPassword`, `AddMember`, `WriteSPN`,
`WriteKeyCredentialLink` (shadow credentials), `WriteRBCD`, `WriteUserAccountControl`,
`WriteAllowedToDelegateTo`, `DCSyncGetChanges`, `DCSyncGetChangesAll`,
`DCSyncGetChangesInFilteredSet`, `LinkGPO`, `CertificateEnroll`, `CertificateAutoEnroll`,
`GenericWrite`, `WriteAllProperties`, `CreateChild`, `DeleteChild`, `Delete`.

Four behaviours that are easy to omit and wrong to omit:

1. **Effective access creates an edge, not a raw allow ACE.** Allow and deny ACEs are evaluated
   under Active Directory access-check semantics — the trustee's token membership, whether the ACE
   applies at all, object- and property-specific rights, inheritance, and ACE ordering. **A deny ACE
   is evidence used in that calculation; it does not independently cancel an allow.**

   An earlier draft said *"deny ACEs cancel allow ACEs"* and carried a flag on the edge. That is a
   simplification that manufactures and destroys edges. Windows does not collect allows and subtract
   denies: it walks applicable ACEs in order, accumulating which requested bits are already granted
   or denied. So this is **not** sufficient:

   ```
   Allow GenericAll   -> GroupA
   Deny  WriteProperty(member) -> UserA        (UserA is in GroupA)
   => "cancel GenericAll"
   ```

   The edge exists only where the security context actually possesses the effective access for the
   capability being claimed. **This is materially harder than allow-minus-deny and is not a wording
   change** — it is the single most load-bearing computation in the derive stage, because the whole
   graph rests on whether an edge is real.
2. **`Owns` derives a capability conditionally, not automatically.** See below.
3. **`S-1-5-10` (Principal Self) is resolved, not discarded.** See below.
4. **Build is atomic.** Delete-and-rebuild in one transaction, so a mid-rebuild failure leaves the
   previous edge set rather than a half-built graph that rules would query happily.

#### Principal Self is resolved to the object it stands for

An earlier draft **excluded** `S-1-5-10` as "a placeholder meaning the object itself, not an
attacker." The premise is right and the conclusion is wrong.

[Security identifiers](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers)
is explicit: SELF is *"a placeholder in an ACE for a user, group, or computer object… During an
access check, the operating system replaces the SID for Self with the SID for the security principal
that the object represents."*

So it resolves rather than disappears:

```
SELF ACE on UserA      -> trustee is UserA
SELF ACE on ComputerA  -> trustee is ComputerA$
```

**Discarding it is a silent false negative.** The default SELF rights are deliberately harmless, but
an administrator can grant more, and a computer account able to write its own
`msDS-KeyCredentialLink` or `msDS-AllowedToActOnBehalfOfOtherIdentity` is a real primitive — an
attacker holding that machine holds the write. Resolve the trustee and let the capability layer
decide whether anything dangerous follows.

Where the target is not a security principal, SELF is evaluated per AD applicability rather than
assumed to grant anything.

**Attribute GUIDs are the sharpest edge in this stage.** The predecessor shipped three wrong
literals — `member` pointing at the group object-class GUID, `userAccountControl` at the computer
object-class GUID, and `msDS-AllowedToDelegateTo` at a property set — each a **silent false
negative**. Every GUID is verified against a first-party Microsoft source before use, per the
standing rule that the old app is never a seed for a harvest. `docs/rules/FIRST-PARTY-VERIFICATION.md`
is the ledger for this and is reused rather than restarted.

#### The authorization context: which SIDs count, against what

An ACE names a trustee. Whether it applies depends on which SIDs the principal actually presents
**in the security context servicing the request** — and that is where group scope lands, per `2a`.

Two sets, and the split is what keeps this affordable:

| Set | Contents | Keyed by |
|---|---|---|
| `BaseAuthorizationSids` | the principal's own SID, SIDHistory, transitive **global** and **universal** groups, applicable special identities | principal |
| `ResourceAuthorizationSids` | base, **plus** domain-local and builtin-local memberships valid for that resource domain | principal **×** domain |

So the access check asks: *does this ACE's trustee match a SID in this principal's authorization
context for this resource domain?* — not *is this principal a member of that group anywhere?*

**Work group-first where possible.** ACEs name trustees, so walking trustee → effective members →
is that group's scope valid here is usually cheaper than expanding every principal. That also
matches how `2b` already derives edges.

**Do not derive this from `tokenGroups` in production.** Microsoft warns that querying it per
principal is expensive enough to affect domain controller performance. It is a good **lab oracle**
for validating the derivation against Windows' own answer, and a bad production mechanism.

##### Special identities are supplied by the context, not walked

`Everyone` (`S-1-1-0`), `Authenticated Users` (`S-1-5-11`) and `This Organization` (`S-1-5-15`) must
be honoured when an ACE names them, but they are **not** group memberships. Microsoft calls them
*special identities* whose *"membership is controlled by the operating system"* — there is no
`member` attribute to walk. They belong in `BaseAuthorizationSids` as contextual trustees, not in
the closure.

This matters the moment the product explains *why* an ACE applied. *"Because this principal is in
that group"* and *"because any authenticated context matches"* are different sentences, and an
administrator acts differently on each.

##### Which domain is the context? — OPEN

For an ordinary domain-NC object the resource domain is the object's domain, and the question does
not arise. **For everything else it does**, and this is recorded as unsettled rather than answered.

| Naming context | Context question |
|---|---|
| Domain NC | the object's domain |
| Configuration NC | replicated forest-wide; which servicing domain applies? |
| Schema NC | forest-wide, with its own behaviour |
| Application NC (`DomainDnsZones`, `ForestDnsZones`) | spans domains; writable replicas listed in `msDS-NC-Replica-Locations` |

Microsoft provides
[`msDS-SDReferenceDomain`](https://learn.microsoft.com/windows/win32/ad/application-directory-partition-security)
on the partition's `crossRef` object for exactly this, defaulting to the parent partition's value,
then the parent domain, then the forest root.

**But it does not solve the case that matters most to an audit.** The same page says:

> *"A similar issue arises if a local group is specified in an ACL for an object in an application
> directory partition. In this case, the `msDS-SDReferenceDomain` attribute cannot be used to
> interpret the reference domain for a local group. To avoid this problem, local groups should not
> be used in the ACLs of application directory partition objects."*

So Microsoft states that a domain-local trustee in an application-partition ACL **has no
interpretable reference domain**. Microsoft's advice is not to create them; a forest audit meets
what exists, not what was advised. **The honest answer is `Unknown`** — the same tri-state that
governs reachability — and it must propagate rather than being resolved by picking a domain.

**`resourceDomain` must not harden into an API contract in this pass.** Tracked as `P-90`.

#### Identity: what names a node, and what classifies it

Two different jobs, and conflating them breaks multi-domain forests silently.

| Purpose | Key |
|---|---|
| **Graph node identity** | `objectGUID` **plus its partition** |
| **Classification** | SID and RID, where applicable |

**Every domain has its own `Builtin` container**, so `S-1-5-32-544` names a *different directory
object* in every domain of the forest. Keying graph nodes on SID would merge the Administrators
groups of every domain into one node and invent control edges between domains that do not exist.

So SID and RID answer *"is this thing a Tier 0 seed?"* — matching by RID is what makes renaming a
well-known group harmless. They never answer *"which node is this?"* That is `objectGUID`, which
`docs/decisions/0023` already relies on for finding identity because it survives rename and move.

#### A capability is the unit everything above this layer consumes

Raw rights are captured facts. **Nothing above `2b` reasons about them.** A capability is what an
attacker can actually do, and it carries everything a later phase needs to judge it:

| Field | Purpose |
|---|---|
| `Name` | `CanResetPassword`, `CanWriteRBCD`, `CanReplicateAllDomainSecrets`, … |
| `EdgeClass` | `DirectoryControl` / `CredentialExposure` / `ConditionalEscalation` — a **semantic category, not a ranking** |
| `Feasibility` | `Direct` / `Conditional` / `Potential` |
| `Confidence` | `High` / `Medium` / `Low` |
| `Preconditions` | what must also be true, **named** |
| `PropagatesControl` | whether this capability may extend a chain |
| `DerivedFrom` | the rights and ownership facts that produced it |

**`EdgeClass` is not an ordered score, and an earlier draft used it as one.** That draft said a
chain is "only as strong as its weakest class", which treats three semantic categories as a ranking.
A `CredentialExposure` hop is not inherently weaker or stronger than a `ConditionalEscalation` hop —
they are different *kinds* of thing. Route grading comes from `Feasibility`, `Confidence` and
`Preconditions`; `EdgeClass` says what sort of step it is.

**`Preconditions` must name the condition.** Telling an administrator a route is "conditional"
without saying what it depends on is not information. For unconstrained delegation the entries are
concrete: the source host is under attacker control; a privileged principal authenticates to it;
reusable credential material becomes available.

**`PropagatesControl` belongs to the capability, and an earlier draft got this wrong too.** It
proposed propagating only through a hard-coded list of raw rights — `GenericAll`, `WriteDacl`,
`WriteOwner`, `Owns`, `AddMember`, `ResetPassword`. That contradicts this layer twice over: `Owns`
is now conditional and is *evidence for* a capability rather than a takeover step itself, and the
list omits capabilities that plainly do propagate, such as `CanWriteKeyCredential`, `CanWriteRBCD`
and `CanReplicateAllDomainSecrets`. **The list is deleted.** Propagation is a property of the
capability, decided once where the semantics live.

**The capability catalogue is not in this document.** Which right, against which target class,
yields which capability — `WriteSPN`, `WriteKeyCredentialLink`, RBCD, certificate enrolment, GPO
linking, `CreateChild` and the rest — is a research pass of its own, and it is where the next crop
of silent errors will live. Named here so its absence is visible.

#### `Owns` derives control conditionally

An object's owner ordinarily has implicit `WRITE_DAC`, and
[Owner of a New Object](https://learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object)
states it plainly. **Two documented mechanisms suppress it.**

[Security identifiers](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers)
gives the first: `S-1-3-4` OWNER RIGHTS — *"When an ACE that carries this SID is applied to an
object, the system ignores the implicit READ_CONTROL and WRITE_DAC standard access rights for the
object owner."*

[MS-ADTS §6.1.1.2.4.1.2](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5)
gives the second: **`BlockOwnerImplicitRights` is character 29 of `dSHeuristics`**, taking values
0–3 and defaulting to 0, with the behaviour specified in MS-ADTS §3.1.1.5.2.1.1 and §3.1.1.5.3.1.
It is supported on the builds listed under `MSFT-CVE-2021-42291`. **Implement against MS-ADTS and
record the operating-system and configuration conditions**, because whether ownership yields control
now depends on a forest-wide setting the audit must read.

So ownership is modelled as:

```
Ownership -> evaluate implicit owner rights -> WriteDacl capability, if actually available
```

with the resulting capability carrying `Feasibility` and its `Preconditions`. **It is not an
unconditional `WriteDacl` edge**, and this is precisely why raw-right equivalence sets must not
survive into the rule layer.

**A correction worth recording, because the mistake will recur.** An earlier draft stated that
`BlockOwnerImplicitRights` was *"not found in a search of Microsoft Learn"* and told the next session
not to implement against it. It is documented, and one page fetch found it. **A search that returns
nothing is not evidence of absence** — it is evidence about the search. Open Specifications are
published as rendered pages and are reached by fetching the section, not by keyword search; the
standing rule in the repository instructions says so and this draft did not follow it.

### 2c — Classification: privileged, protected, dangerous, Tier 0

**Everything in this section is taken from Microsoft's own documentation, read through the Microsoft
Learn service, not from the predecessor's code.** The predecessor is a cross-check afterwards and
never a seed — its well-known SID catalogue was found to carry two wrong values.

#### Four questions, and none of them answers another

The engine keeps four independent properties. **It must not derive one from another** except where
this document says so explicitly.

| Property | The question it answers |
|---|---|
| `IsPrivileged` | Does this principal hold elevated administrative authority? |
| `IsProtectedPrincipal` | Is it subject to AdminSDHolder and SDProp? |
| `HasDangerousPermission` | Does this permission materially control its target? |
| `TierClassification` | Is it part of the identity control plane — a Tier 0 seed, or holding direct control of one? |
| `Tier0Reachability` | Can it *get* to the identity control plane, at any distance? |

**The last two are deliberately different questions**, and separating them is the `P-87` ruling
below. An earlier draft had a single `TierClassification` answering *"can it control the AD DS
identity control plane?"* — which, once indirect control counts, is answered by reachability rather
than by classification.

**The three implications that must not be written**, each with the case that breaks it:

- `IsPrivileged` ⇏ `Tier0`. A helpdesk group that can reset ordinary users' passwords is privileged
  and controls nothing in the identity plane.
- `IsProtectedPrincipal` ⇏ `Tier0`. Protection answers *is this covered by SDProp*, not *what can
  this control*. Print Operators is protected and manages printers; Domain Controllers (516) is
  protected and is a container of computer accounts, not an administrative principal.
- `HasDangerousPermission` ⇏ `Tier0`. `GenericAll` over a test user is dangerous and is not a
  domain takeover. **The same right over a Domain Admins member is.** Dangerousness is only
  meaningful with its target, so an edge is never classified without one.

**An earlier draft of this document made the second mistake**, treating the fifteen
AdminSDHolder-protected groups as the Tier 0 floor. That is recorded rather than quietly fixed,
because it is the error the product is most likely to make again: the protected list is published,
authoritative and easy to find, which is exactly what makes it a tempting wrong answer.

#### What Microsoft says Tier 0 is

> Tier 0 contains assets and identities that directly or indirectly control the directory service
> and enterprise-wide permissions.

Named explicitly, from
[Tier model for Active Directory Domain Services](https://learn.microsoft.com/windows-server/identity/ad-ds/tier-model):

- **Tier 0 administrative accounts and groups, "including built-in Active Directory groups such as
  Backup Operators and Server Operators."** Server Operators can start and stop services on a domain
  controller and back up and restore files regardless of permissions, so it controls the identity
  plane whatever its name suggests.
- AD DS domain controllers and core directory service components.
- Identity services — Microsoft Entra Connect, Entra application proxy, AD FS, AD CS.
- Systems that operate or manage Tier 0 identity systems: backup, monitoring, patching, hypervisor,
  antivirus and EDR, "or any agent with direct operating system-level or AD-object-level control".

**"Such as" is illustrative, not exhaustive**, and that matters: Microsoft names two built-in groups
and leaves the boundary open. Where this document draws a line Microsoft did not draw, it says so.

Two principles from the same page that bear directly on how findings are worded:

- **"The security sensitivity of all Tier 0 assets is equivalent because they are all effectively
  in control of each other."** So a finding about a Tier 0 asset does not need to prove a route to
  a domain controller. Control of any Tier 0 asset *is* the finding.
- **"Collapsing everything into Tier 0"** is listed as an anti-pattern that "dilutes Tier 0 and
  increases the attack surface". A product that marks too much as Tier 0 is not being cautious; it
  is being wrong in the direction that produces noise.

#### What this product can and cannot see

Microsoft's Tier 0 is broader than an AD audit can observe. The following are Tier 0 under the
Enterprise Access Model and are **out of scope here unless they appear as an actionable AD control
relationship**: hypervisors, backup platforms, EDR, Configuration Manager, physical server access,
PAWs, jump servers, network devices, storage, and non-AD application role systems.

**Saying so is load-bearing.** A report that lists Tier 0 assets without stating this boundary
implies a completeness the product does not have, and `docs/decisions/0002` forbids presenting an
unavailable answer as an empty one.

#### Protected principals — a fact reported in its own right

These are the accounts and groups covered by AdminSDHolder and SDProp. **This is not the Tier 0
list**, and the table below is used to answer `IsProtectedPrincipal`, never `TierClassification`.
It is worth capturing on its own: protection disables inheritance, so a protected object placed in
a delegated OU silently does not receive the delegation.

[Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
names fifteen. Every identifier below is from
[Security identifiers](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers),
**not from a documentation search result** — see the note after the table. The final column records
whether the entry is also a proposed Tier 0 seed, and the two are deliberately not the same set.

| Protected group or account | Identifier | Scope | Tier 0 seed? |
|---|---|---|---|
| Administrator | `<domain-SID>-500` | domain | yes |
| Krbtgt | `<domain-SID>-502` | domain | yes |
| Domain Admins | `<domain-SID>-512` | domain | yes |
| Domain Controllers | `<domain-SID>-516` | domain | **no** — the DC *machines* are, the group is not |
| Schema Admins | `<root-domain-SID>-518` | forest root only | yes |
| Enterprise Admins | `<root-domain-SID>-519` | forest root only | yes |
| Read-only Domain Controllers | `<domain-SID>-521` | domain | **no** — the RODC *machine* is |
| Key Admins | `<domain-SID>-526` | domain | **no** — unfinished, see below |
| Enterprise Key Admins | `<root-domain-SID>-527` | forest root | **no** — unfinished, see below |
| Administrators | `S-1-5-32-544` | builtin | yes |
| Account Operators | `S-1-5-32-548` | builtin | **no** |
| Server Operators | `S-1-5-32-549` | builtin | yes — named by Microsoft |
| Print Operators | `S-1-5-32-550` | builtin | **no** |
| Backup Operators | `S-1-5-32-551` | builtin | yes — named by Microsoft |
| Replicator | `S-1-5-32-552` | builtin | open |

**Notation.** `<domain-SID>` stands for a full domain SID of the form `S-1-5-21-x-y-z`. An earlier
draft wrote `S-1-5-<domain>-512`, which mirrors Microsoft's own tables but is wrong if copied
literally into code or a test, because the `21` is not optional.

**Why the source of each value is stated.** A documentation *search* returned `S-1-5-32-548`
labelled Print Operators, because the excerpt had run a heading together with the table beneath it.
The reference page gives 548 as Account Operators and 550 as Print Operators. Taking the excerpt
would have swapped two protected groups — a silent false negative of exactly the kind the
predecessor shipped three times over with attribute GUIDs. **RIDs come from the reference page.**

**Resolved 2026-08-25 — Key Admins is domain-scoped and Enterprise Key Admins is forest-root.**
[Domain-wide schema updates](https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/domain-wide-updates),
operation 85, grants `domain\Key Admins` and `rootdomain\Enterprise Key Admins` the right to modify
`msDS-KeyCredentialLink`. That is the opposite of the SID reference page, which labels 526
root-domain and 527 domain. **The operational source wins**: it describes what domainprep actually
writes. `P-86` closes on this.

The same operation records a Microsoft defect worth knowing about in the field: in non-root domains
it *"resulted in a bogus domain-relative ACE with a nonresolvable -527 SID."* An unresolvable
trustee on a real domain is something an audit tool will meet and should name rather than drop.

**Open — a Microsoft documentation discrepancy.** Appendix C lists fifteen protected groups and
omits **Enterprise Read-only Domain Controllers**, while
[Active Directory security groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups)
gives that group `S-1-5-21-<root domain>-498` and **Protected by AdminSDHolder: Yes**. Two
first-party pages disagree about the membership of the protected set. Recorded, not resolved by
picking one. Tracked as `P-88`.

#### Tier 0 seeds — the fixed starting set

A **seed** is Tier 0 by what it is, before any graph is walked. The set is deliberately narrow,
because everything else is reached from it and an over-wide seed set contaminates the whole closure.

**Principals.** Enterprise Admins, Domain Admins, Schema Admins, `BUILTIN\Administrators`, the
built-in Administrator account, krbtgt, **plus Backup Operators and Server Operators**, which
Microsoft names.

**Assets.** Individual **domain controller computer accounts**, which Microsoft names directly:
*"AD DS domain controllers"* are Tier 0.

**Directory targets**, because control of an object can be Tier 0 control even when the object is
not a principal: the domain naming-context root, the Configuration and Schema naming-context roots,
AdminSDHolder, the Domain Controllers OU, forest and domain trust configuration, replication
topology objects, and GPOs that apply to Tier 0 systems.

**Matching is by SID and RID, never by name.** Renaming a well-known group must not lose its seed
classification.

##### "Applies to" is not "linked to" — and the answer is tri-state

A GPO becomes a Tier 0 target by **applying** to a Tier 0 system, and an earlier draft twice used
*"linked to the Domain Controllers OU"* as though that settled it. A link is a configuration
artefact; application is the result of evaluating it.

Group Policy scope is **site, domain and OU** — an earlier draft listed only domain and OU
ancestry, which misses site-linked policy entirely, and for domain controllers site-level policy is
very plausible. Whether a GPO applies to a given computer depends on all of:

- the **site**, **domain** and **OU** hierarchy above it
- **link order**, whether each **link is enabled**, and whether it is **enforced**
- whether **block inheritance** is set anywhere between the object and the link
- the **GPO status** — the computer half can be disabled independently
- **security filtering** — the target needs both `Read` **and** `Apply Group Policy`
- **WMI filtering**

```
GpoAppliesToComputer:   Applies | DoesNotApply | Unknown
```

**`Unknown` is not defensive padding; it is forced by what the product can see.** A WMI filter is
evaluated **on the destination computer**, and the GPO applies only if that query succeeds there.
This product captures directory objects, permissions and SYSVOL — **it does not capture the local
state of every domain controller**. So where a WMI filter exists and the state it tests was not
captured, the honest answer is that we cannot say.

That `Unknown` **propagates**: into the capability derived from the GPO, into the Tier 0
classification that would rest on it, and into reachability. It never quietly becomes
`DoesNotApply`, which would be a clean verdict over unread data.

Note that security filtering is itself an effective-access question, so it reuses `2b` rather than
needing new machinery — and it inherits `2b`'s honesty about incomplete data along with it.

##### A group of domain controllers is not a domain controller

**The Domain Controllers group (RID 516) is not a seed, and an earlier draft had it as one while
its own text said why it should not be.** That draft observed that 516 is *"a container of computer
accounts, not an administrative principal"* and then listed it anyway — an internal contradiction
caught in review.

The distinction is real: adding an ordinary computer to RID 516 does not make it a domain
controller, so `AddMember → Domain Controllers` is **not** domain takeover. What is Tier 0 is the
**computer account of an actual domain controller**, which is a different object.

The same distinction applies to Read-only Domain Controllers (521) and Enterprise Read-only Domain
Controllers (498): the **RODC machine** is a Tier 0 asset; whether the **group** confers identity-
plane control is a separate question nobody has researched. Recorded in `P-85`.

##### Read-only domain controllers

An RODC computer account is treated as a **Tier 0 asset with a subtype**, so its different
compromise profile — a filtered credential set and its own krbtgt — is visible rather than averaged
away.

**This is our inference, not Microsoft's ruling.** Microsoft's tier model says "AD DS domain
controllers" without distinguishing writable from read-only. Reading that as including RODCs is an
argument from silence; it is a reasonable one, and it is recorded as inference.

##### Deliberately not seeds

Proposed 2026-08-25, agreed by the owner as a working position and expected to move before it is
locked:

- **Account Operators (548)** and **Print Operators (550)**. Both are protected and both are
  privileged. Microsoft's tier-model sentence names neither, and Microsoft separately documents that
  Account Operators cannot modify Administrators or Domain Admins, or the accounts of their members.
  **This is our inference from Microsoft's words, not Microsoft's ruling** — "such as" left the
  boundary open, and this is where we drew it.
- **Key Admins (526)** and **Enterprise Key Admins (527)**. Their documented default capability is
  writing `msDS-KeyCredentialLink`, granted by domainprep operation 85 — and AdminSDHolder disables
  inheritance on protected accounts, so that grant does **not** by default reach Domain Admins.
  Microsoft's own guidance is to add a Key Admins ACE to AdminSDHolder when Windows Hello enrolment
  is needed *for* an administrator, which is the exception proving the default.

  **Unfinished, not settled.** Operation 83 also grants both groups **Full Control over the
  `CN=Keys` container**, and nobody has established what that confers. Do not treat their exclusion
  as researched. Recorded in `P-85`.
- Group Policy Creator Owners, Cryptographic Operators, Distributed COM Users, Exchange groups.

Each of these **still becomes Tier 0 the moment the graph proves it**, through the derivation below.
Excluding them from the seed set is not a claim that they are safe; it is a refusal to assume they
are dangerous before the evidence says so. In practice Print Operators frequently does earn it.

##### Still open

Whether **Replicator (552)** is a seed. It is a legacy file-replication account with no members by
default and has not been researched against a first-party source.

#### Deriving Tier 0 beyond the seeds

Two ways to become Tier 0 without being a seed, and they carry **different remediations**, which is
why they are separate values rather than one.

| `Tier0Basis` | How | What fixes it |
|---|---|---|
| `Seed` | it is on the fixed list | nothing — this is what Tier 0 means |
| `EffectiveMembership` | transitively a member of a seed group, through security-enabled groups | **break the membership chain** |
| `DirectControl` | holds a capability over a seed that the catalogue says confers control | **remove the capability** |

**`EffectiveMembership` was missing from an earlier draft**, which had only `Seed` and
`DirectControl`. Alice nested three groups deep inside Domain Admins is neither: she did not
originate as a seed and she does not *control* Domain Admins — she **is** a Domain Admin, operating
with that authority. Telling an administrator to "remove the capability" would be nonsense; the fix
is the nesting.

It also reflects the asymmetry `2a` already states: **membership is followed transitively, control
is cut at one hop.**

Each principal carries:

| Field | Meaning |
|---|---|
| `TierClassification` | `Tier0` when the basis is any of the three above |
| `Tier0Basis` | `Seed`, `EffectiveMembership` or `DirectControl` |
| `Tier0Reason` | the reason in a sentence an administrator can act on |
| `Tier0Evidence` | the membership chain or the capability and target that earned it |
| `Tier0Scope` | whether the authority is object-, domain- or forest-scoped |

`Tier0Scope` exists because Schema Admins is forest-wide and a delegated OU administrator is not.
Reporting both as "Tier 0" without scope misstates the blast radius of each.

**A derived classification without evidence is not a classification.** Every non-seed result carries
what produced it, or it is not reported.

##### Which capabilities confer `DirectControl` is a catalogue property, not a graph property

`PropagatesControl` answers *may this capability extend a chain?* It does **not** answer *does
holding this make you Tier 0?* Those are different questions and an earlier draft ran them together.

So the catalogue carries a second, separate property:

```
Tier0ClassificationEffect:   None | DirectControl | ReachabilityOnly
```

**Unconstrained delegation is the case that proves they must be separate.** An earlier draft listed
it among derivations that are "exactly" direct control — while the capability section two pages
earlier defines it as `CredentialExposure` requiring three preconditions: attacker control of the
host, a privileged principal authenticating to it, and reusable credential material becoming
available. Both cannot be true. It is `ReachabilityOnly`: a real and serious route, and not a
statement that the host controls the directory today.

**RBCD deserves the same scrutiny.** `CanWriteRBCD` means *I can configure which principal may act
on behalf of identities to this resource* — whether that completes a takeover depends on the
delegating service and on Kerberos conditions. It is not automatically `DirectControl`.

**The values are not assigned in this document.** `Tier0ClassificationEffect` is decided per
capability per target class by the capability catalogue, which does not exist yet and is named in
`2b` as the next research pass. What this document settles is that the decision **has a home**, and
that it is not the same field as propagation.

The derivations the predecessor computed as one-hop queries land in these terms: transitive
membership of a seed group is `EffectiveMembership`; replication of domain secrets and RBCD on a
domain controller are candidates for `DirectControl`; unconstrained delegation and a GPO applying to
a domain controller need the catalogue's ruling and must not be assumed.

**Transitive membership here means the closure from `2a`** — security-enabled groups only.
Distribution-group nesting produces a latent-privilege finding, never a control edge.

**An edge is never created because two objects are both privileged.** Only an actual capability
makes an edge.

#### A raw extended right is not an attack capability

The three replication rights are captured as **facts**, and the capability that matters is
**derived** from them. Treating each as independently escalating over-reports.

[DS-Replication-Get-Changes-All](https://learn.microsoft.com/windows/win32/adschema/r-ds-replication-get-changes-all)
is documented as the *"control access right that allows the replication of secret domain data"* —
GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`.
[DS-Replication-Get-Changes](https://learn.microsoft.com/windows/win32/adschema/r-ds-replication-get-changes)
is the *"extended right needed to replicate changes from a given NC"* — GUID
`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` — and replicates changes, not secrets. So:

```
CanReplicateAllDomainSecrets  =  DS-Replication-Get-Changes
                                 AND DS-Replication-Get-Changes-All
```

and only `CanReplicateAllDomainSecrets` is Tier 0 control. A principal holding `Get-Changes` alone
has a finding worth reporting and is **not** holding the keys to every credential in the domain.

**The name is precise on purpose.** An earlier draft called this `CanReplicateSecrets`, which is
broader than what the conjunction establishes. MS-DRSR has a separate constrained path for RODC
secret replication, gated by whether revealing a given principal's secrets is permitted, and that is
a different capability with a different risk. Naming this one for *all domain* secrets leaves room
for the other without either being mistaken for it.

**Not yet verified, and an attempt was made and failed.** Both right definitions are confirmed above.
The **MS-DRSR authorization procedure has not been opened by anyone working on this document.** A
review cites Microsoft's IsGetNCChangesPermissionGranted procedure as checking
`DS-Replication-Get-Changes` first and then requiring `DS-Replication-Get-Changes-All` for
secret-revealing requests, with a separate EXOP_REPL_SECRETS path for RODC reveal. That is
consistent with the right definitions and it is **a citation, not a reading**.

An attempt on 2026-08-26 did not reach the section: searches return only the schema pages for the
two rights, the specification's landing page carries no section index, and a fetched sibling section
offers no navigation. Section URLs use opaque identifiers that cannot be derived from a section
number. `P-91` records the routes tried and the two that remain — a link from another section, or
the published PDF.

Per `P-89` this stays **not read** — neither absent nor verified on a reviewer's word. **Do not
implement the conjunction until the section has been opened**, because this capability is the basis
for classifying a principal as controlling every credential in the domain.

The same shape applies wherever a capability is more than one right: keep the rights as captured
facts and name the capability separately.

#### The closure problem, and how far Tier 0 spreads — RULED 2026-08-25

The rule `Tier0(P) if Controls(P, X) and Tier0(X)` is correct and unbounded. Run it on a real
forest:

```
Domain Admins                                    seed
  <- Alice           WriteDacl                   Tier 0
  <- Bob             ResetPassword on Alice      Tier 0
  <- Helpdesk        ResetPassword on Bob        Tier 0
  <- Authenticated Users   broad write on that OU      ... everyone
```

**Every step is true.** This is not a defect to fix but the honest consequence of the rule, and the
lab already carries 1,039 instances of the pattern at the last step. Left alone it produces "you
have 8,000 Tier 0 principals", which is Microsoft's dilution anti-pattern reached by arithmetic.

**The owner ruled on 2026-08-25: the recursion is cut.** Tier 0 is what a principal **is** — a seed,
or a principal holding **direct** control over one. Everything further out **reaches** Tier 0, which
is reported in full and is a different claim.

| Field | Values | Meaning |
|---|---|---|
| `TierClassification` | `Tier0` `Tier1` `Tier2` `Unclassified` | what this principal **is** |
| `Tier0Basis` | `Seed` `DirectControl` | why it is Tier 0, where it is |
| `Tier0Reachability` | `Reachable` `NotReachable` `Unknown` | whether it can **get** there |
| `Tier0Distance` | hops | how far |

So the helpdesk group three hops out is:

```
Helpdesk-Tier2:
    TierClassification  = Unclassified
    Tier0Basis          = (none)
    Tier0Reachability   = Reachable
    Tier0Distance       = 3
```

**The example says `Unclassified`, not `Tier2`, and an earlier draft got this wrong.** The enum
reserves `Tier1` and `Tier2`, but the non-goals below decline to define what qualifies for either —
so assigning one here would be a classification this document cannot defend. A principal is
`Unclassified` until a Tier 1 or Tier 2 catalogue exists to place it.

**`TransitiveControl` is deliberately absent.** An earlier draft had a `Tier0Relationship` field with
`None`, `Seed`, `DirectControl` and `TransitiveControl`. Under this ruling the last value is a
contradiction in terms — a transitive controller is precisely the thing that is *not* Tier 0 — and a
field named `Tier0Relationship` holding it would reintroduce the confusion the ruling removes.

Nothing is hidden: the route is discovered, reported and remediable. What changes is that the
administrative tier keeps meaning something, and the count of Tier 0 principals stays small enough
to act on.

**This is a deliberate narrowing of Microsoft's words and is recorded as ours.** Microsoft's
definition is *"assets and identities that **directly or indirectly** control the directory service"*,
and read literally, indirect control at any distance is Tier 0. We decline to follow that to its
conclusion because the conclusion is a classification containing most of the forest — which is the
dilution Microsoft separately names as an anti-pattern. Both statements are Microsoft's; the choice
between them is ours.

**The counter-argument, recorded because it is good:** an attacker who compromises the helpdesk group
does become Domain Admin, so in risk terms it is effectively Tier 0. The answer is that a
classification including everyone drives no action, and `Tier0Reachability` with a full route says
the same thing without destroying the label.

#### `adminCount` is evidence of history, not of current membership

Per *Reducing the Active Directory Attack Surface*: when an account leaves a protected group it is
no longer protected, **but `adminCount` remains 1 unless someone clears it**, and the object still
does not inherit permissions from its parent. So an object may sit in a delegated OU and silently
not receive the delegation.

**`adminCount = 1` must therefore never be used to decide that something is Tier 0.** It says
*this was privileged at some point*. The predecessor's SEC-030 treats this as its own finding, which
is the right shape: a stale `adminCount` is worth reporting as an orphaned object, not as an
administrator.

#### Two predecessor defects to carry forward as tests

Both were silent false negatives — the product reporting clean when it was not:

- The transitive query named RIDs 512, 518 and 519 only. Anyone privileged solely through
  **Key Admins (526), Enterprise Key Admins (527), RODCs (521) or BUILTIN\Administrators (544)**
  was never classified transitively. Measured against the seed set above, the predecessor was
  **also** missing Server Operators, Backup Operators, Administrator, Krbtgt and Domain Controllers
  — every one of them named or implied by Microsoft's tier model. The seed set lives in one
  catalogue consulted by every query, and the catalogue is built from the reference page.
- The Tier 0 object test was `sid LIKE '%-NNN'`. **A domain root object can never match that,
  because its SID *is* the domain SID.** Control of the domain root, of any `nTDSDSA`, of
  `trustedDomain` objects and of AdminSDHolder all went unreported. The Tier 0 object set is
  emitted once, by the classifier that owns the policy, and joined — never restated in a query.

#### What only the owner can rule

Microsoft's list is the floor, not the answer. Open:

- Whether **Print Operators** and **Account Operators** are treated as Tier 0 in this product.
  Microsoft protects both and names neither in the tier-model sentence. Account Operators can create
  and modify accounts outside the Builtin container and the Domain Controllers OU; Print Operators
  holds `SeLoadDriverPrivilege` on domain controllers in practice, which is a known escalation.
- Whether **AD CS and AD FS servers** are classified Tier 0 when found, given Microsoft names them.
- Whether a customer may **declare additional Tier 0 assets**, which most real forests need and
  which `docs/decisions/0082` — the catalogue is not customer-tunable — does not obviously cover,
  because this is scope rather than severity.

### 2d — Reachability, paths and remediation

**The finding is the reachability. A path is evidence for it, and a remediation is a claim about
what is left afterwards.** Getting this order right is what stops the product telling an
administrator he has fixed something he has not.

#### Reachability has three states, not two

**This is the `0002` failure, and an earlier draft of this document committed it in its own text**
after spending pages warning against it. That draft said a finding closes when reachability reaches
zero. **Zero routes found in an incomplete graph is not zero routes.**

```
Tier0Reachability:  Reachable | NotReachable | Unknown
```

`Unknown` is required whenever any input the answer rests on is incomplete — a partial membership
closure, a partition that could not be read, permissions unreadable across part of the domain, or a
derive phase that failed and left the run degraded. A backward sweep that finds no route through a
graph missing a fifth of its permissions has established **nothing**, and must not say `NotReachable`.

This is the same discipline `RuleVerdict.InputsNotCaptured` already encodes one layer up, and the
same reason `StoredFindings.DidNotRun` exists. A production domain in the lab returned 19,927 of
100,000 objects with no readable security descriptor; a sweep over that data answering "no route
found" would be worse than useless.

#### The anchor: what reachability is measured *to*

Reachability is measured to a single synthetic node, the **Tier 0 control plane anchor**. Every
Tier 0 **seed** is attached to it; nothing else is.

```
Domain Admins ─┐
krbtgt        ─┤
DC01$         ─┼──> [ Tier0ControlPlane ]
Schema Admins ─┤
AdminSDHolder ─┘
```

**Three things follow, and each fixes a defect in an earlier draft.**

**The anchor set is fixed.** An earlier draft had phase 4 producing "seeds and direct controllers"
while `2d` swept from "seeds" — different sets under the `P-87` ruling, and it never said which was
the destination. **Derived Tier 0 principals are never endpoints.** If Alice becomes Tier 0 by
holding `WriteDacl` on Domain Admins, she does not become a destination; Bob's distance is measured
to the anchor, not to Alice. Otherwise every principal's distance would move whenever some other
principal gained or lost classification, and findings would churn between runs with nothing changed
in the directory.

**The sweep and the finding now answer the same question.** They did not before, and this is the
sharpest defect any review has found in this document.

An earlier draft paired a **multi-source** backward sweep with a finding identity of
`(ruleId, principal, target)`. Those do not compose. The sweep collapses every destination into one
answer, so:

```
Bob ──> Domain Admins
    └─> DC01

remove the DC01 route:
    sweep still says   Bob = Reachable      (Domain Admins remains)
    finding (rule, Bob, DC01) should close  — and cannot be told to
```

**A finding that should close, does not.** That is exactly the failure this document exists to
prevent, written into the document by the same hand that wrote the warnings.

**The anchor resolves it**, and Microsoft's own equivalence principle is why it is the right
resolution rather than merely a convenient one: *"the security sensitivity of all Tier 0 assets is
equivalent because they are all effectively in control of each other."* If the assets are
equivalent, then **reaching any of them is the finding**, and which ones were reached is evidence.

So a reachability finding is `(ruleId, principal, Tier0ControlPlane)`, and it closes when the
principal reaches **no** seed under complete coverage.

**The destinations are not lost — they are reported underneath.** The headline names the control
plane; the evidence names the seeds actually reached, each with its route:

> **Helpdesk-Tier2 can reach the Tier 0 control plane.** 3 hops.
> Reaches: `Domain Admins` (3), `SVC-ADSync` (3), `DC01$` (5).

**Capability findings keep per-target identity.** SEC-121 *Domain Controllers OU Write Access* is
about one OU and stays `(ruleId, principal, thatOU)`. Only **reachability** findings take the
anchor, because only they were asking the collapsed question.

#### Reachability is computed backwards, once

A **single backward breadth-first sweep from the anchor along reversed edges** marks, for every
principal in the forest: whether it reaches the anchor, the fewest hops, and a predecessor pointer
that reconstructs one shortest route.

This is one traversal of the graph rather than one per principal, and it needs **no depth limit**,
so nothing is missed.

**The predecessor did the opposite and it is why a production forest took hours.**
`EscalationPathService.FindPathsFromInternal` takes a `sourceSid` and searches *forward*, once per
principal; its counters (`PrincipalsAnalyzed`, `PrincipalsSkippedByReverseBfs`) confirm it. It built
a reverse-distance index, but only to skip principals that could not reach anything — the search
itself stayed forward. Tens of thousands of traversals where one suffices.

#### Enumeration is separate, bounded, and only for what is reported

Reachability is linear; **enumerating distinct paths is exponential**, and the two were run together
in the predecessor, which is why it needed a cap of 250,000 retained paths. That cap was protecting
the report from itself rather than doing analysis.

So paths are enumerated **only for findings a reader opens**, guided by the sweep's distance labels,
and always bounded. Twelve helpdesk password-reset rights crossed with two routes onward is
twenty-four paths describing one problem; an administrator handed twenty-four rows can act on none
of them.

**What is shown, and it is not "all paths":**

- the **shortest** route — guaranteed by the sweep
- the **strongest** route, scored by edge danger, which is often *not* the shortest: three hops of
  `GenericAll` beat two hops through a conditional edge. **This needs its own weighted search; it
  does not fall out of the breadth-first sweep.**
- the **chokepoints** those routes share

**A truncated list says so.** "Showing 3 of 120 routes" — never three rows implying three exist.

#### Remediation: mandatory waypoints first, residuals second

Two mechanisms, answering two different questions. **The first is the primary one and was almost
relegated to a footnote; it is the better answer and belongs in the design.**

##### Dominators — what completely fixes this

A **dominator** is a point every route must cross. If every route from a principal to Tier 0 passes
through one membership, removing that membership disconnects the principal entirely, however many
routes there were.

The whole set is computed **globally rather than once per finding** — not by testing candidates one
at a time. Attach a virtual exit to the Tier 0 seeds and compute **post-dominators**: for each
principal, the ordered chain of points every one of its routes must cross.

**No complexity claim is made here.** An earlier draft said "near-linear" while also choosing the
simple iterative algorithm, which does not carry that bound. Expected to be practical at forest
graph sizes, benchmarked against production-scale bundles, and the bound left to the implementation
to state once an algorithm is actually chosen.

**Edges, not nodes.** An administrator removes a permission or a membership, never an object. So
each edge is split into its own node before the analysis, making permissions the things that can be
cut.

**This is provably complete for the graph we hold, and that qualification matters.** A dominator cut
of size one cannot be beaten, so where one exists the product may say that removing it eliminates
every route **it can see**. Under incomplete coverage that is not the same as every route, and the
wording must not pretend otherwise. It also yields a **choice** of waypoints, which matters because
the most effective cut is often the one the administrator is not permitted to make.

> **Every route from `Helpdesk-Tier2` crosses two points.** Cutting either disconnects it completely.
>
> 1. `T1-ServerAdmins` — membership of 12 users
> 2. `SVC-ADSync → member of → Domain Admins` — one membership
>
> Cutting **2** also disconnects 15 other principals.

**Where no single waypoint exists**, two genuinely independent routes mean no one cut suffices and a
multi-point cut is needed — a maximum-flow problem. That is now the uncommon case rather than the
general one, and it is affordable for the handful of findings a person opens. Where it is not
computed, the product says so instead of implying the greedy answer is complete.

**Implementation:** the simple iterative dominator algorithm rather than the classic
optimal one. Around fifty lines, empirically fast at this scale, and far easier to prove correct —
which is the property that matters, because a wrong dominator would state a complete fix that is not
one. That is the worst thing this product can do.

##### Re-sweeping — what a proposed change leaves behind

Dominators answer *what fixes this completely*. They do not answer *what if I cut this other thing
instead*, which is what an administrator asks about the edge he is actually allowed to touch.

Because a sweep is cheap, that question is answered by re-running it with the candidate edge
removed. Each answer is one pass, and the recommendation carries **the residual**:

> Removing `T1-ServerAdmins → WriteDacl → SVC-Backup` eliminates 118 of 120 routes.
> **2 would remain**, via `SVC-Monitoring` and `GPO-Workstations`.

**The most effective change is frequently nowhere near the principal being examined**, and usually
sits at the Tier 0 end — one membership removed can close every finding flowing through it. That is
invisible when reading a path, and it is exactly what the dominator chain surfaces.

##### Two honest limits, which must appear in the wording

- **Minimality is claimed only when it is proven, and only for the graph held.** A dominator cut of
  size one is minimal and may be described as removing every route **in the captured graph**. A
  greedy multi-edge set is an approximation: *"these three remove all known routes"* is checkable,
  *"these three are the fewest possible"* is not, unless a minimum cut was actually computed.
- **No remediation claims completeness under incomplete coverage.** If reachability for that finding
  is `Unknown`, the wording is *"removes every route we could see"* and the gap is named. A complete
  fix asserted over a graph missing a fifth of its permissions is the same false statement as a
  clean verdict over unread data.
- **Sometimes there is no small cut.** If `Authenticated Users` holds a broad write high in the
  tree, the answer is not a list of four thousand edges — it is *"this is not fixable by removing
  individual permissions; the delegation on this OU needs review."* Printing the list is a way of
  not answering.

#### Finding identity is the rule, the principal and the target

A finding is `(ruleId, principal, target)`.

**The rule id is not optional, and an earlier draft dropped it while citing the decision that
requires it.** `docs/decisions/0023` says identity is *the rule*, the subject and the object. Writing
`(principal, target)` alone would collapse genuinely different security problems into one row —
RBCD control over `DC01`, shadow-credential control over `DC01`, and GPO control reaching `DC01` are
three findings with three remediations, not one.

**For a reachability finding the target is the `Tier0ControlPlane` anchor**, for the reason worked
through above: the sweep answers a collapsed question, so the finding must ask the collapsed
question too. The seeds actually reached are evidence beneath it. **Capability findings keep the
concrete object** — SEC-121 is about one OU and stays `(ruleId, principal, thatOU)`.

**The path is still excluded from identity**, and that is the point of the shape:
`docs/decisions/0023` makes identity stable so an acceptance stays attached, and
`docs/decisions/0067` has an acceptance name one finding. A path-shaped identity would change every
time an intermediate object moved, silently detaching every acceptance an administrator had made and
re-presenting the finding as new.

It follows that a reachability finding closes when the principal reaches **no seed** under complete
coverage — not when a displayed path changes, and not when a sweep over incomplete data happens to
find no route. Where required inputs are missing the state is `Unknown`, which is neither open nor
closed. An administrator who cuts the route he was shown and sees the finding return has been
misled, and that is the failure this repository exists to prevent.

#### The grading still applies

A route is only presented as a real attack path when *all* of: coverage complete, within the hop
limit, every step high-confidence, every step directly feasible rather than conditional, and every
step backed by captured evidence. Anything failing any one is presented as graph reachability
**with a written reason**. The predecessor's wording for these is good and is worth porting as
design even though the code is not.

#### Determinism, and what must be recorded

Two consequences of enumerating on demand rather than up front:

- **The same bundle must yield the same routes in the same order.** Deterministic edge ordering —
  weight, then control type, then target — is what makes that true, and without it findings churn
  between runs for no reason.
- **Anything shown to a customer is recorded in the bundle.** The routes displayed and the
  remediation set with its residual counts are written as the finding's evidence, or a report is
  not reproducible and two readings of one bundle could disagree.

#### What this design costs

Recorded here rather than discovered later. None of these is fatal; all are real.

- **There is no complete path inventory.** The predecessor materialised every path into
  `fact_escalation_path`, so "export every path in the forest" was a query. Here it is a
  computation, and an expensive one.
- **Drift is detected at reachability, distance and dominator level, not at path level.** The
  predecessor stored a signature per path and could say *this exact route is new*. This cannot —
  but the loss is far narrower than it first appears, and an earlier draft of this section
  overstated it.

  Three signals come free of the sweep: whether reachability changed, whether the shortest distance
  changed, and **whether the dominator chain changed**. The third is the important one. A new route
  that *bypasses* a mandatory waypoint removes that waypoint from the chain, so it is detected —
  and that is precisely the persistence case, where an attacker adds a second route so that fixing
  the first does not lock him out. A new route that does *not* bypass a waypoint leaves the chain
  unchanged and goes unseen — but cutting that waypoint still disconnects it, so the recommended
  remediation is unaffected.

  Stated as the property worth testing, and **narrowed from an earlier draft that overclaimed it**:
  **for a remediation resting on a single mandatory waypoint, a new route that bypasses that
  waypoint necessarily removes it from the chain, so dominator-chain drift detects changes that
  invalidate a single-waypoint remediation.**

  The earlier wording said *"exactly the changes that matter to remediation"*, which is false in the
  cases the proof never covered: multi-edge cuts, greedy remediation sets, residual counts for
  non-dominator candidates, changes in edge feasibility or class, and a new independent route where
  no single waypoint existed before or after. In that last case the chain is empty both times and
  the best multi-edge cut can change unseen.

  What genuinely remains lost is knowing that a route's middle changed while its endpoints and all
  its mandatory waypoints held. That case does not alter the fix, and in a live directory the
  predecessor would have reported hundreds of them per run as memberships shifted.

  **If the requirement is a tripwire rather than posture** — *someone changed permissions* — path
  drift was always a noisy derived proxy for it. The direct answer is a set difference over the
  control edges between two bundles, which is one pass, catches every permission change including
  those that create no route at all, and does not churn.
- **Forest-wide chokepoint ranking is not lost, but it is a second computation.** An earlier draft
  recorded this as a degradation, on the reasoning that ranking every edge by how many routes it
  carries needs global path data. That was wrong twice over: dominator analysis answers the stronger
  question — *every route from here crosses there* — **computed globally rather than by enumerating
  routes**, and it is now part of the
  design rather than a note about how to recover later. What genuinely remains missing is the
  *count* an edge carries when it is **not** a dominator, which still needs a re-sweep per candidate.
- **Cost moves from batch to interactive.** The run gets much faster; opening a finding now does
  work. Bounds and caching keep it acceptable, but the stall moves to where a person is waiting.
- **Per-path acceptance becomes impossible.** An administrator cannot accept one route and not
  another. This is almost certainly right — an accepted route with live alternatives is a false
  sense of safety — but it is a capability given up.
- **"Strongest path" is not free.** Breadth-first gives shortest. Strongest needs a second,
  weighted search, and skipping it would mean reporting the shortest route as though it were the
  most dangerous one.

## Stage 3 — judge

### The rule interface

`IRule.Judge(EvidenceObject)` is replaced. The replacement hands a rule the **derived facts**, not
one object and not a raw database connection.

What must survive from the current design, because each was bought with a real defect:

- **A rule declares the data it reads** (`RequiredAttributes` today, widened to derived facts).
  Verified against the predecessor: `GetCoverageRequirements` falls through to
  `[CoverageModules.Objects]` on a lookup miss, so a rule whose real inputs were never captured is
  stamped coverage-complete. `docs/decisions/0083` forbids this and the build fails on an
  undeclared rule.
- **A verdict distinguishes "clean" from "could not judge"** (`RuleVerdict.InputsNotCaptured`).
  `docs/decisions/0002` forbids rendering an unavailable answer as an empty result.
- **Typed evidence, no free-form blob.** The predecessor's `ContextJson` was schemaless with an
  informally reserved key namespace, read by three components, and its parse helper swallowed every
  exception — a malformed value silently downgraded a finding rather than erroring.
  `docs/decisions/0080` decides typed evidence and it holds.

### Rule shapes

Three, and they should share implementations rather than repeat them:

- **Capability rules** — parameterised by a **named capability** and a target filter. A rule about
  resource-based constrained delegation asks for `CanWriteRBCD`, and nothing else. Duplicates
  collapse to one finding.
- **Tier and reachability rules** — filter by `TierClassification`, `Tier0Basis`,
  `Tier0Reachability` and `Tier0Distance`. Where a rule filters on a reason, writer and reader share
  one token catalogue so they cannot drift.
- **Attribute rules** — read object attributes across the set.

#### A rule never reconstructs a permission equivalence set

**An earlier draft said the opposite**, and it was the sharpest remaining contradiction in this
document. It had a rule about `msDS-AllowedToActOnBehalfOfOtherIdentity` matching an *equivalence
set* of `GenericAll`, `GenericWrite`, `WriteAllProperties`, `WriteDacl`, `WriteOwner` and `Owns`,
"because each confers the ability."

By `2b`'s own rules that is false. `Owns` confers nothing until implicit owner rights are evaluated
against OWNER RIGHTS and `BlockOwnerImplicitRights`; `WriteOwner` is a route to ownership and
inherits the same conditions. A rule listing them as equivalent **re-implements the security
semantics `2b` exists to get right, and gets them wrong**, in a layer with none of the context
needed to do it properly.

So the derivation belongs entirely below:

```
2b:   WriteOwner -> take ownership -> implicit WriteDacl, if available
                 -> grant WriteProperty(msDS-AllowedToActOnBehalfOfOtherIdentity)
                 -> CanWriteRBCD   [Feasibility=Conditional, Preconditions named]

Rule: CanWriteRBCD ?
```

**If a rule names a raw right, that is a defect.** The right answer is a missing capability, added
where the semantics live.

### Recording what ran

`evaluated_rule` currently stores a rule id and version. **That is not enough**: a rule that ran and
could not read its inputs would be recorded as having run, and its zero findings read as *clean*.
Whatever a rule could not read must be recorded beside the fact that it ran.

### Writing

Findings and the run's record of what was judged are written in **one transaction**, so a crash
cannot leave findings attributed to a judgement that was never recorded. A throwing rule is
recorded as an error and the other rules continue.

## What is deliberately not built

- **Customer-tunable severity.** `docs/decisions/0082` refuses it and `0066` puts severity in the
  catalogue. The predecessor's policy evaluator — roughly 900 lines — sat on the critical path and
  always received an empty policy.
- **A second suppression mechanism.** The predecessor declared `SetSuppressions` and **called it
  from nowhere**; verified 2026-08-25, zero call sites in `src` or `tests`. Meanwhile the
  suppression users experienced was a different mechanism at read time over a separate sidecar
  database. Two systems for one job, one of them dead. Acceptance is governed by
  `docs/decisions/0067` — an acceptance names one finding — and there is one mechanism or none.
- **Live verification** (`docs/decisions/0008`) and **assessment mode** (`docs/decisions/0031`) are
  removal records. Not rebuilt without the owner saying so.

## Scope

**The full stage is built, through escalation paths.** The owner settled this on 2026-08-25: the
product does not ship until the features are implemented, so there is no partial cut to design
around and no reason to defer the chain.

That removes a constraint rather than adding one. The earlier question — whether a product that
cannot show a chain is worth shipping — does not need answering, because nothing ships at the
intermediate point.

**It does not remove the ordering.** The stages stack, and each is useless without the ones before
it, so they are built and proven in sequence:

| Phase | Builds | Proven by |
|---|---|---|
| 1 | reading objects and permissions back from a sealed bundle | the two existing rules become reachable and produce findings |
| 2 | effective group membership, in both closures | "who is really in Domain Admins", against the lab |
| 3 | capabilities from effective access | "who can take over this object", against the lab |
| 4 | Tier 0 seeds and direct controllers | the Tier 0 population is small enough to read, and every entry names its evidence |
| 5 | reachability, bounded enumeration, remediation | chains and residual counts, graded so the tool does not overclaim |

**Phases 4 and 5 are separable, and an earlier draft argued they were not.** That argument said Tier
0 classification and path-finding are one fixpoint, because a principal cannot be classified without
walking the graph whose targets are the things being classified. **That is true only of the
recursive definition the `P-87` ruling rejects.** Under the ruling, phase 4 is seeds plus one hop of
control — finite, cheap, no recursion — and phase 5 is a reachability sweep toward the endpoints
phase 4 produced.

**A retraction is owed to the predecessor as well.** The same draft criticised it for computing
classification as one-hop queries *before* building paths, calling that "a fixpoint stopped at depth
one." Read again, it followed **membership** transitively and **control** one hop — which is
essentially the model just ruled. Its structure was defensible; what it never did was write down
why, so the reasoning could not be checked or inherited. That is the failure worth avoiding, not the
shape.

The value of the ordering is that **each phase is checkable against a real forest before the next
one rests on it.** A defect in effective membership silently corrupts every path built on top of
it, and the predecessor's two silent false negatives were both in this lower half.

**Phases 4 and 5 do not force rework of 2 and 3** provided the derived facts carry, from the start,
what a path needs: stable identifiers on every edge, the capability and scope behind a
classification, and the completeness of the data each rests on. Those are cheap now and expensive
to retrofit.

## Acceptance criteria for classification

These are written to become tests, and each names the mistake it catches. They are the reason the
four properties are kept apart, so they belong beside the design rather than in a later test plan.

| | Criterion |
|---|---|
| AC-01 | Privileged is not automatically Tier 0. A group that can reset ordinary users' passwords is `IsPrivileged` with `TierClassification` other than `Tier0`. |
| AC-02 | Protected is not automatically Tier 0. Account Operators with only default authority is `IsProtectedPrincipal` and is not Tier 0. |
| AC-03 | A dangerous permission is judged with its target. `GenericAll` over an ordinary user is dangerous and not Tier 0. |
| AC-04 | Direct control of a seed is Tier 0. A principal able to modify Domain Admins membership is `Tier0 / DirectControl`. |
| AC-05 | A transitive chain is discovered and reported with its full path. Under the `P-87` ruling the principal is not labelled `Tier0`; the route is still shown in full. |
| AC-06 | A **custom** group is classifiable without appearing in any hard-coded Microsoft name list. |
| AC-07 | `adminCount = 1` alone never produces a Tier 0 classification. |
| AC-08 | A protected principal is reported as protected even when it is not a seed and holds no control. |
| AC-09 | Every derived classification carries at least one human-readable control path. A classification without one is not reported. |
| AC-10 | Cycles terminate. Group membership and control edges both form loops in real forests. |
| AC-11 | Renaming a well-known group does not lose its seed classification. Matching is by SID and RID. |
| AC-12 | Scope is retained — object-, domain- or forest-scoped authority is distinguishable in the result. |
| AC-13 | A finding's identity is `(ruleId, principal, Tier 0 target)`. It survives the routes beneath it changing, so an acceptance stays attached — and two different rules about the same pair remain two findings. |
| AC-14 | A finding closes only on `NotReachable` **under complete coverage** — never because a displayed route changed, and never on a sweep over incomplete data. |
| AC-15 | **Every remediation recommendation states what remains after it is applied**, including when the answer is nothing. This is the promise the design rests on. |
| AC-16 | A remediation claims completeness only when it is proven **and only for the captured graph** — a dominator cut may be described as removing every route *we can see*, never every route that exists. |
| AC-17 | A truncated route list says how many exist. "Showing 3 of 120", never 3 rows implying 3. |
| AC-18 | The same bundle yields the same routes in the same order. |
| AC-19 | Routes shown and remediation sets offered are recorded in the bundle, so a report is reproducible. |
| AC-20 | Where no small cut exists, the product says so in words rather than printing thousands of edges. |
| AC-21 | **A claimed dominator really is one.** For a sample of findings, removing the named waypoint and re-running the sweep yields zero remaining routes. A wrong dominator states a complete fix that is not one, which is the worst thing this product can do. |
| AC-22 | Where no single waypoint exists, the product says a multi-point change is required rather than presenting the best greedy edge as though it were sufficient. |
| AC-23 | A new route that bypasses a mandatory waypoint is detected as drift, because it removes that waypoint from the dominator chain. Asserted by planting a bypassing route between two bundles. |
| AC-24 | **An edge exists only where effective access exists.** A deny ACE that does not actually remove the claimed capability does not remove the edge, and one that does, does. Asserted with an allow-to-group plus deny-to-member fixture in both directions. |
| AC-25 | The authorization closure does not follow distribution groups. A user nested into a seed group through a distribution group has `Tier0Reachability = NotReachable` by that route, and produces a latent-privilege finding instead. |
| AC-26 | The protected closure **does** follow distribution groups, so the same user is `IsProtectedPrincipal`. AC-25 and AC-26 hold simultaneously on one fixture, which is the point of two closures. |
| AC-27 | *(superseded by AC-37, which asserts both suppression mechanisms rather than only OWNER RIGHTS. Retained as a number so citations do not shift.)* |
| AC-28 | An edge's class is preserved and reported. A `CredentialExposure` hop is never presented as equivalent to a `DirectoryControl` hop. **Grading is not done from class** — see AC-39. |
| AC-29 | *(superseded by AC-44, which uses the precise capability name `CanReplicateAllDomainSecrets`. Retained as a number so citations do not shift.)* |
| AC-30 | Adding an ordinary computer to the Domain Controllers group (516) does not make it a Tier 0 asset. |
| AC-31 | **Reachability is tri-state.** With any required input incomplete, a sweep that finds no route reports `Unknown`, never `NotReachable`. |
| AC-32 | A finding closes only on `NotReachable` under complete coverage. `Unknown` is neither open nor closed and never renders as resolved. |
| AC-33 | No remediation claims completeness while the finding's reachability is `Unknown`; the wording names the gap instead. |
| AC-34 | A multi-hop reacher is not `TierClassification = Tier0`. It carries `Tier0Reachability` and `Tier0Distance`, and its route is still reported in full. Asserted against the `P-87` ruling of 2026-08-25. |
| AC-35 | **No rule predicate names a raw right.** Rules ask for named capabilities; a rule mentioning `GenericAll` or `WriteOwner` fails this and the fix is a missing capability, not a rule change. |
| AC-36 | A SELF (`S-1-5-10`) ACE on a security principal resolves to that object's own SID and can produce a capability. A computer able to write its own `msDS-KeyCredentialLink` is found. |
| AC-37 | `Owns` alone produces no capability where OWNER RIGHTS (`S-1-3-4`) or `BlockOwnerImplicitRights` suppresses implicit owner rights. Both mechanisms are asserted. |
| AC-38 | Propagation is decided by the capability's `PropagatesControl`, not by the right it came from. No hard-coded list of raw rights exists in the traversal. |
| AC-39 | `EdgeClass` is not ordered. Route grading derives from `Feasibility`, `Confidence` and `Preconditions`; swapping two edges' classes without changing those does not change the grade. |
| AC-40 | Every `Conditional` capability carries at least one named precondition. "Conditional" with an empty list fails. |
| AC-41 | **Authorization is target-aware while membership is not.** The closure reports a principal as a member of a domain-local group in another domain; the authorization context for a resource in a third domain excludes it. Both hold on one two-domain fixture. |
| AC-42 | `S-1-5-32-544` in two domains resolves to **two** graph nodes. Keying by SID alone would merge them; identity is `objectGUID` plus partition. |
| AC-43 | A GPO that is linked but does not apply — link disabled, inheritance blocked, computer configuration disabled, or security filtering excluding the target — does not make its controllers Tier 0. |
| AC-44 | `CanReplicateAllDomainSecrets` requires both replication rights. `DS-Replication-Get-Changes` alone does not classify its holder Tier 0. |
| AC-45 | A membership cycle is reported as a finding, not merely survived by the traversal. |
| AC-46 | **A reachability finding targets the anchor, and closes only when no seed is reachable.** Removing one of two routes to different seeds does not close it; removing both does. This is the pairing an earlier draft got wrong. |
| AC-47 | The seeds actually reached are reported as evidence under the anchor finding, each with a route. The destination is not lost by being moved out of the headline. |
| AC-48 | Distances do not move when a principal gains or loses `Tier0` classification. Only seeds are endpoints. |
| AC-49 | A principal transitively inside a seed group is `Tier0Basis = EffectiveMembership`, and its remediation names the membership chain rather than a capability. |
| AC-50 | `PropagatesControl` and `Tier0ClassificationEffect` are independent. A capability may extend a chain without conferring `DirectControl`, and unconstrained delegation is asserted as exactly that case. |
| AC-51 | **A GPO with an uncaptured WMI filter yields `Unknown`, not `DoesNotApply`**, and that `Unknown` propagates into the capability, the classification and reachability. |
| AC-52 | A site-linked GPO is considered when deciding applicability. Scope is site, domain and OU. |
| AC-53 | A domain-local trustee in an application-partition ACL resolves to `Unknown`, because Microsoft states it has no interpretable reference domain. It is never resolved by choosing a domain. |
| AC-54 | No principal is assigned `Tier1` or `Tier2` while no catalogue defines them. `Unclassified` is the answer. |

**AC-05 asserts the settled model.** It was originally worded to survive the open ruling; `P-87` was
ruled on 2026-08-25, so it now states directly that a transitive reacher keeps its route and does
not take the `Tier0` label.

## Non-goals

Stated so a reviewer does not read absence as oversight. This specification does not:

- assign a severity to every dangerous permission — severity is fixed by the rule, per `0066`
- define the semantics of every access mask — that is the permission-classification layer's job
- discover Tier 0 infrastructure that is not represented in Active Directory
- infer compromise, intent, or that an attack has occurred
- declare every privileged principal Tier 0
- declare every AdminSDHolder-protected principal Tier 0
- define a full Tier 1 or Tier 2 catalogue

## Rule coverage — what this machinery does and does not reach

**Why this table exists.** Everything above was designed from the predecessor's architecture and
from Microsoft, then checked against reviews. Every check was sound — and every check was anchored
to *what was designed*, not to *what the rules need*. That is the failure recorded as `F-S44-2`: a
closed loop of internally consistent checks anchored to the wrong reference, where a rule shape
nobody wrote is a rule shape nobody misses.

**The 62 cards in `docs/rules/` are the external anchor.** This table is the spec measured against
them.

**It is not bound by a test yet, deliberately.** A check comparing this table to the card files
would be a document agreeing with a document — the pattern archived from the predecessor's map
folder along with the sixteen tests over it, which never touched the product's code. The real anchor
arrives with the first implemented rule: `RuleDefinition` already forces a rule to declare what it
reads, and when that declaration is widened from attributes to derived facts, a rule whose
declaration disagrees with its row here fails the build. **Until then this is a classification
nobody has executed, in a document whose banner says it is not truth.**

**It classifies shape, not correctness.** A rule that gets retuned during the rule audit almost
never changes machinery. A rule that gets re-scoped does, and that is a one-line edit.

### Legend

| Code | Machinery | Stage |
|---|---|---|
| `O` | object attributes | 1 |
| `M` | authorization membership closure | 2a |
| `P` | protected membership closure | 2a |
| `C` | capabilities from effective access | 2b |
| `T` | Tier 0 classification | 2c |
| `R` | reachability, paths, remediation | 2d |

| Marker | Meaning |
|---|---|
| **`gp`** | Group Policy content — **out of scope**, see below |
| **`set`** | needs an aggregate shape the spec does not define |
| **`time`** | needs an evaluation-time concept the spec does not define |
| **`abs`** | absence-as-finding, undesigned |
| **`subj`** | subject is not an account; `FindingSubjectKind` has one value |
| **`tier`** | needs tier vocabulary this spec does not carry |

### The table

| Rule | Name | Needs | Status |
|---|---|---|---|
| SEC-001 | Unexpected GenericAll on Domain | C T `subj` | subject kind |
| SEC-002 | Unexpected Principal can DCSync | C T | supported |
| SEC-003 | Unexpected Principal can Reset Admin Password | C M T | supported |
| SEC-004 | Unexpected Principal can Write DACL on Admin | C M T | supported |
| SEC-005 | Unexpected Principal can Write Owner on Admin | C M T | supported |
| SEC-006 | Unexpected Principal can Add Members to Admin Group | C M T | supported |
| SEC-010 | Unconstrained Delegation | O | **built** |
| SEC-011 | Unconstrained Delegation on Non-DC | O | **built** |
| SEC-012 | Constrained Delegation to Sensitive Service | O T | supported |
| SEC-013 | RBCD Configured on Privileged Resource | O T | supported |
| SEC-014 | Unexpected Principal can Configure RBCD | C | supported |
| SEC-020 | Kerberoastable Account | O | supported |
| SEC-021 | Kerberoastable Privileged Account | O M | supported |
| SEC-022 | AS-REP Roastable Account | O | supported |
| SEC-023 | AS-REP Roastable Privileged Account | O M | supported |
| SEC-024 | Unexpected Principal can Write SPN | C | supported |
| SEC-025 | Shadow Credentials Attack Vector | C | supported |
| SEC-026 | Duplicate SPN Registered | O `set` | **gap** |
| SEC-030 | AdminCount Without Protection | O P | supported — the case the two closures exist for |
| SEC-031 | Non-Default Owner on Admin Object | O M T | supported |
| SEC-032 | Disabled Privileged Account | O M | supported |
| SEC-040 | Unexpected Principal can Enroll Certificates | C `subj` | subject kind |
| SEC-041 | Certificate Auto-Enrollment for Non-Admin | C `subj` | subject kind — disabled in the predecessor |
| SEC-050 | Large Privileged Group | M `set` | **gap** |
| SEC-051 | Nested Group in Domain Admins | M | supported |
| SEC-052 | Circular Group Membership | M | supported — cycle as a finding, `AC-45` |
| SEC-060 | Broad Principal with Dangerous Write Access | C | supported |
| SEC-061 | Pre-Windows 2000 Compatible Access | M C | supported |
| SEC-062 | Domain Users in Local Admins Equivalent | M C | supported |
| SEC-063 | Unexpected Broad Control Over Container | C `subj` | subject kind |
| SEC-064 | Dangerous User Right Granted via Group Policy | `gp` | **out of scope** |
| SEC-065 | Privileged Local Group Membership via Restricted Groups | `gp` | **out of scope** |
| SEC-066 | Weak Directory or SMB Signing Posture | `gp` | **out of scope** |
| SEC-067 | Tier 0 Account Exposed to Delegation Impersonation | O M T | supported |
| SEC-070 | Short Path to Tier 0 Target | R T | supported |
| SEC-071 | Path to Tier 0 Target | R T | supported |
| SEC-072 | Path to Tier 0 Shadow | R T | supported — becomes evidence on the anchor finding, see below |
| SEC-073 | Short Path to Tier 1 Target | R T `tier` | **gap** — Tier 1 undefined here |
| SEC-074 | Path to Tier 1 Target | R T `tier` | **gap** — Tier 1 undefined here |
| SEC-075 | Path to Custom-Tier Target | R T `tier` | **gap** — depends on `P-85` |
| SEC-076 | Path to DCSync Shadow | R T | supported — evidence category |
| SEC-077 | Path to Unconstrained Delegation Host | R T | supported — evidence category, pending its `Tier0ClassificationEffect` |
| SEC-080 | Unexpected Principal can Modify GPO | C `subj` | subject kind — directory ACL, in scope |
| SEC-081 | Unexpected Principal can Create GPO Links | C `subj` | subject kind — directory ACL, in scope |
| SEC-082 | Unexpected Principal can Modify GPO via SYSVOL | `gp` | **out of scope** — file permissions |
| SEC-083 | Group Policy Preferences Password Exposure | `gp` | **out of scope** |
| SEC-090 | Unexpected Principal can Read LAPS Passwords | C | supported |
| SEC-091 | LAPS Missing on Computer | O `abs` | **gap** |
| SEC-092 | LAPS Password Rotation Stale | O `time` | **gap** |
| SEC-093 | LAPS Decryptor is a Broad Principal | O M | supported |
| SEC-100 | Service Account with Admin Privileges | O M | supported |
| SEC-101 | Service Account with Non-Expiring Password | O | supported |
| SEC-102 | Risky gMSA Password Retrieval Principal | O M | supported |
| SEC-120 | AdminSDHolder ACL Backdoor | C T | supported |
| SEC-121 | Domain Controllers OU Write Access | C T `subj` | subject kind |
| SEC-122 | RBCD Configured on Domain Controller | O T | supported |
| SEC-123 | Write SIDHistory Permission | C | supported |
| SEC-124 | Replication Topology Control Permission | C T `subj` | subject kind |
| SEC-126 | Privileged Service Account with Static Password | O M `time` | **gap** |
| SEC-131 | Privileged Account with Delegation Enabled | O M | supported |
| SEC-201 | DACL/Owner Control on Domain Root | C T `subj` | subject kind |
| SEC-204 | Unexpected Principal with High-Impact Right on Tier-0 Target | C T | supported |

### What the table found

**Group Policy content is out of scope — 5 rules.** SEC-064, 065, 066, 082 and 083. The parsers
exist in the kernel and nothing judges their output. SEC-082 is the clearest reason to keep it
separate: **SYSVOL file permissions are a different permission model from AD ACEs**, and folding
them into `2b` would dilute the one computation this document most needs to get right. `P-46` already
defers this to a Group Policy implementation; that deferral now has a named rule list.

**Three of the six path rules were resolved by the `Tier0ControlPlane` anchor; three remain.**
SEC-072, 076 and 077 targeted "Tier 0 Shadow", "DCSync Shadow" and "unconstrained delegation host"
— destinations that the `P-87` ruling retired as a tier vocabulary. Under the anchor they are not
destinations at all: they are **evidence categories on one reachability finding**, answering *which
seeds did this principal reach, and by what kind of route*. That is a better fit than the
predecessor's separate rules, because it stops the same principal producing three near-identical
findings.

**SEC-073, 074 and 075 are still gaps, for reasons the anchor does not touch.** SEC-073 and 074
need **Tier 1**, which the non-goals decline to define. SEC-075 needs customer-declared tiers, open
under `P-85`. These are not vocabulary problems — they need a classification this product does not
have.

**Nine rules need a subject that is not an account.** `FindingSubjectKind` has exactly one value,
`Account`, while these findings are about a GPO, an OU, a certificate template, the domain root or
a replication topology object. `docs/decisions/0023` already warns against wedging non-SID subjects
into a column assuming one. Small code change; invisible until attempted.

**Four rules need a shape the spec does not define.** Two aggregate — SEC-026 duplicate SPNs and
SEC-050 group size — and two need evaluation time, SEC-092 and SEC-126. Both shapes are absent from
the three rule shapes in Stage 3.

**One needs absence as a finding.** SEC-091, LAPS missing, which is where the tri-state discipline
matters most: absent because not deployed, or absent because a confidential attribute could not be
read?

**Roughly 44 of 62 are supported as designed**, 9 more need only a subject kind, and 9 need
something named above. Two are built.

## Improvements over the predecessor worth considering

Listed here because this document is also the place to notice them. None is decided.

- **Anchor the rule set to something outside itself.** The predecessor's catalogue, coverage map and
  cards agreed with each other and were checked in both directions — and fifteen captured
  attributes were still absent, because every check was anchored to the rules already written.
  Ask what a set of checks is anchored to, not only whether each is sound.
- **One catalogue per fact, consulted by every query.** The Tier-0 RID omission and the
  `LIKE '%-NNN'` defect were both a policy restated in SQL instead of asked of the type that owns it.
- **Record the traversal, not just the result.** The predecessor counted nodes expanded, paths
  dropped by cycle and dropped by dominance. Without those a pruning bug looks like a clean forest.
- **`ClearFindingsForRun(runId)` always deleted zero rows** in the predecessor, because the run id
  was generated four lines earlier. Harmless there; worth not reproducing.
