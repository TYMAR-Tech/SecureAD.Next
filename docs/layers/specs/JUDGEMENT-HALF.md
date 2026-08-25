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

#### Everything else both closures need

- the universal SIDs — `Everyone` (S-1-1-0), `Authenticated Users` (S-1-5-11),
  `This Organization` (S-1-5-15)
- **SIDHistory**, forward and reverse. An ACE naming an old SID from a migration grants access to
  the current principal. Missing this under-reports.
- cycle detection — AD permits membership loops

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

   An earlier draft of this document said *"deny ACEs cancel allow ACEs"* and carried a flag on the
   edge. That is a simplification that manufactures and destroys edges. Windows does not collect
   allows and subtract denies: it walks applicable ACEs in order, accumulating which requested bits
   are already granted or denied. So this is **not** sufficient:

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
3. **`S-1-5-10` (Principal Self) is excluded** — a placeholder meaning the object itself, not an
   attacker.
4. **Build is atomic.** Delete-and-rebuild in one transaction, so a mid-rebuild failure leaves the
   previous edge set rather than a half-built graph that rules would query happily.

**Attribute GUIDs are the sharpest edge in this stage.** The predecessor shipped three wrong
literals — `member` pointing at the group object-class GUID, `userAccountControl` at the computer
object-class GUID, and `msDS-AllowedToDelegateTo` at a property set — each a **silent false
negative**. Every GUID is verified against a first-party Microsoft source before use, per the
standing rule that the old app is never a seed for a harvest. `docs/rules/FIRST-PARTY-VERIFICATION.md`
is the ledger for this and is reused rather than restarted.

#### An edge carries a class, because not all hops are the same kind of thing

A sweep walks edges. If every edge looks alike, the traversal treats *"can rewrite this object's
DACL"* and *"privileged users might authenticate to this host"* as interchangeable steps, and they
are not. Each edge therefore declares:

| Class | Meaning | Example |
|---|---|---|
| `DirectoryControl` | The principal can change the target now. | `WriteDacl`, `AddMember`, `ResetPassword` |
| `CredentialExposure` | Credentials **may** become available, given something else happening. | unconstrained delegation on a host |
| `ConditionalEscalation` | Control exists only if a precondition holds. | a capability derived from ownership where implicit rights may be suppressed |

**Unconstrained delegation is the case that forces this.** It does not mean *this server controls
Domain Admins*. It means *if a sufficiently privileged principal authenticates to this server, and
the server is controlled, their credentials can be captured.* That is a real and serious exposure
and it is not the same claim as a directory write. Collapsing the two makes a three-hop chain read
as though every step were equally certain.

The class feeds the grading described in `2d`, and a chain is only ever as strong as its weakest
class.

#### `Owns` derives control conditionally

An object's owner ordinarily has implicit `WRITE_DAC`, and
[Owner of a New Object](https://learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object)
states it plainly. **But it is suppressible**, and
[Security identifiers](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers)
documents the mechanism: `S-1-3-4` OWNER RIGHTS — *"When an ACE that carries this SID is applied to
an object, the system ignores the implicit READ_CONTROL and WRITE_DAC standard access rights for the
object owner."*

So ownership is modelled as:

```
Ownership -> evaluate implicit owner rights -> WriteDacl capability, if actually available
```

with the resulting edge carrying whether it is effective, blocked, or conditional. **It is not an
unconditional `WriteDacl` edge**, and it must not silently join the equivalence set that treats
`WriteOwner` and `Owns` as conferring the ability to write RBCD or `msDS-KeyCredentialLink`. Those
are exactly the objects where owner-right restrictions matter most.

**Unverified and recorded as such:** a review raised `BlockOwnerImplicitRights`, a further mechanism
said to block implicit owner rights for computer-derived objects. It was **not found** in a search
of Microsoft Learn on 2026-08-25. It may exist in the Open Specifications rather than the product
documentation. Do not implement against it until a first-party source is in hand.

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
| `TierClassification` | Can it control the AD DS identity control plane? |

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

#### Deriving Tier 0 from control

Beyond the seeds, Tier 0 is **earned by control and never assumed from a label**. Each principal
carries:

| Field | Meaning |
|---|---|
| `Tier0Relationship` | `None`, `Seed`, `DirectControl`, or `TransitiveControl` |
| `Tier0Reason` | why, in a sentence an administrator can act on |
| `Tier0Path` | the chain of edges that proves it |
| `Tier0Scope` | whether the authority is object-, domain- or forest-scoped |

`Tier0Scope` exists because Schema Admins is forest-wide and a delegated OU administrator is not.
Reporting both as "Tier 0" without scope misstates the blast radius of each.

**A derived classification without a path is not a classification.** Every non-seed Tier 0 result
carries the edges that produced it, or it is not reported.

The derivations the predecessor computed as one-hop queries all fall out of the graph rather than
needing their own pass: transitive membership of a seed group, DCSync rights, unconstrained
delegation on a non-domain-controller, RBCD on a domain controller, and a GPO linked to the Domain
Controllers OU.

**Transitive membership here means the authorization closure** — security-enabled groups only, per
`2a`. Distribution-group nesting produces a latent-privilege finding, never a control edge.

**An edge is never created because two objects are both privileged.** Only an actual capability
makes an edge.

#### A raw extended right is not an attack capability

The three replication rights are captured as **facts**, and the capability that matters is
**derived** from them. Treating each as independently escalating over-reports.

[DS-Replication-Get-Changes-All](https://learn.microsoft.com/windows/win32/adschema/r-ds-replication-get-changes-all)
is documented as the *"control access right that allows the replication of secret domain data"* —
GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`. `DS-Replication-Get-Changes` on its own replicates
changes, not secrets. So:

```
CanReplicateSecrets  =  DS-Replication-Get-Changes
                        AND DS-Replication-Get-Changes-All
```

and only `CanReplicateSecrets` is Tier 0 control. A principal holding `Get-Changes` alone has a
finding worth reporting and is **not** holding the keys to every credential in the domain.

**Partly verified.** That `Get-Changes-All` is the secret-bearing right is confirmed above. That the
capability requires **both** rights together is the widely-held model and is **not** yet confirmed
against MS-DRSR's replication authorization algorithm. Confirm before implementing, and record the
result in `docs/rules/FIRST-PARTY-VERIFICATION.md`.

The same shape applies wherever a capability is more than one right — the pattern is to keep the
rights as captured facts and name the capability separately.

#### The closure problem, and how far Tier 0 spreads — OPEN

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

**The proposed resolution is to separate two questions the rule runs together**, and to name them
differently so they cannot be confused:

| Field | Applies to | Meaning |
|---|---|---|
| `TierClassification = Tier0` | seeds, and principals with **direct** control of a seed | what this principal **is** |
| `CanReachTier0` | anything with a route | what this principal **can do** |
| `Tier0Distance` | anything with a route | how many hops |

So the helpdesk group three hops out is:

```
Helpdesk-Tier2:
    TierClassification = Tier2
    CanReachTier0      = true
    Tier0Distance      = 3
```

and **not** `Tier0`. Nothing is hidden — the route is discovered, reported and remediable — but the
administrative tier keeps meaning something, and the count of Tier 0 principals stays small enough
to act on.

**This is a deliberate narrowing of Microsoft's words and must be recorded as ours.** Microsoft's
definition is *"assets and identities that **directly or indirectly** control the directory service"*,
and read literally, indirect control at any distance is Tier 0. We are declining to follow that to
its conclusion because the conclusion is a classification containing most of the forest — which is
the dilution Microsoft separately names as an anti-pattern. Both statements are Microsoft's; the
choice between them is ours.

Two refinements that compose with it: propagate only through **strong edges**
(`GenericAll`, `WriteDacl`, `WriteOwner`, `Owns`, `AddMember`, `ResetPassword`), and apply any hop
limit to the *plausible* grading rather than to discovery, since an attacker does not respect one.

**The counter-argument, recorded because it is good:** an attacker who compromises the helpdesk
group does become Domain Admin, so in risk terms it is effectively Tier 0. The answer offered is
that a classification including everyone drives no action, and the path report already names which
link to cut. **This is the owner's ruling and it is not yet made.** Tracked as `P-87`.

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

#### Reachability is computed backwards, once

A **single backward breadth-first sweep from the Tier 0 seeds along reversed edges** marks, for
every principal in the forest: whether it reaches a seed, the fewest hops, and a predecessor pointer
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

A finding is `(ruleId, principal, Tier 0 target)`.

**The rule id is not optional, and an earlier draft dropped it while citing the decision that
requires it.** `docs/decisions/0023` says identity is *the rule*, the subject and the object. Writing
`(principal, target)` alone would collapse genuinely different security problems into one row —
RBCD control over `DC01`, shadow-credential control over `DC01`, and GPO control reaching `DC01` are
three findings with three remediations, not one.

**The path is still excluded from identity**, and that is the point of the shape:
`docs/decisions/0023` makes identity stable so an acceptance stays attached, and
`docs/decisions/0067` has an acceptance name one finding. A path-shaped identity would change every
time an intermediate object moved, silently detaching every acceptance an administrator had made and
re-presenting the finding as new.

It follows that a finding closes when **reachability is `NotReachable` under complete coverage** —
not when a displayed path changes, and not when a sweep over incomplete data happens to find no
route. Where required inputs are missing the state is `Unknown`, which is neither open nor closed.
An administrator who cuts the route he was shown and sees the finding return has been misled, and
that is the failure this repository exists to prevent.

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
  question — *every route from here crosses there* — in near-linear time, and it is now part of the
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

- **Control-edge rules** — parameterised by control type and target filter. Takes an *equivalence
  set*: a rule about writing `msDS-AllowedToActOnBehalfOfOtherIdentity` must also match
  `GenericAll`, `GenericWrite`, `WriteAllProperties`, `WriteDacl`, `WriteOwner` and `Owns`, because
  each confers the ability. Duplicates collapse to one finding.
- **Tier/path rules** — filter by target tier, by tier reason, and by path length. Where a rule
  filters on a *reason*, writer and reader share one token catalogue so they cannot drift.
- **Attribute rules** — read object attributes across the set.

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
| 2 | effective group membership | "who is really in Domain Admins", against the lab |
| 3 | control edges | "who can take over this object", against the lab |
| 4 | Tier 0 seeds, and classification derived from the control graph | every finding carries honest severity, and the Tier 0 population is small enough to read |
| 5 | reachability, bounded path enumeration, and remediation sets | chains and residual counts, graded so the tool does not overclaim |

**Phases 4 and 5 were separate in an earlier draft and are not separable.** If Tier 0 is defined by
control reachability, a principal cannot be classified without walking the graph, and the graph's
targets are the things being classified — they are one fixpoint, not two passes. The predecessor
hid this by computing its Tier 0 classification as six one-hop SQL queries *before* building paths,
which is the same computation stopped at depth one; that is why it needed a separate
`Tier0Shadow` concept at all.

The value of the ordering is that **each phase is checkable against a real forest before the next
one rests on it.** A defect in effective membership silently corrupts every path built on top of
it, and the predecessor's two silent false negatives were both in this lower half.

**Phases 4 and 5 are not a rewrite of phases 2 and 3** provided the derived facts carry, from the
start, what a path needs: stable identifiers on every edge, the reason and scope of a Tier 0
classification, and the completeness of the data each rests on. Those are cheap now and expensive
to retrofit.

## Acceptance criteria for classification

These are written to become tests, and each names the mistake it catches. They are the reason the
four properties are kept apart, so they belong beside the design rather than in a later test plan.

| | Criterion |
|---|---|
| AC-01 | Privileged is not automatically Tier 0. A group that can reset ordinary users' passwords is `IsPrivileged` with `Tier0Relationship = None`. |
| AC-02 | Protected is not automatically Tier 0. Account Operators with only default authority is `IsProtectedPrincipal` and is not Tier 0. |
| AC-03 | A dangerous permission is judged with its target. `GenericAll` over an ordinary user is dangerous and not Tier 0. |
| AC-04 | Direct control of a seed is Tier 0. A principal able to modify Domain Admins membership is `Tier0 / DirectControl`. |
| AC-05 | A transitive chain is discovered and reported with its full path, whatever the ruling on `P-87` about labelling it. |
| AC-06 | A **custom** group is classifiable without appearing in any hard-coded Microsoft name list. |
| AC-07 | `adminCount = 1` alone never produces a Tier 0 classification. |
| AC-08 | A protected principal is reported as protected even when it is not a seed and holds no control. |
| AC-09 | Every derived classification carries at least one human-readable control path. A classification without one is not reported. |
| AC-10 | Cycles terminate. Group membership and control edges both form loops in real forests. |
| AC-11 | Renaming a well-known group does not lose its seed classification. Matching is by SID and RID. |
| AC-12 | Scope is retained — object-, domain- or forest-scoped authority is distinguishable in the result. |
| AC-13 | A finding's identity is `(principal, Tier 0 target)`. It survives the routes beneath it changing, so an acceptance stays attached. |
| AC-14 | A finding closes only when reachability reaches zero — never because a displayed route changed. |
| AC-15 | **Every remediation recommendation states what remains after it is applied**, including when the answer is nothing. This is the promise the design rests on. |
| AC-16 | A remediation claims completeness only when it is proven — a dominator cut may be described as eliminating every route; a greedy set may not. |
| AC-17 | A truncated route list says how many exist. "Showing 3 of 120", never 3 rows implying 3. |
| AC-18 | The same bundle yields the same routes in the same order. |
| AC-19 | Routes shown and remediation sets offered are recorded in the bundle, so a report is reproducible. |
| AC-20 | Where no small cut exists, the product says so in words rather than printing thousands of edges. |
| AC-21 | **A claimed dominator really is one.** For a sample of findings, removing the named waypoint and re-running the sweep yields zero remaining routes. A wrong dominator states a complete fix that is not one, which is the worst thing this product can do. |
| AC-22 | Where no single waypoint exists, the product says a multi-point change is required rather than presenting the best greedy edge as though it were sufficient. |
| AC-23 | A new route that bypasses a mandatory waypoint is detected as drift, because it removes that waypoint from the dominator chain. Asserted by planting a bypassing route between two bundles. |
| AC-24 | **An edge exists only where effective access exists.** A deny ACE that does not actually remove the claimed capability does not remove the edge, and one that does, does. Asserted with an allow-to-group plus deny-to-member fixture in both directions. |
| AC-25 | The authorization closure does not follow distribution groups. A user nested into a seed group through a distribution group has `CanReachTier0 = false` by that route, and produces a latent-privilege finding instead. |
| AC-26 | The protected closure **does** follow distribution groups, so the same user is `IsProtectedPrincipal`. AC-25 and AC-26 hold simultaneously on one fixture, which is the point of two closures. |
| AC-27 | `Owns` alone does not produce an unconditional `WriteDacl` edge where an OWNER RIGHTS (`S-1-3-4`) ACE suppresses implicit owner rights. |
| AC-28 | An edge's class is preserved. A `CredentialExposure` hop is never presented as equivalent to a `DirectoryControl` hop, and a chain is graded by its weakest class. |
| AC-29 | `DS-Replication-Get-Changes` alone does not yield `CanReplicateSecrets`, and does not classify its holder Tier 0. |
| AC-30 | Adding an ordinary computer to the Domain Controllers group (516) does not make it a Tier 0 asset. |
| AC-31 | **Reachability is tri-state.** With any required input incomplete, a sweep that finds no route reports `Unknown`, never `NotReachable`. |
| AC-32 | A finding closes only on `NotReachable` under complete coverage. `Unknown` is neither open nor closed and never renders as resolved. |
| AC-33 | No remediation claims completeness while the finding's reachability is `Unknown`; the wording names the gap instead. |
| AC-34 | A multi-hop reacher is not labelled `Tier0`. It carries `CanReachTier0` and `Tier0Distance`, and its route is still reported in full. |

**AC-05 is written to survive the open ruling.** Whether a transitive controller is *labelled* Tier 0
is undecided; that it is *found and shown* is not, and the test asserts only the settled half.

## Non-goals

Stated so a reviewer does not read absence as oversight. This specification does not:

- assign a severity to every dangerous permission — severity is fixed by the rule, per `0066`
- define the semantics of every access mask — that is the permission-classification layer's job
- discover Tier 0 infrastructure that is not represented in Active Directory
- infer compromise, intent, or that an attack has occurred
- declare every privileged principal Tier 0
- declare every AdminSDHolder-protected principal Tier 0
- define a full Tier 1 or Tier 2 catalogue

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
