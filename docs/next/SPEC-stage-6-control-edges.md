# Specification: stage 6, control edges

**Written 2026-09-05. Status: proposal for review. Not authoritative.**

Only two things in this repository state the product's position: a record in `docs/decisions/` with
`Status: Accepted`, and a finding carrying an explicit **Decision:** line. This document is neither.
It is a design put forward for review, and where it disagrees with the code the code wins and the
disagreement is a finding.

**What it is for.** Stage 6 turns permissions into *this principal can take over that object*. The
roadmap calls it the largest single piece and what makes an AD audit tool worth having. This document
says what an edge is, what it means, what the product will and will not claim, and what is still
undecided. It was written before implementation; the implementation boundary below distinguishes
what has since been built from what remains proposed or laboratory-gated.

**Terms are defined where they are first used.** A reader who administers Active Directory but does
not write software should be able to follow the whole document.

**Revised 2026-09-05 after external review.** The revision separates ownership transitions from
existing ownership, distinguishes `Self-Membership` from unrestricted membership modification,
preserves primitive derivations beneath aggregates, defines executable expectedness and counting
rules, clarifies replication scope, and corrects the AdminSDHolder treatment to cover the whole
security descriptor. Open verification items remain explicitly gated in sections 12 and 13.

**Historical implementation checkpoint, 2026-09-06.** The initial WRITE_DAC/WRITE_OWNER slice was implemented,
stored and shown in object-first and named-holder-first views. Its owner-to-DACL supporting compound
remains unknown and uncounted. Catalogue version 2 corrects P-150's BUILTIN domain scope; judgement
schema 15 stores the product. This does not implement membership changes, credential or replication
capabilities, existing-owner control, full-control aggregation or effective member expansion.
The [judgement-store document](../layers/judgement/the-judgement-store.md#p-150-corrected--catalogue-2-2026-09-06)
records the code boundary and measured lab comparison. P-145 and the claim-specific gates below
remain open. The remaining sections are still a proposal except where an accepted decision is cited.

**Current bounded implementation:** judgement schema **20**, control engine **4**, retains that
initial slice and the later membership/requester/password-reset products, and adds the explicitly
approved `CanWriteKeyCredentialLink` capability as `CredentialExposure`. The existing screen shows
password-reset and key-credential write permission evidence, not tested operations or sign-ins.
Automatic Self-Membership discovery remains inactive in both hosts without an approved budget.
Validated-write-only key-credential access, replication,
existing-owner control, full-control aggregation and effective member expansion remain unfinished.
The [implementation record](../layers/judgement/the-judgement-store.md#key-credential-write-permission--bounded-implementation)
owns behavior and validation. Approval of this bounded slice does not accept the entire proposal
or close P-145.

---

## 1. What already exists, verified against the code

Not from the roadmap, and not from the punch list. Originally checked on 2026-09-05; the control-edge
and schema entries below are refreshed for the approved key-credential write slice.

| What | Where | What it does |
|---|---|---|
| `EffectiveAccessCalculator` | `next/src/SecureAD.Evidence/EffectiveAccessCalculator.cs` | Works out what each trustee actually holds over one object: applies deny entries the way Active Directory applies them, ignores inherit-only entries, and keeps scoped entries apart from whole-object ones. Returns an outcome and an `IsComplete` voucher. |
| `GenericRightsExpander` | `next/src/SecureAD.Kernel/Security/GenericRightsExpander.cs` | Expands generic rights to the specific rights Active Directory maps them to, and names `WriteDacl` (`0x00040000`) and `WriteOwner` (`0x00080000`). |
| `BroadPrincipalCanTakeOverObject` (`SEC-060`) | `next/src/SecureAD.Judgement/` | Reports that a principal broad in every organisation can take over an object, conditioning `WriteOwner` on whether the owner's implicit rights survive. |
| `ObjectOwnershipRules` (`SEC-031`, `SEC-032`) | `next/src/SecureAD.Judgement/` | Report unaccepted ownership at `Low` for ordinary objects and `Medium` for protected objects. Both are version 2 and registered in `RuleCatalogue.All`; their shared owner predicate includes `0109`'s schema-only acceptance. |
| `ObjectTakeoverEvidence`, `ObjectOwnershipEvidence` | `next/src/SecureAD.Evidence/Findings/` | Typed evidence carriers, each with an `IsComplete` voucher. |
| `JudgementSchema` | `next/src/SecureAD.Judgement/JudgementSchema.cs` | Version 20. Findings, membership routes, bounded control evidence and separately stored requester assessments/discovery coverage. |
| `ControlEdge`, `ControlEdgeDeriver`, `ControlEdgeStorage` | `next/src/SecureAD.Judgement/` | WRITE_DAC/WRITE_OWNER, membership, password-reset and key-credential write permission slices, plus the unknown uncounted ownership compound. Written by `JudgingRun` and read through `JudgementReader`, with control engine 4. |
| `ControlEdgesSectionViewModel` | `next/src/SecureAD.Shell/ViewModels/ControlEdgesSectionViewModel.cs` | Paged object-first and named-holder-first views, expected primitives hidden by default with their count stated, plus coverage and supporting evidence. |
| **90+ acceptance criteria for this stage** | `docs/layers/specs/JUDGEMENT-HALF.md` | Already specify the capability record, `EdgeClass`, `Feasibility`, `Tier0Basis`, the replication compound capabilities, and the ownership rules. **This document builds on those and does not restate them.** |

**Two punch-list rows were wrong and are corrected.** `P-70` said the product does not judge
ownership; it does. `P-71` said nothing computes effective permissions; `EffectiveAccessCalculator`
does, and `SEC-060` consumes it. Both rows are corrected in `PUNCH-LIST.md` with what was found.

---

## 2. The four decisions this stage is built inside

Accepted 2026-09-05 by the owner.

- [`0095`](../decisions/0095-ownership-is-a-control-edge-where-the-owner-is-not-an-administrator.md)
  Ownership is a control edge, only where the owner is not an administrative principal, and only
  where an owner's implicit rights survive.
- [`0096`](../decisions/0096-effective-permissions-are-shown-object-first-and-principal-first.md)
  Two views over one stored edge set: object-first and principal-first.
- [`0097`](../decisions/0097-a-group-held-permission-is-counted-at-the-group.md)
  A group-held permission is counted at the group and expands to its members.
- [`0098`](../decisions/0098-a-control-edge-is-expected-or-unexpected.md)
  Every edge is stored and tagged expected or unexpected; the screen defaults to unexpected and
  always states how many it hides; a broad principal is never expected.

---

## 3. The ground this rests on, and where each claim comes from

Every claim below is sourced. A claim the product cannot source is marked as such and does not become
code.

| Claim | Source |
|---|---|
| `WRITE_DAC` is the right to change the DACL; `WRITE_OWNER` is the right to change the owner | [Access mask](https://learn.microsoft.com/windows-hardware/drivers/kernel/access-mask) |
| An object's owner implicitly has `WRITE_DAC`, so the owner can control access to the object | [Owner of a new object](https://learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object) |
| An `OWNER RIGHTS` (`S-1-3-4`) entry makes the system ignore the owner's implicit `READ_CONTROL` and `WRITE_DAC` | [Security identifiers, well-known SIDs](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers#well-known-sids) |
| `BlockOwnerImplicitRights` is character 29 of forest-wide `dSHeuristics`, values 0-3, absent defaults to 0, any other value resolves to 1 | [MS-ADTS 6.1.1.2.4.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5) |
| In Active Directory, `GENERIC_ALL` maps to Delete, Read Control, **Write DAC**, **Write Owner**, Create Child, Delete Child, Delete Tree, Read Property, Write Property, List Contents, List Object, Control Access, Write Property Extended | [MS-ADTS 6.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a) |
| `GENERIC_WRITE` maps to Read Control, Write Property Extended and Write Property **only** - so it cannot yield control of the DACL | MS-ADTS 6.1.3, same section |
| An `INHERIT_ONLY_ACE` is an ineffective ACE that does not control access to the object it is attached to | MS-ADTS 6.1.3, requirement 4 |
| `DS-Replication-Get-Changes-All` is the control access right that allows replication of secret domain data, GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | [DS-Replication-Get-Changes-All](https://learn.microsoft.com/windows/win32/adschema/r-ds-replication-get-changes-all) |
| `User-Force-Change-Password` (*Reset Password*) is GUID `00299570-246d-11d0-a768-00aa006e0529`, applying to user, computer, inetOrgPerson and managed service accounts | [User-Force-Change-Password](https://learn.microsoft.com/windows/win32/adschema/r-user-force-change-password) |
| `Self-Membership` (*Add/Remove self as member*) is GUID `bf9679c0-0de6-11d0-a285-00aa003049e2`, applying to groups | [Self-Membership](https://learn.microsoft.com/windows/win32/adschema/r-self-membership) |
| Fifteen accounts and groups are protected, and SDProp compares and resets them against the AdminSDHolder template, by default every 60 minutes | [Appendix C](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) |
| **What is protected is the whole security descriptor, not only the DACL.** `nTSecurityDescriptor` is the value that "defines ownership, permissions, and audited operations", and Active Directory "protects the SD on certain objects by periodically overwriting any changes" | [MS-ADTS 3.1.1.6.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dd3d29f3-8e1e-4e8c-a210-9eaef3abd628) |
| Tier 0 is the identity control plane: domain controllers, AD FS, AD CS, Entra Connect, Tier 0 admin accounts and groups, and systems that operate or manage them | [Tier model](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model) |
| Built-in groups named as Tier 0 are Backup Operators and Server Operators, introduced with *such as* | Tier model, Tier 0 section |
| Collapsing everything into Tier 0 dilutes it and increases the attack surface of the identity control plane | Tier model, anti-patterns |
| The AD FS service account is added to Enterprise Key Admins, and the permission that grant is documented as needing is Read and Write `msDS-KeyCredentialLink` on descendant user objects | [AD FS FAQ](https://learn.microsoft.com/windows-server/identity/ad-fs/overview/ad-fs-faq) |
| Replicator supports legacy file replication and holds no direct user rights | [Appendix B](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory) |
| Read-only Domain Controllers (521) and Enterprise Read-only Domain Controllers (498) are documented as containing RODC accounts, with no direct user rights | Appendix B, same page |

**Not sourced, and therefore not acted on.** The claim that domainprep operation 83 grants Key Admins
and Enterprise Key Admins Full Control over `CN=Keys` was not found in Microsoft's published
documentation during this pass. It is carried as a residual question in section 12 and must be
settled by the protocol specification or a recorded lab observation, not by inference.

---

## 4. What a control edge is

**A control edge is one stored statement: this principal can obtain control over this object, by this
means, and here is the evidence.** *Control* has four forms, and they are not the same thing:

| Category | What the principal obtains | Example |
|---|---|---|
| `DirectoryControl` | authority over the object's own security descriptor | rewrite the DACL, become the owner |
| `CredentialExposure` | the ability to authenticate as the object, without touching its permissions | reset its password, write a key credential |
| `MembershipEscalation` | the ability to change who is inside a group | add an account to Domain Admins |
| `ReplicationControl` | the ability to read secrets the directory holds about others | replicate secret domain data |

**A takeover edge is the `DirectoryControl` subset and that word is reserved for it.** The first
draft of this document defined every control edge as *rewrite the permission list, or a step that
leads directly to it*, and the external review was right that this does not describe the other three.
Resetting a password does not rewrite a DACL one move later; it is worse in some situations and
weaker in others, and calling both *takeover* would make the product's headline promise one model
while the catalogue implemented a broader one.

`EdgeClass` already exists in the capability record and already carries `DirectoryControl` and
`CredentialExposure`. **This document uses the accepted value `CredentialExposure` and does not rename
it.** A previous draft of this section wrote `CredentialControl`, which would have been exactly the
silent specification-to-catalogue drift this document objects to for the replication capability.
Any rename would need an owner decision. **Q10 is now settled by
[`0110`](../decisions/0110-membership-and-replication-have-distinct-control-edge-categories.md):
add `MembershipEscalation` and `ReplicationControl` without renaming existing categories.**
The existing specification's `ConditionalEscalation` vocabulary is retained as well.
Per `AC-28` these are categories and never an ordered risk score. This accepts the category choice,
not the rest of this proposal or any unverified capability.

An edge is **not** an access control entry. One entry can establish several capabilities, and several
entries can jointly establish one capability. **A group-held capability produces one counted group
edge plus a separately stored member expansion; it does not produce one counted edge per member** -
which is decision `0097`, and which is how the predecessor arrived at 111,627 edges on an eight
thousand object lab by doing the opposite.

### The edge is a projection of a capability, not a new concept

`JUDGEMENT-HALF.md` already defines the capability record: `Name`, `Target`, `EdgeClass`,
`Feasibility`, `Confidence`, `Preconditions[]`, `PropagatesControl`, `Tier0ClassificationEffect`,
`DerivedFrom[]`, `SourceFactIds[]`, `RemediationActionIds[]`, `EvaluationState`,
`DerivationGenerationId`.

**`ControlEdge` is that capability plus the two things the decisions of 2026-09-05 added**, and
nothing else:

| Field | Meaning | From |
|---|---|---|
| `Holder` | the principal the access control entry names, or the owner | `0097` |
| `Target` | the directory object or naming context over which the capability is established | matches `Target` in the capability record |
| `Capability` | the capability record above, unchanged | `JUDGEMENT-HALF.md` |
| `Expectedness` | `Expected` / `Unexpected` / `Unknown` | `0098` |
| `ExpectednessReason` | one of the reason codes in section 6, never prose | `0098`, section 6 |
| `ExpectednessCatalogueVersion` | the control-plane catalogue version that produced the answer | section 6 |
| `ResolvedMemberCount`, `UnresolvedMemberCount`, `ExpansionComplete` | the expansion, in three parts rather than one number | `0097`, section 7.1 |
| `Completeness` | whether every input behind this edge arrived | existing `IsComplete` pattern |

**The field is `Target`, not `Object`, and its wording is neutral.** A previous draft called it *the
directory object it can take over*, which contradicted the four categories above: a password reset
does not take over the target's permissions, and the field definition must not say it does. `Target`
also matches the name the capability record already uses, so there is one word for one concept.

**Adding fields to the capability record rather than inventing a parallel one is deliberate.** Two
definitions that must agree is the shape that has already cost this repository three defects.

---

## 5. The edge catalogue for stage 6

Stage 6 ships the edges below and no others. Each names what it is derived from and how it evaluates.
An edge class not on this list is stage 7 work or later, and is named in section 11.

**Primitive capabilities are what the derivation graph holds. Aggregates are for the screen.**

| Capability | Category | Derived from | Evaluation |
|---|---|---|---|
| `CanWriteDacl` | `DirectoryControl` | `WRITE_DAC` reaching the object, from any applicable entry, after denies | `Established` where the descriptor was read and parsed |
| `CanSetOwner` | `DirectoryControl` | `WRITE_OWNER` reaching the object | `Established` for the right itself. It does **not** by itself assert that a takeover follows |
| `CanSetTakeoverOwnerSid` | precondition, not an edge | whether the holder can name itself, or a SID it controls, as the new owner | see 5.1 |
| `OwnerWouldReceiveWriteDacl` | precondition, not an edge | the decision tree in 5.1 | `Established`, `NotEstablished` or `Unknown` |
| `IsOwnerAndCanRewriteDacl` | `DirectoryControl` | the owner field naming this principal, **and** `OwnerWouldReceiveWriteDacl` | compound; see 5.1 |
| `CanBecomeOwnerAndRewriteDacl` | `DirectoryControl` | `CanSetOwner` **and** `CanSetTakeoverOwnerSid` **and** `OwnerWouldReceiveWriteDacl` | compound; see 5.1 |
| `CanModifyGroupMembership` | `MembershipEscalation` | write property reaching `member` on a group | `Established`. Means the holder can add or remove **any** principal |
| `CanAddSelfToGroup` | `MembershipEscalation` | `Self-Membership` (`bf9679c0-0de6-11d0-a285-00aa003049e2`) reaching the group | `Established`, with the semantic precondition `AddedMemberSid == RequesterSid`. See 5.2 |
| `CanResetPassword` | `CredentialExposure` | `User-Force-Change-Password` (`00299570-246d-11d0-a768-00aa006e0529`) reaching the object | `Established` |
| `CanWriteKeyCredentialLink` | `CredentialExposure` | write property reaching `msDS-KeyCredentialLink` | `Established` |
| `CanReplicateSecretDomainData` | `ReplicationControl` | `DS-Replication-Get-Changes` **and** `DS-Replication-Get-Changes-All` on a naming-context root | `Established`. Target is the naming context, never an object beneath it (`AC-78`). Scope defined in 5.3 |
| `CanReplicateFilteredAttributes` | `ReplicationControl` | `DS-Replication-Get-Changes` **and either** `DS-Replication-Get-Changes-All` **or** `DS-Replication-Get-Changes-In-Filtered-Set` (`89e95b76-444d-4c62-991a-0facbeda640c`) | `Established`, exactly the `AC-77` predicate. The derivation records **which** qualifying right completed the compound |

**`HasFullControl` is an aggregate label and is not in the table.** It is displayed when the expanded
mask satisfies `GENERIC_ALL_MAPPING`, and the primitives it summarises stay in the graph underneath
it. The first draft said full control *supersedes* the primitives on the same object, and the review
was right that this loses information the product needs: a later deny may remove one primitive and
not another, a remediation may close the entry granting `WRITE_DAC` while a separate `WRITE_OWNER`
route survives, stage 7 needs the primitive transition rather than the user-facing label, and full
control is often assembled from several grants rather than one `GENERIC_ALL` entry. `AC-65` already
requires that many edges from one inherited entry share one remediation action, which is the right
mechanism for keeping the screen quiet - not discarding derivations.

**So: aggregate for presentation, never collapse the evidence graph.**

**The identity of a counted edge, stated so that aggregation is deterministic.** The first draft said
no configuration may produce two counted edges for one holder, one object and *one grant*, and the
review was right that this does not survive full control being assembled from several entries. The
key is:

```
(Holder, Target, Capability, DerivationGenerationId)
```

- **One entry granting `GENERIC_ALL`**: one aggregate edge; the primitives it expands to are
  derivations beneath it, each with its own source fact.
- **Several entries jointly satisfying the generic-all mapping**: still one aggregate edge, because
  the key does not mention the grant. It references a **set** of derivations, and each derivation
  keeps its own `SourceFactIds` and `RemediationActionId` - which is what makes remediation say
  *close these three entries* rather than *close this one*.
- **A deny removing one mapped primitive**: the aggregate is no longer established. The surviving
  primitives remain as their own counted edges. This is the case the first draft would have got
  wrong by discarding them.
- **Two independent complete routes to full control**: one aggregate edge with two derivation sets,
  and remediation states that closing either alone leaves the other - which `AC-15` already requires
  of every recommendation.

**`GenericWrite` is deliberately absent, and that is provable.** MS-ADTS 6.1.3 maps
`GENERIC_WRITE_MAPPING` to Read Control, Write Property and Write Property Extended and nothing else,
so it cannot yield control of the access control list. It may still produce a `CredentialExposure`
edge where the property it can write is one of the named ones above.

**Where a capability is a compound, it is one edge and not several.** `AC-29` is explicit: full
domain secret replication is one semantic capability, not two replication rights reported separately.
An operator who reads two rows thinks there are two problems.

**The replication capability was renamed.** The first draft called it `CanReplicateAllDomainSecrets`,
following `AC-44`. Microsoft's wording is that `DS-Replication-Get-Changes-All` "allows the
replication of secret domain data" - it does not use the word *all*, and filtered attribute sets make
*all* a stronger claim than the citation carries. `CanReplicateSecretDomainData` says exactly what
the source says. **This differs from the accepted `AC-44` wording and is therefore a finding against
that criterion, not a silent rename** - it is `Q8` in section 12.

### 5.1 Ownership, which the review was right to call too coarse

Becoming the owner is a **two-step sequence** and the first draft modelled it as one. It is now three
named parts, so that each can be established, refused or left unknown on its own evidence.

```
CanSetOwner                    the right to write the owner field exists
CanSetTakeoverOwnerSid         the holder can put itself, or a SID it controls, in that field
OwnerWouldReceiveWriteDacl     an owner of this object would actually get WRITE_DAC

CanBecomeOwnerAndRewriteDacl =
        CanSetOwner
    AND CanSetTakeoverOwnerSid
    AND OwnerWouldReceiveWriteDacl
```

**Being the owner already is a different statement**, and the first draft wrongly gave the two the
same precondition. `IsOwnerAndCanRewriteDacl` starts with the principal in the owner field and needs
only the third part. `CanBecomeOwnerAndRewriteDacl` needs the transition as well. The two also read
differently to an operator, which is the point: *is the owner and can rewrite the permissions* versus
*can make itself the owner and then rewrite the permissions*.

**`OwnerWouldReceiveWriteDacl` is an evaluation, not the presence of an entry, and here is the whole
of it.** The first draft said the precondition was that *no `OWNER RIGHTS` entry applies*, which was
too blunt - an `OWNER RIGHTS` entry may grant the rights the second step needs. The review then asked
for the branch where no such entry exists to be defined too, which was genuinely missing. The
algorithm:

```
1. Does the ordinary effective-access evaluation independently establish WRITE_DAC for
   the principal that would be the owner - that is, after denies, ignoring inherit-only
   entries, and without counting any implicit owner right?
       yes -> Established through the explicit-access route. The owner-specific rules in
              steps 2 and 3 do not affect this route, because it does not depend on
              ownership at all.

2. Does an applicable OWNER RIGHTS (S-1-3-4) entry exist on the object?
       yes -> evaluate the S-1-3-4 trustee through the ordinary accumulation:
              allows and denies in stored order, inherit-only ignored, scoped
              entries excluded from a whole-object question.
              Implicit WRITE_DAC is NOT added in this branch - Microsoft states
              the system ignores the owner's implicit READ_CONTROL and WRITE_DAC
              when such an entry applies.
              WRITE_DAC survives that evaluation -> Established, else NotEstablished.

       no  -> the owner receives implicit WRITE_DAC, subject to step 3.

3. Apply the documented blocks to the implicit-rights branch only:
       BlockOwnerImplicitRights (dSHeuristics character 29, 0-3, absent 0,
           malformed resolves to 1),
       the target object class,
       the documented Domain Admins / Enterprise Admins requester exemptions,
       the recorded server behaviour baseline.
       Not blocked -> Established. Blocked -> NotEstablished.

Any input in steps 1, 2 or 3 that was not read -> Unknown, never NotEstablished.
```

**Step 1 asks for effective access, not for the presence of an allow entry.** An earlier draft said
*does an explicit entry grant `WRITE_DAC`*, which could be read as satisfied by an allow that a later
deny removes - the exact error `EffectiveAccessCalculator` exists to prevent. It also said *nothing
below can take it away*, which overstated the claim: what steps 2 and 3 cannot remove is an
independently established right. A deny certainly can, and does so inside step 1.

Step 1 comes first because an independently established `WRITE_DAC` survives whatever happens to
implicit owner rights, and an implementation that checked the blocks first would report a real
capability as blocked.

Every precondition is named and recorded, because a `Conditional` capability with no named
precondition is invalid evidence:

| Precondition | State it records |
|---|---|
| `CanSetTakeoverOwnerSid` | whether the holder can name itself or a controlled SID as the new owner |
| `OwnerRightsEvaluation` | what `S-1-3-4` entries leave the owner, after denies |
| `IndependentWriteDaclOnOwner` | step 1 above - `WRITE_DAC` effectively held by the prospective owner without relying on ownership - recorded separately so it is visible as the reason |
| `BlockOwnerImplicitRights` | `dSHeuristics` character 29, values 0-3, absent is 0, malformed resolves to 1 (`AC-75`) |
| `TargetObjectClass` | because the block is documented against computer-derived classes (`AC-57`, `AC-58`) |
| `RequesterExemption` | the documented Domain Admins and Enterprise Admins exceptions (`AC-57`) |
| `ServerBehaviourBaseline` | the recorded server behaviour, never a hard-coded release name (`AC-75`) |
| `PrivilegeBasedTakeover` | whether `SeTakeOwnershipPrivilege` or `SeRestorePrivilege` is in scope |

**`CanSetTakeoverOwnerSid`: what the documentation says, and what is actually unverified.** A previous
draft of this document said Microsoft's sources were evenly split on who may be named as the new
owner. **That was wrong, and the correction matters more than the conclusion.** Microsoft's
[Owner of a new object](https://learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object)
states plainly that a process *"with the SE_RESTORE_NAME privilege enabled or with WRITE_OWNER access
to the object can set any valid user or group SID as the owner of an object"*, and the `TOKEN_OWNER`
constraint on the same subject governs the **default owner placed in a token for newly created
objects**. Those are two different operations, and read correctly the page is not split: at the
Windows authorization layer, `WRITE_OWNER` carries the broad behaviour.

So the position is:

- **Documented, Windows layer:** `WRITE_OWNER` establishes the ability to set a valid user or group
  SID as owner. The name `CanSetEligibleOwner` was dropped because *eligible* smuggled in the token
  rule as though it were settled.
- **Unverified, AD DS layer:** whether Active Directory imposes additional server-side constraints on
  this specific operation. The product audits AD DS, not an abstract securable object, and this
  document does not claim what it has not read.
- **Until the lab gate in 13.1 records it:** `CanSetTakeoverOwnerSid` is `Unknown` for AD DS targets,
  which under `AC-56` makes `CanBecomeOwnerAndRewriteDacl` `Unknown` rather than absent. `CanSetOwner`
  is still reported as `Established` on its own, so nothing disappears from the screen.

That conservatism is a deliberate choice and not a documentation finding, and `Q7` puts it to the
owner in those terms.

**Privilege-based takeover is out of scope for stage 6 and is stated rather than omitted.**
`SeTakeOwnershipPrivilege` and `SeRestorePrivilege` are held through user-rights assignment, which is
Group Policy, which the roadmap defers to the end. An edge that depends on a privilege the product
has not read would be a guess.

### 5.2 Self-Membership, which is not general membership modification

`Self-Membership` is a validated write permitting the requester to add or remove **its own account**
as a member. Write property over `member` permits changing membership generally. The first draft
merged them and the review was right that the two support different sentences:

- *Helpdesk can modify the membership of Domain Admins* - Helpdesk can add anyone.
- *This principal can add itself to Domain Admins* - and nobody else.

They are now separate capabilities. The second carries the semantic precondition
`AddedMemberSid == RequesterSid`, and remediation differs: removing a general membership write and
removing a self-membership grant are different changes with different blast radius.

**The hard case is a validated write granted to a group**, and stage 6 does not assume its way
through it. The likely reading is the review's: the group SID in the requester's token authorises the
entry, and the validated-write constraint is then evaluated against the requester and the value being
written, so each member can add **itself** and not arbitrary members of the trustee group. That is a
reading of how validated writes work, not a citation, and the product does not ship readings.

**So the `Unknown` is an interim evidentiary gate and not a claim about Active Directory.** Worded
precisely, so that a later session does not mistake it for settled semantics: *until the
`Self-Membership` requester semantics are established from MS-ADTS or from recorded laboratory
evidence, the expanded member capabilities are `Unknown`.* When the evidence arrives the gate is
replaced by protocol-backed behaviour, and the replacement is not a reversal of an accepted rule.
A trustee that is itself a security principal is `Established` today.

### 5.3 What the replication capability does and does not include

Renaming was not enough; the review was right that the boundary needs stating.

| Question | Answer |
|---|---|
| What does `CanReplicateSecretDomainData` mean? | The secrets reachable through `DS-Replication-Get-Changes` together with `DS-Replication-Get-Changes-All`, which Microsoft describes as allowing replication of secret domain data. Nothing wider. |
| Are RODC filtered-set attributes included? | **No.** They require `DS-Replication-Get-Changes-In-Filtered-Set`, which is a distinct extended right with its own GUID. |
| Does the filtered-set right produce its own capability? | Yes - `CanReplicateFilteredAttributes`, whose predicate is exactly `AC-77`: `Get-Changes AND (Get-Changes-All OR Get-Changes-In-Filtered-Set)`. It is a separate primitive and is never folded into the compound above. The catalogue formula, the capability name and `AC-77` state the same predicate, and the derivation records which qualifying right completed it. |
| So the two replication capabilities overlap? | Yes, deliberately, and `AC-77` already says so: a principal holding `Get-Changes` and `Get-Changes-All` establishes both, while a principal holding `Get-Changes` and `Get-Changes-In-Filtered-Set` alone establishes only `CanReplicateFilteredAttributes` and **not** `CanReplicateSecretDomainData`. They answer different questions - what secrets are reachable, and whether the filtered set is reachable - so neither subsumes the other. |
| Which naming contexts? | The extended rights apply to `Domain-DNS`, `Configuration` and `DMD` (the schema). The capability records **which** naming context it was established against, and a Configuration or schema target is named as such rather than reported as domain secrets. |
| What is the target? | Always the naming-context root, never an object beneath it (`AC-78`). |

---

## 6. Expectedness, which is the decision that makes the screen usable

**The rule, in words.** An edge is `Expected` when its holder is part of the control plane that
already controls the object anyway - Domain Admins over a user account. It is `Unexpected` otherwise.
It is `Unknown` when the control plane or the holder's scope could not be established, and `Unknown`
never renders as `Expected`.

**The rule, as something that can be executed and tested.** The review was right that the words above
are a principle and not an algorithm. Expectedness is a versioned function returning a value and a
reason, never prose:

```
Expectedness(holder, target, capability, authorityScope, catalogueVersion)
    -> (Expected | Unexpected | Unknown, ReasonCode)
```

The reason codes are the whole of the vocabulary, and every stored edge carries one:

| Reason code | Meaning |
|---|---|
| `ExpectedSameDomainControlPlane` | the holder is control plane for the domain the target lives in |
| `ExpectedForestControlPlane` | the holder is forest-wide control plane and the target is in that forest |
| `UnexpectedBroadPrincipal` | the holder is in `BroadPrincipalCatalogue`; this outranks every other answer |
| `UnexpectedOutsideAuthorityScope` | the holder is control plane somewhere, but not over this target |
| `UnexpectedNotControlPlane` | the holder is not control plane anywhere |
| `UnknownControlPlaneCatalogueIncomplete` | `P-85` has not settled the seed set this run needs |
| `UnknownTrustResolutionIncomplete` | the target's domain or the trust to it could not be resolved |
| `UnknownMembershipIncomplete` | the membership walk behind the holder's control-plane status stopped early |
| `UnknownHolderIsPlaceholder` | the holder is `CREATOR OWNER` or another placeholder, so there is no principal to attribute the edge to - added by `0099` |
| `ExpectedPlatformIdentityDirectAce` | the holder is `SYSTEM` and an applicable ACE on the target establishes the capability - added by `0100`, and deliberately distinct from the two control-plane reasons |

**Eight questions the predicate must answer, and none of them may be left to the implementer.** These
are exactly what turns `P-85` from a list of group names into something testable, and each one is a
place where a wrong answer silently hides edges:

1. Does control-plane membership follow direct membership only, or transitive membership? Transitive,
   consistent with `AC-49`, and distribution-only nesting never confers it (`AC-25`, `AC-26`).
2. Does `sIDHistory` participate? A separate question from membership and it must be answered
   explicitly rather than inherited from whichever walk happens to run.
3. Is a domain-local administrative group expected over objects in another domain? `AC-41` already
   holds that membership is target-independent while authorisation usability is context-dependent,
   which is precisely this question.
4. How are forest and domain boundaries evaluated, and what happens across a trust?
5. Is an expected holder expected for **every** capability, or only those consistent with its role?
   **Authority scope and capability scope are two different things and the predicate needs both.**
   Authority scope says *where* a principal has administrative authority; capability scope says
   *which* capabilities are expected for that role. For Domain Admins and Enterprise Admins the
   capability scope is legitimately unrestricted within their authority scope. For a narrower
   control-plane entry - a delegated or role-specific administrative group, which `P-85` may well add
   later - expectedness requires **both** to agree, so that a group expected to reset passwords does
   not silently become expected to rewrite every DACL in the domain. A catalogue entry that does not
   declare an unrestricted capability scope does not get one by default.
6. Do customer-declared Tier 0 **assets** change expectedness? Proposal: no. Declaring an asset marks
   something to watch; it does not make anyone's control of it expected.
7. Does controlling a Tier 0 object make the controller expected? **No.** That is exactly the
   escalation stage 7 exists to find, and answering yes would hide it.
8. Is the answer stable across runs? It must be, and the catalogue version is stored on the edge so
   that a change of answer is visible as a change of version rather than as unexplained drift.

**Four conditions carried unchanged from `0098`.**

1. Nothing is discarded. Every edge is computed, stored, exported and countable.
2. The suppressed count is always on screen: *42 unexpected control edges (111,585 expected,
   hidden)*. A hidden number that is not stated is a hidden number nobody knows to open.
3. A broad principal is never expected. `Everyone`, `Authenticated Users`, `Domain Users` and the
   rest of `BroadPrincipalCatalogue` always surface, whatever they hold and wherever they hold it.
   There is no organisation in which everyone is the expected administrator of anything.
4. Expectedness is a tag and a default filter, never a change to what the product concluded - which
   is the distinction [`0092`](../decisions/0092-a-view-filter-is-not-a-change-to-the-catalogue.md)
   permits, under its three conditions.

**Expectedness is decided by the holder and the object together, not by the holder alone.** Domain
Admins over a user account is expected. Domain Admins over a certificate template in another forest's
trust is not the same statement, and the rule must be able to tell them apart. The mechanism is the
capability catalogue's `Tier0ClassificationEffect` for the target class, which already exists.

**This is where `P-85` gated the stage, and it is now settled.**
[`0099`](../decisions/0099-the-tier-0-control-plane-catalogue.md), accepted 2026-09-06, names the
control-plane catalogue with an authority scope and a capability scope per entry, and answers the
eight questions above: transitive membership, `sIDHistory` never conferring it, placeholders never
being holders, domain controller computer accounts being assets rather than entries, and customer
declaration being available for assets only. **The one thing it left open is now settled too**:
SYSTEM's capability scope is [`0100`](../decisions/0100-system-is-a-descriptor-native-expected-trustee.md)
- expected for what an applicable ACE on the target establishes, scoped by that ACE and its valid
inheritance, transferring to no other principal, and `Unknown` where the descriptor could not be
read. That is a descriptor-native trustee rather than a catalogue administrator, and it carries its
own reason code.

**A stated consequence, so nobody discovers it later.** An expected edge is still a path. Expectedness
affects the default view; it does not remove an edge from a chain in stage 7. A route that runs
through an expected edge to reach an unexpected one is still a route and is still reported.

---

## 7. Attribution, counting, and the number an operator reads

From `0097`. Both the group edge and the member expansion are stored; the group edge is what is
counted; members expand on request.

- The headline reads *Helpdesk (400 members) can take over OU=Finance*.
- The counted edge names the principal the access control entry names, because that is the thing an
  administrator changes. A count an operator cannot act on is a number he learns to scroll past.
- The member expansion is stored, not recomputed at display time, so a view can never disagree with
  the edge that produced it.
- The route travels with the edge, as `PathFromRoot` already does for `SEC-060`, and the completeness
  voucher travels with it. A membership walk that stopped at a budget makes the expansion incomplete,
  and the expansion says so rather than appearing short.

**Remediation counting follows the same principle and it is already specified.** `AC-65`: many edges
produced by one inherited entry share one `RemediationActionId`, so the recommendation names the
source entry once rather than thousands of child edges. `AC-66`: one direct group membership feeding
many transitive paths remains one source action.

**P-105 is fixed by `0106`; do not schedule that fix again.** The current stored protection reason
selects a nearest root deterministically. `0108` subsequently changed the reporting requirement:
one finding must summarize independent membership routes, including longer routes and shared
initial memberships. P-146 now supplies that separate derived summary, persisted finding evidence
and both finding views. The single selected protection path is not that summary. This foundation
does not implement control edges or start stage 6.

**A primitive and its aggregate never both count for the same established aggregate.** Since section 5
keeps `CanWriteDacl` and `CanSetOwner` in the graph beneath `HasFullControl`, the counting rule has to
say which is counted. Where `HasFullControl` is established for a holder, target, capability and
derivation generation, **it** is the counted edge and its primitives remain derivation evidence
beneath it. Where the aggregate is not established - because a deny removed one of the mapped
primitives, or because the mapping was never satisfied - the surviving primitives are counted
independently. The identity that governs this is in section 5, and it deliberately does not mention
the grant, because full control can be assembled from several entries.

### 7.1 What *effective member* means, in full

The expansion counts are shown to an operator as fact, so what they count has to be written down
rather than left to whichever walk runs. The review was right to ask. Several of these already have
accepted criteria and are cited rather than re-decided.

| Case | Treatment | Source |
|---|---|---|
| Nested groups | included, transitively | `AC-49` |
| Cycles | terminate deterministically; may also raise a finding | `AC-10`, `AC-45` |
| Distribution-group nesting | never confers current authorisation; produces a latent-privilege finding and `Feasibility = Potential` | `AC-25`, `AC-26` |
| `primaryGroupID` membership | included; a user whose primary group is Domain Admins is found | `AC-63` |
| Foreign security principals | retained as a SID-based node, never dropped | `JUDGEMENT-HALF.md`, unresolved trustee rule |
| Unresolved SIDs | retained, and they make the expansion incomplete | `AC-56` |
| `sIDHistory` | **open**; see the expectedness question 2 above and `Q9` |
| Domain-local scope across a trust | authorisation usability is context-dependent, so scope is evaluated, not assumed | `AC-41`, `AC-53` |
| Builtin groups with equal SIDs in different naming contexts | distinct directory objects; trustee matching stays SID-and-context based | `AC-42` |
| Disabled accounts | counted, and flagged; a disabled account is a credential that can be re-enabled by anyone holding these very edges | this document |
| Deleted or tombstoned principals | not counted as members; an owner that does not exist is already handled by `ObjectOwnershipEvidence` | existing code |
| Membership captured at a different moment from the descriptor | both carry their derivation generation, and a mismatch makes the expansion incomplete | `AC-71` |

**One count cannot carry all of that**, so there are three numbers and a flag rather than one:

```
ResolvedMemberCount     principals resolved to a directory object
UnresolvedMemberCount   SIDs retained but not resolved, including foreign principals
ExpansionComplete       whether every input the walk needed arrived
```

A single `MemberCount` would look authoritative while unresolved foreign principals sat outside it,
which is the *silently smaller number* failure this repository has already paid for once.

---

## 8. Silences, and the one thing an audit tool must never do

**A permission that could not be read is never reported as safe.** A production domain returned
19,927 of 100,000 objects with no readable security descriptor. `EffectiveAccessCalculator` already
keeps four states apart - computed, descriptor not read, DACL absent meaning everyone has everything,
and entries declared but unparsed - and stage 6 carries all four through to the screen rather than
flattening them.

Three rules, all of which already have acceptance criteria:

- Missing schema, property-set, object-class, inheritance, trustee or security-descriptor evidence
  yields `Unknown`, never *capability absent* (`AC-56`).
- A NULL DACL and a present-but-empty DACL are different states with different results (`AC-55`).
- Unknown is relevant, not global: missing evidence that cannot affect a principal's possible path
  does not turn that principal `Unknown` (`AC-73`).

**And the coverage commitment the dashboard already makes applies here.** How much of the forest was
read is stated before any number on the screen, and stated every time - including when nothing was
missed, so its absence is never read as reassurance.

---

## 9. Where the edges are stored

**In the judgement store beside the findings.** Current `JudgementSchema.Version` is 20. The
implemented bounded slices use the existing control product/object/edge/ACE/precondition tables
described in the judgement-store document; they do not implement all the proposed tables below.

The full-stage design proposes four tables:

- `control_edge` - one row per counted edge: holder SID, holder name, object GUID, object DN,
  capability name, edge class, feasibility, confidence, evaluation state, expectedness, expectedness
  reason code, expectedness catalogue version, resolved and unresolved member counts, expansion
  completeness, derivation generation.
- `control_edge_derivation` - the primitive capabilities beneath an aggregate, so `HasFullControl`
  never erases `CanWriteDacl` or `CanSetOwner`, each row carrying its own `RemediationActionId`.
- `control_edge_member` - the expansion from `0097`: effective principal SID, expansion basis
  (nested, primary group, direct), membership path, resolution state, source fact ids, completeness,
  and derivation-generation linkage.
- `control_edge_precondition` - the named preconditions from 5.1 and their states, because a
  `Conditional` capability with no named precondition is invalid evidence.

**Why the judgement store and not a new one.** The edges are consumed by rules, by the screens, by
export and later by stage 7's path search. A second store would need its own versioning, its own
compatibility check and its own reader, and the two would drift. `AC-71` already requires an explicit
compatibility check between derivation generations, and reusing the store means reusing that check
rather than writing a second one.

---

## 10. What the screens show

From `0096`: two views over one stored edge set, each a query rather than a second computation.

**Object-first.** Pick an object; see every principal that can control it, by which capability, and
whether that is expected. This is the shape an AD administrator already knows from the Windows
*Effective Access* tab, and the familiarity is the point.

**Principal-first.** Pick a principal; see every object it can control, by which capability. This
answers *what does this service account actually reach*, which the object-first view cannot answer at
any cost.

Both default to unexpected edges and state the hidden count. Both inherit the calculator's silences:
an object whose descriptor could not be read is shown as unanswered, never as *nobody can take it
over*.

---

## 11. What stage 6 does not do

Naming these here so a reviewer does not read their absence as an omission.

- **Chaining.** *This principal can reach Tier 0 in three hops* is stage 7. Stage 6 produces the
  edges; it does not walk them. `Tier0Reachability`, the synthetic control-plane anchor and route
  grading all belong to stage 7 and already have criteria (`AC-31`, `AC-46`, `AC-72`).
- **Proving a remediation closes a path.** Stage 8.
- **Group Policy applicability as an edge.** `AC-43` requires site, domain and OU scope, link state
  and order, enforced and blocked inheritance, security filtering and WMI. That is a stage of its
  own and the roadmap already defers Group Policy to the end.
- **Full principal-level effective access as described in `docs/planned/effective-access.md`.** That
  document's R8, R12 and R19 name inputs the current capture does not collect - `fDoListObject`,
  parent-and-child visibility, operation and connection context. Stage 6 answers layer 3, accumulated
  capability, for the named capability list. It does not claim layer 4 for every right.
- **Tier 1 and Tier 2 classification.** `AC-54`: no principal is assigned Tier 1 or Tier 2 until an
  accepted catalogue defines those values, and the harder half - which computers those are - is
  recorded as `F-S45-11`.

---

## 12. Residual questions, for the owner

The question numbers are retained for references. Settled choices name their accepted records;
remaining proposals are explicitly labelled and must not be treated as decisions. Laboratory
verification of a capability is separate from whether its reporting policy has been settled.

**Q1. AD CS and AD FS servers as Tier 0. Settled by `0099`: automatic enterprise CA classification,
declaration-only AD FS.** The directory names certificate authorities in the Configuration
container; nothing reliably marks an AD FS server. Implementation remains on P-142 and P-143,
not an unanswered choice about automatic classification.

**Q2. Key Admins (526) and Enterprise Key Admins (527). Settled 2026-09-06 by `0099`; the paragraph
below was wrong and is corrected in place.** Microsoft's AD FS documentation states the grant these
groups are given is Read and Write `msDS-KeyCredentialLink` on descendant user objects. That is
exactly the `CanWriteKeyCredentialLink` capability in section 5, which the product will report as a
`CredentialExposure` edge on every user in scope. **This document previously recorded that the
`CN=Keys` Full Control claim was not found in Microsoft's published documentation. That was a false
negative and the punch-list row was right.** [Domain-wide schema
updates](https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/domain-wide-updates) -
the same page `P-86` already cites - operation 83: *"Add Full Control allow aces to CN=Keys container
for `domain\Key Admins` and `rootdomain\Enterprise Key Admins`"*, mask
`(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;Key Admins)`, which includes `WD` and `WO` and inherits.
**No lab observation is required and the proposal that one was needed is withdrawn.** The answer is
unchanged: both groups stay out of the control plane, because `CN=Keys` holds key credential objects
rather than accounts and control of it is not administrative authority over a domain - and because
operation 89 shows Microsoft withdrawing the Enterprise Key Admins grant themselves, replacing it
with an object-specific write on `msDS-KeyCredentialLink`. That withdrawal is a rule candidate,
`P-144`.

**Q3. Read-only Domain Controllers (521), Enterprise Read-only Domain Controllers (498) and
Replicator (552).** Microsoft documents all three as containers of accounts or as legacy file
replication support, with no direct user rights. This is the same shape as the Domain Controllers
group (516), which the owner already ruled out on the grounds that a group of domain controllers is
not a domain controller - a ruling `AC-30` already encodes. **Settled by `0099`: all three out; the RODC
computer account remains a Tier 0 asset.**

**Q4. Customer-declared Tier 0.** Two different declarations with opposite risks. Declaring an
**asset** adds something to watch. Declaring a **principal** as control plane hides its edges by
default. **Settled by `0099`: assets only. A specific edge that is fine here is handled by accepting the
finding, which is on the record, one finding at a time.**

**Q5. `P-105`, which root a membership is attributed to. Settled by `0106`; the reporting choice
was revised by [`0108`](../decisions/0108-a-finding-summarizes-independent-membership-routes.md),
2026-09-05, for `P-146`.** A finding summarizes independent membership routes, including longer
routes, grouping shared initial memberships rather than adding a row for each outer group. The
answer must remain deterministic and must not claim that every other form of privilege is removed.
The derivation retains its selected protection basis and also stores the independent route summary.
P-146 implements the latter through SEC-021 finding evidence and both existing finding views; stage 6
must reuse the explanation without multiplying its counted permission edges by route count.

**Q6. How much is too much. Settled 2026-09-06 by
[`0102`](../decisions/0102-group-expansion-is-budgeted.md): budgeted expansion that admits when it is
partial.** The lab is 8,383 objects and a customer forest of 100,000 will produce a large stored
expansion. Microsoft publishes no product-specific safe threshold, so this document does not invent
one. Expansion runs against explicit budgets - nodes, links, elapsed time, stored records - keeps
everything found, never drops the counted group edge, sets `ExpansionComplete = false` with a stop
reason, states on screen that the view is partial, and never presents a partial count as total
effective membership. The same input and budget must stop deterministically, and the export carries
both.

**Q7. Who may be named as the new owner.** Microsoft states that a holder of `WRITE_OWNER` "can set
any valid user or group SID as the owner of an object", and the `TOKEN_OWNER` constraint governs the
default owner for newly created objects rather than this operation. **The documentation is not split
and an earlier draft of this document was wrong to say it was.** What is genuinely unverified is
whether AD DS adds server-side constraints of its own, because the product audits AD DS rather than
an abstract securable object. **Settled 2026-09-06 by
[`0103`](../decisions/0103-an-established-primitive-is-not-contaminated-by-an-unverified-compound.md):
three claims, kept separate.** `CanSetOwner` is `Established` wherever effective access establishes
`WRITE_OWNER`; `CanSetTakeoverOwnerSid` stays `Unknown` until the 13.1 lab gate records what `ad.lab`
permits; `CanBecomeOwnerAndRewriteDacl` is `Unknown` unless every precondition is `Established`.
**Confidence never flows backwards** - the established primitive is not reduced because the compound
above it is unverified, which would make the product quieter about something it can prove.

**Q8. `AC-44` names the capability `CanReplicateAllDomainSecrets`; this document proposes
`CanReplicateSecretDomainData`.** Microsoft's wording is *secret domain data*, without the word
*all*, and filtered attribute sets make *all* a stronger claim than the citation supports. A criterion
and a specification disagreeing is a finding. **Settled 2026-09-06 by
[`0104`](../decisions/0104-the-capability-is-named-canreplicatesecretdomaindata.md):
`CanReplicateSecretDomainData`.** `CanReplicateFilteredAttributes` stays a separate capability and the
target naming context is recorded separately. **`AC-44` is migrated rather than aliased
indefinitely** - the old name survives only as a schema migration alias for reading historical
results, never as a second current capability.

**Q9. Does `sIDHistory` confer control-plane membership for the purpose of expectedness?** It confers
authorisation in Active Directory, and `PrivilegedSidHistory` already reports it as a finding. Whether
it should also make an edge *expected* is a different question, and answering it yes would hide edges
that the existing rule reports as dangerous. **Settled by `0099`: no - `sIDHistory` never makes an edge
expected, and the existing finding continues to report it.** This is now `AC-S6-15` rather than only a
question, because it is a rule an implementer would otherwise have to guess at.

**Q10. `EdgeClass` naming. Settled by
[`0110`](../decisions/0110-membership-and-replication-have-distinct-control-edge-categories.md).**
The owner accepted adding `MembershipEscalation` and `ReplicationControl`, without renaming or
removing existing categories. Retain `DirectoryControl`, `CredentialExposure` and the existing
specification's `ConditionalEscalation` vocabulary. These are SecureAD's semantic categories,
not a Microsoft taxonomy or a risk ranking. Persistence, the capability catalogue, presentation
and future export must agree on the values (`AC-S6-13`). Counting, expectedness, severity and
the claim-specific laboratory gates are unchanged; this does not accept the rest of the proposal.

---

## 13. How this will be shown to work

- **Every gate carries a self-test**, because a check that passes while measuring nothing is the
  worst failure class in this repository and has happened three times.
- **Every test is watched failing before it is believed.** Mutate, observe, revert, one at a time.
- **The lab bundle is the anchor**: `ad.lab-20260905-035415`, three domains, 8,383 objects, with
  planted positives that `Set-LabOwnershipAndTakeover.ps1 -Remove` clears. An edge count is checked
  against the live directory by hand before it is believed.
- **Inspect what dominates the unexpected count, not merely its size.** P-145 distinguishes real
  overdelegation from necessary platform behavior classified or presented incorrectly. A large
  count alone does not justify changing the catalogue, and its gate runs after stage 6 produces
  output, before acceptance.
- **Ask what the checks are anchored to.** `JUDGEMENT-HALF.md` supplies product requirements;
  underlying AD semantics need Microsoft sources and the stated laboratory checks. Agreement
  between this repository's code, tests and prose is not by itself an external anchor (`F-S44-2`).

### 13.1 Laboratory checks for gated semantics

These three checks govern the claims they verify, not the start of every part of stage 6. Under
`0103`, established primitive owner-setting rights remain established while unverified compound
ownership claims remain unknown. Group-held Self-Membership expansion has its own unknown boundary.
The owner-reset observation in F-S45-7 informed SEC-032's Medium severity; it does not claim to
complete the controlled tests listed below.

**The owner-write gate, for `Q7`.** Two halves, and the second is the one the review asked for.

*Who may be named as owner.* Grant a test principal `WRITE_OWNER` and nothing else on a test object;
attempt to set the owner to the principal itself; attempt to set it to an unrelated account; attempt
to set it to a group the principal belongs to. This settles whether AD DS constrains the operation
beyond the documented Windows behaviour.

*What the resulting owner receives.* Eight cases, because varying only `BlockOwnerImplicitRights` and
the presence of an entry proves that `OWNER RIGHTS` matters without proving the accumulation is right:

1. No `OWNER RIGHTS` entry at all.
2. `OWNER RIGHTS` allowing `WRITE_DAC`.
3. `OWNER RIGHTS` denying `WRITE_DAC`.
4. `OWNER RIGHTS` allowing some other right but not `WRITE_DAC`.
5. Conflicting `OWNER RIGHTS` allow and deny entries, in both stored orders.
6. An explicit `WRITE_DAC` granted directly to the account that becomes the owner.
7. A computer-derived target versus a target outside the documented block behaviour.
8. An exempt requester (Domain Admins) versus a non-exempt one.

Each case is run with `BlockOwnerImplicitRights` at 0 and at 1. The result is labelled
**lab-verified**, never *specified*, exactly as `AC-64` requires for its own blocked claim.

**The Self-Membership gate, for 5.2.** Six cases, because the interesting one is the group grant:
`Self-Membership` granted directly to a user; granted to a group containing the user; granted through
a nested group; the requester adding itself; the requester adding a different account; the requester
removing itself versus removing another member. Record which succeed. Until this is recorded, a
group-held `Self-Membership` entry produces `Unknown` for expanded members.

**The AdminSDHolder owner gate, for section 3.** Change **only** the owner of an AdminSDHolder-protected
group, leave the DACL untouched, run `RunProtectAdminGroupsTask`, and record whether the owner is
restored. MS-ADTS 3.1.1.6.1 says the security descriptor is overwritten and that the descriptor
defines ownership; the observation says what actually happens on this build, and the rule is anchored
to both.

---

## 14. Acceptance criteria this specification adds

These extend the criteria in `JUDGEMENT-HALF.md` rather than replacing any. Numbered separately as
`AC-S6-n` until they are folded in, so that nothing here is mistaken for an already-accepted
criterion.

| id | Criterion |
|---|---|
| `AC-S6-1` | A principal holding `WRITE_OWNER` whose owner-rights evaluation does not establish `OwnerWouldReceiveWriteDacl` does not receive an unconditional DACL-takeover edge. It receives `CanSetOwner` and a compound capability that is `Conditional` or `Unknown`. |
| `AC-S6-2` | `CanSetTakeoverOwnerSid` evaluating to `Unknown` makes the compound ownership capability `Unknown`, never *capability absent*, and never `Established`. `CanSetOwner` is still reported on its own. |
| `AC-S6-3` | A principal holding `Self-Membership` receives `CanAddSelfToGroup` carrying the precondition `AddedMemberSid == RequesterSid`, and never `CanModifyGroupMembership`. |
| `AC-S6-4` | **Interim gate, not a durable semantic.** Until `Self-Membership` requester semantics are established from MS-ADTS or recorded laboratory evidence, a `Self-Membership` entry granted to a group produces `Unknown` for expanded members. Replacing this with protocol-backed behaviour is not a reversal of an accepted rule. |
| `AC-S6-5` | An aggregate `HasFullControl` never removes primitive capabilities or their remediation evidence from the derivation graph. While the aggregate is `Established`, its contributing primitives are not also counted as independent edges for the same holder, target, capability and derivation generation. |
| `AC-S6-6` | An unresolved foreign security principal in a member expansion sets `ExpansionComplete` false and is counted in `UnresolvedMemberCount`, never omitted. |
| `AC-S6-7` | Every stored edge carries an expectedness reason code and the catalogue version that produced it; the same bundle judged twice with the same catalogue version produces identical expectedness. |
| `AC-S6-8` | An edge is tagged `Expected` only where the holder's authority scope covers the target's domain or forest; where the scope or the trust could not be resolved the answer is `Unknown`. |
| `AC-S6-9` | Controlling a Tier 0 object never makes the controller `Expected`. |
| `AC-S6-10` | Owner-only modification of an AdminSDHolder-protected object is tested independently of DACL modification, and the product reports which components of the security descriptor enforcement restored. |
| `AC-S6-11` | A capability in the `CredentialExposure`, `MembershipEscalation` or `ReplicationControl` categories is never described to an operator as a takeover of the target object's permissions. |
| `AC-S6-12` | A replication capability names only what its citation establishes; a capability whose name claims more than its source is a finding against the catalogue. |
| `AC-S6-13` | The persisted `EdgeClass` enum, the capability catalogue, the export representation and the screen wording carry the same value for the same category. A value present in one and absent from another is a defect, not a presentation choice. |
| `AC-S6-14` | Inclusion in the control-plane catalogue does not make every capability `Expected` unless that catalogue entry explicitly declares an unrestricted capability scope. Authority scope and capability scope are evaluated separately. |
| `AC-S6-15` | `sIDHistory` may establish authorisation and may contribute to capability derivation, and never makes an edge `Expected`. Authorisation semantics and expectedness semantics are separate functions and no implementation may share one answer between them. |
| `AC-S6-16` | An aggregate `HasFullControl` assembled from several entries is one counted edge keyed on holder, target, capability and derivation generation, referencing a set of derivations each carrying its own source facts and remediation action. |
| `AC-S6-17` | A deny that removes one mapped primitive removes the aggregate and leaves the surviving primitives as counted edges. |
| `AC-S6-18` | `CanReplicateSecretDomainData` does not include RODC filtered-set attributes; those require `DS-Replication-Get-Changes-In-Filtered-Set` and produce `CanReplicateFilteredAttributes` (`AC-77`). Each replication capability records which naming context established it. |

**Negative criteria, which are the regression cases most likely to reintroduce the collapse this
review cycle removed.**

| id | Criterion |
|---|---|
| `AC-S6-19` | `GENERIC_WRITE` alone never establishes `CanWriteDacl`. |
| `AC-S6-20` | `WRITE_OWNER` alone never establishes `CanBecomeOwnerAndRewriteDacl`. |
| `AC-S6-21` | `Self-Membership` alone never establishes `CanModifyGroupMembership`. |
| `AC-S6-22` | `User-Force-Change-Password` never establishes a `DirectoryControl` capability over the target. |
| `AC-S6-23` | A replication capability never targets a child object beneath the naming-context root. |
| `AC-S6-24` | An owner-right precondition that could not be read never becomes `NotEstablished`. |
| `AC-S6-25` | An explicit `WRITE_DAC` grant to the owner remains `Established` even where `BlockOwnerImplicitRights` blocks the implicit route. |
