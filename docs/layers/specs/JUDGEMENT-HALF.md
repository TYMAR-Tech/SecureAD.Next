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

## What this document has already got wrong

**These are not confessions; they are the working parts of the specification.** Each row is a wrong
answer that four drafts and three external reviews produced, and every one of them was *tempting* —
which is the only reason it is worth writing down. A design that reads as though it was always right
invites the next reader to re-derive the mistake.

Two of them recurred in this repository's own history, and one of them recurred **inside this
document**: a layer was corrected and the layer above it was left contradicting the correction,
twice.

| The tempting answer | Why it is wrong | Where |
|---|---|---|
| Deny ACEs cancel allow ACEs | Windows walks applicable ACEs in order accumulating granted bits; it does not subtract. The edge exists only where effective access exists | `2b` effective capability |
| `S-1-5-10` (SELF) is a placeholder, so discard it | It **resolves** to the object's own SID. Discarding it hides a computer writing its own `msDS-KeyCredentialLink` | `2b` SELF |
| Ownership implies `WriteDacl` | Suppressible by OWNER RIGHTS and by `BlockOwnerImplicitRights` | `2b` ownership |
| A rule matches an equivalence set of raw rights | It re-implements the security semantics `2b` exists to get right, in a layer without the context to do it | Stage 3 rule shapes |
| A hard-coded list of "strong" raw rights propagates control | Propagation is a property of the capability, not of the right it came from | `2b` capability |
| `EdgeClass` grades a route | It is a semantic category, not a rank. Grading comes from feasibility, confidence and preconditions | `2b` capability |
| The AdminSDHolder-protected list is the Tier 0 floor | Protection answers a different question. `Domain Controllers` is protected and is a container of computer accounts | `2c` protected principals |
| The `Domain Controllers` group (516) is a Tier 0 seed | A group of domain controllers is not a domain controller. Adding a computer to it does not make one | `2c` seeds |
| Unconstrained delegation is direct control | It is conditional credential exposure with three named preconditions | `2c` classification effect |
| `Tier0Basis` is `Seed` or `DirectControl` | A principal nested inside a seed group is neither, and its remediation is the chain | `2c` three bases |
| A GPO linked to an OU applies to it | Link is configuration; application depends on site, inheritance, filtering and WMI — and WMI is not captured | `2c` GPO applicability |
| Membership is contextual against the target | Membership is a fact; only *usability* is contextual, keyed on domain. The wrong shape costs principals × objects | `2a` membership |
| One multi-source sweep plus per-target finding identity | The sweep collapses destinations, so a finding that should close cannot be told to | `2d` anchor |
| Split every capability edge so permissions become cuttable | One inherited OU ACE derives thousands of edges; remediation must name the removable action | `2d` remediation |
| Reachability is reachable or not | Zero routes in an incomplete graph is not zero routes | `2d` tri-state |
| A finding is `(principal, target)` | `docs/decisions/0023` requires the rule id; without it three different problems collapse into one row | `2d` identity |
| Dominator drift detects every change that matters | Only for single-waypoint remediations; a multi-edge cut can change with the chain unmoved | `2d` design costs |
| Assign `Tier2` to an unclassified principal | The non-goals decline to define Tier 1 and Tier 2, so no principal can be placed in them yet | `2c` P-87 |
| Phases 4 and 5 are one fixpoint | True only of the recursive definition `P-87` rejects. Under the ruling they separate | the stages |
| A search that returns nothing means the thing does not exist | It means the search failed. `BlockOwnerImplicitRights` and MS-DRSR 5.101 were both found by fetching after searches failed | `P-89` |
| An attribute on Microsoft's protected list is the shadow-credentials target | `altSecurityIdentities` is certificate mapping. Shadow credentials write `msDS-KeyCredentialLink`, which is not on that list at all | `2b` ownership |
| The answer depends on the requested operation, so the answer is `Unknown` | `EvaluateCapability` carries a `RequestedOperation`. Declining to compute is not the same as having nothing to compute with | `2b` ownership |
| A heuristic character is on or off | `BlockOwnerImplicitRights` takes `0`–`3`, and **any other value resolves to `1`** — so a typo turns blocking on | `2b` ownership |
| The protocol proves why the capability matters | It proves the boolean. Security significance is a separate claim needing a separate citation | `2b` replication |
| The shortest route is the best one to show | A short route through uncertain steps may not exist. Certainty is ranked above brevity | `2d` route ordering |
| Weight the route criteria and add them up | Summing lets length outweigh certainty, which is the trade the ruling forbids | `2d` route ordering |

**The last row is the one that generalises.** Two first-party facts were recorded as unavailable
because a keyword search did not surface them; both were one page fetch away. Open Specifications
are long rendered pages, and MS-DRSR in particular puts helper procedures in a **section 5 appendix**
rather than beside the operation they serve — which is why 5.101 was not where anyone looked.

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

### 2a — Membership and directory nesting

This phase builds the relationships above which authorization, protected-principal classification,
latent-privilege findings and Tier 0 effective membership are derived. **Membership is a directory
fact; whether a membership SID is usable for a particular access check is an authorization question
and belongs in `2b`.**

#### Three products, because one graph answers three different questions

An earlier draft treated all group expansion as one closure. That is unsafe. The directory nesting
facts are captured once, then three different products are derived from them:

| Product | Follows | Answers |
|---|---|---|
| `AuthorizationMembershipClosure` | security-enabled groups, including primary-group membership | *Which security-group memberships can participate in authorization?* |
| `ProtectedPrincipalClosure` | security and distribution groups, including primary-group membership where applicable | *Is this principal covered by AdminSDHolder / SDProp?* |
| `LatentPrivilegePaths` | directory nesting through distribution groups | *What privilege would become effective if a distribution group were converted to security-enabled?* |

The names are deliberately different. A distribution-only path can be relevant to SDProp and to a
latent-privilege finding while being **invalid for current authorization**.

Microsoft's *Reducing the Active Directory Attack Surface* guidance states that accounts nested
through distribution groups do not receive the protected security group's SID in their access token.
A distribution group therefore never creates a present-tense authorization edge merely because it
is nested under a privileged security group.

Example:

```
Alice -> member of -> DistributionGroup-A -> member of -> Domain Admins
```

Current authorization:

```
Alice does NOT receive Domain Admins through that distribution-only hop.
```

Latent privilege:

> `DistributionGroup-A` is nested in Domain Admins. Converting it to a security group would make its
> effective members inherit the Domain Admins authorization path at the next applicable logon/token
> construction.

That is useful and serious, but it is not current control.

#### Primary-group membership is real membership and is not represented by `member` / `memberOf`

A naïve traversal of only `member` or `memberOf` is incomplete. Microsoft Open Specifications state
that `primaryGroupID` identifies a group of which the account **is a member**, while neither the
account's `memberOf` nor the group's `member` attribute contains that relationship.

Sources:

- [MS-ADA3: primaryGroupID](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/e12954a4-6865-4432-94e6-00c310ca87c0)
- [MS-ADA2: member](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/763d0861-f4f6-4251-847e-7e8dedcfe73f)
- [MS-ADA2: memberOf](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/cc24555b-61c7-49a2-9748-167b8ce5a512)

The derived relationship is therefore:

```
PrimaryGroupSid(account) = account-domain-SID + account.primaryGroupID
```

and the phase maintains a reverse index from primary-group SID to accounts. This relationship feeds
both security membership and protected-principal analysis. It is not a special-case reporting hint;
it is membership Windows itself recognizes.

This is especially important because writable domain-controller accounts normally use the Domain
Controllers group as primary group, and an administrator can change a user account's primary group.
A user whose `primaryGroupID` names a privileged security group must not disappear from the closure
because there is no ordinary `member` backlink.

#### Membership is target-independent

Alice can be transitively a member of a domain-local group in another domain. That fact does not
change according to the object being judged:

```
AuthorizationMembershipClosure(principal, group)    // target-independent fact
```

What changes is whether that group is **usable** in the security context for a requested operation
against a resource. Domain-local scope, Builtin-local scope, special identities, SID filtering and
servicing/resource context are evaluated later in `2b`.

Do not implement:

```
IsEffectiveMember(principal, group, targetObject)
```

as the core membership store. That multiplies a directory fact by every target and conflates two
layers that Windows itself keeps separate.

#### SIDHistory participates in authorization identity

An ACE naming an old SID can grant access to a migrated principal through `sIDHistory`. The phase
therefore indexes current object SID and SIDHistory in both directions so that trustee resolution and
authorization evaluation can explain the relationship.

SIDHistory is not treated as an ordinary `member` edge. It is an additional authorization identity
carried by the principal and is retained as typed evidence so the UI can distinguish:

```
matched current SID
matched SIDHistory
matched group membership
matched primary-group membership
```

#### Cycles terminate and are reportable

AD permits group-membership loops. Expansion must terminate deterministically, and a cycle can also
be surfaced as its own finding rather than merely being counted as a traversal guard.

#### Completeness is part of the result

Expansion runs against explicit budgets and capture coverage. A partial answer is never serialized as
a complete closure.

At minimum each derived closure records:

```
IsComplete
PartialGroups[]
MissingPartitions[]
UnresolvedTrustees[]
DerivationGenerationId
```

A rule resting on a partial closure has not established a clean result. The missing input propagates
through later derivation and judgement rather than being converted to an empty set.

### 2b — Effective authorization and semantic capabilities

Raw ACEs and ownership facts are evidence. Everything above this phase consumes **semantic
capabilities** produced by an operation-specific authorization evaluation. No rule above `2b`
reconstructs an access mask or permission-equivalence set.

The predecessor's useful raw vocabulary includes rights such as:

`GenericAll`, `WriteDacl`, `WriteOwner`, `ResetPassword`, `AddMember`, `WriteSPN`,
`WriteKeyCredentialLink`, `WriteRBCD`, `WriteUserAccountControl`, `WriteAllowedToDelegateTo`,
`DCSyncGetChanges`, `DCSyncGetChangesAll`, `DCSyncGetChangesInFilteredSet`, `LinkGPO`,
`CertificateEnroll`, `CertificateAutoEnroll`, `GenericWrite`, `WriteAllProperties`, `CreateChild`,
`DeleteChild`, and `Delete`.

Those names are **inputs**, not the unit the rule layer consumes.

#### Effective capability is operation-specific

"Effective access" must not become shorthand for a partial access-check engine or one flat bitmap.
AD authorization is evaluated for a requested operation against a specific target and security
context.

The conceptual contract is:

```
EvaluateCapability(
    Principal,
    TargetObject,
    RequestedOperation,
    AuthorizationContext,
    SecurityDescriptor,
    SchemaContext,
    ServerBehavior,
    CoverageState
) -> CapabilityEvaluation
```

A capability evaluation must preserve everything necessary to decide the operation correctly,
including where applicable:

- standard rights and directory-service rights
- object-specific ACE type and ordering
- `ObjectType` GUID
- `InheritedObjectType` GUID
- property-set membership / `attributeSecurityGUID`
- control-access-right GUID
- validated-write semantics
- ACE inheritance flags, including inherit-only
- target object class and applicable schema hierarchy
- explicit versus inherited ACEs
- trustee authorization identity, including SIDHistory and primary-group-derived membership
- SELF resolution
- owner implicit rights and OWNER RIGHTS
- server/version-specific authorization behavior
- capture and schema completeness

Microsoft references:

- [MS-ADTS: Checking Simple Access](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c55e113e-25a2-45eb-abba-bf5a9e521a8f)
- [MS-ADTS: Checking Object-Specific Access](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3da5080d-de25-4ac8-9f2b-982709253dfb)
- [MS-DTYP: ACCESS_ALLOWED_OBJECT_ACE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe)
- [MS-ADTS: Access Rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584)

A deny ACE is evidence used by the access-check procedure. It is not modeled as a separate flag that
"cancels" an allow ACE. Likewise, a broad allow and a property-specific deny are not reduced to a
single allow-minus-deny arithmetic operation outside the authorization evaluator.

#### NULL DACL and empty DACL are different security states

Capture and derivation must preserve this distinction exactly.

Microsoft's MS-ADTS section **Null vs. Empty DACLs** states:

- no DACL / NULL DACL grants full access for the normal DACL authorization check;
- an allocated empty DACL grants no ACE-based access, while applicable implied rights such as owner
  rights are evaluated separately.

Source:
[MS-ADTS: Null vs. Empty DACLs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ee18efbf-e8d4-4eb0-8b27-79773e96d61f)

Therefore these must never serialize to the same representation:

```
DaclState = Null
DaclState = PresentEmpty
DaclState = PresentWithAces
DaclState = Unreadable
```

`ACECount = 0` alone is insufficient.

#### Missing authorization inputs produce an unknown capability, not an absent capability

If the requested operation cannot be evaluated because required evidence is unavailable — for
example schema GUID mapping, property-set membership, object class, inherited-object applicability,
trustee resolution, target security descriptor, or required authorization context — the result is:

```
CapabilityEvaluation.State = Unknown
```

not:

```
Capability absent
```

No high-confidence edge is emitted from a partially evaluated capability. The uncertainty is retained
for the possible-edge graph described in `2d`.

#### Principal SELF is resolved rather than discarded

`S-1-5-10` (`SELF`) is a placeholder used during authorization. For a user, group, or computer object,
the operating system substitutes the SID of the security principal represented by the object.

So:

```
SELF ACE on UserA      -> trustee authorization identity is UserA
SELF ACE on ComputerA  -> trustee authorization identity is ComputerA$
```

Where the target is not a security principal, SELF is evaluated according to AD applicability rather
than presumed to grant anything.

**An earlier draft excluded SELF entirely**, on the reasoning that it is *"a placeholder meaning the
object itself, not an attacker."* The premise is right and the conclusion is wrong, and it is
recorded because the reasoning is genuinely persuasive — the default SELF rights are harmless, so
dropping them looks like noise reduction rather than a silent false negative.

Discarding SELF would create a false negative for a custom ACE such as a computer being able to write
its own `msDS-KeyCredentialLink` or another security-relevant attribute.

#### Authorization membership is cached by context; capability evaluation remains target-specific

The security-group closure from `2a` is target-independent. `2b` constructs the authorization SID
context used to match ACE trustees.

At a conceptual level:

| Set | Contents | Cache boundary |
|---|---|---|
| `BaseAuthorizationSids` | principal SID, SIDHistory, applicable global/universal security groups, contextual special identities | principal |
| `ResourceAuthorizationSids` | base plus applicable domain-local / Builtin-local authorization identities | principal × applicable resource/security context |

This is an optimization for **which trustee SIDs can count**. It is not a statement that effective
access is computed once per domain. Capability evaluation still occurs against the target security
descriptor and requested operation.

Prefer group-first derivation where possible: an ACE already names a trustee, so resolving that
trustee to effective members and then validating scope can be cheaper than eagerly materializing a
complete token-like SID set for every principal.

Do not query `tokenGroups` for every principal in production merely to avoid implementing the model.
Microsoft documents `tokenGroups` as an expensive computed attribute; it is useful as a lab oracle for
selected fixtures against Windows' own result.

#### Special identities are runtime/context trustees, not group membership edges

`Everyone` (`S-1-1-0`), `Authenticated Users` (`S-1-5-11`), `This Organization` (`S-1-5-15`) and
similar special identities are matched according to the authorization context. They have no AD
`member` attribute and must not be inserted into the group-membership graph as ordinary groups.

Evidence must be able to say why an ACE applied:

```
matched direct SID
matched SIDHistory
matched transitive security-group membership
matched primary-group membership
matched special identity
```

Those are different administrative facts.

#### Which resource/security context applies to non-domain naming contexts remains open (`P-90`)

For an ordinary domain-NC object, the relevant domain context is normally straightforward. For the
Configuration, Schema and application naming contexts, a forest audit must not hard-code
`targetObjectDomain` as though every object belongs to one resource domain.

Application directory partitions can have writable replicas on DCs in multiple domains. Microsoft
provides `msDS-NC-Replica-Locations` to identify the replica locations and `msDS-SDReferenceDomain`
to resolve **local-domain references in default security descriptors**.

Sources:

- [Application Directory Partition Security](https://learn.microsoft.com/en-us/windows/win32/ad/application-directory-partition-security)
- [Modifying Application Directory Partition Configuration](https://learn.microsoft.com/en-us/windows/win32/ad/modifying-application-directory-partition-configuration)

The application-partition guidance also warns that a **local group** in an ACL has a reference-domain
problem that `msDS-SDReferenceDomain` cannot solve. This statement must not be rewritten as "any
AD domain-local trustee is uninterpretable". A domain-local AD SID already identifies its domain; the
remaining question is whether that identity is usable in a valid servicing/resource context for the
operation.

`P-90` therefore asks:

> For each non-domain NC, which servicing/resource authorization contexts can perform the operation,
> and does the capability exist in any valid writable context?

If the captured evidence is insufficient to answer that question, the result is `Unknown`. The API
must not harden a simplistic `resourceDomain` field before this is resolved.

#### Directory-object identity and authorization identity are separate concepts

The graph contains directory objects, SID-only trustees, special identities, unresolved trustees and
synthetic nodes. One identity scheme cannot serve all of those jobs.

Use a discriminated reference model such as:

```
DirectoryObjectRef
    ForestId
    PartitionId
    ObjectGuid

AuthorizationTrusteeRef
    Sid
    AuthorizationContext
    ResolutionStatus
    ResolvedDirectoryObjects[]

SpecialIdentityRef
    Sid

SyntheticRef
    StableId
```

Directory-object identity is used for provenance, attributes, containment and change tracking.
Authorization matching is SID-based in the applicable context. They must not be collapsed.

This matters especially for Builtin groups. Each domain naming context has its own Builtin container,
while the objects can expose the same well-known SID such as `S-1-5-32-544`. Distinct directory
objects remain distinct nodes even when authorization matching observes the same SID value in
context.

An unresolved trustee is retained as a SID-based node/evidence object rather than dropped.

#### Capability is the unit everything above this layer consumes

A derived capability carries at least:

| Field | Purpose |
|---|---|
| `Name` | `CanResetPassword`, `CanWriteRBCD`, `CanReplicateAllDomainSecrets`, … |
| `Target` | stable directory/synthetic reference |
| `EdgeClass` | `DirectoryControl` / `CredentialExposure` / `ConditionalEscalation` — semantic category, not ranking |
| `Feasibility` | `Direct` / `Conditional` / `Potential` |
| `Confidence` | `High` / `Medium` / `Low` |
| `Preconditions[]` | named conditions that must also hold |
| `PropagatesControl` | whether the capability may extend a control/reachability chain |
| `Tier0ClassificationEffect` | `None` / `DirectControl` / `ReachabilityOnly`, set by the capability catalogue for the target class |
| `DerivedFrom[]` | raw rights, ownership, membership and other evidence used |
| `SourceFactIds[]` | configuration facts from which this capability was derived |
| `RemediationActionIds[]` | configuration actions that can remove the capability |
| `EvaluationState` | `Established` / `NotEstablished` / `Unknown` |
| `DerivationGenerationId` | provenance/version isolation |

`EdgeClass` is not an ordered score. Route grading derives from feasibility, confidence and named
preconditions.

A `Conditional` capability with no named precondition is invalid evidence.

`PropagatesControl` and `Tier0ClassificationEffect` are independent. A capability can extend an
attack chain without meaning the current holder is itself operationally Tier 0.

#### Ownership derives control only when the requested owner rights actually exist

An object owner ordinarily receives implicit owner rights, but there are multiple documented ways the
result can differ.

`OWNER RIGHTS` (`S-1-3-4`) ACEs can change the implicit owner rights generally.

`BlockOwnerImplicitRights` is more specific. MS-ADTS documents conditions including:

- applicable `BlockOwnerImplicitRights` setting and supported server behavior;
- requester is neither Domain Admins nor Enterprise Admins;
- target object class is `computer` or derived from `computer`;
- on newer documented behavior, additional operation/protected-property rules can affect whether the
  security-descriptor modification is blocked.

**The setting is at `dSHeuristics` character 29, and its values do not mean what a reader expects.**
Fetched 2026-08-25 from the blocking rules:

> The BlockOwnerImplicitRights dsHeuristic is set to 1, or to 0 or 1 on Windows 11, version 26H1.

**An earlier draft read that as "`0` blocks on 26H1 and later" and added "there is no documented
value that leaves owner rights intact on those builds." Both overreach**, and the value-definition
section — MS-ADTS 6.1.1.2.4.1.2, a *different* page, fetched 2026-08-26 — shows why:

> If this character is "0", "1", "2", or "3" the BlockOwnerImplicitRights heuristic is set to the
> equivalent numeric value. If this character is not set, the heuristic defaults to 0. **If this
> character has any other value, the heuristic defaults to 1.**

Four valid values, not two. `2` and `3` exist and the blocking section says nothing about them, so
the claim that no value leaves owner rights intact was never established — it was inferred from a
page that only discusses two of the four. `3` is itself 26H1-and-later. And the applicability is
Microsoft's exact wording, *the operating systems identified by MSFT-CVE-2021-42291 with the related
update installed*, which is not the same set as "26H1 and later" and must not be generalised to it.

Two things survive, and they are the ones that matter:

- **`0` must not be treated as "disabled".** It is both the documented default and a value that can
  trigger blocking under the identified behavior. A derive reading `0` as *not configured* can
  report a suppressed capability as live.
- **A malformed value is not inert.** Anything outside `0`–`3` defaults to **`1`**, the blocking
  value. So a typo in this heuristic silently turns blocking *on*, and a reader who assumes garbage
  means "ignored" has it backwards.

The capture records the raw character and the server behavior; the derive resolves the value against
the applicable MS-ADTS version rather than against a hard-coded release name.

**On 26H1 the block is also decided per requested modification, not per object.** The specification
makes it depend on which ACEs are being added or removed, and it names ten protected properties —
`altSecurityIdentities`, `dnshostname`, `msDS-AdditionalDnsHostName`,
`msDS-AdditionalSamAccountName`, `msDS-AllowedToDelegateTo`, `msDS-AssignedAuthNPolicy`,
`msDS-AssignedAuthNPolicySilo`, `sAMAccountName`, `servicePrincipalName` and `userPrincipalName`.

**An earlier draft of this paragraph said "the first is the shadow-credentials target", and that is
wrong.** Shadow credentials write `msDS-KeyCredentialLink`, which is **not** in this list;
`altSecurityIdentities` is the certificate-mapping attribute, a different abuse with a different
capability. The correction is recorded rather than quietly fixed because of what the mistake would
have caused downstream: an implementer reading that sentence would map `altSecurityIdentities` to
the key-credential capability, and the product would then report a certificate-mapping weakness
using the language of a shadow-credentials attack. **That is the product saying something false
about a customer's directory**, which is the one thing it must not do — and the error would be
invisible, because both attributes are real, both are dangerous, and the finding would look
plausible.

What the list *does* establish is narrower and still worth having: several of these attributes carry
identity- or Kerberos-related abuse potential, and Microsoft protects them here for that reason.
Which attribute belongs to which capability is settled in the capability catalogue against its own
citation, not inferred from membership of this list.

**The derive does not evaluate the 26H1 rules.** A static evidence bundle records what an ACL says,
not what a hypothetical modification would be permitted to change.

**But that does not make every 26H1 ownership case `Unknown`, and an earlier draft said it did.**
The mistake was to read "the answer depends on the requested operation" as "there is no requested
operation", when `EvaluateCapability` already takes a `RequestedOperation`. A capability is not a
question about ownership in the abstract; it is a question about a specific change. *Can this owner
add an ACE granting itself write on a non-protected property?* has an answer under the documented
rules. So does *can it grant `WRITE_DAC` to another principal?* — rule 4 says no, and that is
`NotEstablished` rather than unknown.

The correct shape:

```
Ownership alone
    -> no generic take-over capability, on any build

Ownership + a capability that names its security-descriptor modification
    -> Established | NotEstablished | Unknown, per the documented rules

Ownership + a capability that does not name one
    -> Unknown
```

`Unknown` is for the case where the capability has no defined modification template, or where the
server behavior needed to pick the rule set was not captured. Blanket-`Unknown` looked like
honesty and was the opposite: it would suppress every ownership-derived route on the newest servers
in the estate, and a "found nothing" that is really "declined to compute" is the failure mode this
document exists to prevent.

Source:
[MS-ADTS 6.1.3.4: Blocking Implicit Owner Rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/fb7c101d-ec8b-4fbf-bca8-7d7c2d747d0c)

Therefore do **not** implement a generic forest-wide rule:

```
BlockOwnerImplicitRights enabled -> owner lacks WriteDacl on every object
```

The evaluator asks whether implicit owner rights are available for the concrete target, requester,
operation and server behavior.

Conceptually:

```
Ownership
    -> EvaluateOwnerImplicitRights(...)
    -> requested capability, only if established
```

`WriteOwner` likewise does not become an unconditional equivalence for every downstream write. It can
be one step in a conditional route to ownership, which must then pass the owner-right evaluation.

#### Derived-phase outputs are versioned generations

Atomic delete-and-rebuild is not enough. If derivation v5 fails and v4 remains physically present,
Stage 3 must not silently treat v4 as a successful v5 result.

Each derived product records at least:

```
DerivationGenerationId
InputBundleId / EvidenceHash
DerivationType
DerivationEngineVersion
CapabilityCatalogueVersion
SchemaGuidCatalogueVersion
TierPolicyVersion          // where applicable
Status
Completeness
CreatedAt
```

Judge consumes only a compatible successful generation. Retaining the previous successful generation
for diagnostics or fallback inspection is fine; presenting it as current derivation is not.

#### The capability catalogue is a separate verified artefact

Which right, against which target class, produces which semantic capability is intentionally not
fully enumerated in this architecture document. The catalogue is the next protocol-level research
pass and must cite first-party Microsoft documentation/Open Specifications for every security
semantic it encodes.

A capability whose required semantics are not yet verified can carry:

```
CapabilityResearchStatus = ResearchBlocked
```

and rules must not consume it as established until the block is cleared.

### 2c — Classification: privileged, protected, dangerous, Tier 0

This phase consumes membership and established capabilities. It does not reinterpret raw ACEs.

#### Five independent questions

The engine keeps five separate properties/relationships. None is inferred from another except by an
explicit rule in a versioned catalogue or policy.

| Property | Question |
|---|---|
| `IsPrivileged` | Does this principal currently hold elevated administrative authority under the product's privileged-role/capability policy? |
| `IsProtectedPrincipal` | Is this principal currently subject to AdminSDHolder / SDProp protection? |
| dangerous capability | Does an established capability materially control, impersonate, expose or alter its target? |
| `TierClassification` | Is this principal part of SecureAD's operational Tier 0 population under the active Tier policy? |
| `Tier0Reachability` | Can this principal reach the Tier 0 control-plane anchor through the control graph? |

The following implications are invalid:

```
IsPrivileged            -> Tier0
IsProtectedPrincipal    -> Tier0
DangerousCapability     -> Tier0
adminCount == 1         -> Tier0
```

A helpdesk password-reset delegation can be privileged and not Tier 0. A protected built-in group can
be non-Tier0 under the active product policy. `GenericAll` over an ordinary test account can be
dangerous without being control of the identity plane.

#### `IsPrivileged` is a versioned product classification, not an implicit synonym for Tier 0

The property is only useful if it has a derivation. SecureAD therefore records why a principal is
classified privileged:

```
PrivilegedBasis:
    BuiltInOrMicrosoftPrivilegedRole
    EffectiveMembership
    DelegatedAdministrativeCapability
```

The authoritative inputs are versioned catalogues:

```
PrivilegedRoleCatalogueVersion
PrivilegedCapabilityCatalogueVersion
```

A principal is `IsPrivileged = true` when one of the following is established:

1. it is a role/principal explicitly listed by the active privileged-role catalogue;
2. it is an effective security-group member of such a role;
3. it holds an administrative capability that the privileged-capability catalogue marks as conferring
   privileged authority for that target/scope.

The Microsoft *Privileged access security levels* documentation is a source for privileged role
examples; it must not be treated as a literal Tier 0 list.

Rules named "Privileged Account" must declare this derived fact as an input. They do not infer
privilege independently from group names or `adminCount`.

#### Dangerousness belongs to a capability instance

`HasDangerousPermission` is not a clean principal-level primitive because dangerousness is meaningful
only with the capability, target, scope and preconditions.

The normalized model is:

```
Capability.IsDangerous
Capability.DangerReason
```

and, if a principal aggregate is useful for filtering:

```
Principal.HasDangerousCapability = any established capability where IsDangerous
```

Dangerousness never creates Tier 0 by itself. A capability can be dangerous against an ordinary user,
computer, group, OU or service without touching the Tier 0 control plane.

#### What Microsoft says Tier 0 is

Microsoft's current AD DS Tier Model says Tier 0 contains assets and identities that directly or
indirectly control the directory service and enterprise-wide permissions. It explicitly includes Tier
0 administrative accounts/groups, AD DS domain controllers and identity services, and names built-in
groups such as Backup Operators and Server Operators as Tier 0 examples.

Source:
[Tier model for Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model)

The same guidance warns that collapsing excessive resources into Tier 0 dilutes the tier and expands
the attack surface.

SecureAD is an AD-audit product, so broader infrastructure Tier 0 assets — hypervisors, backup
platforms, patching/monitoring systems, EDR, storage, physical access and similar infrastructure — are
out of scope unless the captured AD data exposes an actionable AD control relationship to them.

#### SecureAD's Tier policy is explicit and versioned

`P-87` is a product policy decision, not a claim that Microsoft defines Tier 0 this narrowly.
SecureAD's operational classification deliberately separates:

- what is **classified** Tier 0 for administration/reporting;
- what can **reach** Tier 0 through arbitrary transitive control.

The active policy is recorded with every derivation and finding:

```
TierPolicyId      = FixedSeedMembershipAndDirectControl
TierPolicyVersion = <version>
```

Reports must make clear that `TierClassification` is SecureAD's operational classification under that
policy, while `Tier0Reachability` preserves longer indirect-control chains. Microsoft's broader model
can describe indirect controllers as Tier 0; SecureAD does not hide those paths, but does not expand
the operational Tier 0 label recursively through the entire attack graph.

#### Protected principals are reported independently

AdminSDHolder/SDProp protection is a directory behavior, not a Tier 0 detector. The protected-principal
derivation consumes `ProtectedPrincipalClosure` from `2a` and the Microsoft protected-account/group
catalogue.

**An earlier draft treated this list as the Tier 0 floor**, and the mistake is worth recording
because the list is published, authoritative and easy to find — which is exactly what makes it a
tempting wrong answer. It would have classified `Domain Controllers` (516), a container of computer
accounts, and `Print Operators`, which manages printers, as crown jewels.

`adminCount` is **not** used as the current-protection oracle. It can remain set after a principal
leaves a protected group and is therefore historical/hygiene evidence rather than current Tier0 or
protected membership by itself.

The current Microsoft Appendix C list includes:

| Protected group or account | Identifier | Scope | Tier 0 seed under current working policy? |
|---|---|---|---|
| Administrator | `<domain-SID>-500` | domain | yes |
| Krbtgt | `<domain-SID>-502` | domain | yes |
| Domain Admins | `<domain-SID>-512` | domain | yes |
| Domain Controllers | `<domain-SID>-516` | domain | no — DC machines are assets; the group is not treated as a seed |
| Schema Admins | `<root-domain-SID>-518` | forest root | yes |
| Enterprise Admins | `<root-domain-SID>-519` | forest root | yes |
| Read-only Domain Controllers | `<domain-SID>-521` | domain | no — RODC machines are assets |
| Key Admins | `<domain-SID>-526` | domain | no — research open |
| Enterprise Key Admins | `<root-domain-SID>-527` | forest root | no — research open |
| Administrators | `S-1-5-32-544` | Builtin | yes |
| Account Operators | `S-1-5-32-548` | Builtin | no under current working policy |
| Server Operators | `S-1-5-32-549` | Builtin | yes — named by Microsoft |
| Print Operators | `S-1-5-32-550` | Builtin | no under current working policy |
| Backup Operators | `S-1-5-32-551` | Builtin | yes — named by Microsoft |
| Replicator | `S-1-5-32-552` | Builtin | open |

Use full domain SIDs (`S-1-5-21-x-y-z`) plus RID where applicable; do not copy shorthand such as
`S-1-5-<domain>-512` into code.

Microsoft's current documentation has a known discrepancy around Enterprise Read-only Domain
Controllers (RID 498): one protected-account list omits it while the default security-group reference
marks it protected. `P-88` remains open until protocol behavior/lab validation resolves the catalogue
entry rather than choosing one page silently.

#### Tier 0 fixed seeds

A seed is attached to the Tier 0 control-plane anchor by what it is, before graph traversal.
The working fixed set is deliberately narrow.

**Principal seeds:**

- Enterprise Admins
- Domain Admins
- Schema Admins
- domain Builtin\Administrators objects
- built-in Administrator account
- krbtgt
- Backup Operators
- Server Operators

**Asset seeds:**

- actual writable domain-controller computer accounts
- RODC computer accounts, tagged with an RODC subtype; this remains a documented SecureAD inference
  from Microsoft's broader "AD DS domain controllers" wording

**Directory target seeds:**

- domain naming-context roots
- Configuration naming-context root
- Schema naming-context root
- AdminSDHolder
- Domain Controllers OU where control can affect DC descendants
- forest/domain trust configuration objects
- security-significant replication topology objects
- GPOs whose effective application to Tier 0 subjects is established
- other AD-visible targets explicitly added by an accepted Tier policy decision

Seed matching uses stable SID/RID or stable object identity as appropriate, never display-name string
matching.

The Domain Controllers group (RID 516) is **not** equivalent to an actual domain controller. Adding an
ordinary computer to the group does not promote it into a DC. The same distinction applies to the
RODC groups versus actual RODC computer accounts.

#### GPO Tier 0 applicability is tri-state and evidence-rich

"Linked to" is not the same as "applies to". Group Policy applicability can depend on site/domain/OU
scope, link order and state, enforced/block-inheritance behavior, policy-half status, security
filtering and WMI filtering.

The derived result is structured:

```
GpoApplicabilityResult
    SubjectRef
    SubjectType: Computer | User
    State: Applies | DoesNotApply | Unknown
    SiteLinks[]
    DomainLinks[]
    OuLinks[]
    LinkOrderEvidence
    EnabledStateEvidence
    EnforcedEvidence
    BlockInheritanceEvidence
    PolicyHalfStatus
    SecurityFilterDecision
    WmiFilterReference
    UnknownReasons[]
```

For DC-computer control, the computer half is the first required use case. The model is generalized so
user-side policy affecting Tier 0 administrative identities can be evaluated when the corresponding
capability catalogue/rules exist.

`Unknown` is required whenever an input necessary for applicability is unavailable. A WMI filter is a
common example because the query executes on the destination computer and this audit does not capture
arbitrary local state from every DC, but WMI is not the only possible unknown reason. Missing site
membership, unreadable GPO/security-filter data, partial membership or unavailable policy status also
produce structured uncertainty.

GPO security filtering reuses the effective authorization engine from `2b`.

#### Deliberately not fixed seeds under the current working policy

The following are not classified as fixed Tier 0 seeds merely because they are privileged/protected or
because their names sound administrative:

- Account Operators
- Print Operators
- Key Admins
- Enterprise Key Admins
- Group Policy Creator Owners
- Cryptographic Operators
- Distributed COM Users
- Exchange administrative groups

They can still become operational Tier 0 through effective seed-group membership or a capability that
the catalogue says confers `DirectControl` over a seed.

Key Admins / Enterprise Key Admins remain research-open because domainprep documents rights over
`msDS-KeyCredentialLink` and Full Control on `CN=Keys`; the security consequence of the latter must be
settled before the seed policy is locked.

Replicator (552), AD CS/AD FS asset discovery, customer-declared Tier0 scope, and the final treatment
of Account/Print Operators remain owner/research items in `P-85` or successor decisions.

#### Three Tier 0 bases, with different remediations

The authoritative enumeration is:

```
Tier0Basis:
    Seed
    EffectiveMembership
    DirectControl
```

| Basis | Meaning | Remediation shape |
|---|---|---|
| `Seed` | intrinsic under the active Tier policy | none — this is the defined Tier 0 population |
| `EffectiveMembership` | principal currently operates with a seed security group's authority, including transitive and primary-group membership | break the source membership relationship/path |
| `DirectControl` | principal holds an established capability over a seed that the capability catalogue marks `DirectControl` | remove the source configuration/capability |

A user nested three security groups deep inside Domain Admins is `EffectiveMembership`; the user is not
merely someone who can reach Domain Admins. A principal that can modify Domain Admins membership is
`DirectControl`.

Longer control chains do **not** add another Tier0Basis value. They are represented by
`Tier0Reachability`.

Every non-seed classification carries typed evidence and scope. A classification without the evidence
that earned it is invalid.

#### `PropagatesControl` and Tier 0 classification effect are different catalogue decisions

A capability has two separate properties:

```
PropagatesControl
Tier0ClassificationEffect: None | DirectControl | ReachabilityOnly
```

`PropagatesControl` asks whether the step can extend a chain.
`Tier0ClassificationEffect` asks whether holding that capability over the relevant target is enough to
classify the holder as direct operational Tier 0.

Unconstrained delegation illustrates the difference: it can create a serious credential-exposure
route only when its preconditions occur; it is not automatically a present-tense direct control
classification.

RBCD also requires target- and protocol-specific catalogue research rather than being globally assumed
`DirectControl` merely because the attribute is writable.

#### DCSync / full-domain secret replication — `P-91` closed

The raw extended rights remain captured facts:

- `DS-Replication-Get-Changes`
- `DS-Replication-Get-Changes-All`
- `DS-Replication-Get-Changes-In-Filtered-Set`

The capability used for normal full-domain secret replication is:

```
CanReplicateAllDomainSecrets =
    DS-Replication-Get-Changes
    AND DS-Replication-Get-Changes-All
```

This is now verified against Microsoft's actual protocol authorization procedure:
[MS-DRSR: IsGetNCChangesPermissionGranted](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/15bbda52-7742-4ce3-9327-018647b0fc26)

**It was recorded as unreachable first, and that is `P-89`.** An earlier pass searched for the
procedure by name, found nothing, and wrote down that the citation could not be made — rather than
that the search had failed. The page was one fetch away. MS-DRSR keeps helper procedures in a
**section 5 appendix**, not beside the operation in 4.1.10 that invokes them, so no amount of
searching around the operation would ever have surfaced it. The same shape had already produced a
wrong "not found" for `BlockOwnerImplicitRights`, which sits at `dSHeuristics` character 29.

The rule that follows: **for Open Specifications, fetch the document and read it; do not conclude
absence from a search.** A search returning nothing is evidence about the search.

The procedure checks `DS-Replication-Get-Changes`, and secret-revealing requests additionally require
`DS-Replication-Get-Changes-All` except for the separately defined `EXOP_REPL_SECRETS` /
`RevealSecretsForUserAllowed` path used for constrained secret reveal. That constrained path is a
different capability and is not conflated with full-domain DCSync.

`P-91` therefore closes. Other capabilities can remain `ResearchBlocked` until their applicable
protocol sections are actually read.

**The filtered attribute set is a third capability, and it is a disjunction rather than a
conjunction.** Read from the same procedure:

```
CanReplicateFilteredAttributes =
    DS-Replication-Get-Changes
    AND ( DS-Replication-Get-Changes-All
          OR DS-Replication-Get-Changes-In-Filtered-Set )
```

The filtered attribute set is a distinct authorization outcome because MS-DRSR authorizes it through
a **different boolean condition** from ordinary secret revelation — a disjunction where secrets take
a conjunction. That much is established by the procedure alone.

**What the procedure does not establish is why it matters, and an earlier draft asserted that from
memory.** The security characterisation has its own source, fetched 2026-08-26:

> Some applications that use Active Directory Domain Services as a data store may have
> credential-like data (such as passwords, credentials, or encryption keys) that should not be
> stored on a Read-Only Domain Controller in case the RODC is stolen or compromised. For this type
> of application, you can add the attribute to the RODC filtered attribute set to prevent it from
> replicating to RODCs in the forest.

[Read-Only DCs and the Active Directory Schema](https://learn.microsoft.com/windows/win32/ad/rodc-and-active-directory-schema)

So the filtered set is defined by the customer, holds credential-like data by design, and is
populated precisely *because* someone decided it must not leave the writable estate. A principal
holding `Get-Changes` and `Get-Changes-In-Filtered-Set`, and **not** `Get-Changes-All`, reads exactly
that material while failing the DCSync test entirely. Treating `Get-Changes-In-Filtered-Set` as a
weaker sibling of `Get-Changes-All` and folding the two together would either miss this holder or
report it as full DCSync; both are wrong, and the second is the kind of false statement an audit
tool must not make.

**Three access rights, two compound outcomes.** The rights are captured facts. `CanReplicateAllDomainSecrets`
and `CanReplicateFilteredAttributes` are derived capabilities, and the catalogue defines those two
by name; the constrained `EXOP_REPL_SECRETS` path is a third and is not folded into either.

**All three checks are `AccessCheckCAR(ncRoot, ...)` — against the naming context root, not against
the object whose secrets are read.** The permission is granted once at the top of a partition and
confers replication of everything beneath it, which is why the finding's target is the partition and
why removing the ACE at the root is the whole of the remediation.

#### P-87 — operational Tier 0 versus transitive reachability

SecureAD intentionally cuts recursive **control classification** after direct control while preserving
arbitrary reachability.

Example:

```
Domain Admins                    Seed
    ^
    | CanModifyMembership
Alice                            Tier0 / DirectControl
    ^
    | CanResetPassword
Bob                              Unclassified / Reachable
    ^
    | CanResetPassword
Helpdesk                         Unclassified / Reachable
```

Effective security-group membership is different from that control chain and remains Tier0:

```
Alice -> GroupA -> GroupB -> Domain Admins
Alice = Tier0 / EffectiveMembership
```

The authoritative fields are:

| Field | Values |
|---|---|
| `TierClassification` | `Tier0` / `Tier1` / `Tier2` / `Unclassified` |
| `Tier0Basis` | `Seed` / `EffectiveMembership` / `DirectControl` |
| `Tier0Reachability` | `Reachable` / `NotReachable` / `Unknown` |
| `Tier0Distance` | distance to a fixed seed/control-plane anchor; synthetic anchor edges are zero-cost |
| `Tier0Scope` | object / domain / forest / other defined scope |
| `TierPolicyId` / `TierPolicyVersion` | exact policy that produced the classification |

No principal is assigned Tier1 or Tier2 until an accepted catalogue defines those tiers; the correct
value is `Unclassified`.

#### `adminCount` is historical/hygiene evidence

A principal that leaves protected membership can retain `adminCount = 1`, and inheritance restoration
is a separate administrative issue. `adminCount` is therefore suitable for an orphaned/stale-protection
finding but never for current Tier0 classification.

#### Open owner/policy decisions

Still open unless separately accepted:

- final Account Operators / Print Operators operational Tier0 treatment;
- Replicator seed status;
- Key Admins / Enterprise Key Admins `CN=Keys` consequence;
- AD CS / AD FS asset representation when discoverable through AD;
- customer-declared Tier0 scope;
- Enterprise RODC protected-set documentation discrepancy (`P-88`);
- non-domain-NC authorization servicing context (`P-90`).

### 2d — Reachability, paths and remediation

A reachability finding is a statement about the Tier 0 control plane. A path is evidence for that
statement. A remediation is a claim about which **source configuration action** would remove one or
more routes and what would remain afterwards.

Those three concepts are stored separately.

#### Reachability is tri-state and executable

A clean-looking graph built from incomplete evidence is not a clean forest. `Tier0Reachability` is:

```
Reachable
NotReachable
Unknown
```

The implementation must make those values computational rather than merely reportorial.

Conceptually maintain two edge views:

```
G_definite
    capabilities established by complete required evidence

G_possible
    G_definite plus capability edges that could exist because a required input is Unknown
```

Then:

```
if principal reaches Tier0ControlPlane in G_definite:
    Reachable
else if principal cannot reach Tier0ControlPlane even in G_possible:
    NotReachable
else:
    Unknown
```

Not every missing-data condition will be representable as one concrete possible edge; the same rule
still applies. If the missing evidence could affect a route from the principal to the control plane,
`NotReachable` is not established.

**That rule is right and, taken literally, unimplementable.** One unreadable security descriptor
means *anyone might control anything through it*, and building `G_possible` by materialising those
edges connects everything to everything: quadratic in the forest, and useless — every principal
would come back `Unknown`. An implementation given only the rule above will either do that or
quietly drop the case, and dropping it is the `NotReachable`-that-means-*could-not-compute* failure.

So missing evidence is carried as a **bounded region** rather than as edges:

```
UncertaintyRegion:
    AffectedSubjects[]          who might gain an edge
    AffectedTargets[]           what they might gain it over
    AffectedCapabilityKinds[]   which capabilities are in doubt
    Reason                      the UnknownReason that produced it
    CanAffectReachability       whether it could touch a route to the anchor
```

The reachability question then asks whether a region **intersects** a candidate route, instead of
enumerating the edges inside it. An unreadable descriptor on one OU produces one region naming that
OU's subtree and the capability kinds an ACL there could confer — not a cross product.

**Every region must be bounded by captured facts.** A region whose subjects or targets cannot be
enumerated from the bundle is a capture defect, not a wider region: the honest response is to say
which partition could not be read, not to let one unbounded region make the whole forest `Unknown`.

The evaluator should preserve **why** uncertainty exists:

```
UnknownReasons[]
    PartialMembershipClosure
    PrimaryGroupDataMissing
    SecurityDescriptorUnreadable
    SchemaContextIncomplete
    NonDomainNcAuthorizationContextUnknown
    GpoApplicabilityUnknown
    DerivationPhaseFailed
    ResearchBlockedCapability
    ...
```

A missing unrelated object must not automatically turn the entire forest `Unknown`; uncertainty is
propagated according to whether it can affect the answer being evaluated.

#### The Tier 0 control-plane anchor is fixed and synthetic

Reachability is measured to one stable synthetic node:

```
[Tier0ControlPlane]
```

Only **fixed Tier 0 seeds** attach to it. `EffectiveMembership` and `DirectControl` classifications do
not become additional destinations.

Anchor attachments are modeling edges with explicit semantics:

```
Synthetic = true
TraversalCost = 0
Remediable = false
DisplayedAsHop = false
```

Thus a seed has distance zero to the Tier 0 control plane. A change in a principal's
`TierClassification` metadata does not itself move another principal's distance; only an actual graph
change can do that.

This makes the reachability algorithm and finding identity ask the same question:

> Can this principal reach **any fixed Tier 0 seed**?

The individual seeds reached remain evidence beneath the finding rather than becoming separate
reachability finding identities.

#### Reachability is computed backwards once

A backward breadth-first sweep from the fixed seed set / zero-cost anchor along reversed definite
edges computes, for every principal:

- definite reachability;
- shortest distance to a fixed seed;
- one deterministic predecessor chain for a shortest route.

A corresponding possible-edge analysis supports `Unknown` classification where needed.

This is one global traversal rather than a forward search from every principal. It has no arbitrary
security depth limit. A UI display limit is not a graph-analysis limit.

#### Route enumeration is bounded and does not promise an exact total it did not compute

Reachability and shortest distance do not require enumerating every simple path. Full path enumeration
can be exponential and is therefore performed only on demand for a finding, under explicit bounds.

The product may show:

- one deterministic shortest route;
- one best route under the ruled ordering, from a separate ordered search;
- mandatory chokepoints/remediation actions;
- a bounded sample of additional distinct routes.

**Shortest and best are different routes and both are worth showing.** Shortest answers *how close
is this principal to Tier 0* — it is the measure of exposure. Best answers *what would I actually
go and fix* — it is the one the ruling governs. They coincide often and not always, and a design
that shows only the shortest presents the most alarming route rather than the most actionable one.

Do **not** promise:

> Showing 3 of 120 routes

unless `120` was actually established by an exact path-count algorithm under precisely defined path
semantics.

Preferred wording when enumeration is truncated is:

> Showing 3 routes. Additional routes exist; enumeration was bounded.

or, where a lower bound is known:

> Showing 3 routes; at least 120 distinct routes were discovered before the bound was reached.

If the product later implements an exact count of a restricted path class, the UI names that class
explicitly (for example, `120 shortest routes`).

#### Remediation operates on source configuration actions, not merely derived capability edges

A derived graph edge is often **not** one independent thing an administrator can remove.

Examples:

- one inherited OU ACE can derive hundreds or thousands of object-level capability edges;
- one direct group-membership relationship can create many transitive effective-membership routes;
- one GPO link can influence many subjects;
- one ownership assignment can be evidence behind several downstream capability evaluations.

Therefore every capability/remediation-relevant relationship carries stable source facts and one or
more remediation actions:

```
SourceFact
    SourceFactId
    Kind
    StableSourceObject
    RawEvidence

RemediationAction
    RemediationActionId
    Kind
    SourceFactIds[]
    HumanDescription
    Preconditions
    IsRemovable
```

Many graph edges may refer to the **same** `RemediationActionId`.

Examples:

```
RemoveAce(OU=Servers, AceId=...)
RemoveDirectGroupMember(GroupA, Alice)
DisableGpoLink(LinkId=...)
ChangeOwner(ObjectX, ...)
```

This is the unit dominator/min-cut analysis should recommend. Splitting every derived capability edge
into an independently removable node would misrepresent one broad ACE as thousands of separate fixes.

**`RemediationActionId` identifies configuration state, never display text.** Deriving it from
`HumanDescription` — a hash of the sentence shown to the operator — is the obvious shortcut and it
is wrong in both directions: rewording the description invents a new action and closes the old one,
while two genuinely different ACEs that read alike collapse into one. The consequence is not
cosmetic. A dominator is the action present on *every* route, so two merged ACEs produce a
remediation that claims removing one ACE cuts every path when it cuts half of them. **The product
would tell a customer the escalation is closed when it is open.**

For an ACE the identity is built from captured facts sufficient to name it again on a later run:

```
object reference (objectGUID, not DN - a DN moves)
which security descriptor component (DACL / SACL)
canonical normalized ACE representation, or its bytes
inheritance source: explicit here, or inherited and from where
captured ordinal, where order is what distinguishes it
evidence hash of the descriptor it came from
```

**Explicit and inherited ACEs are never the same action even when identical**, because they are
removed in different places: one at the object, one at the container above it. Collapsing them
tells the administrator to edit an object where the ACE cannot be removed at all.

#### Dominators — mandatory remediation actions

Dominator analysis asks:

> Which removable action is present on every known route from this principal to the Tier 0 control
> plane?

The analysis is performed over the action-expanded graph, where shared source actions remain shared.
Synthetic anchor attachments are non-removable and excluded from remediation candidates.

A single mandatory action is a provably minimal one-action cut **for the graph being analyzed**.
Under incomplete evidence, the wording remains qualified:

> removes every route established in the captured graph; unresolved evidence remains.

Do not state "complete fix" over an `Unknown` reachability result.

Where no one action is mandatory, a multi-action minimum cut can be computed when practical. A greedy
set can be offered only as an approximation and must not be described as minimum unless minimum is
actually proven.

No complexity promise is made until the implementation algorithm and production-scale benchmark are
chosen.

#### Re-sweeping answers residual impact

For an administrator considering a specific allowed change, remove the corresponding
`RemediationActionId` from the analysis view and re-run the global sweep.

Report the residual, for example:

> Removing the inherited ACE on `OU=Servers` disconnects 118 principals from every known Tier 0 seed.
> Two principals remain reachable through independent source actions.

Residual statements are about principals/findings/routes in the captured graph, not about hypothetical
unseen evidence.

#### What an administrator actually experiences across two runs

The parts above describe machinery. This section states the loop they add up to, because a design
can be correct in every component and still deliver a miserable experience — and the question that
exposes it is: *I fixed something. Do I now have to re-audit, and will I be shown a near-identical
path all over again?*

**Answer: re-audit yes, near-identical path no — provided the product recommends cuts rather than
paths.** The distinction is the reason the anchor and the source-action model exist.

**Why a re-audit is unavoidable.** A bundle is sealed evidence of one moment. The product does not
hold a live connection and cannot know you removed an ACE; nothing about the old bundle changes when
the directory does. That is deliberate — `0008` removed live verification — and it is also honest:
a tool that marked a finding resolved because someone *said* they fixed it would be reporting an
intention, not a fact. **Closure is proved by the next capture, not asserted by the operator.**

**Why the near-identical path is not the outcome.** The failure being described is real and it is
what path-enumerating tools do:

```
Run 1   Alice -> HelpdeskGroup -> ServerAdmins -> DC01     "fix this"
        (operator removes Alice from HelpdeskGroup)
Run 2   Bob   -> HelpdeskGroup -> ServerAdmins -> DC01     "fix this"
        ... and 40 more, one per member
```

Forty findings for one misconfiguration, each closing individually and pointlessly, because the
thing that was wrong was never Alice. Three commitments prevent it:

1. **The recommendation is a `RemediationAction`, not a route.** Dominator analysis names the action
   present on *every* route — here the ACE granting `ServerAdmins` control of `DC01`, not the
   membership of whoever walked through it. Removing Alice was treating one symptom.
2. **All forty share one anchor.** Under `P-92` there is one reachability rule and one destination,
   so the report leads with *this one ACE puts 41 principals on the Tier 0 control plane*, not with
   41 rows.
3. **Residual is stated before you act.** *"Removing this ACE disconnects 118 principals; two remain
   through independent actions."* The two are named up front, so the second run holds no surprise.

**What the second run legitimately shows.** Some things reappearing are correct and not noise:

| Second run shows | What it means |
|---|---|
| The finding is gone | The cut worked. Proved by evidence, not asserted |
| The same finding, `Reopened` | The change did not take, or was reverted. Worth knowing |
| The named residual, alone | Exactly what you were told would remain |
| A genuinely new route | Something changed in the directory, or capture now reads what it could not before |
| `Unknown` where it was `Reachable` | **Not** a fix. Capture got worse, and the product says so |

That last row is the one an auditor should care about most, and it is why `Unknown` is a first-class
answer. A cut that appears to have worked because a permission became *unreadable* is not a cut, and
this design refuses to report it as one.

**What is genuinely lost, and it is the honest cost.** Because a finding is keyed on the rule, the
principal and the anchor — not on the route — **you cannot accept one path while staying alerted to
others for the same principal.** Accepting is coarse: it silences that principal's reachability
finding entirely. The alternative, per-route acceptance, was rejected because route identity is not
stable across runs — add one unrelated group and every signature through it changes, so acceptances
would silently evaporate and the operator would never know which. A coarse switch that behaves
predictably beats a fine one that quietly forgets.

**That rejection is sound and the resulting behaviour may still be wrong**, so it is open as `P-93`
rather than settled here. The reasoning above rules out per-route acceptance; it does not establish
that per-principal acceptance is what an administrator should be given. Deciding it now would mean
designing a lifecycle before anything produces a finding to accept, so it is deferred to when the
lifecycle is built — with the alternatives recorded in the row so the argument does not have to be
reconstructed. **Nothing downstream depends on the answer:** acceptance is lifecycle, and the derive
computes identical routes whichever shape wins.

#### Finding identity is generalized; reachability uses the anchor as its object

The rule catalogue already contains account findings, directory-object findings, aggregate/set
findings, absence findings and temporal findings. A root finding model that requires every finding to
be `(principal, target)` is too narrow.

Use:

```
FindingKey
    RuleId
    SubjectRef
    ObjectRef?        // optional second stable referent / scope
```

`SubjectRef` and `ObjectRef` use discriminated stable references appropriate to the finding:

- directory object;
- authorization/SID principal;
- aggregate key such as normalized SPN;
- synthetic control-plane anchor;
- other accepted typed subject kinds.

Examples:

```
Reachability:
    RuleId      = canonical Tier0Reachability rule
    SubjectRef  = principal
    ObjectRef   = Tier0ControlPlane

Capability finding:
    RuleId      = UnexpectedPrincipalCanWriteRBCD
    SubjectRef  = principal
    ObjectRef   = target computer

Duplicate SPN aggregate:
    RuleId      = DuplicateSpn
    SubjectRef  = AggregateKey(normalized SPN)
    evidence    = all objects carrying it

LAPS missing:
    RuleId      = LapsMissing
    SubjectRef  = computer
```

The path is not part of finding identity. Stable identity preserves acceptance/lifecycle across route
changes.

#### The path-rule catalogue needs one canonical Tier 0 reachability owner (`P-92`)

The predecessor has multiple overlapping path rule IDs (short Tier0 path, Tier0 path, shadow/DCSync/
delegation path categories). Under the anchor model, the last categories are evidence types under the
same collapsed question.

Before Stage 3 is locked, an owner decision must choose one of:

1. one canonical Tier0 reachability rule ID, with distance and route type as evidence/grade;
2. intentionally multiple anchor findings per principal with clearly non-overlapping rule semantics;
3. retire the old path rule IDs and introduce a new canonical rule.

The current preferred architecture is **one canonical reachability rule**, because the multi-source
sweep computes one reachability state per principal and the anchor deliberately collapses equivalent
Tier 0 destinations. Severity/grade can still depend on distance and route properties without creating
several nearly identical findings.

Tracked as `P-92` until accepted.

#### Evaluation outcome and lifecycle are different state machines

Do not overload reachability `Unknown` as a quasi finding lifecycle state.

Every rule produces an evaluation outcome:

```
EvaluationOutcome:
    Established
    NotEstablished
    Indeterminate
    DidNotRun
    Error
```

The stored finding has a separate lifecycle:

```
LifecycleState:
    Active
    Accepted
    Resolved
    Reopened
```

For the Tier0 reachability rule:

```
Reachable     -> Established
NotReachable  -> NotEstablished
Unknown       -> Indeterminate
```

Other rule types map their own predicate into the same generic evaluation outcomes.

A **reachability finding** resolves only when its evaluation becomes `NotEstablished` because
`Tier0Reachability = NotReachable` under complete required evidence. That rule does not apply to every
finding type.

#### Temporal rules use a recorded evaluation reference time

Rules such as stale password rotation or static-password age must not call `DateTime.Now` invisibly
when judging a sealed historical bundle, or the same evidence will produce different results merely
because it was opened later.

The default deterministic contract is:

```
EvaluationAsOf = Bundle.CaptureCompletedAt
```

If the product later supports "evaluate this old evidence as of today", that is a separate explicit
assessment mode whose reference timestamp is recorded as an input.

Every temporal finding records:

```
EvaluationAsOf
Threshold / rule parameters
Source timestamp(s)
```

#### Route grading remains evidence-aware

A route is presented as a directly feasible, high-confidence attack path only when all required
inputs are complete, every step is high-confidence, and no step depends on an unmet/unknown
precondition.

Otherwise the route remains visible as reachability with typed reasons such as:

```
Conditional capability
Credential exposure requires authentication event
GPO applicability unknown
Non-domain NC authorization context unresolved
Capability research blocked
Coverage incomplete
```

`EdgeClass` is reported as semantics, not used as an ordinal score by itself.

#### Determinism and provenance are required for reproducibility

The same sealed bundle judged under the same semantic versions and reference time must produce the
same findings, shortest routes and displayed ordering.

Anything displayed to a customer is retained as typed evidence or can be deterministically
reconstructed from recorded inputs.

A finding/evaluation records at least:

```
RuleId / RuleVersion
DerivationGenerationIds[]
CapabilityCatalogueVersion
PrivilegedRoleCatalogueVersion
PrivilegedCapabilityCatalogueVersion
TierPolicyId / TierPolicyVersion
SchemaGuidCatalogueVersion
DerivationEngineVersion
EvaluationAsOf
Coverage/UnknownReasons
```

Rerunning the same bundle under a newer catalogue is allowed to produce a different result, but the
old and new results must explain **which semantics changed** rather than appearing as unexplained
finding churn.

#### Design costs retained deliberately

- there is no materialized inventory of every simple escalation path;
- route enumeration work moves partly to interactive/on-demand analysis;
- per-path acceptance is intentionally not the root lifecycle model;
- best route requires a separate ordered search, over and above shortest-path — **ordering ruled
  2026-08-26, see below**;
- non-dominator impact counts can require candidate re-sweeps;
- non-domain-NC authorization context and some capability semantics remain research gates.

#### The best route is the one an administrator can act on — ruled 2026-08-26

Saying a search is *weighted* names a mechanism, not a comparison. `EdgeClass` is deliberately not a
rank, so there was no ordering to inherit from it, and an earlier draft asserted a capability it
never specified. The owner settled it: **prefer the longer route that definitely works over the
shorter one that might.** Certainty beats brevity, because the point of showing a route is that
someone does something about it.

The plausible orderings disagree on real inputs, so the choice had to be made rather than left open:

| Ordering | What it prefers | Why not |
|---|---|---|
| Additive weights | a long cheap chain over a short expensive one | uncertainty becomes a number that trades against length — the trade the ruling forbids |
| Bottleneck | the route whose worst step is least bad | ignores everything but one edge; two routes with the same weak link are indistinguishable |
| Pareto | no single winner, a set of non-dominated routes | correct and unusable — it answers "here are nine" when the question was "what do I fix" |
| **Lexicographic** | **first criterion decides absolutely** | **chosen** |

**Lexicographic, in this order.** Each criterion is exhausted before the next is consulted, so no
amount of advantage lower down can outweigh a difference higher up:

```
1. Definite before possible        no route resting on Unknown outranks one that does not
2. Direct before conditional       preconditions are things that might not hold
3. Fewer unmet preconditions       among conditional routes, the one needing least to be true
4. Higher confidence               how well the capability semantics are established
5. Shorter                         only now does length matter
6. Stable route signature          determinism, never a judgement
```

**Length is fifth on purpose.** A four-hop chain of plain group memberships beats a two-hop chain
resting on a capability the catalogue is unsure about, because the first can be verified and cut
today and the second may not be real. That is the ruling, applied.

**Confidence sits below preconditions** because they fail differently. An unmet precondition is a
fact about the forest an administrator can check — *is unconstrained delegation actually enabled on
that host?* Low confidence is a limitation in **our** understanding of the capability semantics, and
it is not his to resolve. The thing he can act on is ranked above the thing he cannot.

**A tie above the signature is not broken by preference.** If two routes are equal through all five,
the signature decides, so repeated runs agree. Determinism is not an opinion about which route is
better.

**This ordering does not change which findings exist**, only which evidence leads. Every route to
the anchor remains available; ordering is presentation. And it is not a severity — `0066` fixes
severity on the rule card, so a route being weak never quietens a finding.

For drift/tripwire use cases, diff the underlying source facts/capabilities between bundles directly.
Path-signature churn is a noisy proxy for a permission or membership change.

## Stage 3 — judge

### The rule interface

`IRule.Judge(EvidenceObject)` is replaced by a rule interface over declared, versioned derived facts.
A rule never receives a raw database handle from which it can silently discover undeclared inputs.

Each rule declaration includes at least:

```
RuleId
RuleVersion
RequiredFactKinds[]
RequiredCoverage[]
RequiredCatalogueVersions / compatibility constraints
FindingSubjectKind
EvaluationShape
```

A missing declared input produces `Indeterminate` / `InputsNotCaptured`, not zero findings.

Typed evidence is mandatory. Free-form `ContextJson`-style blobs are not part of the contract.

### Rule shapes

The complete predecessor rule audit proves that three shapes are insufficient. The judgement layer
supports these reusable shapes:

1. **Capability rules** — query a named semantic capability plus target/scope filters.
2. **Tier/reachability rules** — query operational tier classification, basis, reachability, distance,
   scope and route evidence.
3. **Attribute/state rules** — evaluate captured object state without reconstructing authorization.
4. **Aggregate/set rules** — evaluate a set condition such as duplicate SPN values or group size.
5. **Absence rules** — establish that expected state is missing only when capture/visibility is complete
   enough to distinguish absence from unread data.
6. **Temporal rules** — evaluate captured timestamps against the recorded `EvaluationAsOf` reference.

The finding-reference model is typed so a subject can be an account, GPO, OU, certificate template,
domain root, topology object, aggregate key or other supported stable reference. The storage schema
must not assume every finding subject has a SID.

#### A rule never reconstructs a permission equivalence set

A rule about resource-based constrained delegation asks:

```
CanWriteRBCD ?
```

It does not list `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `Owns` or property rights and
attempt to infer equivalence itself.

If a rule needs to name a raw ACE/right to produce the security meaning it wants, the missing feature
is a capability in `2b`, not a cleverer rule predicate.

This is how the product prevents the rule catalogue from becoming dozens of slightly different and
slightly wrong implementations of Windows authorization semantics.

### Research-blocked capabilities are build-visible

A capability whose required Microsoft semantics have not been verified can be marked:

```
CapabilityResearchStatus = ResearchBlocked
```

A production rule cannot silently consume a research-blocked capability as established. The build or
rule-catalogue validation fails unless the rule explicitly handles the capability only as
`Indeterminate`/research evidence.

DCSync full-domain-secret replication is no longer research-blocked because the applicable MS-DRSR
procedure has been read and cited in `2c`.

### Recording what ran

Recording only a rule ID/version is insufficient. The run records:

- whether the rule ran;
- `EvaluationOutcome`;
- inputs/coverage that were unavailable;
- applicable derivation-generation IDs;
- semantic catalogue/policy versions;
- `EvaluationAsOf` for temporal evaluation;
- errors without preventing unrelated rules from running.

A rule that executed but could not read its required inputs is not a successful clean evaluation.

### Writing

Finding/evaluation writes and the run record that says what was judged are committed atomically.
A throwing rule is recorded as `Error`; other independent rules continue.

Lifecycle updates (`Active`, `Accepted`, `Resolved`, `Reopened`) are applied from stable `FindingKey`
identity and the new evaluation outcome rather than inferred from whether a row happened to be emitted.

## What is deliberately not built

- **Customer-tunable severity.** Severity remains catalogue-owned unless an accepted decision changes
  that policy.
- **A second suppression mechanism.** Finding acceptance/suppression has one stable-identity model.
- **Live verification** and **assessment mode** remain removed unless explicitly reintroduced.
- **A full Tier 1/Tier 2 catalogue.** Values may exist in enums, but no principal is assigned them
  until an accepted catalogue exists.
- **A universal capability catalogue inside this architecture file.** Capability semantics live in a
  separately versioned, first-party-verified catalogue.

## Scope

**The full judgement stage is in scope through escalation paths, remediation analysis and finding
lifecycle; it is not built yet.** Capture exists today, while the derive/judge phases described here
are implementation work.

The product does not ship this stage at an intermediate point where capture works but findings cannot
be produced. That does not remove implementation ordering: each phase is built and proven before the
next rests on it.

| Phase | Builds | Proven by |
|---|---|---|
| 1 | reading objects/permissions back from a sealed bundle | existing attribute rules can execute against bundle evidence |
| 2 | directory nesting, authorization membership and primary groups | effective privileged membership agrees with lab/token oracle fixtures |
| 3 | operation-specific capabilities from effective authorization | capability fixtures agree with Microsoft protocol semantics and lab checks |
| 4 | privileged/protected classification, fixed Tier0 seeds, effective seed membership and qualifying direct controllers | every classification names typed evidence, scope and policy/catalogue version |
| 5 | definite/possible reachability, bounded route display, source-action remediation | reachability/unknown/remediation acceptance tests and production-scale benchmarks |
| 6 | generic rule judgement and lifecycle | all supported rule shapes produce deterministic findings from sealed bundles |

Phase 5 computes reachability to the synthetic `Tier0ControlPlane` connected **only to fixed seeds**.
Derived Tier0 principals remain graph participants and evidence; they do not become new reachability
endpoints.

Phases remain separable because operational Tier0 classification is not recursively defined through
all transitive control paths under the active Tier policy.

The value of the ordering is testability: a defect in membership or authorization otherwise silently
corrupts every higher-layer finding.

## Acceptance criteria

These criteria are written to become executable tests. Where a criterion depends on an open owner
policy, the build must treat the corresponding feature as unresolved rather than silently choosing a
value.

**A criterion that has not become a named test is not satisfied, however obviously true it reads.**
That is the founding rule of this repository's gates applied here: the deciding question is *what
change to the product would make this fail?* If the answer is *nothing*, nothing is being checked.
Name each test for the criterion it discharges — `AC_055_NullDaclAndEmptyDaclDiffer`,
`AC_077_FilteredReplicationDoesNotImplyFullSecrets` — so the mapping survives a rename, and state
in the commit which criteria it covers.

**Most of these criteria are stated in the negative, and that is deliberate.** They name the
tempting wrong answer and require it to fail — the shortcut that reads as sensible until it reports
something false. A test that only proves the right answer works will still pass when the shortcut is
taken; a test that proves the shortcut fails will not.

**Two things cannot be checked by internal consistency, and both have already gone wrong here.**

The first is a set of tests agreeing with each other while anchored to the wrong reference. A
capability catalogue can be proved self-consistent in every direction and still be missing a
capability nobody wrote down — the failure recorded as `F-S44-2`, where fifteen attributes went
missing behind three sound test suites. **Ask what the checks are anchored to, not only whether each
one is sound.**

The second is semantics. Whether `Get-Changes-All` really implies secret revelation cannot be
settled by any arrangement of this repository's own code. Every capability needs at least one
external oracle before its implementation merges: a fixture derived from the protocol pseudocode, a
lab observation from a real forest, a comparison against the platform's own access check, or a
negative case proving the tempting shortcut produces the wrong answer. **Ownership, object-specific
ACEs, group scope, GPO applicability and the replication rights are the five where an agreeable
simplification is most likely and most costly.**

**Vague words are the mechanism by which this goes wrong.** *Where applicable*, *normally*, *when
practical*, *qualifying*, *similar special identities* — twelve such phrases remain in this document
and each is a decision deferred. They are acceptable in prose that argues; they are not acceptable
in the sentence an implementation is written from. Where one of them governs behaviour, the
capability catalogue must say what it means in machine-readable terms — target classes, requested
operation, required facts, authorization procedure, feasibility, propagation, classification effect,
research status and sources — and the code is generated from that, not from the paragraph.

| ID | Criterion |
|---|---|
| AC-01 | Privileged is not automatically Tier0. A helpdesk group delegated password reset over ordinary users can be `IsPrivileged` while `TierClassification != Tier0`. |
| AC-02 | Protected is not automatically Tier0. A protected principal with no seed membership/direct-control basis is not promoted solely because SDProp covers it. |
| AC-03 | Dangerousness is target/capability-specific. `GenericAll`-derived control over an ordinary test account is dangerous without being Tier0. |
| AC-04 | A qualifying capability that directly controls a fixed Tier0 seed produces `Tier0Basis = DirectControl` and names the capability/target evidence. |
| AC-05 | A transitive control chain is discovered and reported without recursively assigning `Tier0` beyond the active policy's direct-control boundary. |
| AC-06 | A custom group/principal can become Tier0 without appearing in a hard-coded name list when evidence establishes `EffectiveMembership` or `DirectControl`. |
| AC-07 | `adminCount = 1` alone never produces current Tier0 or protected classification. |
| AC-08 | Current protected status is reported independently from Tier0 status. |
| AC-09 | Every non-seed classification carries typed evidence; `EffectiveMembership` carries a membership chain and `DirectControl` carries a capability/target. |
| AC-10 | Membership and control cycles terminate deterministically. Membership cycles can also produce a dedicated finding. |
| AC-11 | Renaming a well-known seed does not lose seed classification; matching uses stable SID/RID/object identity as appropriate. |
| AC-12 | Scope is retained so object/domain/forest authority is distinguishable. |
| AC-13 | Generic finding identity is `RuleId + typed SubjectRef + optional ObjectRef`; path is not part of identity. |
| AC-14 | A **reachability** finding resolves only when `Tier0Reachability = NotReachable` under complete required evidence; this lifecycle rule is not applied to unrelated finding types. |
| AC-15 | Every remediation recommendation states its residual effect; if nothing remains, that is stated explicitly. |
| AC-16 | Completeness/minimality is claimed only when proven for the analyzed captured graph. Unknown evidence prevents a "complete fix" claim. |
| AC-17 | Bounded route display never invents an exact total. Exact `Showing X of Y` wording is used only when `Y` was actually computed for a named path class. |
| AC-18 | Same bundle + same semantic versions + same `EvaluationAsOf` produces deterministic findings/routes/order. |
| AC-19 | Customer-visible routes/remediation evidence is stored or deterministically reconstructable from recorded versions/inputs. |
| AC-20 | Where no small remediation cut exists, the product says so rather than printing an unusable edge list as an answer. |
| AC-21 | A claimed mandatory remediation action really lies on every definite route for the finding; removing it and re-sweeping establishes the claimed residual. |
| AC-22 | When no single mandatory action exists, a multi-action change is required; a greedy approximation is not presented as a proven minimum. |
| AC-23 | A new route bypassing a previously mandatory action removes that action from the mandatory set and is detected as remediation drift. |
| AC-24 | A capability edge exists only where the requested operation is established by the applicable AD authorization semantics; allow-minus-deny shortcuts fail this test. |
| AC-25 | Distribution-only nesting does not create current authorization/Tier0 reachability. |
| AC-26 | The same distribution-only nesting can contribute to protected-principal derivation and a latent-privilege finding. |
| AC-27 | OWNER RIGHTS (`S-1-3-4`) is evaluated as part of owner implicit-right semantics and can alter the owner's implied access. |
| AC-28 | `EdgeClass` is preserved as semantic category and is not treated as an ordered risk score. |
| AC-29 | Full-domain secret replication is represented by a compound semantic capability, not by treating each replication right independently. |
| AC-30 | Adding an ordinary computer to RID 516 does not make it a domain controller/Tier0 asset. |
| AC-31 | Reachability is tri-state: missing relevant evidence can produce `Unknown`; zero definite routes alone does not imply `NotReachable`. |
| AC-32 | `Unknown` reachability maps to `EvaluationOutcome = Indeterminate`, not to a resolved lifecycle. |
| AC-33 | No remediation claims complete coverage while relevant reachability is `Unknown`; unknown reasons are reported. |
| AC-34 | Multi-hop reachers remain `Unclassified` (unless another accepted tier catalogue classifies them) while retaining `Tier0Reachability` and distance. |
| AC-35 | No judgement rule reconstructs a raw-right equivalence set; rules ask for semantic capabilities/derived facts. |
| AC-36 | SELF (`S-1-5-10`) on a security principal resolves to that object's authorization SID and can participate in capability evaluation. |
| AC-37 | Ownership alone does not create an unconditional `WriteDacl`/takeover edge. |
| AC-38 | `PropagatesControl` is a capability property, not a hard-coded list of raw ACE names. |
| AC-39 | Route grade derives from feasibility/confidence/preconditions, not `EdgeClass` ordering. |
| AC-40 | Every conditional capability names at least one concrete precondition. |
| AC-41 | Membership is target-independent while authorization usability is context-dependent; cross-domain domain-local scope is asserted on a fixture with enough domains/contexts to make the distinction real. |
| AC-42 | Builtin groups in different domain NCs remain distinct directory objects even when SID values match; authorization trustee matching remains SID/context-based and provenance is not merged. |
| AC-43 | GPO applicability considers site/domain/OU scope, link state/order, enforced/block inheritance, policy-half status, security filtering and WMI; missing required evidence produces `Unknown`. |
| AC-44 | `CanReplicateAllDomainSecrets` requires `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`; `Get-Changes` alone is not classified as full-domain secret replication. |
| AC-45 | A membership cycle can be surfaced as a finding in addition to being safely traversed. |
| AC-46 | A Tier0 reachability finding targets the synthetic control-plane anchor and resolves only when no fixed seed is reachable. |
| AC-47 | Individual fixed seeds reached remain evidence under the anchor finding, each with route/distance evidence where requested. |
| AC-48 | Derived Tier0 classifications do not become new anchor endpoints; merely changing classification metadata does not change another principal's distance. |
| AC-49 | Effective security-group membership in a seed group produces `Tier0Basis = EffectiveMembership` and remediation points to the source membership relationship/path. |
| AC-50 | `PropagatesControl` and `Tier0ClassificationEffect` are independent catalogue properties. |
| AC-51 | A GPO with unresolved applicability inputs produces `Unknown` and names the missing evidence; WMI is one possible reason, not the only one. |
| AC-52 | Site-linked GPOs are considered; user and computer subjects are representable even if only the computer-side Tier0 capability is initially implemented. |
| AC-53 | Application-partition handling does not equate Microsoft's "local group" warning with every AD domain-local group. Ambiguous servicing/resource context produces `Unknown`; a domain-local SID is not declared uninterpretable merely because the NC is an application partition. |
| AC-54 | No principal is assigned Tier1/Tier2 until an accepted catalogue defines those values. |
| AC-55 | NULL/no DACL and present-but-empty DACL serialize as different states and produce different normal access-check results. |
| AC-56 | Missing schema/property-set/object-class/inheritance/trustee/security-descriptor evidence yields `CapabilityEvaluation = Unknown`, never "capability absent". |
| AC-57 | `BlockOwnerImplicitRights` tests documented requester exceptions (Domain Admins / Enterprise Admins), applicable setting/server behavior and computer-derived target class. |
| AC-58 | Non-computer ownership is not suppressed by the computer-specific `BlockOwnerImplicitRights` rule; OWNER RIGHTS remains independently applicable. |
| AC-59 | Directory-object identity and authorization-trustee identity remain separate typed concepts throughout capture, derive, findings and remediation evidence. |
| AC-60 | A direct controller over a seed is graph evidence/classification but is not connected to the control-plane anchor as a destination. |
| AC-61 | `Tier0Basis` has one authoritative enumeration everywhere: `Seed`, `EffectiveMembership`, `DirectControl`. |
| AC-62 | Every finding records the rule, derivation-engine, capability-catalogue, privileged-catalogue, tier-policy and schema/GUID semantic versions that produced it. |
| AC-63 | `primaryGroupID` membership is included even when neither `memberOf` nor the group's `member` attribute contains the account. A user whose primary group is Domain Admins is found. |
| AC-64 | Primary-group membership participates in protected-principal derivation as well as authorization membership where the group is in the protected set. **Blocked pending evidence:** the `primaryGroupID` citation establishes membership and its use in authorization, not the SDProp traversal. This criterion may not be implemented until either a Microsoft protocol citation shows primary-group membership participating in protected-group evaluation, or a lab observation is recorded and labelled as lab-verified rather than specified. |
| AC-65 | Many derived capability edges produced by one inherited ACE share one `RemediationActionId`; dominator/min-cut analysis recommends the source ACE once, not thousands of child edges. |
| AC-66 | One direct group membership that feeds many transitive paths remains one source remediation action. |
| AC-67 | Findings can have non-account subjects (OU, GPO, certificate template, domain root, topology object) without inventing a SID. |
| AC-68 | Aggregate/set, absence and temporal rules have typed rule shapes and stable finding keys. |
| AC-69 | `EvaluationOutcome` (`Established`, `NotEstablished`, `Indeterminate`, `DidNotRun`, `Error`) is separate from lifecycle (`Active`, `Accepted`, `Resolved`, `Reopened`). |
| AC-70 | Temporal rules use recorded `EvaluationAsOf` (default capture completion time) so the same bundle does not change merely because it is opened later. |
| AC-71 | A failed new derivation generation cannot cause Stage 3 to consume an older generation as though it were current; compatibility/status is checked explicitly. |
| AC-72 | Synthetic anchor edges are zero-cost, non-removable and not displayed as security hops. Seed distance is zero. |
| AC-73 | Unknown propagation is relevant, not global: missing evidence that cannot affect a principal's possible path does not automatically turn that principal `Unknown`. |
| AC-74 | Capability research blocks are build/rule-visible. A production rule cannot consume a `ResearchBlocked` capability as established. |
| AC-75 | `BlockOwnerImplicitRights` reads `dSHeuristics` character 29 and accepts values `0`–`3`, resolving any other value to `1` and an absent character to `0`. Treating `0` as "not configured" fails, and so does treating a malformed value as inert. Applicability follows the recorded server behavior, not a hard-coded release name. |
| AC-76 | Ownership-derived capabilities are evaluated against the concrete security-descriptor modification the capability requires. A capability that names no modification evaluates to `Unknown`; one that does follows the documented rules and may be `Established` or `NotEstablished`. Returning `Unknown` for every ownership case on a given build fails. |
| AC-77 | `CanReplicateFilteredAttributes` is derived as `Get-Changes AND (Get-Changes-All OR Get-Changes-In-Filtered-Set)`. A principal holding `Get-Changes` and `Get-Changes-In-Filtered-Set` alone yields this capability and does **not** yield `CanReplicateAllDomainSecrets`. |
| AC-78 | All three replication capabilities are evaluated against the naming-context root, and a finding carrying one targets the partition rather than an object beneath it. |
| AC-79 | Reachability to the anchor emits findings under SEC-071 only. A finding carrying SEC-070, SEC-072, SEC-076 or SEC-077 fails, and those identifiers are never reissued for anything else. |
| AC-80 | Path length and the reached destination are evidence fields on the SEC-071 finding, present and orderable. A design that recovers the distinction by varying severity per finding fails, because `0066` fixes severity on the rule card. |
| AC-81 | The key-credential capability names `msDS-KeyCredentialLink` and no other attribute. Mapping `altSecurityIdentities` to it fails: that attribute is certificate mapping, a separate capability with its own citation, and membership of the `BlockOwnerImplicitRights` protected-property list confers no capability meaning. |
| AC-82 | `CanReplicateFilteredAttributes` carries its own security-significance citation, separate from the MS-DRSR procedure that establishes its boolean. A capability whose only source proves the authorization condition and not the impact fails. |
| AC-83 | Missing evidence produces bounded `UncertaintyRegion` records whose subjects and targets are enumerable from the bundle. No implementation materialises possible edges as a cross product, and an unbounded region is reported as a capture defect naming the unread partition rather than making the forest `Unknown`. |
| AC-84 | `RemediationActionId` is derived from captured configuration state and not from `HumanDescription`. Rewording a description does not change the id, and two ACEs differing only by inheritance source, ordinal or descriptor never share one. |
| AC-85 | Route ordering is lexicographic in the ruled sequence: definite before possible, direct before conditional, fewer unmet preconditions, higher confidence, shorter, then stable signature. A two-hop route resting on an `Unknown` input never outranks a longer definite one, and no implementation trades certainty against length by summing weights. |
| AC-86 | Route ordering never alters severity, which `0066` fixes on the rule card, and never removes a route from the evidence. Two routes equal through all five criteria are ordered by signature alone, so repeated runs of one bundle agree. |
| AC-87 | Where one source action dominates every route from many principals, the report's primary recommendation is that action once, not one recommendation per affected principal. A design emitting a row per principal for a single dominating ACE fails. |
| AC-88 | A reachability finding resolves only when a later bundle evaluates it `NotEstablished` under complete evidence. An operator marking it fixed cannot resolve it, and a finding whose evaluation moves from `Reachable` to `Unknown` is reported as reduced coverage rather than as resolved. |
| AC-89 | A residual statement names what remains before the change is made, and the principals it names are the ones still reachable in the next bundle if only the stated action was taken. |

## Non-goals

This specification does not:

- assign severity to every dangerous capability — severity remains rule/catalogue-owned;
- define the complete semantic capability catalogue — that is a separate first-party-verified artefact;
- discover Tier0 infrastructure that has no observable AD relationship;
- infer compromise, attacker intent or that an attack occurred;
- declare every privileged or AdminSDHolder-protected principal Tier0;
- define a full Tier1/Tier2/custom-tier catalogue;
- perform a complete enumeration of every escalation path in the forest;
- treat Group Policy **content/SYSVOL file authorization** as AD DACL semantics; those need their own
  implementation layer;
- silently resolve research-open protocol behavior by convention.

## Rule coverage — what this machinery does and does not reach

The predecessor's rule cards are an external anchor for whether the architecture can express the
findings the product intends to support. This table classifies **machinery**, not security correctness;
each rule still needs its own first-party semantic review.

### Legend

| Code | Machinery |
|---|---|
| `O` | captured object/state attributes |
| `M` | authorization membership / privileged derivation |
| `P` | protected-principal derivation |
| `C` | semantic capabilities from `2b` |
| `T` | operational Tier0 classification/policy |
| `R` | Tier0 reachability/route evidence |
| `S` | aggregate/set rule shape |
| `A` | absence rule shape |
| `H` | temporal rule shape + `EvaluationAsOf` |
| `GP` | Group Policy content / SYSVOL file authorization layer outside this spec |
| `TierX` | Tier1/custom-tier vocabulary not defined here |

### The table

| Rule | Name | Needs | Architecture status |
|---|---|---|---|
| SEC-001 | Unexpected GenericAll on Domain | C T | supported |
| SEC-002 | Unexpected Principal can DCSync | C T | supported; DCSync compound capability verified |
| SEC-003 | Unexpected Principal can Reset Admin Password | C M T | supported |
| SEC-004 | Unexpected Principal can Write DACL on Admin | C M T | supported |
| SEC-005 | Unexpected Principal can Write Owner on Admin | C M T | supported; owner semantics remain capability-specific |
| SEC-006 | Unexpected Principal can Add Members to Admin Group | C M T | supported |
| SEC-010 | Unconstrained Delegation | O | built today; higher-layer route semantics are capability catalogue work |
| SEC-011 | Unconstrained Delegation on Non-DC | O | built today |
| SEC-012 | Constrained Delegation to Sensitive Service | O T | supported |
| SEC-013 | RBCD Configured on Privileged Resource | O T | supported |
| SEC-014 | Unexpected Principal can Configure RBCD | C | supported; exact classification effect remains catalogue-owned |
| SEC-020 | Kerberoastable Account | O | supported |
| SEC-021 | Kerberoastable Privileged Account | O M | supported once privileged catalogue is populated |
| SEC-022 | AS-REP Roastable Account | O | supported |
| SEC-023 | AS-REP Roastable Privileged Account | O M | supported once privileged catalogue is populated |
| SEC-024 | Unexpected Principal can Write SPN | C | supported |
| SEC-025 | Shadow Credentials Attack Vector | C | supported |
| SEC-026 | Duplicate SPN Registered | O S | supported by aggregate/set rule shape |
| SEC-030 | AdminCount Without Protection | O P | supported |
| SEC-031 | Non-Default Owner on Admin Object | O M T | supported |
| SEC-032 | Disabled Privileged Account | O M | supported once privileged catalogue is populated |
| SEC-040 | Unexpected Principal can Enroll Certificates | C | supported by typed non-account subject model |
| SEC-041 | Certificate Auto-Enrollment for Non-Admin | C | supported by typed subject model; predecessor state remains a rule-policy question |
| SEC-050 | Large Privileged Group | M S | supported by aggregate/set rule shape |
| SEC-051 | Nested Group in Domain Admins | M | supported, including primary-group correctness where applicable |
| SEC-052 | Circular Group Membership | M | supported |
| SEC-060 | Broad Principal with Dangerous Write Access | C | supported |
| SEC-061 | Pre-Windows 2000 Compatible Access | M C | supported |
| SEC-062 | Domain Users in Local Admins Equivalent | M C | supported; authorization context must be correct |
| SEC-063 | Unexpected Broad Control Over Container | C | supported by typed subject model |
| SEC-064 | Dangerous User Right Granted via Group Policy | GP | outside this architecture layer |
| SEC-065 | Privileged Local Group Membership via Restricted Groups | GP | outside this architecture layer |
| SEC-066 | Weak Directory or SMB Signing Posture | GP | outside this architecture layer |
| SEC-067 | Tier 0 Account Exposed to Delegation Impersonation | O M T | supported |
| SEC-070 | Short Path to Tier 0 Target | R T | retired into SEC-071; path length becomes evidence `P-92` |
| SEC-071 | Path to Tier 0 Target | R T | supported; the one reachability finding, absorbing SEC-070/072/076/077 `P-92` |
| SEC-072 | Path to Tier 0 Shadow | R T | retired into SEC-071; destination becomes evidence `P-92` |
| SEC-073 | Short Path to Tier 1 Target | R TierX | gap — Tier1 undefined |
| SEC-074 | Path to Tier 1 Target | R TierX | gap — Tier1 undefined |
| SEC-075 | Path to Custom-Tier Target | R TierX | gap — custom tier policy undefined |
| SEC-076 | Path to DCSync Shadow | R T | retired into SEC-071; destination becomes evidence `P-92` |
| SEC-077 | Path to Unconstrained Delegation Host | R T | retired into SEC-071; destination becomes evidence `P-92` |
| SEC-080 | Unexpected Principal can Modify GPO | C | supported by typed GPO subject model |
| SEC-081 | Unexpected Principal can Create GPO Links | C | supported |
| SEC-082 | Unexpected Principal can Modify GPO via SYSVOL | GP | outside AD DACL capability layer; file authorization required |
| SEC-083 | Group Policy Preferences Password Exposure | GP | outside this architecture layer |
| SEC-090 | Unexpected Principal can Read LAPS Passwords | C | supported |
| SEC-091 | LAPS Missing on Computer | O A | supported by absence rule shape; coverage must distinguish absent from unreadable |
| SEC-092 | LAPS Password Rotation Stale | O H | supported by temporal rule shape |
| SEC-093 | LAPS Decryptor is a Broad Principal | O M | supported |
| SEC-100 | Service Account with Admin Privileges | O M | supported once privileged catalogue is populated |
| SEC-101 | Service Account with Non-Expiring Password | O | supported |
| SEC-102 | Risky gMSA Password Retrieval Principal | O M | supported |
| SEC-120 | AdminSDHolder ACL Backdoor | C T | supported |
| SEC-121 | Domain Controllers OU Write Access | C T | supported by typed directory-object subject model |
| SEC-122 | RBCD Configured on Domain Controller | O T | supported |
| SEC-123 | Write SIDHistory Permission | C | supported |
| SEC-124 | Replication Topology Control Permission | C T | supported by typed topology-object subject model |
| SEC-126 | Privileged Service Account with Static Password | O M H | supported by temporal rule shape once privileged catalogue is populated |
| SEC-131 | Privileged Account with Delegation Enabled | O M | supported once privileged catalogue is populated |
| SEC-201 | DACL/Owner Control on Domain Root | C T | supported by typed domain-root subject model |
| SEC-204 | Unexpected Principal with High-Impact Right on Tier-0 Target | C T | supported |

### What the table now says

**Reconciled 2026-08-26, in both directions.** The table carries 62 rows, all distinct; the rule
cards under `docs/rules/` number 62; and the two sets are equal — no row without a card, no card
without a row. Counted by extracting `SEC-\d+` from the leading cell of each table row and from the
card filenames listed by `git ls-files docs/rules/*.md`, then differencing each set against the
other. Of the 62, 47 read `supported` and 3 are marked `gap`; the remainder carry a stated condition,
usually a catalogue that must be populated first.

**A count is not coverage.** Every row is one reader's judgement that the machinery *can* express
the rule, made against a specification, and no rule is implemented. Two rules are written and both
are unreachable. Treat the table as a claim to be falsified when each rule is built, not as progress.

The high-level judgement machinery can represent the great majority of the predecessor rule shapes.
The remaining **architectural** gaps are explicit rather than accidental:

1. Group Policy content/SYSVOL file-permission rules need their own layer.
2. Tier1/custom-tier path rules need a tier policy that does not exist in this spec.
3. Old overlapping Tier0 path rule IDs are consolidated — `P-92` ruled 2026-08-26, see below.
4. Rules that depend on `IsPrivileged` require the privileged-role/capability catalogues to be
   populated and versioned before they are implementation-ready.
5. Every individual capability/rule still requires security-semantic verification; "supported" in
   this table means the architecture has the right input/output shape, not that the rule is already
   correct.

### Five path rules become one — `P-92`, ruled 2026-08-26

The predecessor reported one problem under five identifiers. SEC-070 and SEC-071 are the same
finding at two path lengths. SEC-072, SEC-076 and SEC-077 name three destinations — Tier 0 shadow,
DCSync shadow, unconstrained-delegation host — that the `Tier0ControlPlane` anchor makes a single
destination.

**They collapse into SEC-071.** The other four are retired and, under `0024`, never reissued.

The reason the question needed the owner was that a customer reading SEC-076 in last year's report
would lose the identifier. **There is no such customer** — the predecessor was only ever run by its
author — so that cost is zero and the decision is free on that axis.

**One consequence is real and is accepted.** `0066` fixes severity on the rule card, so with one id
a one-hop path and a nine-hop path carry the same severity. Path length instead becomes evidence on
the finding, and the report orders on it. This is a genuine loss of the distinction SEC-070 drew,
and it is taken because five rows opening and closing in unison for one problem is the worse
reading — particularly under `0023`, where the rule id is part of the identity, so five ids would
make them five distinct findings rather than one problem seen five ways.

**If ordering by evidence proves insufficient in use, the fix is a second id split by length** —
not a per-finding severity, which `0066` forbids.

## Improvements over the predecessor worth carrying forward

- **Anchor rule coverage outside the implementation itself.** Internally consistent catalogues can
  still agree with each other while missing a rule shape nobody modeled.
- **One authoritative catalogue per semantic fact.** Tier seeds, privileged roles, capability effects,
  schema GUIDs and rule severity are referenced, not restated in ad-hoc queries.
- **Record traversal and derivation diagnostics.** Nodes expanded, cycles encountered, possible/unknown
  edges, pruning reasons and generation IDs make a derivation bug distinguishable from a clean forest.
- **Diff source facts for tripwire/change detection.** Permission/membership changes are better detected
  directly than inferred from path-signature churn.
- **Split this discussion file as sections become accepted/code-backed.** The steady-state artefacts
  should become a small architecture document plus versioned capability, tier-policy, research-ledger
  and acceptance-test documents rather than one permanent monolith.
