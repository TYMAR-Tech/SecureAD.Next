# SEC-030 — non-protected object with an AdminSDHolder marker and blocked inheritance

**Status:** revised candidate specification, not yet implemented and not yet canonical.
**Severity:** Medium.
**Rule identifier:** `SEC-030`.
**Supersedes if accepted:** `SEC-030-admincount-without-protection.md`.
**Shared semantics:** [Shared AdminSDHolder catalogue semantics](../../derivation/adminsdholder-catalogue-semantics.md),
accepted by [0089](../../../decisions/0089-principal-protection-and-member-propagation-are-separate-claims.md).

---

## For a reviewer

This is the revised specification for SEC-030. It incorporates two rounds of review against Microsoft Learn and MS-ADTS. The first specification remains beside it so changes in reasoning can be reviewed rather than hidden.

**The two central corrections are:**

1. `adminCount=1` does not prove that an object's current ACL is still non-inheriting, so the rule also requires the current security descriptor to have DACL inheritance disabled.
2. A principal being protected is not the same as membership beneath that principal propagating protection. The catalogue therefore records those semantics separately rather than flattening both into one protected set.

Every Active Directory claim below cites a Microsoft source. Review should focus on:

1. whether each catalogue entry has the correct principal-protection and member-propagation semantics;
2. whether any disputed Microsoft claim has been presented as settled;
3. whether any positive case could describe an object whose DACL currently inherits;
4. whether incomplete evidence is converted into a finding or a clean answer; and
5. whether the wording asserts history that present-state evidence cannot prove.

The exact Microsoft Support sentence reported by an external review — *"Only group is protected, not the members"* — is **not quoted as evidence here**, because the review did not provide a URL and Microsoft Learn search did not recover it. The principal/root distinction rests on the MS-ADTS protected-object algorithm. The Support statement may be added as corroboration when its exact source is pinned.

---

## 1. Finding definition

Report an object only when all of the following are established:

1. its `adminCount` attribute is `1`;
2. it is not an undisputed protected principal itself;
3. it has no complete direct or transitive membership route to an active root whose member
   propagation is `Established`;
4. its current security descriptor has DACL inheritance disabled (`SE_DACL_PROTECTED`); and
5. SID identity, protected-catalogue semantics, membership and security-descriptor evidence needed for those conclusions are complete.

The finding says:

> This object currently carries the marker associated with AdminSDHolder protection and has a non-inheriting DACL, but the captured protected-principal and membership evidence do not establish that AdminSDHolder currently protects it.

It does **not** say:

- that the object was definitely privileged in the past;
- that the system, rather than an administrator or another process, set `adminCount`;
- that its current ACL is byte-for-byte the last ACL copied from AdminSDHolder;
- when inheritance was disabled; or
- that clearing `adminCount` and enabling inheritance is safe without reviewing the ACL.

Present-state evidence cannot establish those historical or remedial claims.

## 2. Why the condition matters

Microsoft documents the common state this rule is intended to detect in
[Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory):

> When an account is removed from a protected group, it is no longer considered a protected account,
> but its adminCount attribute remains set to 1 if it is not manually changed. The result of this
> configuration is that the object's ACLs are no longer updated by SDProp, but the object still does
> not inherit permissions from its parent object.

Microsoft therefore establishes that this combination occurs and has a real consequence: the object is no longer maintained by SDProp and does not receive inherited permissions from where it lives.

The rule still checks the current DACL state independently. The Microsoft passage describes what commonly remains after protected membership is removed; it does not make `adminCount=1` a substitute for reading the security descriptor.

Microsoft's
[Troubleshoot insufficient access rights error](https://learn.microsoft.com/entra/identity/app-provisioning/insufficient-access-rights-error-troubleshooting#resolution)
also directs administrators to locate accounts governed by AdminSDHolder and check whether inheritance is disabled. This supports reporting the condition for review, not automatically changing it.

## 3. `adminCount` is a marker, not proof of current ACL state or history

Microsoft's
[Admin-Count attribute](https://learn.microsoft.com/windows/win32/adschema/a-admincount) says:

> Indicates that a given object has had its ACLs changed to a more secure value by the system because
> it was a member of one of the administrative groups (directly or transitively).

The schema page also records:

- `Update Privilege: This value is set by the system`;
- `System-Only: False`;
- classes used in: `Group` and `User`; and
- update frequency: when an object is added to an administrative group.

These statements support treating `adminCount=1` as a marker associated with protected membership. They do not prove the object's current DACL is still protected from inheritance, and `System-Only: False` means the schema does not categorically reserve modifications to the directory system. The captured value alone cannot prove who set it.

Therefore:

- `adminCount=1` with inheritance enabled is a marker inconsistency, but not this finding;
- inheritance disabled with `adminCount` absent or zero may still be important, but is not this finding; and
- a separate rule may be warranted for non-protected objects with blocked inheritance regardless of `adminCount`.

## 4. Current DACL condition

This rule requires the captured security descriptor to state that DACL inheritance is disabled. That is the present-state fact corresponding to Microsoft's phrase *"the object still does not inherit permissions from its parent object."*

The collector must retrieve and preserve the security-descriptor control value, or a semantically
equivalent representation that distinguishes a protected DACL from an inheriting DACL. Successfully
retrieving only the ACE list is insufficient: absence of inherited ACEs does not establish that
`SE_DACL_PROTECTED` is set, and the rule must not infer control state from the entries it happens to
see.

A security descriptor that was not retrieved, could not be parsed, or whose DACL state is incomplete cannot satisfy this condition. The object is not reported clean; it is not judged for SEC-030 and the missing input is named.

The rule does not compare the object's ACL with AdminSDHolder's ACL. Equality would still not prove history, and inequality would not disprove that AdminSDHolder once stamped it and somebody later edited it. This rule reports the observable combination, not a reconstructed timeline.

### 4.1 Normative evaluation order

Evaluation is tri-state and follows this order:

1. If `adminCount` is absent or is not `1`, the object is **not applicable** to SEC-030. This rule
   does not require derived evidence to answer a predicate its marker never entered.
2. If required SID or current security-descriptor control data is missing or incomplete, return
   **Not judged** and name the missing input.
3. If the current DACL inherits, return a clean suppression: the active ACL condition is absent.
4. If required catalogue or membership evidence is missing or incomplete, return **Not judged** and
   name the missing input.
5. If principal protection is `Established`, return a clean suppression: the object itself is
   protected.
6. If principal protection is `Disputed` or `Unverified`, return **Unknown**, unless another
   established route independently proves protection.
7. If any possible membership route reaches a root whose propagation is `Disputed` or `Unverified`,
   return **Unknown**, unless another established route independently proves protection.
8. If an active `Established` membership route exists, return a clean suppression: membership proves
   protection.
9. Only after the negative catalogue and membership answers are complete emit the positive finding.

“Not established as protected” is never treated as “established as not protected.”

## 5. Catalogue semantics

The catalogue must answer two independent questions for each entry:

| Semantic | Values | Meaning |
|---|---|---|
| Principal protection | `Established`, `EstablishedNo`, `Disputed`, `Unverified` | Whether the catalogue entry's own object receives AdminSDHolder protection |
| Member propagation | `Established`, `EstablishedNo`, `Disputed`, `Unverified`, `DoesNotApply` | Whether direct or transitive membership beneath this group causes another object to receive AdminSDHolder protection |

The values are independent, not mutually exclusive. Domain Admins is both an established protected principal and an established membership-protection root. Administrator is an established protected principal but cannot be a membership root because it is not a group. A group can be protected itself without membership beneath it propagating protection.

This distinction is the canonical shared derivation vocabulary under decision `0089`, not a
SEC-030-only exception. This rule consumes it and may not reconstruct the catalogue differently.

### 5.1 Established membership-protection roots

Decision `0089` accepts these classic roots as `MemberPropagation=Established` on the exact Microsoft
product-guidance statement that any account with direct or transitive membership in any protected
group inherits the restricted security, including through distribution groups:

| Candidate root | Identifier |
|---|---|
| Administrators | `S-1-5-32-544` |
| Account Operators | `S-1-5-32-548` |
| Server Operators | `S-1-5-32-549` |
| Print Operators | `S-1-5-32-550` |
| Backup Operators | `S-1-5-32-551` |
| Replicator | `S-1-5-32-552` |
| Domain Admins | domain RID 512 |
| Schema Admins | forest-root RID 518 |
| Enterprise Admins | forest-root RID 519 |

The exact MS-ADTS algorithm fragment and revision remain worth pinning as stronger provenance. Their
absence does not make these accepted product-documentation claims unimplemented guesses, and absence
from a visible constants list remains an evidence gap rather than proof of exclusion.

### 5.2 Undisputed standalone protected principals

Current first-party sources establish that these group or account objects are protected themselves.
The member-propagation values below remain candidates until the normative algorithm is pinned:

| Principal | Identifier | Principal protection | Member propagation |
|---|---|---|---|
| Administrator | domain RID 500 | Established | DoesNotApply — not a group |
| Krbtgt | domain RID 502 | Established | DoesNotApply — not a group |
| Domain Controllers group object | domain RID 516 | Established | Unverified |
| Read-only Domain Controllers group object | domain RID 521 | Established | Unverified |

The group object and its members answer separate questions. The current evidence establishes that
RIDs 516 and 521 are protected group objects; it does not yet establish whether membership beneath
either group propagates AdminSDHolder protection. Until that is pinned, a member whose answer depends
only on RID 516 or 521 is `Unknown` rather than protected or unprotected.

Until the exact Microsoft Support wording reported by external review is pinned, this member-propagation conclusion must be anchored to the normative MS-ADTS protected-object algorithm and verified in a controlled lab before canonicalization.

### 5.3 Disputed first-party entries: 498, 526 and 527

Three entries need per-semantic treatment because current first-party evidence does not establish
the same answer for principal protection and member propagation.

#### Enterprise Read-only Domain Controllers — forest-root RID 498

Microsoft's
[Active Directory security groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups#enterprise-read-only-domain-controllers)
page marks the group `Protected by AdminSDHolder? Yes`, while Appendix C omits it. That conflict
supports `PrincipalProtection=Disputed`. The currently captured evidence neither establishes nor
denies propagation, so `MemberPropagation=Unverified`.

#### Key Admins — domain RID 526

Appendix C and
[Active Directory security groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups#key-admins)
both mark the Key Admins group object protected. That establishes principal protection. The currently
captured MS-ADTS evidence has not established whether membership beneath RID 526 propagates
AdminSDHolder protection.

#### Enterprise Key Admins — forest-root RID 527

Appendix C and
[Active Directory security groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups#enterprise-key-admins)
both mark the Enterprise Key Admins group object protected. That establishes principal protection.
The currently captured MS-ADTS evidence has not established whether membership beneath RID 527
propagates AdminSDHolder protection.

Until controlled behavior or a stronger source resolves each conflict:

- the 498 group object does not produce SEC-030 because its principal protection is disputed;
- the 526 and 527 group objects do not produce SEC-030 because their principal protection is
  established by two current Microsoft Learn sources;
- an object whose only possible protection route is through one of them is `Unknown`;
- RID 498 carries `PrincipalProtection=Disputed` and `MemberPropagation=Unverified`;
- RIDs 526 and 527 carry `PrincipalProtection=Established` and `MemberPropagation=Unverified`; and
- none is silently added to or removed from the candidate root catalogue.

The exact MS-ADTS algorithm revision and fragment must be independently verified before settling
member propagation. The specification does not infer a normative exclusion from absence in a
visible constants list. RID 498 is already tracked by repository item `P-88`; the 526/527
principal-versus-propagation distinction must be added to that recorded conflict.

### 5.4 Group Policy Creator Owners is not protected

Microsoft's
[Active Directory security groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups#group-policy-creator-owners)
page explicitly marks Group Policy Creator Owners, domain RID 520, `Protected by AdminSDHolder? No`.

It is also absent from Appendix C and the current MS-ADTS protected-object algorithm. Membership in GPCO therefore does not suppress SEC-030.

### 5.5 Cert Publishers is not in the modern set

Cert Publishers is absent from Appendix C's current list. Microsoft's historical version table in
[Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory)
shows it only for Windows 2000 SP4 through Windows Server 2003, and not for Windows Server 2003 SP1+ or later columns.

The current product does not target an operating-system range in which Cert Publishers was protected.

### 5.6 Forest-specific root exclusions

`dSHeuristics` character 16, `dwAdminSDExMask`, disables these membership-protection roots for computing the effective protected population:

- Account Operators;
- Server Operators;
- Print Operators; and
- Backup Operators.

Sources:

- Position and hexadecimal encoding:
  [MS-ADTS 6.1.1.2.4.1.2](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5)
- Bit-to-group assignments:
  [Microsoft KB 56a70fa8](https://support.microsoft.com/topic/delegated-permissions-are-not-available-and-inheritance-is-automatically-disabled-56a70fa8-6d17-35ac-0f2c-87ec14b61980)

`dwAdminSDExMask` changes effective member propagation for the selected roots. It does not erase the
group object, its identity, or the record that Microsoft otherwise includes it in AdminSDHolder
processing. Principal-protection status is not changed by this rule unless the normative algorithm
explicitly establishes that effect.

For membership evaluation:

```text
EffectiveMembershipProtectionRoots
    = UndisputedMembershipProtectionRoots
    - ForestDisabledRoots
```

If the bundle predates capture of `dSHeuristics`, the catalogue is incomplete for any answer depending on the four excludable roots.

## 6. Membership routes

### 6.1 Direct and transitive membership

Microsoft states that `adminCount` is associated with direct or transitive administrative-group membership. The rule therefore uses the complete membership closure, not only direct `member` or `memberOf` values.

### 6.2 Distribution-group nesting is included for active roots

[Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory)
states:

> Any account that has direct or transitive membership in any protected group (regardless of whether
> the membership is derived from security or distribution groups) inherits this restricted
> security.

It then gives the explicit example of a user in a distribution group nested beneath a protected
group being flagged as protected. This quotation and its section anchor must also be recorded in
`MICROSOFT-VERIFICATION.md` before canonicalization.

Therefore:

> An object whose membership route to an active, established AdminSDHolder membership-protection root crosses one or more distribution groups does not fire SEC-030.

Distribution nesting does not turn membership beneath a standalone protected group object into a protection route.

### 6.3 Primary-group-only routes are conservative and root-specific

The available first-party sources establish that `primaryGroupID` represents real membership for authorization, but do not establish that AdminSDHolder protected-member enumeration follows a route represented only by primary-group membership in every relevant case.

Therefore:

- if primary-group membership is the only possible route to an established or disputed membership-protection root, the result is `Unknown` until that traversal is evidenced;
- `primaryGroupID=516` or `521` leaves the result `Unknown` while propagation from those groups is
  unverified; it must not be treated as either a proven protection route or a proven non-route;
  and
- a writable DC or RODC computer with another established protection route is protected through
  that other route.

## 7. Positive cases — must fire

Every positive case also requires complete SID, catalogue, membership and security-descriptor evidence, with DACL inheritance disabled.

| # | Captured state | Fires | Reason |
|---|---|---|---|
| P1 | User: `adminCount=1`, no protected membership | **Yes** | Observable marker-plus-ACL inconsistency. |
| P2 | User: `adminCount=1`, only member of GPCO | **Yes** | GPCO is explicitly not AdminSDHolder-protected. |
| P3 | User: `adminCount=1`, nested only beneath non-protected groups | **Yes** | No route reaches an active membership-protection root. |
| P4 | Group: `adminCount=1`, neither a protected principal nor nested beneath an active root | **Yes** | `adminCount` is defined on `group` as well as `user`. |
| P5 | User: `adminCount=1`; its only otherwise-established propagation route is Account Operators; the forest disables that root through `dwAdminSDExMask`; the user is not itself an established or disputed protected principal; and no other established, disputed or unverified route exists | **Yes** | The forest disabled the only membership-protection route. |
| P6 | Captured computer security principal: `adminCount=1`, no established, disputed or unverified protection route | **Yes, computer wording** | The required marker, SID, membership and descriptor evidence establishes the same current condition. |

## 8. Negative cases — must not fire

| # | Captured state | Fires | Reason |
|---|---|---|---|
| N1 | Any undisputed protected principal object, `adminCount=1` | **No** | The object itself is protected. |
| N2 | User directly in Domain Admins, `adminCount=1` | **No** | Direct route to an active root. |
| N3 | User nested three deep under Domain Admins through security groups | **No** | Transitive route to an active root. |
| N4 | User nested beneath Domain Admins through one or more distribution groups | **No** | Microsoft explicitly includes distribution-group nesting for a protection root. |
| N5 | User in Account Operators, ordinary forest | **No** | Account Operators is an active membership-protection root. |
| N6 | User in Replicator | **No** | Replicator is an established active root; the mask's exact first-party bit mapping names only Account, Server, Print and Backup Operators. |
| N7 | Domain Controllers group object, `adminCount=1` | **No** | The group object itself is protected. |
| N8 | Read-only Domain Controllers group object, `adminCount=1` | **No** | The group object itself is protected. |
| N9 | `adminCount=1`, but DACL inheritance currently enabled | **No SEC-030** | Marker inconsistency only; the active ACL condition is absent. |
| N10 | Inheritance disabled, but `adminCount` absent or `0` | **No SEC-030** | Outside this rule; candidate for a separate ACL rule. |
| N11 | No `adminCount`, and inheritance enabled | **No** | Neither part of the condition exists. |

## 9. Unknown / not-judged cases

These are not findings and are not counted as clean evaluations.

| # | Missing or disputed input | Outcome |
|---|---|---|
| U1 | SID absent or unreadable | Not judged: cannot compare identity with catalogue semantics. |
| U2 | Security descriptor absent, unreadable or incomplete | Not judged: cannot establish current inheritance state. |
| U3 | Membership closure incomplete for the object | Not judged: an unseen route may reach a root. |
| U4 | `dSHeuristics` unavailable and the answer depends on an excludable root | Not judged. |
| U5 | Primary-group membership is the only possible route to an established, disputed or unverified membership root | Unknown until traversal and the root's propagation are evidenced. |
| U6 | Object is RID 498, or its only possible protection route is through RID 498 | Unknown because principal protection is disputed and member propagation is unverified. |
| U7 | Another object's only possible protection route is through RID 526 or 527 | Unknown because member propagation is unverified; the 526/527 group objects themselves are established protected principals. |
| U8 | Writable DC computer whose only potential route is RID 516 | Unknown until Domain Controllers member propagation is pinned. |
| U9 | RODC computer whose only potential route is RID 521 | Unknown until Read-only Domain Controllers member propagation is pinned. |

**No positive finding may be emitted under U1–U9.** A caveated positive would still accuse an object of being unprotected when missing, disputed or unverified evidence might prove protection.

## 10. What the previous product got wrong

### 10.1 It inferred current DACL state from `adminCount`

It did not require the security descriptor to state that inheritance was disabled.

### 10.2 It flattened protected principals and membership roots

It treated membership beneath every protected group object as a protection route. Domain Controllers,
Read-only Domain Controllers, Key Admins, Enterprise Key Admins and Enterprise Read-only Domain
Controllers demonstrate why principal protection and member propagation need separate evidence and
confidence.

### 10.3 It treated Group Policy Creator Owners as protected

Microsoft explicitly marks GPCO as not protected by AdminSDHolder.

### 10.4 It omitted established operator roots from its closure check

It omitted Account, Server, Print and Backup Operators, and Replicator, producing false positives for their members in an ordinary forest.

### 10.5 It ignored `dwAdminSDExMask`

It could not distinguish an ordinary forest from one that disabled selected operator roots.

### 10.6 It omitted per-semantic disputes for 498, 526 and 527

It resolved first-party disagreement silently rather than carrying uncertainty into the result.
For 526 and 527 the current Learn evidence establishes principal protection while propagation stays
disputed; one confidence value for the whole entry would lose that distinction.

### 10.7 It underspecified incomplete evidence

A partial closure can make a protected object appear unprotected. This candidate forbids a positive finding when relevant evidence is incomplete or disputed.

## 11. Decisions and work required before implementation

1. **Severity is Medium.** The condition is an inconsistent, non-inheriting ACL state, not proof of a dangerous ACE or active compromise. Permission findings remain separate.

2. **Pin the normative MS-ADTS algorithm as stronger provenance.** Record the exact revision and
   algorithm fragment distinguishing membership roots from standalone protected principals. Do not
   infer exclusions from omission in the rendered page's constants list.

3. **Locate or discard the Support quotation.** If *"Only group is protected, not the members"* cannot be tied to an exact Microsoft URL and section, do not cite it.

   This is separate from the already fetched `dwAdminSDExMask` Support article. That article's exact
   bit-to-group passage was retrieved when `DirectoryHeuristicsMicrosoftAnchorTests` was written;
   implementation acceptance requires copying the passage and URL into `MICROSOFT-VERIFICATION.md`
   so the mask limitation rests on reviewable evidence rather than on the test author's recollection.

4. **Resolve with controlled lab evidence where possible.** Test Domain Controllers and RODC group
   objects separately from their member computer accounts. Until then, the member-computer cases are
   `Unknown`, not positive acceptance cases. Test Key Admins, Enterprise Key Admins and Enterprise
   RODC behavior without silently promoting lab observation above protocol documentation.

5. **Separate follow-up rule decisions.** `adminCount=1` with inheritance enabled and inheritance disabled without `adminCount=1` are outside SEC-030. Decide later whether each deserves a separate rule.

6. **Deleted objects.** Decide whether SEC-030 excludes tombstoned/deleted objects or reports them
   separately. They are not ordinary active principals, but restore/undelete ACL state can still
   matter. This is an operator-facing product decision rather than an implementation detail and was
   not settled merely by accepting the catalogue corrections.

7. **Define closure completeness operationally.** Before implementation, state how the rule treats:
   cross-domain and forest-root resolution, unresolved foreign security principals, unknown builtin
   SID scope, missing declared domains, expansion-budget limits, and any collection failure that can
   hide a route. A deleted link not present in the captured current state is not automatically a
   collection failure; no history is inferred from its absence.

## 12. Required evidence

The rule requires:

- `adminCount`;
- object SID and SID scope;
- object class;
- current security-descriptor control flags sufficient to establish `SE_DACL_PROTECTED`;
- complete transitive membership closure, including distribution-group nesting;
- separate principal-protection and member-propagation catalogue semantics;
- effective membership roots after `dwAdminSDExMask`;
- explicit unknown states for primary-group-only routes; and
- explicit disputes for RIDs 498, 526 and 527.

For this rule, a membership answer is complete only when every declared domain relevant to the
candidate and possible roots was read, every captured direct edge was resolved, no unresolved
trustee or foreign-security-principal can hide a route, builtin SID scope is known, no expansion
budget stopped the closure, and forest-root groups used across domains were resolved. Failure of any
one condition produces not judged, never a finding or clean pass.

## 13. Microsoft sources

| Claim | Source |
|---|---|
| Formerly protected account can retain `adminCount=1`, stop receiving SDProp updates and remain non-inheriting | [Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory) |
| Distribution-group nesting participates in protected membership | [Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory) |
| `adminCount` meaning, direct/transitive membership, schema metadata and classes | [Admin-Count attribute](https://learn.microsoft.com/windows/win32/adschema/a-admincount) |
| Published list of fifteen protected accounts/groups | [Appendix C](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) |
| Per-group `Protected by AdminSDHolder?` values, including GPCO=No and 498/526/527=Yes | [Active Directory security groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups) |
| Normative protected-object algorithm and its enumerated constants | [MS-ADTS 3.1.1.6.1](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/dd3d29f3-8e1e-4e8c-a210-9eaef3abd628) — exact revision/algorithm fragment still to be pinned as stronger provenance |
| `dwAdminSDExMask` character 16 and hexadecimal encoding | [MS-ADTS 6.1.1.2.4.1.2](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5) |
| `dwAdminSDExMask` bit assignments | [KB 56a70fa8](https://support.microsoft.com/topic/delegated-permissions-are-not-available-and-inheritance-is-automatically-disabled-56a70fa8-6d17-35ac-0f2c-87ec14b61980) |
| Operational troubleshooting checks inheritance and treats orphaned AdminSDHolder-affected objects as actionable | [Troubleshoot insufficient access rights error](https://learn.microsoft.com/entra/identity/app-provisioning/insufficient-access-rights-error-troubleshooting#resolution) |
