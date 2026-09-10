# Shared AdminSDHolder catalogue semantics

**Status:** canonical semantic model under decision
[`0089`](../../decisions/0089-principal-protection-and-member-propagation-are-separate-claims.md);
implemented by Wave 5 under decision `0090`.
**Layer:** Derivation.
**Consumers:** `ProtectedPrincipalClosure`, SEC-030, and any later rule asking whether an object is currently subject to AdminSDHolder/SDProp protection.

---

## For an independent reviewer

This document specifies shared Active Directory semantics, not one rule. Decision `0089` accepts the
model: principal protection and member propagation are independent claims with per-semantic evidence
status. Individual entries remain `Disputed` or `Unverified` where Microsoft behavior is unresolved;
canonicalizing the model does not promote either state to `Established` or `EstablishedNo`.

Do not assume the current implementation is correct: the existing `ProtectedGroupCatalogue`
flattens several questions into one set and is explicitly incompatible with this model.

Please check, against current first-party Microsoft sources:

1. which objects are themselves protected by AdminSDHolder/SDProp;
2. which groups propagate that protection to direct or transitive members;
3. whether distribution-group and primary-group-only routes participate;
4. what `dwAdminSDExMask` changes;
5. whether any source conflict below has been resolved too confidently; and
6. whether any absence from a rendered page or constants list is being treated as proof.

**Evidence rule:** absence from one list, search result, rendered constants block, or inaccessible
algorithm fragment is not proof that behavior is absent. Conflicting affirmative and omitted claims
are carried as a dispute until a stronger source or controlled observation resolves them.

**A lab observation can corroborate behavior but does not silently outrank a Microsoft protocol
specification.** Where lab and documentation differ, both remain visible until the discrepancy is
resolved.

---

## 1. Why one protected set is insufficient

The phrase *protected group* can hide two different semantics:

1. **Principal protection:** the account or group object itself receives AdminSDHolder's security
   descriptor and has inheritance disabled.
2. **Member propagation:** direct or transitive membership beneath a group causes another object to
   enter the protected population.

These properties overlap but are not interchangeable.

- Administrator and krbtgt can be protected principals but cannot propagate membership because they
  are not groups.
- Domain Admins can be both a protected principal and a membership-protection root.
- A group object may itself be protected while the available evidence does not establish whether its
  members become protected through that route.

A single `IsProtected(sid)` catalogue cannot represent these distinctions. It invites an algorithm to
seed a graph walk from every protected group object, thereby converting *this group is protected*
into the stronger and potentially false claim *every member beneath this group is protected*.

## 2. Required semantic model

Each catalogue entry records the following facts independently.

### 2.1 Principal-protection claim

Whether the catalogue entry's own directory object receives AdminSDHolder/SDProp protection.

### 2.2 Member-propagation claim

Whether membership beneath the group causes another object to receive AdminSDHolder/SDProp
protection.

### 2.3 Claim status

Each semantic has its own status:

| Status | Meaning |
|---|---|
| `Established` | A cited first-party source affirmatively establishes the behavior |
| `Disputed` | Current first-party sources conflict, or one affirmatively states behavior another normative source appears not to include |
| `Unverified` | Available evidence does not establish either `Established` or `EstablishedNo`; this is absence of sufficient evidence, not a conflict and not a negative claim |
| `DoesNotApply` | The semantic cannot apply by construction, such as member propagation from an account that is not a group |
| `EstablishedNo` | A cited first-party source affirmatively states the behavior does not occur |

**`Unverified` and `EstablishedNo` are not synonyms.** A consumer may treat an
`EstablishedNo` route as absent. An `Unverified` or `Disputed` route can make the consumer's
answer `Unknown`.

### 2.4 Provenance

Every semantic claim carries its own provenance:

| Provenance | Meaning |
|---|---|
| `ProtocolSpecification` | A Microsoft Open Specification describes server behavior |
| `MicrosoftProductDocumentation` | Current Microsoft product or security guidance states the behavior |
| `MicrosoftSupport` | A Microsoft Support article states the behavior |
| `ControlledLabObservation` | A controlled forest exhibited the behavior, with setup and result recorded |

Provenance records why a claim is held; it does not automatically settle conflicts. Protocol text is
normally the strongest description of server behavior, but a newer product addition omitted from an
older algorithm needs investigation rather than automatic rejection.

### 2.5 Scope

An entry also records the scope needed to recognize its SID correctly:

- forest root only;
- one instance per domain;
- builtin SID repeated independently in every domain; or
- not applicable to SID matching.

This is required because `S-1-5-32-*` principals are local to each domain's Builtin container even
though their SID text repeats, while Enterprise Admins and other forest-root groups exist only once.

## 3. Current first-party evidence

### 3.1 Current Microsoft product list

[Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
lists fifteen protected accounts and groups:

- Account Operators;
- Administrator;
- Administrators;
- Backup Operators;
- Domain Admins;
- Domain Controllers;
- Enterprise Admins;
- Enterprise Key Admins;
- Key Admins;
- krbtgt;
- Print Operators;
- Read-only Domain Controllers;
- Replicator;
- Schema Admins; and
- Server Operators.

This establishes a current product-documentation claim that each listed **object** is protected. The
list alone does not distinguish principal protection from member propagation.

### 3.2 Current transitive-membership guidance

[Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory)
states:

> Any account that has direct or transitive membership in any protected group (regardless of whether
> the membership is derived from security or distribution groups) inherits this restricted
> security.

It then gives the explicit example of a user in a distribution group nested beneath a protected group
being flagged as protected.

This establishes that at least the membership-protection roots intended by that guidance follow both
security-group and distribution-group nesting. It does **not**, by itself, settle whether every group
object appearing in every protected-object list is a propagation root; the normative protected-object
algorithm remains the source needed for that classification.

### 3.3 Normative algorithm evidence still required

[MS-ADTS 3.1.1.6.1, AdminSDHolder](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/dd3d29f3-8e1e-4e8c-a210-9eaef3abd628)
is the intended normative source for:

- the protected-object algorithm;
- the distinction between objects included directly and groups whose transitive members are
  enumerated; and
- the effect of `dwAdminSDExMask` within that algorithm.

The currently accessible Learn rendering exposes background and a constants list but not enough of
the algorithm to verify every classification below. Before this specification becomes canonical,
`MICROSOFT-VERIFICATION.md` must record:

- the exact MS-ADTS revision and publication date;
- the exact algorithm fragment;
- the roots enumerated for transitive-member expansion;
- principals inserted directly without member expansion; and
- where and how `dwAdminSDExMask` alters the algorithm.

**No classification below may cite omission from the visible constants list as normative proof.**

## 4. Canonical catalogue of current evidence states

This table records the product's accepted interpretation of the evidence currently collected. Its
`Disputed` and `Unverified` values are final statements about present uncertainty, not placeholders
silently treated as Yes or No. A later source or accepted decision may change an entry's state.

| Principal or group | SID form and scope | Principal protection | Member propagation | Current basis |
|---|---|---|---|---|
| Administrator | domain RID 500, per domain | `Established` | `DoesNotApply` | Appendix C; not a group |
| krbtgt | domain RID 502, per domain | `Established` | `DoesNotApply` | Appendix C; not a group |
| Administrators | `S-1-5-32-544`, independently per domain | `Established` | `Established` | Appendix C and exact transitive-membership guidance accepted by 0089 |
| Account Operators | `S-1-5-32-548`, independently per domain | `Established` | `Established` | Appendix C and transitive guidance; mask can disable effective propagation |
| Server Operators | `S-1-5-32-549`, independently per domain | `Established` | `Established` | Appendix C and transitive guidance; mask can disable effective propagation |
| Print Operators | `S-1-5-32-550`, independently per domain | `Established` | `Established` | Appendix C and transitive guidance; mask can disable effective propagation |
| Backup Operators | `S-1-5-32-551`, independently per domain | `Established` | `Established` | Appendix C and transitive guidance; mask can disable effective propagation |
| Replicator | `S-1-5-32-552`, independently per domain | `Established` | `Established` | Appendix C and exact transitive-membership guidance accepted by 0089 |
| Domain Admins | domain RID 512, per domain | `Established` | `Established` | Appendix C and exact transitive-membership guidance accepted by 0089 |
| Domain Controllers group object | domain RID 516, per domain | `Established` | `Unverified` | Appendix C establishes object protection; available evidence does not settle member behavior |
| Schema Admins | forest-root RID 518 | `Established` | `Established` | Appendix C and exact transitive-membership guidance accepted by 0089 |
| Enterprise Admins | forest-root RID 519 | `Established` | `Established` | Appendix C and exact transitive-membership guidance accepted by 0089 |
| Read-only Domain Controllers group object | domain RID 521, per domain | `Established` | `Unverified` | Appendix C establishes object protection; available evidence does not settle member behavior |
| Key Admins | domain RID 526, per domain | `Established` | `Unverified` | Appendix C and group-specific Learn page establish object protection; available evidence does not settle propagation |
| Enterprise Key Admins | forest-root RID 527 | `Established` | `Unverified` | Appendix C and group-specific Learn page establish object protection; available evidence does not settle propagation |
| Enterprise Read-only Domain Controllers | forest-root RID 498 | `Disputed` | `Unverified` | Group-specific Learn page says the object is protected while Appendix C omits it; neither source settles propagation |
| Group Policy Creator Owners | domain RID 520, per domain | `EstablishedNo` | `EstablishedNo` | Group-specific Learn page explicitly says `Protected by AdminSDHolder? No`; Appendix C omits it |
| Cert Publishers | domain RID 517, per domain | `EstablishedNo` for supported modern scope | `EstablishedNo` for supported modern scope | Historical Microsoft version table includes it only in older Windows ranges |

### 4.1 Uncertainty is canonical too

Consumers encountering `Disputed` or `Unverified` semantics must either:

- remain unimplemented; or
- return `Unknown` where their answer depends on the unresolved classification.

The entry may change to `Established` or `EstablishedNo` only with a source and accepted correction.

### 4.2 RIDs 526 and 527

Key Admins and Enterprise Key Admins have **established principal protection** because two current
Microsoft Learn sources affirm it: Appendix C and their group-specific entries in
[Active Directory security groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups).

Only member propagation is unverified. One confidence value for the whole entry would discard this
distinction.

### 4.3 RID 498

Enterprise Read-only Domain Controllers has disputed principal protection and unverified member
propagation:

- its group-specific Microsoft Learn entry says `Protected by AdminSDHolder? Yes`;
- Appendix C omits it from the published list; and
- the normative algorithm classification has not been pinned; and
- none of the captured sources affirmatively establishes or denies member propagation.

The group object itself and a route depending on it therefore produce `Unknown` for consumers needing
a definitive answer, for different reasons in the two cases.

### 4.4 RIDs 516 and 521

Appendix C establishes that the Domain Controllers and Read-only Domain Controllers **group objects**
are protected. Current collected evidence does not establish whether membership beneath either group
propagates protection.

Therefore:

- each group object has `PrincipalProtection=Established`;
- each has `MemberPropagation=Unverified`;
- a writable DC computer whose only possible route is RID 516 is `Unknown`;
- an RODC computer whose only possible route is RID 521 is `Unknown`; and
- neither case is treated as a finding or a clean non-protected result until propagation is pinned.

The reported Microsoft Support sentence *"Only group is protected, not the members"* is not used here
because its exact URL and location have not been provided or recovered. Add it only when it can be
checked directly.

## 5. Forest-specific `dwAdminSDExMask`

`dSHeuristics` character 16, `dwAdminSDExMask`, is a hexadecimal four-bit mask.

- Position and encoding:
  [MS-ADTS 6.1.1.2.4.1.2](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5)
- Bit assignments:
  [Microsoft KB 56a70fa8](https://support.microsoft.com/topic/delegated-permissions-are-not-available-and-inheritance-is-automatically-disabled-56a70fa8-6d17-35ac-0f2c-87ec14b61980)

| Bit | Group |
|---|---|
| 0 (`0x1`) | Account Operators |
| 1 (`0x2`) | Server Operators |
| 2 (`0x4`) | Print Operators |
| 3 (`0x8`) | Backup Operators |

Under decision `0089`, the mask changes **effective member propagation**:

```text
EffectiveMemberPropagation(entry, forest)
    = entry.MemberPropagation
      adjusted by the forest's dwAdminSDExMask when entry is one of the four excludable roots
```

The mask does not delete the catalogue entry or its SID. It must not change principal-protection
status merely because the same group is removed as a propagation root, unless the pinned normative
algorithm explicitly establishes that the group object itself also stops receiving protection.

### 5.1 Three forest-evidence states

| Captured state | Meaning |
|---|---|
| Mask character present and valid | Apply the stated bits to effective member propagation |
| Attribute/object read and character absent | Documented default `0`; no roots disabled |
| Attribute not captured or configuration evidence unread | Catalogue incomplete for answers depending on excludable roots |

A malformed or undocumented character must be represented explicitly. It must not be silently read as
zero or as all bits set.

## 6. Membership traversal semantics

### 6.1 Direct and transitive membership

A member-propagation root applies through direct and transitive membership when the claim is
`Established` and active for the forest.

### 6.2 Distribution-group nesting

Microsoft states exactly:

> Any account that has direct or transitive membership in any protected group (regardless of whether
> the membership is derived from security or distribution groups) inherits this restricted
> security.

Source:
[Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory).

It also gives an explicit user → distribution group → protected group example. Therefore distribution
edges are followed when walking to an active, established membership-protection root.

This exact quotation and section anchor must be copied into `MICROSOFT-VERIFICATION.md` before the
model is canonical.

### 6.3 Primary-group-only membership

The evidence establishes that `primaryGroupID` represents membership for authorization. It does not
establish that AdminSDHolder protected-member enumeration follows a route represented only by
primary-group membership, and no Microsoft source does — Appendix C, *Reducing the Active Directory
Attack Surface* and MS-ADA3 were re-read on 2026-09-11 and every one of them confirms which groups
are protected while saying nothing about which routes SDProp walks to find their members.

**A laboratory observation settled it in the negative on 2026-09-10, and the closure does not follow
the edge.** A principal whose only possible route to a member-propagation root is a primary-group
edge is `NotProtected`. In `ba.ad.lab` the Domain Controllers group was itself stamped, held no
explicit `member` entries so the primary-group edge was the only route into it, and `dSHeuristics`
excluded nothing — while its domain controller carried neither `adminCount` nor a DACL refusing
inheritance, eighteen months after creation, against a stamped Domain Admins and an unstamped Domain
Users in the same run. Recorded under
[`0118`](../../decisions/0118-primary-group-only-membership-is-not-protected.md) and reproducible by
`tools/Observe-Ac64PrimaryGroupTraversal.ps1`.

**Lab-verified is a weaker warrant than specified.** One forest, one domain, one domain controller,
one Windows version. A forest that contradicts it reverts the answer to `Unknown`, which is why
`ProtectionUnknownReason.PrimaryGroupTraversalResearchBlocked` remains in the enumeration — it is
also persisted as flag value 1 in every derivation written before schema 13, so it could not be
removed in any case.

**RID 516 and 521 carried two independent gates and now carry neither in this path.** Their member
propagation is `Unverified`, which places them among the possible roots, and the walk over those
roots marks what it reaches `Unknown`. That walk follows ordinary nesting alone, so a DC or RODC
computer whose only route is its primary group is never reached by it and is `NotProtected`. The
`Unverified` propagation still applies to a DC listed as an explicit `member`, which is a different
directory and a different answer.

## 7. Derived principal evaluation

For a principal `p`, the protected-principal derivation returns one of:

| Evaluation | Meaning |
|---|---|
| `Protected` | Principal protection is established for `p`, or a complete route reaches an active root whose member propagation is established |
| `NotProtected` | Principal protection is `EstablishedNo`, and complete evidence proves no route reaches an established, disputed or unverified possible root |
| `Unknown` | Missing, incomplete, disputed or unverified evidence could change the answer |

### 7.1 Direct principal protection

If `p` is itself a catalogue entry:

- `Established` → `Protected`;
- `EstablishedNo` → continue to membership evaluation;
- `Disputed` or `Unverified` → `Unknown` unless another established route independently proves
  protection; and
- `DoesNotApply` is invalid for principal protection.

### 7.2 Membership propagation

For every membership route from `p`:

- route to an active `Established` root → `Protected`;
- route only to a `Disputed` or `Unverified` possible root → `Unknown`;
- route to `EstablishedNo` or `DoesNotApply` → no protection from that route; and
- incomplete traversal that could hide an active or possible root → `Unknown`.

An established protection route wins over uncertainty elsewhere: once one complete route proves the
principal protected, another disputed route cannot make that fact less true.

### 7.3 Completeness required for `NotProtected`

`NotProtected` is the expensive answer. It may be returned only when all relevant negative evidence
is complete:

- every declared domain relevant to the principal and possible roots was read;
- every captured direct membership edge was resolved;
- no unresolved trustee or foreign security principal can hide a route;
- repeated builtin SIDs are scoped to the correct domain;
- forest-root groups used across domains are resolved to the root domain;
- no expansion budget stopped the closure;
- no primary-group-only path can reach a possible root; and
- no disputed catalogue entry can change the answer.

If any condition is false, the result is `Unknown`, not `NotProtected`.

A deleted membership link absent from a current-state capture is not automatically a collection
failure. This model does not infer historical links from current absence.

## 8. Provenance and explanation returned with the result

A consumer must be able to explain why an answer was reached. The shared result therefore needs, at
minimum:

- the catalogue version;
- the catalogue entry or membership root that established protection;
- principal-protection and member-propagation statuses used;
- provenance for each decisive status;
- the forest's mask character and resolved disabled roots;
- the membership path or direct-principal match used;
- completeness state; and
- every reason an answer is `Unknown`.

A smaller protected population without an explanation reads as the product having lost principals.
A clean `NotProtected` without completeness reads as certainty nobody established.

## 9. Storage requirements

The derivation store must preserve enough information for a later rule to reach the same conclusion
without rerunning capture:

1. catalogue version and claim semantics;
2. forest mask input and resolved effective roots;
3. principal evaluation;
4. decisive root or direct-principal basis;
5. membership path or path reference where protection was established;
6. per-principal unknown reasons; and
7. closure completeness.

A schema version change is required if the current store cannot represent principal protection and
member propagation separately.

## 10. Required tests before implementation is accepted

### 10.1 Catalogue tests

- every entry has independent principal-protection and member-propagation status;
- 526 and 527: principal protection established, member propagation disputed;
- 498: both semantics disputed;
- 516 and 521: principal protection established, member propagation not established;
- GPCO: both semantics established No;
- Administrator and krbtgt: propagation does not apply;
- no entry obtains `EstablishedNo` merely from omission in another list.

### 10.2 Traversal tests

- direct member of an established root is protected;
- nested security-group route to an established root is protected;
- nested distribution-group route to an established root is protected;
- route only to a disputed root is unknown;
- route only to an unverified root is unknown;
- primary-group-only route to a possible root is unknown;
- one established route wins over a separate disputed route;
- incomplete traversal never returns not protected.

### 10.3 DC and RODC tests

- Domain Controllers group object is protected;
- Read-only Domain Controllers group object is protected;
- writable DC computer relying only on RID 516 is unknown;
- RODC computer relying only on RID 521 is unknown;
- either computer with another established route is protected.

### 10.4 Forest-mask tests

- each bit disables only its named root's effective member propagation;
- combinations disable exactly the selected roots;
- the group object is not removed from the catalogue;
- principal-protection status does not change without normative evidence;
- absent character defaults to zero when the object was read;
- uncaptured/unread value makes dependent answers unknown; and
- malformed value remains explicit and does not silently become zero.

## 11. Open evidence and future corrections

The model is canonical under `0089`. These evidence questions remain unresolved and retain their
explicit `Disputed` or `Unverified` states until a later accepted correction:

1. **MS-ADTS algorithm pin:** exact revision, date and protected-object algorithm fragment.
2. **516/521 propagation:** establish Yes or No, or retain `Unverified` permanently.
3. **498 principal and propagation:** resolve the Appendix C versus group-specific-page conflict, or
   retain `Disputed`.
4. **526/527 propagation:** establish behavior while retaining established principal protection.
5. **Primary-group traversal:** establish whether AdminSDHolder follows primary-group-only routes.
6. **Mask effect on group objects:** establish whether disabling an operator root also changes the
   group object's own principal protection.
7. **Malformed mask behavior:** establish server behavior or specify an evidence-safe unknown state.
8. **Supported Windows range:** name the oldest and newest AD DS behavior this catalogue claims to
   model, especially because Cert Publishers changed historically.

## 12. Consequence for the current implementation

The current `ProtectedGroupCatalogue` and `ProtectedPrincipalDeriver` are not sufficient to implement
this specification safely:

- one set is used for both direct principal protection and graph seeds;
- every protected group object becomes a member-propagation root;
- `dwAdminSDExMask` removes a group from `IsProtected`, thereby changing principal protection and
  member propagation together;
- 498 cannot be represented as disputed;
- 526/527 cannot be represented as established principals with unverified propagation; and
- 516/521 cannot be represented as established principals with unverified propagation.

The existing real-forest check proved what the current code did with mask `f`; it did not prove that
removing the four operator group objects themselves was the correct interpretation. Documentation
claiming that lab run confirmed the entire protected-set model must be narrowed accordingly.

The shared catalogue and closure must be redesigned and revalidated before SEC-030 consumes them.

## 13. Microsoft sources

| Claim | Source |
|---|---|
| Current published protected accounts/groups | [Appendix C](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) |
| Direct/transitive and distribution-group protected membership | [Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory) |
| Current per-group AdminSDHolder values, including GPCO, 498, 526 and 527 | [Active Directory security groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups) |
| Normative protected-object algorithm | [MS-ADTS 3.1.1.6.1](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/dd3d29f3-8e1e-4e8c-a210-9eaef3abd628) — exact revision and algorithm fragment still required |
| Mask position and hexadecimal encoding | [MS-ADTS 6.1.1.2.4.1.2](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5) |
| Mask bit assignments | [Microsoft KB 56a70fa8](https://support.microsoft.com/topic/delegated-permissions-are-not-available-and-inheritance-is-automatically-disabled-56a70fa8-6d17-35ac-0f2c-87ec14b61980) |
| `adminCount` marker semantics | [Admin-Count attribute](https://learn.microsoft.com/windows/win32/adschema/a-admincount) |
