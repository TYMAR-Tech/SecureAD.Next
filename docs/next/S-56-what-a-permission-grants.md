# S-56 — What a permission grants

**Status: draft specification — freeze candidate. Derived from Microsoft documentation only.**

Revision 4, 2026-08-19. **This specification is grounded in Microsoft first-party documentation,
not in the existing implementation or implementation behavior.** Version 4 is a freeze-candidate
precision revision of Version 3. It retains R1–R20 and the same authorization model while tightening
security-descriptor wording, the AD DS Generic All description, reporting terminology, subtle
inheritance/protected-group citations, and capture-dependency language.

Every material technical claim below carries a Microsoft first-party link. A claim without one is a
mistake and should be treated as one. Where Microsoft documentation appears to conflict, this
specification identifies the conflict and follows the more AD-specific or operation-specific source
when that resolves the behavior for AD DS.

---

## 1. Why this exists

The product has to answer one question — *what does this permission let somebody do* — and it has
been answering it from an accumulated model rather than from the specification. This is that
specification, restated.

The scope is deliberately narrow: **what an access control entry means**. Not which meanings are
dangerous. Severity is a separate judgement and must be built on top of this, not mixed into it.

**Reporting terminology.** Terms such as *unsupported*, *unclassified*, *anomalous*, *unresolved*,
*partial*, and *unknown* describe **S-56 reporting states** unless a cited Microsoft source explicitly
characterizes the underlying representation as invalid or nonconformant. S-56 must not present its own
reporting policy as though it were Microsoft platform terminology.

---

## 2. The shape of the thing

Every Active Directory object has a **security descriptor** containing owner and control information
and representing its DACL and SACL state. A populated DACL is an ordered list of ACEs; later sections
distinguish absent, null, empty, populated, partially retrieved, and unparseable states.
([Access control lists](https://learn.microsoft.com/windows/win32/secauthz/access-control-lists))

An ordinary object ACE begins with an `ACE_HEADER`, whose fields include `AceType`, `AceFlags`, and
`AceSize`, followed by an `ACCESS_MASK`; object ACE formats then contain a `Flags` field plus up to
two GUIDs, `ObjectType` and `InheritedObjectType`, followed by the trustee SID.
([ACE_HEADER](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-ace_header),
[ACCESS_ALLOWED_OBJECT_ACE](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace))

**Both GUIDs are optional and independent.** `Flags` says which are present:
`ACE_OBJECT_TYPE_PRESENT`, `ACE_INHERITED_OBJECT_TYPE_PRESENT`, both, or neither. If neither
GUID-presence flag is set, Microsoft defines the object ACE as having the same access semantics as
its corresponding non-object ACE; neither `ObjectType` nor `InheritedObjectType` narrows access or
inheritance scope. A reader that infers presence from a null GUID rather than from `Flags` is guessing.

**This specification does not claim that one field list describes every Microsoft ACE format.** Its
full semantic model covers ordinary access-allowed, access-denied, access-allowed-object, and
access-denied-object ACEs. Microsoft callback ACE formats can carry `ApplicationData`; conditional
ACEs are callback ACEs whose application data contains a condition evaluated during access check.
A false condition makes the ACE inapplicable, while an unknown result has allow/deny-specific
behavior.
([Conditional ACEs](https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/10dc22eb-788d-4343-b556-0b6969fe58ca),
[Conditional ACE Applicability](https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/a7a7c600-5a5f-4391-b6fe-d073ce8e8a77))

> **R1.** For supported ordinary ACE types, model `AceType`, `AceFlags`, `ACCESS_MASK`, object
> `Flags`, optional `ObjectType`, optional `InheritedObjectType`, and trustee SID. Preserve the raw
> ACE type and raw bytes for every ACE. Callback, conditional, or otherwise unsupported ACE types
> must be reported as unsupported or unclassified and must not be interpreted through the ordinary
> ACE model. `ObjectType` absent and `ObjectType` equal to the null GUID must remain distinguishable,
> or their equivalence must be proven for the parser and source representation.

## 3. The access mask

These are the values. They are Microsoft's, from `ADS_RIGHTS_ENUM`.
([ADS_RIGHTS_ENUM](https://learn.microsoft.com/windows/win32/api/iads/ne-iads-ads_rights_enum))

| Bit | Constant | Meaning |
|---|---|---|
| `0x00000001` | `DS_CREATE_CHILD` | Create child objects. `ObjectType` may name the class. |
| `0x00000002` | `DS_DELETE_CHILD` | Delete child objects. `ObjectType` may name the class. |
| `0x00000004` | `ACTRL_DS_LIST` | List child objects. |
| `0x00000008` | `DS_SELF` | Perform a validated write. `ObjectType` may name which. |
| `0x00000010` | `DS_READ_PROP` | Read properties. `ObjectType` may name a property **or property set**. |
| `0x00000020` | `DS_WRITE_PROP` | Write properties. `ObjectType` may name a property **or property set**. |
| `0x00000040` | `DS_DELETE_TREE` | Delete all children **regardless of their own permissions**. |
| `0x00000080` | `DS_LIST_OBJECT` | List this particular object. Ignored unless list-object mode is on. |
| `0x00000100` | `DS_CONTROL_ACCESS` | Perform an extended-right operation. `ObjectType` may name which. |
| `0x00010000` | `DELETE` | Delete the object. |
| `0x00020000` | `READ_CONTROL` | Read the security descriptor, **excluding** the SACL. |
| `0x00040000` | `WRITE_DAC` | Modify the DACL. |
| `0x00080000` | `WRITE_OWNER` | Authorize an owner-field update subject to AD owner-SID validation; it does not by itself permit arbitrary third-party ownership. |
| `0x00100000` | `SYNCHRONIZE` | Microsoft defines synchronization/wait access. S-56 does not infer a directory operation from this bit without an applicable AD-specific operation definition. |
| `0x01000000` | `ACCESS_SYSTEM_SECURITY` | **Not valid in a DACL** — SACL access is privilege-gated; see below. |

**Two of these are wider than they read.** `DS_DELETE_TREE` deletes children *regardless of the
permissions on those children* — it is not bounded by the subtree's own ACLs. And `WRITE_OWNER`
matters because of §6.2, not on its own terms.

### Two entries in that table need qualifying

**`ACCESS_SYSTEM_SECURITY` does not belong in a DACL.** Microsoft is explicit:

> The system grants this access right only if the SE_SECURITY_NAME privilege is enabled in the
> access token of the requesting thread. […] The ACCESS_SYSTEM_SECURITY access right **is not valid
> in a DACL** because DACLs do not control access to a SACL.
> ([SACL access right](https://learn.microsoft.com/windows/win32/secauthz/sacl-access-right))

Therefore `ACCESS_SYSTEM_SECURITY` must not be interpreted as an ordinary DACL grant. If the bit is
captured in a DACL ACE, report the evidence as invalid or anomalous rather than assigning normal ACE
semantics to it. SACL access itself is privilege-gated and belongs to principal/operation-level
authorization, not to the meaning of an ordinary DACL ACE.

Microsoft also defines `SYNCHRONIZE` in `ADS_RIGHTS_ENUM` as the right to use the object for
synchronization, enabling a thread to wait for its signaled state. That definition applies to an
access-mask bit, but S-56 does not establish a concrete AD DS directory operation whose authorization
depends on it. Preserve and report the bit; do not translate it into additional directory capability
without an applicable AD-specific operation definition.
([ADS_RIGHTS_ENUM](https://learn.microsoft.com/windows/win32/api/iads/ne-iads-ads_rights_enum))

**For AD DS, `WRITE_OWNER` is resolved by MS-ADTS.** `RIGHT_WRITE_OWNER` is one authorization
path for writing the OWNER field, alongside `SE_TAKE_OWNERSHIP_PRIVILEGE` and the `DS-Set-Owner`
control access right on the naming-context root. Authorization to write OWNER does not permit an
arbitrary value: without `SE_RESTORE_PRIVILEGE`, the new owner must be the requester SID or the
documented default administrators group SID when the requester qualifies. Arbitrary owner SIDs
require `SE_RESTORE_PRIVILEGE`.
([Security Considerations](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/7afacb02-548b-4e74-bf96-04b0bf0c71b6),
[DS-Set-Owner](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/5b0c2d7d-37df-469e-9e3e-b7abd6f017a3))

For entry-level wording, `WRITE_OWNER` permits an owner-field update subject to AD's owner-SID
validation. It must not be described as granting arbitrary transfer to a third party. Privilege and
NC-root control-access paths belong to principal/operation-level analysis.

### Generic rights

Four high-order bits represent generic access categories. Their mapping is specific to the type of
securable object. Microsoft publishes both the generic values and the Active Directory mappings.
([ADS_RIGHTS_ENUM](https://learn.microsoft.com/windows/win32/api/iads/ne-iads-ads_rights_enum),
[ActiveDirectoryRights](https://learn.microsoft.com/dotnet/api/system.directoryservices.activedirectoryrights),
[Generic access rights](https://learn.microsoft.com/windows/win32/secauthz/generic-access-rights))

| Generic | Value | Active Directory mapping | Decimal |
|---|---|---|---|
| `GENERIC_READ` | `0x80000000` | `READ_CONTROL \| DS_READ_PROP \| ACTRL_DS_LIST \| DS_LIST_OBJECT` | 131220 |
| `GENERIC_WRITE` | `0x40000000` | `READ_CONTROL \| DS_WRITE_PROP \| DS_SELF` | 131112 |
| `GENERIC_EXECUTE` | `0x20000000` | `READ_CONTROL \| ACTRL_DS_LIST` | 131076 |
| `GENERIC_ALL` | `0x10000000` | **AD DS Generic All mapping** — `0x000F01FF` | 983551 |

For AD DS, `GENERIC_ALL` maps to `DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER |
DS_CREATE_CHILD | DS_DELETE_CHILD | ACTRL_DS_LIST | DS_SELF | DS_READ_PROP | DS_WRITE_PROP |
DS_DELETE_TREE | DS_LIST_OBJECT | DS_CONTROL_ACCESS`, yielding `0x000F01FF` (983551). It does **not**
include `SYNCHRONIZE` or `ACCESS_SYSTEM_SECURITY`. `0x000F01FF` is also what the ACL editor calls
**Full Control**.
([Security Descriptor Requirements](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a),
[Exchange permissions reference](https://learn.microsoft.com/exchange/exchange-2013-deployment-permissions-reference-exchange-2013-help))

**The stage at which a mask is observed matters.** When a generic mask is submitted as an access
request, or when an ACE containing generic bits is assigned to an object, the resource manager maps
the generic bits to object-specific and standard rights and clears the generic bits. But Microsoft
also states that the access-check algorithm does **not** map generic bits found in an ACE already
attached to an object; such an ACE can produce unintended results.
([ACCESS_MASK](https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b))

Therefore a generic bit captured from a stored ACE is not automatically evidence that the mapped
rights are effective. The product must distinguish an assignment-time or request-time mask from the
mask actually stored in a security descriptor.

> **R2.** Store the **raw** mask exactly as captured and record its context: **stored ACE**, **mask
> being assigned**, or **requested access**. Apply the Active Directory generic mapping exactly once
> only where that context calls for mapping. Do not automatically expand generic bits remaining in
> an ACE already attached to an object; report them as anomalous or unresolved unless the retrieval
> path is proven to return a pre-mapping representation. If a mapped mask is derived, store it
> separately with the mapping context and source so the transformation is auditable.

---

## 4. The GUID means different things depending on the bit beside it

This is the single most important structural fact about an object ACE, and Microsoft states it as a
table: **the purpose of `ObjectType` depends on the access rights in `Mask`.**
([ACCESS_ALLOWED_OBJECT_ACE](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace))

| Bit in the mask | What `ObjectType` names |
|---|---|
| `DS_CONTROL_ACCESS` | an extended right |
| `DS_CREATE_CHILD` / `DS_DELETE_CHILD` | a class of child object |
| `DS_READ_PROP` / `DS_WRITE_PROP` | a property **or a property set** |
| `DS_SELF` | a validated write |

**A single mask can carry several of these bits at once.** One entry with
`DS_CONTROL_ACCESS | DS_READ_PROP` and one GUID is asking that GUID to be two different kinds of
thing. It is legal, it occurs, and any model that stores "the kind of this entry's GUID" as one
value is wrong.

> **R3.** The kind of a GUID is a function of `(GUID, mask bit)`, not of the GUID alone and not of
> the entry. Resolution must be performed per bit.

### Telling the three kinds apart

Extended rights, property sets and validated writes all live as `controlAccessRight` objects in the
same Extended-Rights container. **`validAccesses` is the authoritative classification metadata for
the intended type of a `controlAccessRight` object.**
([Control Access Rights](https://learn.microsoft.com/windows/win32/ad/control-access-rights))

| `validAccesses` | Kind |
|---|---|
| `256` (`DS_CONTROL_ACCESS`) | extended right |
| `48` (`READ_PROP \| WRITE_PROP`) | property set |
| `8` (`DS_SELF`) | validated write |

Microsoft is explicit that property sets and validated writes **are not extended rights**, and are
only stored there for convenience. A reader that treats the container as a list of extended rights
mislabels every property set in the forest. This metadata classification does not itself establish
which attributes participate in a property set during authorization; that comes from each
attribute's `attributeSecurityGUID`.

### Property set membership is the forest's, and is stored backwards

A property set does not list its members. Each attribute points at the set through its own
`attributeSecurityGUID`, and that value equals the `rightsGUID` of the `controlAccessRight`.
([Example code for setting an ACE](https://learn.microsoft.com/windows/win32/ad/example-code-for-setting-an-ace-on-a-directory-object))

So membership can only be computed by reading the schema of the forest in front of you. A customer
can place their own attribute into a Microsoft-defined set.

> **R4.** Property-set membership for AD property-access semantics must be read from
> `attributeSecurityGUID` across the schema partition. `validAccesses` classifies the intended use of
> a `controlAccessRight` object; `attributeSecurityGUID` determines whether an attribute actually
> participates in the property set identified by that GUID. A run that did not read the schema
> cannot answer what a property-set grant reaches and must say so rather than assume either way.

---

## 5. How access is actually decided

### 5.1 AD has several access-check families

There is no single ACE-evaluation algorithm for every AD right. Before checking access, the DC
selects an appropriate security descriptor for the operation, substitutes contextual identities
such as `PRINCIPAL_SELF`, and applies the algorithm defined for the right or operation being checked.
The descriptor is usually the target object's, but some AD operations use the parent or another
related directory object.
([Checking Access](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/dc1b0dbc-cee1-4661-aa87-810b3c6759ab))

#### Standard or simple access

For standard rights represented in simple ACEs, AD initializes separate Granted and Denied masks.
It examines the **entire DACL** in stored sequence. A matching deny adds rights not already granted
to the Denied mask; a matching allow adds rights not already denied to the Granted mask. At the end
of the DACL, the Granted mask is the maximum standard access available and is compared with the
requested mask. This is not the general Windows early-stop description.
([Checking Simple Access](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/c55e113e-25a2-45eb-abba-bf5a9e521a8f))

#### Object-specific and property access

For object-specific rights, AD evaluates an object-type tree appropriate to the request. For
property access the tree contains the target object/class scope, applicable property-set scopes,
and applicable attribute scopes. Applicable ACEs are examined in stored sequence while grant and
deny state is maintained at the relevant tree nodes. The tree determines scope; it does not replace
ACE ordinal.
([Property Set](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/177c0db5-fa12-4c31-b75a-473425ce9cca),
[ACEs to control access to an object's properties](https://learn.microsoft.com/windows/win32/secauthz/aces-to-control-access-to-an-object-s-properties))

#### Control access rights

A control access right is evaluated for its GUID. An unscoped applicable object ACE or an applicable
object ACE whose `ObjectType` equals that GUID can determine the result. The first applicable allow
or deny for that requested control-access right terminates that check.
([Control Access Rights](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb))

#### Validated writes

Validated writes use `RIGHT_DS_WRITE_PROPERTY_EXTENDED` and a validated-write GUID. AD examines ACEs
in stored sequence and stops at the first applicable unscoped ACE or GUID-specific ACE that allows
or denies the requested validated write.
([Checking Validated Write-Based Access](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/aa2c17ed-7a7e-45f8-83b6-0682b9d95e25),
[Validated Writes](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/20504d60-43ec-458f-bc7a-754eb64446df))

> **R20.** Select and identify the AD authorization family for each evaluated right or operation,
> including the operation-specific class/property/GUID parameters and the security descriptor or
> related descriptors that algorithm selects. Stored ACE order is always evidence, but how that order
> is consumed depends on the selected AD algorithm. Do not apply the general Windows early-stop
> algorithm to all AD rights.

### 5.2 Stored order and canonical order

The general preferred order is:

1. all explicit ACEs before all inherited ACEs;
2. within explicit ACEs, deny before allow;
3. inherited ACEs in inheritance-generation order — parent, grandparent, and so on;
4. within each inherited generation, deny before allow.

([Order of ACEs in a DACL](https://learn.microsoft.com/windows/win32/secauthz/order-of-aces-in-a-dacl),
[ACL](https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428))

AD protocol ordering rules add details for canonical ACLs, including regular ACEs before object ACEs
and lexicographic ordering within specified groups at applicable forest functional levels.
([ACE Ordering Rules](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/dbfdc00c-1e4b-4165-939b-974e8ea23733))

Microsoft notes that ACE-adding APIs can append to the end and that the caller is responsible for
maintaining proper order. A noncanonical DACL can therefore exist, and stored order can change an
access-check result.

**But an inherited ACE does not carry an inheritance-depth field.** The local DACL can prove that an
ACE is inherited, but not by itself whether it came from the parent, grandparent, or an earlier
ancestor. Full validation of inherited-generation order requires reconstructing provenance from
ancestor descriptors, schema applicability, inheritance flags, protection boundaries, and any
mapping that occurred when an ACE became effective.
([ACE Inheritance Rules](https://learn.microsoft.com/windows/win32/secauthz/ace-inheritance-rules))

> **R5.** Treat stored order, canonicality, DC standardization expectation, and inheritance
> provenance as separate claims under one requirement:
>
> 1. Preserve and display every ACE in stored ordinal.
> 2. Determine AD canonicality using the MS-ADTS rules applicable to the forest.
> 3. Explain whether the DC was expected to standardize the ACL using forest functional level and
>    `fDontStandardizeSDs` (character 12 of forest-wide `dSHeuristics`).
> 4. Report locally provable defects separately from full inheritance provenance, which may be
>    claimed only with sufficient ancestor, schema, inheritance, and protection-state evidence.

### 5.3 No DACL and empty DACL are opposites

"If the object does not have a DACL, the system grants access" … "If the object's DACL has no
ACEs, the system denies all attempts to access the object."
([Access control lists](https://learn.microsoft.com/windows/win32/secauthz/access-control-lists),
[Null vs. Empty DACLs](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/ee18efbf-e8d4-4eb0-8b27-79773e96d61f))

A missing or null DACL causes normal DACL access checks to grant requested access. An allocated DACL
containing zero ACEs grants no access through the DACL, subject to independently applicable implicit
rights and privileges. The two behaviors can otherwise render as the same empty table.

There are also two structurally distinct grant-all representations: **SE_DACL_PRESENT not set**, and
**SE_DACL_PRESENT set with a null DACL value**. Once a descriptor is associated with a securable
object, Microsoft says SE_DACL_PRESENT is normally set, but a parser must preserve what it actually
received rather than collapse representation into behavior.
([SECURITY_DESCRIPTOR_CONTROL](https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-control))

> **R6.** Record security-descriptor retrieval context before asserting DACL structure: protocol,
> requested attributes, `LDAP_SERVER_SD_FLAGS_OID` use and flags, whether
> `DACL_SECURITY_INFORMATION` was requested, and whether the requested portion was returned and
> parsed. Only then classify descriptor structure: DACL absent, null, empty, populated, or
> unparseable. Preserve absent/null representations, but report them as anomalous or nonconformant
> evidence when encountered in a complete current descriptor maintained by an AD DC, because
> MS-ADTS disallows NULL DACLs for DC-maintained security descriptors. An empty DACL grants no rights
> through ACEs; independently applicable owner rules and privileges remain separate.

### 5.4 Properties have three applicable scope levels

For property access, an ACE can apply at three scope levels:

1. the object's properties generally;
2. the property set containing the requested property;
3. the requested property itself.

Object-specific ACEs for unrelated property sets or properties do not apply. Rights granted or
denied at a higher scope also reach lower scopes.
([ACEs to control access to an object's properties](https://learn.microsoft.com/windows/win32/secauthz/aces-to-control-access-to-an-object-s-properties))

These are **scope levels**, not a replacement ACE traversal order. The system still examines
applicable ACEs in stored DACL sequence while evaluating the requested object/property tree.
([How DACLs control access](https://learn.microsoft.com/windows/win32/secauthz/how-dacls-control-access-to-an-object),
[Property Set](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/177c0db5-fa12-4c31-b75a-473425ce9cca))

An unscoped `DS_READ_PROP` therefore reaches every property applicable to the target object. A
property-set `DS_READ_PROP` reaches every applicable target-object property whose schema object
carries that property-set GUID.

> **R7.** Present object-wide, property-set, and named-property rights as distinct scope levels.
> Object-wide property rights reach every property applicable to the target object, and property-set
> rights reach every applicable target-object property identified as a member by the forest's
> schema. Scope determines whether an ACE applies; stored ordinal still
> determines ACE traversal.

To enumerate the properties **applicable to the target object**, the model also needs the class/attribute
applicability relation, not only the target's class identity. MS-ADTS defines the constructed
`allowedAttributes` value from the attributes in `CLASSATTS(C)` for classes in the object's
`objectClass`. A collector can therefore capture `allowedAttributes` for the target object or capture
the complete class-schema inputs needed to derive the same set. `allowedAttributesEffective` must not
be substituted because it is already permission-filtered.
([allowedAttributes](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/de249d38-9493-425a-89f5-4650e65f2dc8),
[allowedAttributesEffective](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/c16a23d1-6847-4b25-9f6b-f09fc29e8627),
[Class classSchema](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/ccd55373-2fa6-4237-9f66-0d90fbd866f5))

---

## 6. Grants that are not visible in one mask

**This section is the part most likely to be got wrong, because none of it is deducible from an ACE
in isolation.**

### 6.1 Confidential attributes need two bits, not one

> "If confidential attributes exist and if READ_PROPERTY permissions are set for these attributes,
> Active Directory will **also require CONTROL_ACCESS permissions** for the attributes or for their
> property sets."
> ([Mark an attribute as confidential](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential))

An attribute is confidential when bit 7 (`0x80`) of its `searchFlags` is set. The flag is **ignored
for base-schema attributes**. Because `systemFlags` is a bitmask and `FLAG_SCHEMA_BASE_OBJECT` is
bit `0x10`, the correct test is `(systemFlags & 0x10) != 0`, not equality with `0x10`.
([Search-Flags attribute](https://learn.microsoft.com/windows/win32/adschema/a-searchflags))

Three things follow, all of which cut both ways:

- **`DS_READ_PROP` alone is insufficient to read a confidential attribute** through an ordinary
  directory read. Enforced by every DC since Server 2003 SP1, independent of functional level. The
  entry still grants the `READ_PROP` component — it just does not satisfy the extra check — so
  "grants nothing" would overstate it in the other direction.
- **`DS_CONTROL_ACCESS` granted by a *generic* ACE confers it over the whole object.** Microsoft:
  "CONTROL_ACCESS permission is granted by assigning a generic access control entry" — and lists
  *All Extended Rights* as one of the permissions that generic ACE grants. Therefore unscoped
  `DS_READ_PROP` plus unscoped `DS_CONTROL_ACCESS` satisfy the **authorization-rights component** for
  confidential attributes on the object. They do not, by themselves, prove that a particular LDAP
  operation will successfully return or modify the value.
- **Windows LAPS attributes that contain password material are configured with the confidential
  bit, but not every Windows LAPS schema attribute is confidential.** For example,
  `msLAPS-Password` has `searchFlags` 904, including `fCONFIDENTIAL`, while
  `msLAPS-PasswordExpirationTime` has `searchFlags` 0. Classification must therefore come from each
  forest's schema, not from an `msLAPS` name prefix.
  ([Windows LAPS schema extensions reference](https://learn.microsoft.com/windows-server/identity/laps/laps-technical-reference))
  Microsoft's own tooling reflects this: `Find-LapsADExtendedRights` exists precisely to find who
  holds extended rights, "because users who have this permission can read confidential attributes."

**And the two rights need not come from the same entry.** §5.1 says rights accumulate across ACEs,
so `DS_READ_PROP` from one and `DS_CONTROL_ACCESS` from another — or from a group the principal is
in — satisfy the check exactly as well as one mask carrying both. *The first draft said "another bit
of the same mask", which is the narrow case and not the rule.*

That makes a confidential read **not an entry-level question at all.** No amount of care applied to
a single row can answer it.

**Windows Server 2025 DCs add an operation prerequisite that is not a DACL grant.** Microsoft
documents encrypted-session requirements for LDAP search, modify, and add operations involving
confidential attributes against Windows Server 2025-based DCs, and current MS-ADTS exposes
`DisableConfidentialAttributeEncryptionRequirements` as character 31 of forest-wide `dSHeuristics`.
When the corresponding disabling bit is not set, the applicable operation requires transport-level
encryption or SASL message encryption. This is separate from the `READ_PROP` + `CONTROL_ACCESS`
authorization requirement. A statement that the rights are present is therefore not the same as a
statement that a particular LDAP operation succeeds.
([dSHeuristics](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5),
[Confidential attributes on Windows Server 2025 DCs](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/confidential-attributes-unexpected-behavior-using-windows-server-2025-dc))

> **R8.** The AD authorization-rights requirement for a confidential attribute is `DS_READ_PROP`
> **and** `DS_CONTROL_ACCESS` both reaching that attribute, from any combination of applicable
> entries. Neither alone may be reported as satisfying authorization, and neither alone may be
> reported as harmless. Do not equate satisfaction of those rights with success of an actual LDAP
> operation when AD imposes additional transport or operation prerequisites.
>
> **R9.** Confidentiality is a property of the forest's schema. Test `searchFlags` bit `0x80`, and
> treat `FLAG_SCHEMA_BASE_OBJECT` as present when `(systemFlags & 0x10) != 0`. Capture both complete
> values. They cannot be replaced by shipped constants, and a run that did not read them cannot
> answer R8.
>
> **R10.** The model must express a capability that depends on **rights accumulated across several
> applicable entries**, not merely on two bits of one mask. Any per-entry or per-right presentation
> is structurally incapable of stating R8 and must not imply otherwise.

### 6.2 Ownership can supply implicit rights not represented by an ordinary trustee ACE

For AD DS **simple-access evaluation**, MS-ADTS adds **READ_CONTROL**, **WRITE_DAC**, and
**WRITE_OWNER** to the granted mask when the SID in the descriptor's Owner field matches a SID in
the requester's security context. These rights do not originate in an ordinary DACL ACE. WRITE_DAC
can let the owner modify the DACL and thereby arrange additional access. WRITE_OWNER is still subject
to AD's separate validation of the new owner SID described in §3; authorization to write the OWNER
field does not imply arbitrary third-party ownership.
([Checking Simple Access](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/c55e113e-25a2-45eb-abba-bf5a9e521a8f),
[Security Considerations](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/7afacb02-548b-4e74-bf96-04b0bf0c71b6))

**OWNER RIGHTS changes the documented implicit-owner handling for READ_CONTROL and WRITE_DAC.**
`OWNER RIGHTS` (`S-1-3-4`) represents the current owner. When an ACE carrying that SID applies to an
object, Microsoft documents suppression of the owner's normal implicit READ_CONTROL and WRITE_DAC
permissions so that applicable OWNER RIGHTS ACEs can control those rights. The AD-specific simple
access algorithm separately documents implicit WRITE_OWNER for an owner SID match; S-56 must not
assume that OWNER RIGHTS suppresses that additional AD rule unless the applicable AD authorization
algorithm documents it.
([Well-Known SID Structures](https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab),
[Owner Rights](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/26d60820-69f3-4dcc-a373-1b115b39dead))

**The default owner rule has another documented qualification.** Microsoft documents
`BlockOwnerImplicitRights`, a `dSHeuristics`-controlled behavior that can block the ordinary implicit
READ_CONTROL and WRITE_DAC owner rights for computer objects under specified conditions. The result
depends on the forest setting, object class, relevant token membership, and domain-controller
operating-system and servicing behavior. The documented owner-blocking rule must not be extended to
implicit WRITE_OWNER merely because the AD simple-access algorithm grants WRITE_OWNER on an owner-SID
match.
([Blocking Implicit Owner Rights](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/fb7c101d-ec8b-4fbf-bca8-7d7c2d747d0c),
[dSHeuristics](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5))

Even where owner-derived WRITE_DAC applies, every other right is not thereby current effective
access. Additional rights obtainable by changing the DACL are reachable rights and must be labelled
as an escalation path.

> **R11.** Capture the owner SID, applicable OWNER RIGHTS ACEs, and the
> `BlockOwnerImplicitRights` context. For AD simple-access evaluation, account for the documented
> owner-SID grant of READ_CONTROL, WRITE_DAC, and WRITE_OWNER, then apply OWNER RIGHTS and
> owner-blocking behavior only to the rights for which Microsoft documents those qualifications.
> Include object class, relevant token membership, and domain-controller version/servicing behavior.
> Rights obtainable by subsequently modifying the DACL are escalation paths, not current effective
> access.

### 6.3 `DS_LIST_OBJECT` is one component of object visibility

`DS_LIST_OBJECT` is enforced only when `fDoListObject`, the third character of forest-wide
`dSHeuristics`, is `1`. The default is disabled.
([dSHeuristics](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5))

When List Object mode is enabled, a child object is visible when either:

1. the requester has `RIGHT_DS_LIST_CONTENTS` on the parent; or
2. the requester lacks that right but has `RIGHT_DS_LIST_OBJECT` on **both the child and its
   parent**.

An object-level LIST_OBJECT ACE by itself does not establish visibility.
([Checking Object Visibility](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/4a7705f7-c61e-4020-86a7-41a44fb233e5))

> **R12.** Capture `fDoListObject`. When disabled, LIST_OBJECT is not enforced. When enabled, model
> visibility as the documented parent/object capability: LIST_CONTENTS on the parent is sufficient;
> otherwise LIST_OBJECT is required on both child and parent. Never report an isolated child-level
> LIST_OBJECT ACE as granting visibility.

---

## 7. Inheritance

The flags are in `AceFlags` and their effects are tabulated by Microsoft.
([ACE_HEADER](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-ace_header),
[ACE inheritance rules](https://learn.microsoft.com/windows/win32/secauthz/ace-inheritance-rules))

| Flag | Value | Effect |
|---|---|---|
| `OBJECT_INHERIT_ACE` | `0x1` | Non-container children inherit it as effective. |
| `CONTAINER_INHERIT_ACE` | `0x2` | Container children inherit it as effective. |
| `NO_PROPAGATE_INHERIT_ACE` | `0x4` | Children inherit, grandchildren do not. |
| `INHERIT_ONLY_ACE` | `0x8` | **Does not control access to the object it is attached to.** |
| `INHERITED_ACE` | `0x10` | Set by the system when it propagated this entry. |

Two traps:

**`INHERIT_ONLY_ACE` means the entry does nothing here.** An inherit-only Full Control entry on an
OU grants nothing on that OU. Presenting it as a grant on the object it sits on is simply false.

**The directory treats every object as a container.** "the DS treats all object types as
containers", so `CONTAINER_INHERIT_ACE` is the operative flag throughout AD, and
`InheritedObjectType` narrows inheritance to a named class.
([ACE inheritance rules](https://learn.microsoft.com/windows/win32/secauthz/ace-inheritance-rules))

> **R13.** `INHERIT_ONLY_ACE` must suppress any claim that the entry grants access on the object
> carrying it, while still showing what it will grant below.
>
> **R14.** `InheritedObjectType` is separate from `ObjectType` and answers who can inherit, not what
> the ACE reaches. Apply AD's target-class rule using the object's most-specific structural class
> and applicable dynamic auxiliary classes; do not treat every less-specific structural ancestor or
> static auxiliary class as an equivalent match. Capture the target object's ordered `objectClass`
> and schema classification when reconstructing inheritance applicability.

MS-ADTS states this class-selection rule directly during security-descriptor inheritance processing:
the check uses the object's most-specific structural class and its dynamic auxiliary classes, while
less-specific structural classes and static auxiliary classes are not equivalent matches for this
purpose.
([Security Descriptor Requirements](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a))

**Trustee SIDs can also transform or depend on context.** When an inherited ACE becomes effective,
Windows substitutes inheritance-placeholder SIDs such as `CREATOR_OWNER` and `CREATOR_GROUP` with
the applicable owner or group SID. If the ACE remains inherit-only, the placeholder remains
unsubstituted so it can be resolved when a later inherited copy becomes effective. `PRINCIPAL_SELF`
is an object-context identity for an object representing a principal, and OWNER RIGHTS represents
the current owner rather than a static directory group.
([ACE Inheritance Rules](https://learn.microsoft.com/windows/win32/secauthz/ace-inheritance-rules),
[ComputeACL](https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/7c59604a-945c-4f6f-a706-1cbb80041e83),
[Well-Known SID Structures](https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab),
[Special Identity Groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-special-identities-groups))

> **R18.** Preserve the literal trustee SID but classify its semantics as a literal principal or
> group, token-dependent special identity, object-context identity, inheritance placeholder, or
> unresolved/unsupported identity. Do not perform ordinary account lookup or group expansion as
> though every trustee SID represented a static directory principal.

Inheritance can be blocked entirely by `SE_DACL_PROTECTED`.
([Security descriptors for new objects](https://learn.microsoft.com/windows/win32/secauthz/security-descriptors-for-new-objects))

---

## 8. Where entries come from

### 8.1 DACL construction for a new directory object

Microsoft documents conditional construction paths, not three sources that are always merged:

1. **A security descriptor is explicitly supplied.** AD starts with the supplied DACL and merges
   applicable inheritable ACEs from the parent unless `SE_DACL_PROTECTED` is set.
2. **No security descriptor is supplied.** AD builds the DACL by merging applicable inheritable
   parent ACEs with the `defaultSecurityDescriptor` DACL on the object's `classSchema`.
3. **The schema class has no default DACL.** AD can use the default DACL from the creator's primary
   or impersonation token.
4. **No specified, inherited, schema-default, or token-default DACL exists.** AD creates the object
   with no DACL, producing grant-all DACL behavior.

([How security descriptors are set on new directory objects](https://learn.microsoft.com/windows/win32/ad/how-security-descriptors-are-set-on-new-directory-objects),
[DACL for a new object](https://learn.microsoft.com/windows/win32/secauthz/dacl-for-a-new-object))

The class `defaultSecurityDescriptor` is therefore a creation default used when no descriptor was
supplied; it is not an additional DACL merged into every explicitly supplied descriptor.
([Default security descriptor](https://learn.microsoft.com/windows/win32/ad/default-security-descriptor))

A current descriptor does not necessarily prove which creation path originally supplied each
explicit ACE. Historical provenance must not be invented from current state.

**Microsoft documents a boundary condition inconsistently.** The Win32 AD creation documentation
describes a theoretical fallback that produces no DACL when no source supplies one, while MS-ADTS
states that NULL DACLs are disallowed for security descriptors maintained by a DC. Preserve the
creation rule as documented, but do not assume that a current persisted AD object can normally hold
a NULL DACL.
([How security descriptors are set on new directory objects](https://learn.microsoft.com/windows/win32/ad/how-security-descriptors-are-set-on-new-directory-objects),
[Security Descriptor Requirements](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a))

**Microsoft also describes `defaultSecurityDescriptor` inconsistently at the schema-field level.**
The `classSchema` field description says the class default is assigned when no descriptor is supplied
or merged when one is supplied. The operation-specific AD DS Add/defaulting rules, however, first
default from `defaultSecurityDescriptor` only when no descriptor was supplied and then process the
resulting creator descriptor with inherited ACEs. For AD DS object creation, S-56 follows the more
specific operation path rather than treating the class default as an unconditional additional input.
([Class classSchema](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/ccd55373-2fa6-4237-9f66-0d90fbd866f5),
[LDAP Add processing](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/5ba06266-a8ef-4d34-9c29-411676249bcd),
[Security Descriptor Requirements](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a))

> **R15.** Model new-object DACL construction as the documented conditional paths. Capture the
> creation inputs only when construction or historical provenance is actually being analyzed; do
> not describe the supplied DACL, class default DACL, and token default DACL as simultaneous inputs.

### 8.2 Protected accounts and groups

Protected accounts are periodically re-stamped. SDProp runs on the PDC Emulator, compares the
security descriptor of every currently protected account and group against the AdminSDHolder
template, overwrites differences, and disables inheritance. The default interval is 60 minutes, but
`AdminSDProtectFrequency` is configurable and the task can be invoked on demand.
([Appendix C: Protected accounts and groups](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory))

The default protected set is published by Microsoft and can vary by release. The forest-wide
`dSHeuristics` value is stored on
`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,<forest-root-DN>`. Its 16th
character can exclude only the documented operator groups: Account Operators, Server Operators,
Print Operators, and Backup Operators. It is not an attribute on the AdminSDHolder object.
([dSHeuristics](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5),
[Configurable State](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/50097362-ede5-40fa-973e-8d65e782e384))

`adminCount` can remain 1 after an object leaves the protected set, and inheritance can remain
disabled. But `adminCount` is not the current inheritance flag. Current protection against inherited
DACL changes is represented by `SE_DACL_PROTECTED` in the descriptor control bits.
([Reducing the AD attack surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface),
[Security descriptor components](https://learn.microsoft.com/windows/win32/ad/security-descriptor-components))

Microsoft explicitly includes direct and transitive protected-group membership reached through
nested **distribution groups** as well as security groups. That rule is directory-membership based:
a token-only view is insufficient because distribution-group nesting can affect protected-object
enumeration even though distribution-group SIDs are not used as ordinary authorization SIDs in the
member's access token.
([Reducing the AD attack surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface))

> **R16.** Determine current protected-set membership using the published protected principals,
> the applicable forest-wide `dSHeuristics` exclusion mask, and sufficient membership edges to
> compute direct and transitive membership through nested groups, including distribution groups.
> Do not substitute token-only expansion such as `tokenGroups`. Report differences from
> AdminSDHolder as subject to replacement without promising a fixed time.
>
> **R17.** Treat `adminCount = 1` on a principal that is not currently protected as evidence of prior
> protected-object processing. Determine current inheritance protection from
> `SE_DACL_PROTECTED`, never from `adminCount`.

## 9. What an ACE cannot tell you

Stated plainly, because every one of these is a way to be confidently wrong:

- **Who or what the trustee resolves to in context.** A literal group SID reaches nested enabled
  members, but contextual identities such as PRINCIPAL_SELF, OWNER RIGHTS, and inheritance
  placeholders require object or inheritance context rather than ordinary group expansion.
- **Whether a literal trustee is disabled or orphaned.** That is not in the descriptor.
- **Privileges.** `SE_TAKE_OWNERSHIP_NAME`, `SE_RESTORE_NAME`, and `SE_SECURITY_NAME` can affect
  operations independently of ordinary DACL grants.
  ([Privilege constants](https://learn.microsoft.com/windows/win32/secauthz/privilege-constants))
- **Token SID attributes.** Disabled group SIDs do not satisfy allow ACEs; deny-only SIDs cannot
  satisfy allows but can match denies.
  ([How DACLs control access](https://learn.microsoft.com/windows/win32/secauthz/how-dacls-control-access-to-an-object))
- **Conditional-ACE truth.** It requires the claims and attributes referenced by the condition and
  evaluation according to Microsoft's conditional-expression rules.
- **Operation-specific related-object authorization.** Some AD operations use the target object's
  parent or another related security descriptor. This is operation-specific, not arbitrary
  cross-object accumulation.

> **R19.** Every entry-level statement is about that entry under the descriptor and ACE-type rules.
> Any claim about what a principal can do is a separate computation requiring the relevant token SID
> attributes, nested membership, privileges, ownership rules, contextual trustee substitution,
> object state, conditional-ACE inputs where supported, the requested right or operation, and every
> target/parent/NC-root/related descriptor selected by the applicable AD authorization algorithm.
> Label the two levels explicitly.

---

## 10. The requirements, collected

**The `Built` column was added 2026-08-20 and is the only change to this section.** Every
requirement must name the type or test that satisfies it, or say `not built`. A requirement whose
entry is neither fails the build, so this table cannot quietly stop describing the product.
`next/tools/trace-permission-requirements.ps1` produced the first pass.

| # | Requirement | Source | Built |
|---|---|---|---|
| R1 | Fully analyze supported ordinary ACE types; preserve and classify every unsupported ACE raw | §2 | `SecurityDescriptorParser` |
| R2 | Preserve raw mask and context; map generic rights only where that context requires it | §3 | `GenericRightsExpander` |
| R3 | Resolve GUID meaning per mask bit, not once per entry | §4 | `SchemaGuidKind` |
| R4 | Use `validAccesses` for controlAccessRight classification and `attributeSecurityGUID` for actual property-set membership | §4 | `CapturedSchemaGuidReader` |
| R5 | Preserve stored ordinal; separately evaluate canonicality, DC standardization expectation, and inheritance-provenance limits | §5.2 | `AceCanonicalization` |
| R6 | Capture retrieval context before asserting DACL structure; flag complete current NULL DACL evidence as anomalous | §5.3 | `SecurityDescriptorParser` |
| R7 | Model property scopes over attributes applicable to the target object; capture or derive the target's allowed attribute set | §5.4 | `PermissionScope` |
| R8 | Confidential-attribute authorization requires READ_PROP and CONTROL_ACCESS from any applicable entries; operation prerequisites remain separate | §6.1 | `DangerousPermissionClassifier` |
| R9 | Test `searchFlags` and `systemFlags` bits; capture complete schema values | §6.1 | `CapturedAttributeCatalog` |
| R10 | Support capabilities accumulated across multiple applicable entries | §6.1 | `ObjectPermissions` |
| R11 | Model AD's owner-SID grant of READ_CONTROL, WRITE_DAC, and WRITE_OWNER, applying OWNER RIGHTS and owner-blocking qualifications only where documented | §6.2 | `ObjectPermissions` — partial, see F-1 |
| R12 | Model LIST_OBJECT using List Object mode and the documented parent/child visibility combination | §6.3 | `GenericRightsExpander` |
| R13 | INHERIT_ONLY suppresses a local grant claim | §7 | `CanonicalAce` |
| R14 | Apply `InheritedObjectType` using the most-specific structural and dynamic-auxiliary class rule | §7 | `AceNormalizer` |
| R15 | Model new-object DACL construction as documented conditional paths | §8.1 | not built |
| R16 | Compute current protection using transitive directory membership, including distribution groups, plus exclusions | §8.2 | not built |
| R17 | Treat `adminCount` as history; derive current inheritance protection from `SE_DACL_PROTECTED` | §8.2 | `AceNormalizationResult` |
| R18 | Classify literal, contextual, token-dependent, and placeholder trustee SID semantics | §7, §9 | `WellKnownSidCatalog` |
| R19 | Never present an entry-level interpretation as principal-level effective access; operation-level claims require every descriptor selected by the AD algorithm | §9 | `EntryReach` |
| R20 | Select the AD-specific access-check family and its operation-specific parameters/descriptors for the requested right or operation | §5.1 | `DangerousPermissionClassifier` |

### Findings against this table

**F-1 — the OWNER RIGHTS qualification was missing. Fixed 2026-08-20, and the original wording of
this finding was wrong.** It said an object protected by `OWNER RIGHTS` was "still reported as
owner-controlled". Checked against the code, nothing concluded that: the Overview card printed the
owner's name and stopped, and no finding anywhere was raised on the basis of who owns an object.
The code won the disagreement and this text was corrected rather than the code.

**The real defect was a sentence.** `DangerousPermissionClassifier` said, of any entry granting
Modify Owner, that "an object's owner has the implicit right to modify its permissions". MS-DTYP
2.4.2.4 contradicts that for any object carrying an `S-1-3-4` entry: the system ignores the owner's
implicit `READ_CONTROL` and `WRITE_DAC`. So an administrator who had applied the standard hardening
was told in the product's own words that it did not hold — the product stating something false,
which is never deferred.

Two changes. The classifier now says what is ordinarily true and says plainly that one entry cannot
settle it, because it sees an access mask and never the object's DACL. And
`ObjectPermissions.OwnerRightsEntryIsPresent` reports that such an entry is present, shown beside
the owner on the Overview card. **R11 remains partial deliberately.** Microsoft documents the
suppression for `READ_CONTROL` and `WRITE_DAC` and is silent on `WRITE_OWNER`, so the product
states the entry is present and withholds the conclusion; §6.2's caution against extending the rule
stands. `BlockOwnerImplicitRights` is still not modelled.

**An `INHERIT_ONLY` entry does not count, which is not a detail.** The first version of the check
counted any `S-1-3-4` entry. Adding a permission to an organisational unit and setting *Applies to:
descendant objects* sets `INHERIT_ONLY_ACE`, and such an entry governs the objects beneath the unit
while granting nothing on the unit itself — so the check would have reported a container as
owner-restricted when only its children were. That is the same class of false statement F-1 was
raised about, pointing the other way, and it was found while writing the lab instructions rather
than by a test. The check now asks `EntryReachReader`, which R13 already made answerable for the
question.

**The access mask is deliberately not consulted, and the lab showed why.** MS-DTYP 2.4.2.4 ties the
suppression to the entry being applied, not to what it grants: *"When an ACE that carries this SID
is applied to an object, the system ignores the implicit READ_CONTROL and WRITE_DAC permissions for
the object owner."* On 2026-08-20 an OWNER RIGHTS entry was added to `OU=test01` in the `ba.ad.lab`
forest with every permission left unticked, and the captured descriptor holds it as
`ace_type=AccessAllowed`, `access_mask=0`, `propagation_flags=0`. A check requiring particular
rights would have missed a real entry made the ordinary way.

**Active Directory keeps that entry and the standard tool does not show it.** The same lab run
found that after clicking OK, the Security tab in Active Directory Users and Computers no longer
lists the zero-mask entry, while the directory still holds it and still honours it. An
administrator applying this hardening therefore cannot confirm it with the tool he applied it in,
and one reading his own directory would conclude it had not taken. Reporting it is a thing this
product can do that the built-in tool does not.

**F-2 — placeholder trustee SIDs (`S-1-3-0`, `S-1-5-10`) were read as literal principals. Fixed
2026-08-20, and it was worse than recorded.** The finding assumed these SIDs went unresolved. They
did not: Active Directory keeps real objects for them under `CN=WellKnown Security Principals`, so
the ordinary lookup found `CN=Self` and reported *Self* as a named principal in the forest root's
domain, formatted identically to a group beside it. In one lab bundle that credited **1,394**
entries to `S-1-5-10` (PRINCIPAL SELF) and **314** to `S-1-3-0` (CREATOR OWNER), among them
`Write ms-Mcs-AdmPwd` and `Write msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer object.

`WellKnownSidCatalog` is now consulted before the captured objects, so a well-known SID is named
from MS-DTYP rather than from whichever object happened to match. `PRINCIPAL SELF` resolves to the
object itself, `CREATOR OWNER` is named as a template and deliberately left unresolved, and neither
is counted as holding a permission.

**F-3 — a trustee's name and domain could be arbitrary. Found and fixed 2026-08-20.** Trustee
resolution ran `SELECT … WHERE objectsid = $sid LIMIT 1` with no `ORDER BY`, and `captured_object`
has no index on `objectsid`. In one lab bundle `S-1-5-11` matched four rows — the well-known
principal and three `ForeignSecurityPrincipals` objects in different domains — so which name and
domain a reader saw was decided by table order. It was correct only because the Configuration
partition happened to be captured first; a different capture order, or an index added for
performance, would have changed what the product said about who holds a permission. Nothing
anywhere asserted which of the four was right. Consulting the catalogue first removes the
ambiguity rather than tie-breaking it.

**F-4 — the stored projection and the re-parse of one descriptor disagree by one entry. Open,
found 2026-08-20.** For `OU=test01,OU=Servers,OU=BA Lab,DC=ba,DC=ad,DC=lab` in bundle
`ad.lab-20260821-014720`, descriptor `147` has **57** rows in the `ace` table while the Permissions
screen reports **56** entries. The screen reads `ObjectPermissions.Entries`, which is re-parsed from
the descriptor's stored bytes; the `ace` table is the canonical projection written at capture time.
The bytes cannot have changed, because the seal covers them, so one of two readings of one
descriptor is wrong.

The OWNER RIGHTS entry is *not* the missing one — it is present in the re-parse, which is why the
owner qualification appears on screen. The descriptor records `dacl_state=Present`,
`dacl_completeness=Complete` and `dacl_was_canonical=1`, so nothing in the product currently
reports that anything is missing.

**Severity: an entry count an operator reads may be short by one, and one permission may not be
listed at all.** Which representation is correct is not yet established, and guessing at it is what
this finding exists to prevent. The next step is to walk the DACL header in the stored bytes and
compare its declared ACE count against both readings. `S-57` anticipated this when it upheld that a
projection cannot stand in for the stored DACL; here both exist and they do not agree.

---

## 11. What must be captured for any of this to be answerable

**This table is a dependency matrix, not an always-capture requirement.** An input is required only
when the product evaluates a requirement or makes a claim that depends on it. ACE-level
interpretation must not require principal-, operation-, provenance-, or version-specific inputs
unless the requested conclusion crosses into those layers. Conversely, if a claim depends on an
input listed here and that input was not captured, the result must remain partial, conditional,
unsupported, or unknown rather than silently substituting a constant.

| Data | Needed by | Source/partition |
|---|---|---|
| Whole returned `nTSecurityDescriptor`, including owner, control flags, DACL state, ACL revision, ACE ordinal/type, and raw ACE bytes | R1, R5, R6, R11, R13, R14, R17, R18 | object retrieval |
| Retrieval evidence: requested attributes, SD Flags Control and flags, requested/returned portions, and parse status | R6 | collection path |
| Raw access mask plus observation context | R2 | collection path |
| `searchFlags`, `systemFlags`, and `attributeSecurityGUID` per attribute | R4, R8, R9 | schema |
| `schemaIDGUID`, class category/ancestry, `lDAPDisplayName`, target ordered `objectClass`, dynamic auxiliary classes, and either target `allowedAttributes` or the complete class-schema inputs needed to derive `CLASSATTS` | R3, R5, R7, R11, R14, R18 | object and schema |
| `validAccesses`, `rightsGUID`, and names per `controlAccessRight` | R3, R4 | configuration/Extended-Rights |
| Forest functional level, **when evaluating canonicality or DC standardization expectation** | R5 | forest configuration |
| Ancestor descriptors and object classes when full inheritance provenance is claimed | R5 | ancestor objects and schema |
| Applicable forest-wide `dSHeuristics` characters, **when evaluating a rule affected by them**, including `fDoListObject`, `fDontStandardizeSDs`, `BlockOwnerImplicitRights`, `DisableConfidentialAttributeEncryptionRequirements`, and AdminSDHolder exclusions | R5, R8, R11, R12, R16 | configuration |
| Domain-controller OS and servicing behavior, **when Microsoft documents version- or servicing-dependent behavior for the check** | R8, R11 | run context |
| AdminSDHolder descriptor, protected principal identities, and membership edges sufficient for direct/transitive expansion including distribution groups | R16 | domain directory and configuration |
| `adminCount` per object | R17 | object's own |
| Parent descriptor and target descriptor when LIST_OBJECT visibility is computed | R12 | object and parent |
| Complete set of applicable ACEs/descriptors, scope metadata, and trustee/security-context inputs, **only when accumulated-capability analysis is performed** | R10 | object, schema, and principal context as applicable |
| Operation identity, requested right, applicable property/class/control-access GUID parameters, and every target/parent/NC-root/related descriptor selected by the applicable MS-ADTS algorithm, **when operation-level or principal effective authorization is claimed** | R19, R20 | operation and related directory objects |
| LDAP operation type and connection protection state when claiming successful access to confidential attributes, together with applicable DC behavior | R8 | operation/run context |
| Explicitly supplied descriptor, parent inheritance inputs, class `defaultSecurityDescriptor`, and creator-token default DACL, but only when analyzing object creation | R15 | creation-time inputs |

Only if principal-level effective access is computed, also capture the ultimate user SID, enabled
and deny-only SIDs, nested group membership, restricted SIDs where in scope, relevant privileges,
OWNER RIGHTS/object-owner context, PRINCIPAL_SELF substitution context, the requested right or
operation, every related descriptor selected by that operation's AD authorization algorithm, and any
claims or attributes required by supported conditional ACEs.

A collector that lacks any required input must report the corresponding answer as conditional,
partial, unsupported, or unknown rather than silently substituting a constant.

### Version 4 freeze-candidate notes

Version 4 does not change the core authorization model or renumber R1–R20. It corrects the
`GENERIC_ALL` description so it no longer implies `SYNCHRONIZE` or `ACCESS_SYSTEM_SECURITY`,
tightens structural/reporting wording, strengthens direct sourcing for R14, R16, and inheritance
placeholder SIDs, and makes §11's conditional capture dependencies explicit.

---

## 12. Open questions this specification does not settle

1. **Severity.** Nothing here says which grants are dangerous. That must be a separate document
   sourced to rule specifications, and it must consume this one rather than restate it.
2. **Where R10 is answered.** R10 requires the product to be *able* to express a capability
   accumulated across entries. It does not say whether that belongs to a principal-level
   computation, a rules layer, or both — only that a permission row cannot be it.
3. **How wide the principal-level computation goes.** R19 names the inputs but does not place the
   second computation or bound its cost.
4. **`SE_DACL_PROTECTED` and effective-access reconstruction.** Whether the product ever computes
   effective access, as opposed to reporting entries, is not decided here.

---

## 13. What went wrong in the first draft

Recorded because the shape recurs and is cheap to repeat.

The draft opened with a rule — *every claim carries a link, and one without is a mistake* — and then
broke it about a dozen times in the same way. Not by inventing citations: **by attaching a true
citation to a conclusion it did not support.**

| Cited, correctly | Written, wrongly |
|---|---|
| generic owner documentation describes implicit `READ_CONTROL` and `WRITE_DAC`, while AD-specific simple access additionally grants `WRITE_OWNER` on an owner-SID match | … therefore use the generic two-right rule as the complete AD owner model |
| `adminCount` persists after removal | … therefore inheritance is off |
| SDProp runs every 60 minutes by default | … therefore the entry is erased within the hour |
| a confidential read needs two rights | … therefore two bits of one mask |
| the system examines each ACE in sequence | … therefore the loop is over rights, not entries |

The last is the worst, because it is the one that flattered a design already built. The others are
haste; that one is motivated.

**The tell is the word *therefore*.** A specification derived from documentation may quote and it
may cite, but the moment it reasons one step past its source it is producing new claims, and those
need their own evidence or their own label. Where this document now reasons past Learn, it says so.


### Additional lessons retained from earlier review work

- A field list is not universal merely because it covers the ACE types most commonly seen in AD.
- A trustee SID can be contextual or a placeholder, not only a static principal identifier.
- A flag-valued attribute requires a bit test, even when another Microsoft page uses equality as
  descriptive shorthand.
- Current state does not necessarily prove creation provenance or inheritance generation.
- Platform algorithms described as conditional paths must not be rewritten as an unconditional
  merge of all possible inputs.
