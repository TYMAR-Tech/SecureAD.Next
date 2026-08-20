# SecureAD — Microsoft Source Deep Review

**Scope:** Review of the attached `SecureAD-microsoft-source-review.zip` bundle, focused on areas where implementation correctness depends on Microsoft-documented Active Directory, LDAP, Group Policy, SID, and Windows security semantics.

**Source standard:** Microsoft first-party documentation only, with Microsoft Open Specifications (especially MS-ADTS / MS-DTYP / MS-GPOL / MS-GPSB) preferred where they directly define Active Directory behavior.

## Overall assessment

There are several **real Microsoft-semantics problems** in the implementation, not just stylistic disagreements.

The biggest architectural issue is that several parts of the code normalize or simplify raw security descriptor evidence **before the product has finished deciding what that evidence means**. That can cause a correct Microsoft rule to produce the wrong final interpretation.

I would **not trust the current permission interpretation/classification output yet** until the highest-priority issues below are corrected.

## Recommended priority

| Priority | Area | Severity | Why it matters |
|---|---:|---|---|
| 1 | Generic-right expansion | HIGH | Changes raw stored ACE meaning/evidence |
| 2 | ACE sorting/deduplication/hashing | HIGH | Can erase security-significant stored order |
| 3 | Security descriptor / ACE parser fidelity | HIGH | Collapses unknown/malformed/null states |
| 4 | Callback/conditional ACE handling | HIGH | Can interpret conditional access as unconditional |
| 5 | `ObjectType` semantics | HIGH | CREATE/DELETE/FULL CONTROL classifications can be scoped incorrectly |
| 6 | Confidential/LAPS access | HIGH | Reports capability from one ACE when Microsoft requires accumulated rights |
| 7 | `WRITE_OWNER` | HIGH | Overstates what that ACE itself grants |
| 8 | Schema `validAccesses` handling | HIGH | Unknown schema semantics are guessed as extended rights |
| 9 | Inheritance scope | HIGH/MEDIUM | OI/CI semantics are oversimplified for AD |
| 10 | LDAP connection-security conclusions | HIGH | Can make false claims about a DC's security posture |
| 11 | GPO identity + link precedence/options | HIGH | Can associate/read or order the wrong policy |
| 12 | DN parser | HIGH | Valid AD DNs can be split incorrectly |
| 13 | Security-template encoding | MEDIUM | Accepts formats Microsoft says are nonconformant |
| 14 | UAC current-state wording | MEDIUM | Lockout/password state can be reported incorrectly |
| 15 | SID validation | MEDIUM | Accepts binary/text SID forms outside Microsoft's structure |

The first nine should be corrected before treating SecureAD's permission output as authoritative.

---

# Findings

## 1. Stored generic rights must not be expanded

### Code

`SecureAD.Kernel/Security/GenericRightsExpander.cs`

The class effectively treats a raw generic bit and the expanded AD-specific rights as equivalent representations of the same stored permission.

`AceNormalizer` and `DangerousPermissionClassifier` both expand the mask.

### Why this is wrong

For Active Directory security descriptors, generic bits are mapped before being stored. Microsoft AD-specific protocol documentation states that generic bits are mapped into object-specific/standard rights before the security descriptor is persisted.

Therefore, if SecureAD captures a current `nTSecurityDescriptor` and sees a generic bit such as:

- `GENERIC_ALL`
- `GENERIC_WRITE`
- `GENERIC_READ`
- `GENERIC_EXECUTE`

that should not be silently expanded as though it were a normal alternate encoding of stored AD permissions.

It is anomalous evidence and should remain visible as such.

### Recommended fix

Preserve:

```text
RawAccessMask
ObservationContext = StoredAce | AssignmentMask | RequestedAccess
MappedAccessMask?   // only where mapping is appropriate
GenericBitsPresent
```

For a stored ACE captured from AD:

- preserve the generic bit exactly;
- do not expand it before classification;
- flag it as anomalous/unexpected if it appears in a current DC-maintained descriptor.

The mapping constants themselves are broadly correct. The problem is **when the mapping is applied**.

### Microsoft source

Microsoft Open Specifications — MS-ADTS, security descriptor handling / generic access mapping.

---

## 2. `AceNormalizer` must not sort and deduplicate raw evidence

### Code

`AceNormalizer.cs`

The pipeline performs canonical ordering, computes ACE hashes, and deduplicates entries.

### Why this is dangerous

Stored ACE order is part of the security evidence.

Active Directory does not use one universal access-check algorithm for every right. Different AD authorization families consume DACL order differently.

Examples include:

- simple/standard access;
- object-specific/property access;
- control-access-right checks;
- validated-write checks.

Therefore, the ordinal position of an ACE cannot be discarded or replaced by a canonical projection.

Two identical ACEs at different ordinals are still two ACEs that existed at different places in the stored DACL.

### Recommended fix

Raw model:

```text
StoredAce
    Ordinal
    RawAceBytes
    AceType
    AceFlags
    RawMask
    ObjectFlags
    ObjectTypePresent
    ObjectType
    InheritedObjectTypePresent
    InheritedObjectType
    TrusteeSid
```

If desired, create a separate presentation-only projection:

```text
CanonicalDisplayProjection
```

Do not replace the stored DACL with the canonicalized form.

Do not deduplicate raw ACE evidence.

### Microsoft source

Microsoft Open Specifications — MS-ADTS access-check procedures and ACE ordering rules.

---

## 3. `AceSetHash` can report unchanged when the DACL changed

### Code

`AceSetHash.cs`

The hash is intentionally based on normalized order so the same ACE set hashes the same regardless of stored order.

### Why this is a problem

These are different descriptors:

```text
Allow X
Deny X
```

and:

```text
Deny X
Allow X
```

Even when a specific requested right ultimately evaluates the same under one AD authorization family, the DACLs are different evidence.

For other rights and access-check families, stored order can affect the outcome.

### Recommended fix

Use two hashes if both are useful.

**Evidence/state hash**

Order-sensitive:

```text
raw DACL bytes
```

or:

```text
ordinal + raw ACE bytes
```

**Semantic-set hash**

Optional and explicitly order-insensitive.

Do not use an order-insensitive hash as the security descriptor's authoritative state hash.

---

## 4. The descriptor parser turns unreadable evidence into a confident null DACL

### Code

`SecurityDescriptorParser.cs`

Malformed, short, invalid-base64, or invalid-offset descriptors can become:

```text
DaclState.Null
DaclCompleteness.Complete
DaclWasCanonical = true
```

### Why this is wrong

These states are not equivalent:

```text
DACL not retrieved
DACL absent
DACL present but NULL
empty DACL
populated DACL
unreadable DACL
descriptor malformed
```

Microsoft distinguishes absent/null DACL behavior from empty DACL behavior.

MS-ADTS additionally states that NULL DACLs are not valid for security descriptors maintained by a DC.

A malformed descriptor must not become a confident permission result.

### Recommended fix

Use a state model such as:

```csharp
enum DaclState
{
    NotRetrieved,
    Absent,
    Null,
    Empty,
    Present,
    Unreadable
}
```

and track separately:

```text
RetrievalCompleteness
ParseCompleteness
```

Invalid base64, impossible offsets, truncated ACLs, and malformed ACE bounds should produce **Unreadable/Unknown**, not Null/Complete/Canonical.

---

## 5. The parser does not preserve enough raw ACE structure

### Current model

`ParsedAce` retains fields such as:

```text
AceType
AceFlags
AccessMask
TrusteeSid
ObjectTypeGuid?
InheritedObjectTypeGuid?
```

### Missing evidence

At minimum:

```text
stored ordinal
raw ACE bytes
raw object Flags
ACE_OBJECT_TYPE_PRESENT
ACE_INHERITED_OBJECT_TYPE_PRESENT
ApplicationData for callback ACEs
```

GUID presence is determined by the ACE's object flags, not by whether the parsed GUID happens to be null.

### Recommended fix

Do not use only:

```csharp
string? ObjectTypeGuid
```

as the evidence model.

Prefer:

```csharp
bool ObjectTypePresent;
Guid ObjectType;
```

or preserve the raw `ObjectFlags` and derive presence from that.

Do the same for `InheritedObjectType`.

---

## 6. Callback/conditional ACEs are treated too much like ordinary ACEs

### Code

The parser recognizes callback-object ACE types and parses their ordinary prefix, but does not preserve or evaluate callback `ApplicationData`.

### Why this matters

A conditional ACE is not just:

```text
Allow X WRITE_PROPERTY
```

It is conceptually:

```text
Allow X WRITE_PROPERTY
IF condition evaluates true/applicable
```

Microsoft defines conditional ACE applicability separately, including allow/deny behavior when a condition cannot be fully evaluated.

If the condition is discarded, the remaining ACE can be misinterpreted as an unconditional grant or deny.

### Recommended fix

Until the Microsoft conditional-expression evaluator is implemented:

```text
CallbackConditional
UnsupportedForSemanticEvaluation
```

Preserve:

```text
raw ACE bytes
raw ApplicationData
ACE type
ordinal
```

Do not feed these ACEs into ordinary grant/risk logic.

Unknown is the correct answer here.

---

## 7. The canonicality checker is not Microsoft's AD canonicality model

### Code

`AceCanonicalization.cs`

The checker largely models:

```text
explicit deny
explicit allow
inherited deny
inherited allow
```

### Why this is incomplete

Microsoft AD canonicalization has additional rules, including distinctions between regular and object ACEs at applicable forest functional levels.

Whether the DC is expected to standardize an ACL also depends on:

- forest functional level;
- `fDontStandardizeSDs` in `dSHeuristics`.

Inherited-generation provenance also cannot be fully reconstructed from the local DACL alone.

### Recommended fix

Avoid a single:

```csharp
bool DaclWasCanonical
```

unless the evidence is actually complete.

Prefer something like:

```text
ProvablyNonCanonical
LocallyPassesCanonicalRules
FullyCanonicalVerified
Unknown
```

and retain:

```text
ForestFunctionalLevel
fDontStandardizeSDs
inheritance provenance completeness
```

---

## 8. `CREATE_CHILD` and `DELETE_CHILD` are being classified without class scope

### Code

`DangerousPermissionClassifier.ClassifyObjectIndependentBits()`

`CreateChild` and `DeleteChild` are classified before `objectTypeGuid` is considered.

### Why this is wrong

For these access bits, `ObjectType` identifies the child class.

Example:

```text
CREATE_CHILD + user-class GUID
```

means create children of that class.

That is different from:

```text
CREATE_CHILD with ObjectType absent
```

which is unscoped across child classes allowed by schema.

### Recommended fix

Remove CREATE_CHILD and DELETE_CHILD from an object-independent bucket.

Resolve them from:

```text
(mask bit, ObjectType presence, ObjectType GUID)
```

The meaning of `ObjectType` must be evaluated per mask bit.

---

## 9. The "Full control" shortcut can discard scope and extra bits

### Code

`PermissionWording.cs`

The implementation returns "Full control" when the Full Control bit set is contained within the mask.

### Problems

#### A. Subset test

A mask containing Full Control plus another bit still collapses to "Full control", hiding the extra bit.

#### B. Object-specific ACE scope

An object ACE can contain the Full Control bits while also containing `ObjectType`.

That GUID does not have one universal meaning across all access bits.

The same GUID field means different things next to:

- CREATE_CHILD;
- READ_PROPERTY;
- SELF;
- CONTROL_ACCESS.

### Recommended fix

Only collapse to "Full control" when:

```text
ordinary/unscoped ACE
ObjectType absent
mask exactly equals known AD full-control mask
no unknown/generic/anomalous bits
```

Otherwise enumerate the rights and resolve each right's scope separately.

---

## 10. `ACCESS_SYSTEM_SECURITY` should not be presented as an ordinary DACL grant

### Code

`PermissionWording` treats `ACCESS_SYSTEM_SECURITY` like other permission bits.

### Why this is wrong

Microsoft defines `ACCESS_SYSTEM_SECURITY` as privilege-controlled SACL access.

It is not a normal DACL permission.

### Recommended fix

If captured in a DACL ACE:

```text
ACCESS_SYSTEM_SECURITY present in DACL:
invalid/anomalous right; do not interpret as ordinary DACL grant
```

Principal-level SACL access is a separate computation involving the relevant privilege.

---

## 11. `WRITE_OWNER` is overstated

### Code

The classifier treats `WRITE_OWNER` as effectively reaching the same result as Modify Permissions.

### Why this is too strong

`WRITE_OWNER` authorizes an owner-field update, but AD separately validates which SID can become owner.

Without the applicable privilege, a requester cannot arbitrarily transfer ownership to any third party.

Then there is a separate owner-rights layer:

- implicit owner rights;
- OWNER RIGHTS;
- `BlockOwnerImplicitRights`;
- object-class and OS/version-specific behavior.

### Recommended fix

ACE-level wording:

> Modify owner — authorizes an owner-field update subject to AD's owner-SID validation rules.

Then keep any later ownership-to-DACL path in a separate capability/escalation layer.

Do not equate `WRITE_OWNER` with `WRITE_DAC`.

---

## 12. Confidential attributes and Windows LAPS are classified at the wrong layer

### Problem

The classifier can identify READ_PROPERTY against "secret" attributes and treat that as dangerous capability.

### Microsoft behavior

A confidential attribute requires:

```text
READ_PROPERTY
+
CONTROL_ACCESS
```

reaching the attribute or applicable property set.

Those rights may come from different applicable ACEs.

Therefore:

```text
ACE 1 -> READ_PROPERTY msLAPS-Password
```

does not itself mean the principal can read the password.

Likewise, CONTROL_ACCESS alone does not establish the read.

### Recommended architecture

**ACE layer**

```text
READ_PROPERTY component reaches confidential attribute
CONTROL_ACCESS component reaches confidential attribute
```

**Accumulated capability**

```text
READ_PROPERTY + CONTROL_ACCESS
=> confidential-read authorization satisfied
```

**Principal effective access**

Apply:

- trustee/token membership;
- denies;
- ownership;
- conditional ACEs;
- privileges;
- context.

**Operation layer**

For applicable Windows Server 2025 behavior, apply the encrypted LDAP-session prerequisite separately.

That prerequisite is not another ACE permission.

---

## 13. `validAccesses` is guessed as Extended Right when unknown

### Code

`CapturedSchemaGuidReader.KindOfRight()`

Missing, invalid, or unexpected `validAccesses` values can default to ExtendedRight.

### Why this is wrong

Microsoft uses `validAccesses` to classify `controlAccessRight` objects.

Relevant values:

```text
256 -> extended/control access right
48  -> property set
8   -> validated write
```

If the value is missing, malformed, or something else, the result is **Unknown**, not Extended Right.

### Recommended fix

```csharp
256 => ExtendedRight
48  => PropertySet
8   => ValidatedWrite
_   => Unknown
```

Preserve the raw value.

Worst-case risk inference may be done later in the risk layer, but it must not replace the semantic fact with a guessed classification.

---

## 14. Property-set capture collapses "empty" and "unknown"

### Problem

Property-set membership records may only be created when at least one attribute references the set.

That can collapse:

```text
known property set with zero members
```

and:

```text
membership not captured / unknown
```

### Recommended fix

When a captured `controlAccessRight` has:

```text
validAccesses = 48
```

initialize:

```text
PropertySetGuid -> []
```

Then populate it from schema attributes whose `attributeSecurityGUID` matches that GUID.

Also track:

```text
SchemaCaptureComplete
```

separately.

---

## 15. Not enough schema data is captured to answer "all properties applicable to this object"

### Problem

The current capture includes attribute GUIDs and `objectClass`, but not enough class-schema state to derive the complete set of properties allowed for a target class.

For object-wide READ_PROPERTY / WRITE_PROPERTY semantics, SecureAD must know which attributes are structurally applicable to that class.

### Recommended fix

Capture enough class-schema information to derive:

- class attribute definitions;
- superclass inheritance;
- applicable auxiliary classes;
- dynamic auxiliary classes where relevant.

This also matters for inheritance.

MS-ADTS inheritance processing uses the most-specific structural class plus applicable dynamic auxiliary classes rather than every class in the target's `objectClass` chain.

---

## 16. `PermissionScope` overstates OI/CI inheritance

### Code

A simple "either OI or CI means reaches descendants" test is used.

### Why this is insufficient for AD

AD inheritance behavior depends on more than whether either inheritance bit is present.

The engine must consider:

- `OBJECT_INHERIT_ACE`;
- `CONTAINER_INHERIT_ACE`;
- `INHERIT_ONLY_ACE`;
- `NO_PROPAGATE_INHERIT_ACE`;
- `InheritedObjectType`;
- target class applicability.

### Recommended fix

Separate:

```text
Will this ACE propagate below this object?
```

from:

```text
Will the inherited copy be effective on this child?
```

Do not collapse inheritance into one friendly string too early.

---

## 17. The LDAP connection-security ladder can produce false conclusions

### Code

`ConnectionFailureReason.cs`

LDAP error 91 is treated as a protected-channel failure, and broad `DirectoryOperationException` cases can be labeled as protection refusal.

### Why this is wrong

LDAP error 91 means a connection error. It does not establish that TLS was attempted or refused.

Many unrelated transport or server conditions can produce connection failure.

Only explicit LDAP results such as:

```text
StrongAuthRequired
ConfidentialityRequired
```

support the conclusion that the server is requiring stronger authentication or confidentiality.

### Recommended fix

Use a narrower taxonomy:

```text
TransportUnreachable
ConnectFailed
Timeout
CredentialRejected
ServerExplicitlyRequiresStrongAuthentication
ServerExplicitlyRequiresConfidentiality
ServerReturnedOtherOperationError
LocalTlsValidationFailed
Unknown
```

Only make claims about the DC's security policy when the server explicitly supplies evidence supporting them.

---

## 18. GPO identity is using the wrong GUID

### Code

GPO logic appears to use the AD object's `objectGUID` as the Group Policy ID / SYSVOL folder identity.

### Microsoft behavior

The Group Policy protocol derives the GPO GUID from the GPO object's `cn` value.

The GPO's AD-side identity and the GUID represented in the SYSVOL/GPT path must match the Group Policy ID.

`objectGUID` is the AD directory object's object identity and is not the GPO GUID used to name the policy folder.

### Recommended fix

Capture both:

```text
DirectoryObjectGuid = objectGUID
GpoId = parse cn "{GUID}"
GpoFileSysPath = gPCFileSysPath
```

Validate:

```text
CN GPO GUID == GUID represented by gPCFileSysPath
```

If they do not match, report the discrepancy.

Do not join SYSVOL policy evidence to the AD object using `objectGUID`.

---

## 19. `gPLink` options are documented and should be parsed

### Problem

The implementation appears to treat GPO link options as undocumented.

Microsoft documents them.

Relevant semantics:

```text
0 = enabled, not enforced
1 = disabled/ignored
2 = enforced
3 = disabled/ignored; enforced bit irrelevant
```

### Recommended fix

Parse the option bit field:

```csharp
Disabled = (options & 1) != 0;
Enforced = !Disabled && (options & 2) != 0;
```

Preserve the raw numeric value.

Also capture `gpOptions` at site/domain/OU scope if computing Group Policy applicability, because Block Inheritance depends on it.

---

## 20. GPO link precedence is reversed

### Problem

The implementation appears to interpret the last link in a stored `gPLink` string as the highest-precedence link.

Microsoft Group Policy semantics treat link order 1 as the highest same-SOM link precedence.

### Recommended fix

If stored link order is read left to right:

```text
first stored link = LinkOrder 1 = highest same-SOM precedence
```

Do not reverse it with:

```text
Count - Order + 1
```

Also consider calling this field:

```text
LinkOrder
```

instead of `Precedence`, because total effective GPO precedence also depends on:

- site/domain/OU processing order;
- enforced links;
- block inheritance;
- security filtering;
- WMI filtering.

---

## 21. `DnHelper` is not a valid AD DN parser

### Code

The helper determines comma escaping by looking only at the immediately preceding backslash and only unescapes a small subset of DN forms.

### Why this is wrong

LDAP distinguished names can contain:

- escaped reserved characters;
- escaped backslashes;
- hexadecimal escape sequences;
- escaped leading/trailing spaces.

Whether a delimiter is escaped depends on the actual escape sequence, not merely whether the preceding character is `\`.

### Recommended fix

Implement a real DN tokenizer that understands:

```text
escaped reserved characters
escaped backslash
hex escape pairs
leading/trailing escaped spaces
RDN boundaries
attribute-type/value boundaries
```

Preserve the exact raw DN returned by the DC.

Where possible, use durable identity fields such as:

```text
objectGUID
objectSid
```

rather than DN-string equality for cross-source identity.

---

## 22. `SecurityTemplateParser` accepts encodings Microsoft says are nonconformant

### Code

The parser accepts:

```text
UTF-16LE
UTF-16BE
UTF-8 BOM
UTF-8 no BOM
```

### Microsoft protocol behavior

Group Policy Security policy files are defined as UTF-16LE with the required BOM.

### Recommended fix

Evidence-grade handling:

```text
UTF-16LE + BOM
    => conforming, parse normally

anything else
    => nonconformant / unsupported encoding
```

If best-effort decoding is retained for recovery/display, label it explicitly:

```text
BestEffortDecoded = true
ProtocolConformant = false
```

Do not silently treat nonconformant evidence as authoritative protocol data.

---

## 23. Current lockout/password-expired state should not come from raw `userAccountControl`

### Code

The wording layer uses raw UAC bits to state:

- currently locked out;
- password expired;
- cannot change password.

### Why this is wrong

Modern AD exposes current lockout and password-expired state through the constructed:

```text
ms-DS-User-Account-Control-Computed
```

Additionally, `PASSWD_CANT_CHANGE` is not a normal persistent UAC flag that should be used to determine the current effective "cannot change password" state. That behavior is enforced through permissions on the user object.

### Recommended fix

Raw UAC:

```text
show raw legacy bit if present
```

Current state:

```text
LockedOut -> computed/current state
PasswordExpired -> computed/current state
CannotChangePassword -> derive from DACL semantics
```

Do not let a raw flag masquerade as current effective state.

---

## 24. SID parser should reject invalid SID structures

### Problem

The parser can render arbitrary revision values and very large subauthority counts.

### Why this matters

Microsoft's SID structure has defined structural constraints.

Malformed bytes should not be converted into a plausible-looking SID and then treated as authoritative identity evidence.

### Recommended fix

Validate structural constraints before accepting the SID.

Malformed input should become:

```text
InvalidSid
UnparsedSid
```

rather than a normal-looking SID string.

---

# Architectural recommendation

## `DangerousPermissionClassifier` is currently doing too many jobs

The implementation mixes:

```text
what the ACE means
+
what capability results
+
whether the capability is dangerous
```

Those should be distinct layers.

Recommended pipeline:

```text
RAW EVIDENCE
     ↓
ACE SEMANTICS
     ↓
ACCUMULATED CAPABILITIES
     ↓
PRINCIPAL EFFECTIVE ACCESS
     ↓
RISK / DANGEROUSNESS RULES
```

The first two layers should not contain risk-language such as:

```text
dangerous
takeover
DCSync
secret
safe
```

unless the term is literally part of Microsoft's defined semantic meaning.

Unknown/custom schema semantics should become:

```text
NotAssessed
Unknown
Unresolved
```

not:

```text
Safe
NotDangerous
```

Worst-case inference belongs in the final risk layer and should be explicitly labeled as inference.

---

# What looked good

Several design decisions were directionally correct.

## Generic mapping constants

The AD generic-right mapping constants themselves are broadly correct.

The problem is not the constants; it is expanding them when reading an already-stored AD ACE.

## Forest-derived schema

The schema code correctly recognizes that property sets, extended rights, and custom schema semantics must be derived from the customer's forest rather than assumed entirely from a shipped GUID list.

That is the right architecture.

## Property-set membership direction

The implementation correctly moves toward deriving property-set membership from attributes via `attributeSecurityGUID`, rather than treating the `controlAccessRight` object as though it directly contained a member list.

## Security descriptor collection scope

Requesting the owner/group/DACL portion of `nTSecurityDescriptor` while deliberately excluding the SACL for this audit scope is a defensible capture strategy.

## Registry policy parsing

No Microsoft-semantics issue was found in `RegistryPolicyParser` comparable in severity to the GPO link / identity / security template issues above.

## Unknown UAC bits

Preserving unknown UAC bits rather than discarding them is a good evidence-preservation decision.

The problem is in current-state interpretation, not raw capture.

---

# Recommended repair order

## Phase 1 — Evidence fidelity

Fix:

- `SecurityDescriptorParser`
- `ParsedAce`
- stored ACE ordinal
- raw ACE bytes
- raw object flags
- GUID-presence state
- callback `ApplicationData`
- raw access mask
- DACL retrieval/parse state

Do this before changing the risk classifier.

## Phase 2 — ACE semantics

Fix:

- remove generic expansion from stored ACEs;
- eliminate raw evidence sorting/deduplication;
- preserve stored order;
- implement per-bit `ObjectType` interpretation;
- correct inheritance handling;
- correct schema `validAccesses` classification;
- fix `ACCESS_SYSTEM_SECURITY`;
- fix `WRITE_OWNER`.

## Phase 3 — Accumulated capability

Implement capability aggregation for rights that inherently require more than one ACE/state input, including:

- confidential attribute reads;
- ownership-derived paths;
- LIST_OBJECT visibility;
- property-set/property scope;
- any other Microsoft-defined compound requirement.

## Phase 4 — Principal effective access

Only where SecureAD actually chooses to compute it, include:

- enabled and deny-only token SIDs;
- nested membership;
- ownership;
- contextual trustees such as PRINCIPAL_SELF;
- conditional ACE inputs;
- privileges;
- related-object descriptors;
- operation-specific state.

## Phase 5 — Risk classification

Rebuild `DangerousPermissionClassifier` on top of validated semantic/capability objects.

Do not allow it to reinterpret raw ACE evidence directly.

## Phase 6 — Adjacent collectors

Then fix:

- LDAP connection ladder;
- GPO identity;
- `gPLink` options;
- GPO link order;
- DN parsing;
- security-template encoding;
- UAC current-state wording;
- SID validation.

---

# Bottom line

Copilot **did miss the mark in several important places**, particularly in the security descriptor / ACE pipeline.

The implementation is still salvageable.

The core problem is not that Microsoft semantics are completely absent. In several places the right Microsoft concepts are present, but the code normalizes evidence too early or merges separate semantic layers.

The highest-value correction is to enforce the following separation:

```text
1. What exactly did Active Directory return?
2. What does this individual ACE mean?
3. What capability results from multiple applicable ACEs/state?
4. What can a particular principal effectively do?
5. Is that result dangerous?
```

If SecureAD preserves those boundaries, most of the downstream classification problems become much easier to fix and much harder to reintroduce.
