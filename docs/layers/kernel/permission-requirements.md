# What a permission grants: the requirements

The twenty requirements the permission model is measured against, and what in the product answers
each. Every row names a type that exists, or says plainly that it is **not built**.

**A named type is not a claim that the requirement is met well.** The check that guards this table
confirms the name is real; it cannot confirm the behaviour. Where the two are known to differ, the
row says so and points at [the punch list](../../PUNCH-LIST.md).

Requirements are numbered as the original specification numbered them, so references to `R13` or
`R19` elsewhere in the code and documentation still resolve.

---

## The requirements

| # | Requirement | Source | Built |
|---|---|---|---|
| R1 | Fully analyze supported ordinary ACE types; preserve and classify every unsupported ACE raw | §2 | `SecurityDescriptorParser` |
| R2 | Preserve raw mask and context; map generic rights only where that context requires it | §3 | `GenericRightsExpander` |
| R3 | Resolve GUID meaning per mask bit, not once per entry | §4 | `SchemaGuidKind` |
| R4 | Use `validAccesses` for controlAccessRight classification and `attributeSecurityGUID` for actual property-set membership | §4 | `CapturedSchemaGuidReader` |
| R5 | Preserve stored ordinal; separately evaluate canonicality, DC standardization expectation, and inheritance-provenance limits | §5.2 | `AceCanonicalization` — partial, see P-13 |
| R6 | Capture retrieval context before asserting DACL structure; flag complete current NULL DACL evidence as anomalous | §5.3 | `SecurityDescriptorParser` — detects, does not flag |
| R7 | Model property scopes over attributes applicable to the target object; capture or derive the target's allowed attribute set | §5.4 | not built |
| R8 | Confidential-attribute authorization requires READ_PROP and CONTROL_ACCESS from any applicable entries; operation prerequisites remain separate | §6.1 | `DangerousPermissionClassifier` — partial, see P-14 |
| R9 | Test `searchFlags` and `systemFlags` bits; capture complete schema values | §6.1 | `CapturedAttributeCatalog` |
| R10 | Support capabilities accumulated across multiple applicable entries | §6.1 | not built |
| R11 | Model AD's owner-SID grant of READ_CONTROL, WRITE_DAC, and WRITE_OWNER, applying OWNER RIGHTS and owner-blocking qualifications only where documented | §6.2 | `ObjectPermissions` — partial |
| R12 | Model LIST_OBJECT using List Object mode and the documented parent/child visibility combination | §6.3 | not built |
| R13 | INHERIT_ONLY suppresses a local grant claim | §7 | `EntryReach` |
| R14 | Apply `InheritedObjectType` using the most-specific structural and dynamic-auxiliary class rule | §7 | not built |
| R15 | Model new-object DACL construction as documented conditional paths | §8.1 | not built |
| R16 | Compute current protection using transitive directory membership, including distribution groups, plus exclusions | §8.2 | not built |
| R17 | Treat `adminCount` as history; derive current inheritance protection from `SE_DACL_PROTECTED` | §8.2 | `AceNormalizationResult` |
| R18 | Classify literal, contextual, token-dependent, and placeholder trustee SID semantics | §7, §9 | `WellKnownSidCatalog` |
| R19 | Never present an entry-level interpretation as principal-level effective access; operation-level claims require every descriptor selected by the AD algorithm | §9 | `EntryReach` |
| R20 | Select the AD-specific access-check family and its operation-specific parameters/descriptors for the requested right or operation | §5.1 | not built |

---

## Findings against this table

Two defects were found by working through these requirements against a real forest. Both are closed,
and both are recorded here because each was a case of the product stating something false to an
operator — the one category that is never deferred.

**`F-1` — the Modify Owner wording asserted something that is not always true.**
It said an object's owner *has* the implicit right to modify its permissions. That is false for any
object carrying an `OWNER RIGHTS` (`S-1-3-4`) entry: where one applies, the system ignores the
owner's implicit `READ_CONTROL` and `WRITE_DAC`. **An administrator who had applied exactly that
hardening was told, in the product's own words, that it did not hold.** The wording now states the
ordinary case and says plainly that one entry cannot settle it. Confirmed in lab 2026-08-20.

**`F-2` — placeholders were reported as principals.**
`CREATOR OWNER` and `PRINCIPAL SELF` (`S-1-5-10`) were shown as named principals with a domain,
because Active Directory keeps real objects for them under `CN=WellKnown Security Principals`, so
the search for a matching `objectSid` succeeded. **1,708 entries in one lab bundle were credited to
something that holds nothing.** `WellKnownSidRole` now separates a principal from a placeholder.
Confirmed in lab 2026-08-20.

Both are the same shape: a lookup that succeeded and returned an answer nobody checked was the right
*kind* of answer.

---

## What the unbuilt rows have in common

Six of the seven — R7, R10, R12, R14, R16 and R20 — are the same missing capability seen from
different angles: the product judges **one entry at a time** and has no layer that accumulates a
capability across several. That work is specified in
[planned effective access](../../planned/effective-access.md).

R15 is the exception. It asks the product to model how a *new* object's DACL would be constructed,
which is a prediction rather than a reading of stored evidence, and it may simply be out of scope.

---

## Rows that were optimistic

This table previously named a type for R7, R10, R12 and R14. Those types exist, so the check passed
— but none of them satisfies its requirement:

- **R7** named `PermissionScope`, which words an entry's declared reach. It does not know which
  attributes apply to the target's class, and `allowedAttributes` is not captured at all.
- **R10** named `ObjectPermissions`, which reads one object's entries. Accumulating a capability
  across entries is what it does not do.
- **R12** named `GenericRightsExpander`, which is unrelated to List Object mode.
- **R14** named `AceNormalizer`, which sorts and hashes entries and does not resolve class hierarchy.

**This is what a check anchored to the wrong thing looks like.** Each row named something real, the
gate went green, and four requirements were recorded as met. The gate's own documentation is honest
that it cannot check behaviour — the rows were simply filled in optimistically, and nothing else ever
asked.
