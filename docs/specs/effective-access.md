# Planned: effective access evaluation

**Status: not built. Specification captured from archived design work so it survives outside the
archive.**

This is the product's answer to *what can this principal actually do*, as opposed to *what does this
entry say*. It is wanted, it cannot account for every factor in a live environment, and it must
state its limits.

---

## Where it fits

The archived Microsoft source review sets out a strict ordering of questions, and the product
currently answers three of the five:

| | Question | State |
|---|---|---|
| 1 | What exactly did Active Directory return? | built ΓÇö `SecurityDescriptorParser` |
| 2 | What does this individual ACE mean? | built ΓÇö `PermissionWordingWriter`, `PermissionScopeWriter` |
| 3 | What capability results from multiple applicable ACEs and state? | **not built** |
| 4 | What can a particular principal effectively do? | **not built** |
| 5 | Is that result dangerous? | built ΓÇö `DangerousPermissionClassifier` |

> "If SecureAD preserves those boundaries, most of the downstream classification problems become much
> easier to fix and much harder to reintroduce."

Layers 3 and 4 are this feature. The review's repair order calls them Phase 3, *accumulated
capability*, and Phase 4, *principal effective access*.

**The constraint that must survive:** an entry-level reading must never be presented as a
principal-level conclusion. Effective access has to be a separate, clearly labelled claim ΓÇö not a
change to what an entry's verdict means.

---

## The requirements

Copied verbatim from the archived specification. **Do not paraphrase these** ΓÇö the qualifications
are the substance, and that document records that its own first draft failed by attaching a true
citation to a conclusion it did not support.

> **R8.** The AD authorization-rights requirement for a confidential attribute is `DS_READ_PROP`
> **and** `DS_CONTROL_ACCESS` both reaching that attribute, from any combination of applicable
> entries. Neither alone may be reported as satisfying authorization, and neither alone may be
> reported as harmless. Do not equate satisfaction of those rights with success of an actual LDAP
> operation when AD imposes additional transport or operation prerequisites.

> **R10.** The model must express a capability that depends on **rights accumulated across several
> applicable entries**, not merely on two bits of one mask. Any per-entry or per-right presentation
> is structurally incapable of stating R8 and must not imply otherwise.

> **R11.** Capture the owner SID, applicable OWNER RIGHTS ACEs, and the `BlockOwnerImplicitRights`
> context. For AD simple-access evaluation, account for the documented owner-SID grant of
> READ_CONTROL, WRITE_DAC, and WRITE_OWNER, then apply OWNER RIGHTS and owner-blocking behavior only
> to the rights for which Microsoft documents those qualifications. Include object class, relevant
> token membership, and domain-controller version/servicing behavior. Rights obtainable by
> subsequently modifying the DACL are escalation paths, not current effective access.

> **R12.** Capture `fDoListObject`. When disabled, LIST_OBJECT is not enforced. When enabled, model
> visibility as the documented parent/object capability: LIST_CONTENTS on the parent is sufficient;
> otherwise LIST_OBJECT is required on both child and parent. Never report an isolated child-level
> LIST_OBJECT ACE as granting visibility.

> **R16.** Determine current protected-set membership using the published protected principals, the
> applicable forest-wide `dSHeuristics` exclusion mask, and sufficient membership edges to compute
> direct and transitive membership through nested groups, including distribution groups. Do not
> substitute token-only expansion such as `tokenGroups`. Report differences from AdminSDHolder as
> subject to replacement without promising a fixed time.

> **R20.** Select and identify the AD authorization family for each evaluated right or operation,
> including the operation-specific class/property/GUID parameters and the security descriptor or
> related descriptors that algorithm selects. Stored ACE order is always evidence, but how that order
> is consumed depends on the selected AD algorithm. Do not apply the general Windows early-stop
> algorithm to all AD rights.

---

## What must be captured first

**This is a capture-design problem before it is an analysis problem.** A run that did not collect
these inputs can never answer the requirement afterwards, so every bundle taken before the change is
permanently unable to support the feature.

| Evidence | For | Scope |
|---|---|---|
| `fDoListObject`, plus parent and child capability | R12 | object and parent |
| Complete set of applicable entries and descriptors, scope metadata, trustee/security-context inputs | R10 | object, schema, principal context |
| Operation identity, requested right, applicable property/class/control-access GUID parameters, and every target/parent/NC-root/related descriptor the MS-ADTS algorithm selects | R19, R20 | operation and related objects |
| LDAP operation type and connection protection state when claiming successful access to confidential attributes, with applicable DC behaviour | R8 | operation/run context |
| Owner SID, applicable OWNER RIGHTS entries, `BlockOwnerImplicitRights` context, object class, token membership, DC version | R11 | object and forest |
| Published protected principals, `dSHeuristics` exclusion mask, membership edges for transitive expansion | R16 | forest |

For principal-level effective access specifically, the specification additionally requires the
ultimate user SID, enabled and deny-only SIDs, nested group membership, restricted SIDs where in
scope, relevant privileges, OWNER RIGHTS and object-owner context, `PRINCIPAL_SELF` substitution
context, the requested right or operation, every related descriptor selected by that operation's
authorization algorithm, and any claims or attributes required by supported conditional entries.

**The rule that governs the whole feature:**

> A collector that lacks any required input must report the corresponding answer as conditional,
> partial, unsupported, or unknown rather than silently substituting a constant.

---

## An operation prerequisite that is not a permission

On Windows Server 2025 domain controllers, LDAP search, modify and add operations involving
confidential attributes require an encrypted session, governed by
`DisableConfidentialAttributeEncryptionRequirements` at character 31 of forest-wide `dSHeuristics`.

This is **separate** from the `READ_PROP` + `CONTROL_ACCESS` authorization requirement. A statement
that the rights are present is not a statement that a particular LDAP operation succeeds, so this
belongs to an operation layer rather than to layers 3 or 4.

---

## Open questions

Two the archived specification left, and one it raised as a constraint:

- **Where is R10 answered?** The requirement says the product must be *able* to express a capability
  accumulated across entries. It does not say whether that belongs to a principal-level computation,
  a rules layer, or both ΓÇö only that a permission row cannot be it. **This decides which layer owns
  the work and should be settled first.**
- **How wide does the principal-level computation go?** R19 names the inputs but does not place the
  computation or bound its cost.
- *Whether the product ever computes effective access* was listed as undecided. **It is now decided:
  yes.**

---

## What this would fix immediately

One live defect is waiting on layer 3: a confidential-attribute read is currently reported as a
takeover on `READ_PROPERTY` alone, without consulting `CONTROL_ACCESS`. See the punch list.
