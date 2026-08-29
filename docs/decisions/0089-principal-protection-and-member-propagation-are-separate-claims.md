# 0089 - Principal protection and member propagation are separate claims

Date: 2026-08-28
Status: Accepted.

Sits under [0086](0086-a-qualified-statement-beats-silence.md), beside
[0087](0087-a-sid-is-unique-within-its-scope.md), and corrects the AdminSDHolder interpretation in
[0006](0006-tier-0-and-expected-admin-are-separate-sets.md) without reopening its central decision
that Tier 0 and expected-admin are different sets.

## Context

Stage 2a shipped a `ProtectedGroupCatalogue` holding the fifteen accounts and groups in Microsoft's
Appendix C. It asked one question of each SID — *is this protected?* — and used every `true` answer as
a seed for a downward membership walk.

That flattened two different claims:

1. **Principal protection:** the account or group object itself receives AdminSDHolder/SDProp
   protection.
2. **Member propagation:** membership beneath a group causes another object to receive that
   protection.

Most familiar administrative groups may satisfy both, which hid the distinction. The less familiar
entries expose it. Microsoft currently publishes affirmative principal-protection claims for Domain
Controllers, Read-only Domain Controllers, Key Admins and Enterprise Key Admins, while the algorithm
fragment needed to establish member propagation from those groups has not been pinned in this
repository. Enterprise Read-only Domain Controllers is omitted from Appendix C while its group-
specific Microsoft page says it is protected. One flat boolean cannot represent any of that.

The flattening reached `dwAdminSDExMask` too. The product captured character 16, parsed its four bits,
and made `IsProtected` false for the selected operator group objects. Because the same method also
selected traversal seeds, one operation changed principal protection and member propagation together.
The Microsoft evidence pinned so far establishes the four group assignments and supports changing
member propagation; it does not yet establish that the group object itself loses protection.

Independent review of SEC-030 found the defect before the first derived-fact rule consumed it. The
review is recorded in `docs/reviews/adminsdholder-catalogue-review.md`.

## Decision

**Principal protection and member propagation are separate, independently evidenced claims.**

Every shared AdminSDHolder catalogue entry carries, for each semantic:

- a status: `Established`, `EstablishedNo`, `Disputed`, `Unverified`, or `DoesNotApply`;
- provenance naming why that status is held; and
- scope sufficient to resolve its SID without merging domains.

**`Unverified` is not `EstablishedNo`.** Missing evidence cannot become a negative claim.
**`Disputed` is not `Unverified`.** Conflicting affirmative first-party sources are different from no
sufficient source.

**Only active roots whose member propagation is `Established` produce established protected members.**
A route reaching a `Disputed` or `Unverified` possible root produces `Unknown` unless another
established route independently proves protection.

**One established route wins over uncertainty elsewhere.** Once protection is proven, another
unverified route cannot make it less true.

**`NotProtected` requires complete negative evidence.** Missing domains, unresolved trustees,
unresolved foreign security principals, unknown builtin SID scope, stopped expansion, disputed
catalogue claims, or possible primary-group-only routes prevent a clean negative wherever they could
change the answer.

**Distribution-group nesting is established with Microsoft product-documentation provenance.**
Microsoft's *Reducing the Active Directory Attack Surface* states:

> Any account that has direct or transitive membership in any protected group (regardless of whether
> the membership is derived from security or distribution groups) inherits this restricted security.

It gives the nested distribution-group example explicitly. This supersedes only the distribution-
traversal blocking clauses in `0086`, `AC-26`, and the stale summary table in
`JUDGEMENT-HALF.md`. Primary-group-only traversal remains unverified and gated.

**`dwAdminSDExMask` changes effective member propagation for Account, Server, Print and Backup
Operators.** It does not change principal-protection status unless a pinned normative source or an
explicit later decision establishes that effect. The raw mask, parse outcome and disabled roots stay
available as evidence.

**A malformed present mask character is not absence and is not complete.** MS-ADTS defines the valid
character-16 values as hexadecimal digits and defines absent characters as defaulting to zero. It
does not define an invalid present character as absent. The product preserves the raw character,
marks the mask unsupported/incomplete, and returns `Unknown` for dependent conclusions.

**The shared derived result is tri-state:** `Protected`, `NotProtected`, or `Unknown`, with decisive
basis, per-principal reasons and completeness. Typed uncertainty is customer-visible under `0086`; an
aggregate missing-attribute count is not a substitute.

**The following classifications are accepted now:**

| Entry | Principal protection | Member propagation |
|---|---|---|
| Enterprise Read-only Domain Controllers, RID 498 | `Disputed` | `Unverified` |
| Domain Controllers, RID 516 | `Established` | `Unverified` |
| Read-only Domain Controllers, RID 521 | `Established` | `Unverified` |
| Key Admins, RID 526 | `Established` | `Unverified` |
| Enterprise Key Admins, RID 527 | `Established` | `Unverified` |
| Group Policy Creator Owners, RID 520 | `EstablishedNo` | `EstablishedNo` |
| Administrator, RID 500 | `Established` | `DoesNotApply` |
| Krbtgt, RID 502 | `Established` | `DoesNotApply` |

These are product positions about the current evidence state, not fabricated answers to unresolved
Microsoft behavior. An `Unverified` classification remains unresolved by design.

## Corrections to earlier records

**0006 remains accepted for its central separation of Tier 0 and expected-admin sets.** Its sentence
that Microsoft protects RID 498 unconditionally is superseded. RID 498 protection is disputed until
the Appendix C omission and the group-specific affirmative statement are reconciled.

**0086 remains accepted for qualified uncertainty.** Its statements that AC-26 blocks distribution
traversal are superseded by the exact Microsoft passage above. Its primary-group statements remain
unchanged.

**JUDGEMENT-HALF and its acceptance file must be aligned.** Distribution traversal is documented and
enabled; primary-group-only traversal remains unverified. Summaries and acceptance status may not
continue to state both positions.

## Consequences

`ProtectedGroupCatalogue` and `ProtectedPrincipalDeriver` must be redesigned before SEC-030 or any
other rule consumes their results. The current flat seed set is not a compatible implementation of
this decision.

The derivation store must persist protected-principal evaluations, basis, unknown reasons, catalogue
semantic version, effective roots and mask outcome. `DerivationReader` must expose a narrow read model
to rules; recomputing the closure inside judgement would create a second implementation.

The rule contract must carry typed unavailable/uncertain derived input, not only missing LDAP
attribute names. This changes architecture because `IRule` currently lives below Derivation in the
project dependency graph. A separate implementation decision may choose the seam, but it may not
invert the dependency or smuggle derived facts into captured evidence.

Current tests that pin the flat fifteen-entry set and mask-removes-group-object behavior are not
proof of this model. They must be split by semantic with negative controls.

The `tymar.lab` run remains evidence that capture, parsing and current product execution worked. It
is not evidence that the old flat catalogue matched server behavior, and documentation must say so.

SEC-030 remains a candidate until this shared model is implemented, persisted and readable.
