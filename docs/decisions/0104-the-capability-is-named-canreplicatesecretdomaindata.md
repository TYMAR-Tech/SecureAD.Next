# 0104 - The capability is named CanReplicateSecretDomainData

Date: 2026-09-06
Status: Accepted.

Settles `Q8` of `SPEC-stage-6-control-edges.md`, where a criterion and a specification disagreed.

## Context

`AC-44` names the capability `CanReplicateAllDomainSecrets`; the stage 6 specification proposed
`CanReplicateSecretDomainData`. Microsoft's wording for `DS-Replication-Get-Changes-All` is **secret
domain data**, without the word *all*, and filtered attribute sets make *all* a stronger claim than
the citation supports.

A criterion and a specification disagreeing is a finding, not a preference.

## Decision

**The capability is `CanReplicateSecretDomainData`.**

- It mirrors Microsoft's description of the control access right rather than paraphrasing it.
- It avoids implying that every secret or filtered attribute is included, which the right does not
  guarantee.
- **`CanReplicateFilteredAttributes` remains a separate capability**, so the distinction is expressed
  in the model rather than in a name.
- **The target naming context is recorded separately** from the capability, because *what can be
  replicated* and *from where* are two facts.

**`AC-44` is migrated rather than aliased indefinitely.** The old name survives only as a schema
migration alias for reading historical results, never as a second current capability. New exports,
new stored edges and every screen use `CanReplicateSecretDomainData`.

## Consequences

- **A rename touches four places together or none**: the persisted enum, the capability catalogue,
  the export representation and the screen wording (`AC-S6-13`). A partial rename is the silent drift
  this record exists to avoid.
- **`AC-44`'s text is corrected in the acceptance manifest**, so the criteria and the specification
  stop disagreeing rather than being reconciled by whoever reads them next.
- **`CredentialExposure` is deliberately not renamed** at the same time. A draft of the specification
  renamed it to `CredentialControl`, which would have been exactly the drift objected to here.
