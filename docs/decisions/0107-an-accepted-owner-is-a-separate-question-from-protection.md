# 0107 - An accepted owner is a separate question from AdminSDHolder protection

Date: 2026-09-05
Status: Accepted.

Implements `P-140` under the constraint `0101` sets. Applies `0099` to `0095`.

## Context

`0095` makes ownership a control edge where the owner is not an administrator, and leaves
`ObjectOwnershipReading` to say who counts as one. `0099` then settled which principals are the
control plane and excluded five operator groups - Account Operators (548), Server Operators (549),
Print Operators (550), Backup Operators (551) and Replicator (552).

`ObjectOwnershipReading` counted all five as administrative. Left alone, an operator group owning an
object would produce **silence** on the ownership screen and a **visible unexpected edge** on the
control-edge screen, about the same principal - the product answering one question two ways on two
screens.

**Two things were found by opening the code that the punch-list row did not know.**

First, the identifier lists were not what decided this. `ObjectOwnershipReading.Decide` had a second
path: where the lists did not match, it consulted the protection closure and read
`ProtectedPrincipalEvaluation.Protected` as administrative. The five operator groups are protected
principals in their own right - `ProtectedGroupCatalogue` entries 14 to 18, on Microsoft's own
documentation - so removing them from the lists **would have changed nothing observable**, and every
test of the lists would have gone green. A test naming an ordinary account that is in no list at all
is what proved the second path live.

Second, the answer could not be filtered out of the protection answer afterwards.
`ProtectedPrincipalBasis` records a **single** root, so an account inside both Domain Admins and
Account Operators carries whichever the walk attributed it to. Filtering on that basis would have
reported a domain administrator as a non-administrative owner - a false statement to a customer,
which is worse than the defect being fixed.

## Decision

**Whether the product accepts a principal as an object's owner is its own question, derived once
with its own evidence, and never inferred from AdminSDHolder protection.**

`OwnerAcceptance` is computed in `ProtectedPrincipalClosure` by walking the **accepted** catalogue
roots alone, and is stored in its own column. The accepted set is `ProtectedGroupCatalogue.AcceptedOwnerRids`:
the built-in Administrator (500), Domain Admins (512), Enterprise Admins (519) and
`BUILTIN\Administrators` (544) - the entries `0099` gives an unrestricted authority scope.

**The five operator groups are not accepted owners.** Out does not mean safe: Backup Operators stays
Tier 0-sensitive and stays in `PrivilegedSidCatalogue`. It means its ownership stays visible rather
than being hidden as routine, and ownership is an edge because an owner implicitly holds Modify
Permissions.

**CREATOR OWNER and SYSTEM remain accepted, and are matched on the identifier rather than walked.**
An owner recorded as a placeholder or as the platform is a directory artefact rather than a person,
which is a different question from who holds a control edge - `0099` governs CREATOR OWNER and
`0100` governs SYSTEM. Nobody is a *member* of CREATOR OWNER, so there is nothing to walk.
`BUILTIN\Administrators` is matched on the identifier as well, because it is the default owner of
most objects in the directory and an answer that depended on the derivation holding a fact about it
would report the whole directory the moment it did not.

**An incomplete membership walk yields `Unknown`, never `NotAccepted`.** Finding a path is positive
evidence and a partial walk cannot invent one, so an owner already found inside an accepted root is
unaffected; an owner not found might simply not have been reached, and `0002` forbids reading that
silence as an answer.

## Scope

This builds **one** of the five questions `0101` requires of a principal registry. The other four
keep their existing homes, and nothing here is inferred from any of them. Building all five in this
pass would have touched every consumer of `PrivilegedSidCatalogue` and `ProtectedGroupCatalogue` at
the moment the ownership side had hours-old coverage and the control-edge side had none.

## Consequences

- The ownership rules `SEC-031` and `SEC-032` now report an object owned by one of the five operator
  groups, or by an account whose only route to protection runs through one.
- Volume can rise where the five groups or their members own reportable objects. The isolated
  comparison on ad.lab-20260905-212426, measured 2026-09-05, produced no change: `SEC-031` remained
  at 1,788 and `SEC-032` at zero, with four objects undecided by each rule under both policies.
  Of the unchanged findings, 1,778 concern Schema Admins on its own schema, making `P-147` an
  observed reporting defect, subsequently fixed by scoped acceptance under `0109`. The earlier
  counts are retained as the five-operator comparison, not as the current scoped result. Method,
  coverage and evidence identities are recorded in
  [WHAT-THE-PRODUCT-IS.md](../WHAT-THE-PRODUCT-IS.md). This does not predict other forests' volume.
  The former claim that this measurement must wait for `P-145` was wrong: that gate requires
  stage 6 control-edge output and is separate from this ownership comparison.
- `owner_acceptance` is `NOT NULL` with no default, so a writer that has not computed it cannot
  leave a silence that reads as `NotAccepted`.

## What this does not settle

**Schema Admins (518) remains outside the unrestricted set.** Its previously unanswered target
scope is now settled by [0109](0109-schema-admins-ownership-is-accepted-only-in-the-schema.md): the
forest-root group and its members are accepted only within that forest's schema partition. The
separate scoped answer fixes `P-147`; it does not widen this record's unrestricted list or infer
owner acceptance from protection.

**The outcome `OwnerIsAdministrative` is now named wrongly.** CREATOR OWNER is not an administrator;
it is a directory artefact. The consequence is identical so the name was not changed mid-row.
Carried as `P-148`.
