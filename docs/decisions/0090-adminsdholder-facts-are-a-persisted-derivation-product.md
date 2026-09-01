# 0090 - AdminSDHolder facts are a persisted Derivation product

Date: 2026-08-30
Status: Accepted.

Sits under [0089](0089-principal-protection-and-member-propagation-are-separate-claims.md), and adopts
its independent principal-protection and member-propagation claims without changing any catalogue
classification.

## Context

Decision `0089` requires protected-principal evaluations to be derived once, persisted beside Evidence,
and exposed through a narrow read model. It deliberately did not choose the implementation seam.
The draft implementation specification proposed moving executable rule contracts into Judgement and
adding a Judgement-to-Derivation dependency. Wave 2a subsequently made that the current architecture:
Judgement owns executable rules and already references Derivation, while immutable finding data remains
in Evidence.

Wave 3 added exact Evidence and generation binding plus atomic replacement for disposable products.
Wave 4 added the shared completeness and uncertainty vocabulary. Implementing the older draft literally
would repeat both changes and would combine the Derivation product with rule inputs, judgement
uncertainty storage, Shell presentation and SEC-030 that the accepted workflow assigns to Wave 6.

## Decision

**The Decision 0089 protected-principal result is a versioned, persisted Derivation product.**

The product:

- stores catalogue claims, effective member-propagation roots, forest-mask outcome, per-principal
  evaluation, decisive basis, unknown reasons and one deterministic membership path where membership
  establishes protection;
- uses the existing Derivation store's Evidence seal, generation identifier, atomic replacement and
  completion state rather than introducing parallel lifecycle metadata;
- uses the existing derivation completeness result as the initial conservative boundary: when
  membership evidence is incomplete, every principal not independently proven `Protected` is
  `Unknown`, never `NotProtected`;
- exposes a narrow reader-owned result and scoped SID lookup, not the graph or mutable store internals;
- keeps Derivation independent of rules and keeps derived facts out of Evidence; and
- increments the disposable Derivation schema and refuses older stores rather than migrating them.

A directly established principal claim or complete path to an active established root remains
`Protected` despite unrelated uncertainty. One established route wins over disputed or unverified
routes. Path choice is deterministic and cannot depend on collection iteration order.

**Wave 5 ends when this product is implemented, persisted and readable.** Rule input packages,
object-level judgement uncertainty, Shell presentation and SEC-030 belong to Wave 6. They may consume
the public read model but may not recompute the closure.

## Consequences

`ProtectedGroupCatalogue` no longer exposes one flat protected set. Each entry carries independent
principal and propagation claims, provenance and SID scope. `dwAdminSDExMask` changes effective member
propagation for the four operator groups and never rewrites principal protection.

`ProtectedPrincipalClosure` becomes a tri-state product with typed reasons and deterministic basis.
Incomplete membership evidence produces more `Unknown` answers in the first implementation than a
future localized model might, but cannot produce a false clean negative.

The Derivation schema, writer, reader and production run must change together. A run cannot name a
completed Derivation product when the protected-principal phase claims success or degradation but its
product was not written.

Real-forest verification remains an acceptance gate. It corroborates the implementation but does not
promote a `Disputed` or `Unverified` catalogue claim to an established product position.
