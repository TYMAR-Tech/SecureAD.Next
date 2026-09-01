# Implementing the shared AdminSDHolder catalogue

**Status:** accepted implementation specification under decision 0090
[`../../decisions/0090-adminsdholder-facts-are-a-persisted-derivation-product.md`]; built 2026-08-30.
**Governing semantics:**
[Shared AdminSDHolder catalogue semantics](adminsdholder-catalogue-semantics.md), accepted by
[`0089`](../../decisions/0089-principal-protection-and-member-propagation-are-separate-claims.md).
**First consumer:**
[SEC-030 reviewed candidate](../judgement/rules/SEC-030-admincount-without-protection.reviewed.md).

---

## Accepted boundary

Decision 0090 settles:
persisted Derivation product, conservative global Unknown for every unproven principal when membership evidence is incomplete,
one deterministic stored membership path, and Wave 5 ending at persistence/read-back.
Rule inputs, judgement uncertainty, Shell presentation, and SEC-030 are Wave 6.

---

## 1. Goals

The implementation must:

- represent principal protection and member propagation independently;
- preserve `Established`, `EstablishedNo`, `Disputed`, `Unverified` and `DoesNotApply` without
  flattening them;
- apply `dwAdminSDExMask` to effective member propagation only;
- produce per-principal `Protected`, `NotProtected` or `Unknown` evaluations;
- make every `Unknown` explainable;
- persist the result beside the evidence;
- expose a narrow rule-facing read model;
- keep Derivation independent of rules; and
- preserve the existing Evidence binding, atomic replacement and completeness contracts.

## 2. Non-goals

This work does not:

- implement SEC-030;
- resolve currently `Disputed` or `Unverified` Microsoft behavior;
- implement general graph queries for arbitrary rules;
- expose `NestingGraph` publicly;
- move derived facts into sealed evidence;
- infer historical protected membership from `adminCount`;
- compare an object's ACL byte-for-byte with AdminSDHolder;
- implement a customer-editable catalogue; or
- implement Wave 6 rule inputs, judgement uncertainty storage, Shell presentation or SEC-030.

## 3. Project and dependency boundary

### 3.1 Current architecture

Wave 2a already established the dependency seam the draft proposed:

```text
Judgement -> Derivation -> Evidence -> Kernel
Judgement -------------> Evidence -> Kernel
```

Executable rule contracts and implementations live in Judgement. Immutable finding data contracts remain in Evidence. Derivation never references Judgement or a rule, and Evidence never references Derivation.

### 3.2 Why not add an interface to Evidence

Do not place an `IProtectedPrincipalFacts` abstraction in Evidence merely to invert the dependency. Protected-principal semantics are derived facts, not captured-evidence vocabulary. Doing so would make Evidence own a question it deliberately does not answer and would let future derived concepts leak through lower-layer interfaces one by one. Decision `0090` accepts the current project boundary.

## 4. Catalogue types

The implementation uses immutable internal types in `SecureAD.Derivation`.

```csharp
internal enum CatalogueClaimStatus
{
    Established,
    EstablishedNo,
    Disputed,
    Unverified,
    DoesNotApply,
}

internal enum CatalogueClaimProvenance
{
    ProtocolSpecification,
    MicrosoftProductDocumentation,
    MicrosoftSupport,
    ControlledLabObservation,
}

internal enum CataloguePrincipalScope
{
    PerDomainRid,
    ForestRootRid,
    BuiltinPerDomain,
}

internal sealed record CatalogueClaim(
    CatalogueClaimStatus Status,
    CatalogueClaimProvenance Provenance,
    string SourceId);

internal sealed record AdminSdHolderCatalogueEntry(
    string Name,
    CataloguePrincipalScope Scope,
    int Rid,
    CatalogueClaim PrincipalProtection,
    CatalogueClaim MemberPropagation,
    bool CanBeDisabledByAdminSdExMask);
```

`SourceId` is a stable short identifier resolved by documentation/tests, not a long URL copied into
every stored row. Examples: `MS-APPENDIX-C-2026-08`, `MS-AD-SECURITY-GROUPS-2026-08`,
`MS-ATTACK-SURFACE-2026-08`.

### 4.1 Catalogue version

The compiled catalogue has a semantic version independent of the SQLite schema version:

```text
AdminSdHolderCatalogueVersion = 2
```

Version 1 denotes the old flat fifteen-entry model. Version 2 denotes decision `0089` semantics.
Version 1 is never read as version 2.

### 4.2 Entry invariants

- `DoesNotApply` is valid for member propagation only when the entry cannot be a group.
- `CanBeDisabledByAdminSdExMask` is true only for RIDs 548–551.
- A mask never changes `PrincipalProtection`.
- Every `Established` or `EstablishedNo` claim names at least one source.
- Every `Disputed` claim names both sides of the conflict in documentation and anchor tests.
- `Unverified` may name the strongest source read, but does not imply that source said No.
- SID scope is explicit; no entry is matched by suffix alone without validating SID kind and scope.

## 5. Mask parsing and effective propagation

### 5.1 Parse outcomes

Extend the mask outcome vocabulary:

```csharp
public enum HeuristicReadOutcome
{
    Stated,
    DefaultedByAbsence,
    NotRead,
    Malformed,
}
```

Rules:

| Input | Outcome | Complete |
|---|---|---|
| valid hex character | `Stated` | yes |
| object read, character absent | `DefaultedByAbsence` | yes |
| object/attribute not captured | `NotRead` | no |
| present non-hex character | `Malformed` | no |

The raw character is always preserved when present.

### 5.2 Effective member propagation

For each catalogue entry:

```text
if MemberPropagation != Established
    EffectiveMemberPropagation = MemberPropagation
else if entry is selected by a complete valid mask
    EffectiveMemberPropagation = EstablishedNo
    Basis = ForestMask
else if mask is NotRead or Malformed and entry is mask-excludable
    EffectiveMemberPropagation = Unverified
    Basis = MissingOrUnsupportedForestMask
else
    EffectiveMemberPropagation = Established
```

`PrincipalProtection` is unchanged by this calculation.

### 5.3 Compatibility

A bundle captured before catalogue version 5 has no `dSHeuristics` column. Its excludable roots are
`Unverified`, not enabled by default and not disabled by assumption.

## 6. Protected-principal derivation

### 6.1 Inputs

The phase receives:

- direct nesting graph;
- principal/SID dictionary with scope;
- primary-group references held separately from ordinary edges;
- catalogue version 2 entries;
- forest-mask result;
- capture coverage;
- unresolved trustees/FSPs;
- expansion-budget outcome; and
- cancellation.

### 6.2 Direct principal evaluation

For each principal matching a catalogue entry:

| Principal claim | Evaluation contribution |
|---|---|
| `Established` | principal is `Protected` immediately |
| `EstablishedNo` | no direct protection; continue to routes |
| `Disputed` | possible direct protection; result is at least `Unknown` |
| `Unverified` | possible direct protection; result is at least `Unknown` |
| `DoesNotApply` | invalid catalogue state; fail the phase |

An established direct match wins over route uncertainty.

### 6.3 Membership roots

Build three root sets, not one:

1. `EstablishedRoots`
2. `PossibleRoots` (`Disputed` or `Unverified`)
3. `NonRoots` (`EstablishedNo` or `DoesNotApply`)

Apply the forest mask before building these sets.

### 6.4 Traversal

- Follow ordinary `member`/`memberOf` edges through security and distribution groups.
- Do not follow primary-group edges as established routes.
- Compute candidate primary-group reachability separately, so a principal whose answer depends on it
  becomes `Unknown`.
- A path to an established root yields `Protected`.
- A path only to a possible root yields `Unknown`.
- No path yields `NotProtected` only under the completeness rule below.

### 6.5 One established route wins

Evaluation precedence:

```text
Protected > Unknown > NotProtected
```

This is not a risk score. It expresses proof strength:

- one established route proves protection;
- uncertainty matters only when nothing proves protection;
- `NotProtected` requires complete negative evidence.

## 7. Completeness policy

### 7.1 Initial safe implementation

The current graph cannot localize every unresolved trustee or missing domain to the principals it may
affect. The initial implementation therefore uses a conservative global rule:

> If membership evidence is globally incomplete, every principal not already proven `Protected`
> evaluates `Unknown` rather than `NotProtected`.

Global incompleteness includes:

- missing declared domain/partition relevant to group membership;
- unresolved trustee;
- unresolved foreign security principal;
- unscoped builtin SID;
- membership expansion not run or budget-limited;
- failed membership/nesting phase; or
- unsupported/unread forest mask where an excludable possible root could matter.

This may produce more `Unknown` results than a future localized model. It cannot produce a false clean
negative.

### 7.2 Future localization

A later version may attach uncertainty regions to specific principals when it can prove scope. That
optimization requires its own tests and catalogue semantic version. It may reduce `Unknown`; it may
never retroactively interpret old global-Unknown stores as complete negatives.

### 7.3 Direct established protection under incomplete evidence

Global incompleteness does not erase established positive proof. A directly protected principal or a
principal with a complete established path remains `Protected`.

## 8. Derived result model

```csharp
public enum ProtectedPrincipalEvaluation
{
    Protected,
    NotProtected,
    Unknown,
}

public enum ProtectedPrincipalBasisKind
{
    DirectPrincipalClaim,
    MembershipRoot,
}

[Flags]
public enum ProtectedPrincipalUnknownReason
{
    None = 0,
    PrincipalClaimDisputed = 1,
    PrincipalClaimUnverified = 2,
    PossibleRootReached = 4,
    PrimaryGroupTraversalUnverified = 8,
    MembershipEvidenceIncomplete = 16,
    ForestMaskNotRead = 32,
    ForestMaskUnsupported = 64,
    CatalogueEntryDisputed = 128,
}
```

A stored principal result contains:

- principal SID id;
- evaluation;
- direct or root basis where protected;
- decisive catalogue entry id;
- unknown-reason flags;
- optional deterministic membership-path reference;
- catalogue version; and
- derivation generation id through the store header.

## 9. Derivation schema version 4

Increment `DerivationSchema.Version` from 3 to 4.

### 9.1 New tables

```sql
CREATE TABLE adminsd_catalogue_entry (
    catalogue_entry_id          INTEGER NOT NULL,
    name                        TEXT    NOT NULL,
    scope                       TEXT    NOT NULL,
    rid                         INTEGER NOT NULL,
    principal_status            TEXT    NOT NULL,
    principal_provenance        TEXT    NOT NULL,
    principal_source_id         TEXT    NOT NULL,
    propagation_status          TEXT    NOT NULL,
    propagation_provenance      TEXT    NOT NULL,
    propagation_source_id       TEXT    NOT NULL,
    mask_excludable             INTEGER NOT NULL,
    PRIMARY KEY (catalogue_entry_id)
);

CREATE TABLE adminsd_derivation (
    catalogue_version           INTEGER NOT NULL,
    mask_outcome                TEXT    NOT NULL,
    mask_character              TEXT        NULL,
    only_one_row                INTEGER NOT NULL DEFAULT 1 CHECK (only_one_row = 1),
    PRIMARY KEY (only_one_row)
);

CREATE TABLE protected_principal (
    sid_id                      INTEGER NOT NULL REFERENCES sid(sid_id),
    evaluation                  TEXT    NOT NULL,
    basis_kind                  TEXT        NULL,
    basis_catalogue_entry_id    INTEGER     NULL REFERENCES adminsd_catalogue_entry(catalogue_entry_id),
    unknown_reasons             INTEGER NOT NULL,
    PRIMARY KEY (sid_id)
);

CREATE TABLE protected_principal_path (
    sid_id                      INTEGER NOT NULL REFERENCES protected_principal(sid_id),
    ordinal                     INTEGER NOT NULL,
    path_sid_id                 INTEGER NOT NULL REFERENCES sid(sid_id),
    PRIMARY KEY (sid_id, ordinal)
);
```

### 9.2 Constraints

- `Protected` requires non-null `basis_kind` and `basis_catalogue_entry_id`.
- `NotProtected` requires null basis and zero unknown reasons.
- `Unknown` requires nonzero unknown reasons and null established basis.
- Direct-principal basis path is empty.
- Membership-root basis path starts at the protected principal and ends at the decisive root.
- Every path SID exists in the same dictionary/store.
- Exactly one `adminsd_derivation` row exists.

Enforce invariants in writer validation and tests; use SQL `CHECK` constraints where expressible without
duplicating enum logic unsafely.

### 9.3 Existing stores

Schema 3 stores are refused by a schema 4 reader. They are not migrated in place. Evidence remains
untouched and can be re-derived with the newer build.

## 10. Writer and reader API

### 10.1 Writer

Add one internal operation:

```csharp
void WriteProtectedPrincipals(StoredProtectedPrincipalDerivation result)
```

It writes catalogue entries, mask result, principal evaluations and paths in one transaction after
the SID dictionary exists.

A second write is refused. Completion is refused if the `ProtectedPrincipals` phase succeeded or
degraded but no protected-principal result was written.

### 10.2 Reader

Expose a narrow public read model:

```csharp
public sealed record StoredProtectedPrincipalFact(
    int SidId,
    ProtectedPrincipalEvaluation Evaluation,
    ProtectedPrincipalBasis? Basis,
    ProtectedPrincipalUnknownReason UnknownReasons);

public sealed record StoredProtectedPrincipalDerivation(
    int CatalogueVersion,
    AdminSdExclusionMask Mask,
    IReadOnlyList<StoredProtectedPrincipalFact> Principals,
    bool IsComplete);
```

`DerivationReader.Read()` includes this result or explicitly states that the phase did not run. It does
not expose `NestingGraph`, mutable collections, or a general graph query API.

### 10.3 Rule-oriented lookup

`StoredProtectedPrincipalDerivation` provides:

```csharp
StoredProtectedPrincipalFact? FindBySid(int sidId)
```

SEC-030 additionally needs to map an evidence object's scoped SID to a derivation SID id. Provide a
reader-owned lookup accepting canonical SID text and domain scope; do not expose dictionary internals.

## 11. Wave 6 boundary

The read model is deliberately sufficient for a later rule to obtain a scoped principal fact and its explanation without opening or recomputing the graph. Wave 6 owns:

- declared derived-input packages;
- typed rule-input issues and judgement uncertainty storage;
- operator presentation of those issues; and
- SEC-030 evaluation.

Those concerns do not alter this store's catalogue, evaluation, basis, path or completeness model.

## 12. Delivery phases

### Phase A — mask correctness (already built)

- `Malformed` is distinct from absence and is incomplete;
- the raw character is preserved; and
- anchor and unit tests hold the behavior.

### Phase B — catalogue model

- add per-semantic entry/status/provenance/scope;
- replace flat lists and `IsProtected`;
- implement effective propagation roots;
- tests with negative controls.

### Phase C — derivation algorithm

- separate direct principal claims, established roots and possible roots;
- implement conservative global completeness;
- preserve deterministic basis/path.

### Phase D — persistence/read-back

- schema 4;
- writer transaction;
- reader model and scoped SID lookup;
- round-trip and mismatch tests.

Each phase is separately buildable and testable. No phase may leave the old flat behavior presented as canonical.

## 13. Acceptance criteria

### Catalogue and mask

- malformed mask is incomplete and raw character preserved;
- mask changes effective propagation only;
- every entry has independent semantic claims;
- 498/516/521/526/527 states match decision 0089;
- source/provenance and scope are recorded;
- tests fail when principal and propagation status are swapped.

### Derivation

- direct protected principal evaluates Protected without graph traversal;
- established membership path evaluates Protected;
- path only to possible root evaluates Unknown;
- no path under complete evidence evaluates NotProtected;
- any global membership incompleteness turns unproven principals Unknown;
- primary-group-only possible route is Unknown;
- one established route wins;
- deterministic basis/path.

### Persistence

- all three evaluations round-trip;
- mask and catalogue version round-trip;
- unknown reasons round-trip;
- evidence seal/generation binding remains intact;
- schema 3 is refused by a schema 4 reader;
- no partial store is named complete.

### Read model and boundary

- a caller can resolve a fact by canonical SID text and explicit scope;
- graph internals are not public;
- Derivation has no dependency on Judgement;
- missing or incompatible products return a typed unavailable state; and
- Wave 6 concerns are not introduced into the Derivation product.

## 14. Settled review questions

Decision `0090` settles the open questions: keep the current dependency seam, use conservative global `Unknown`, persist one deterministic path, and defer judgement uncertainty rows to Wave 6. Tests include negative controls that swap principal and propagation claims, vary SID scope, and prove that a mask never changes principal protection.

## 15. Files expected to change

- `next/src/SecureAD.Derivation/ProtectedGroupCatalogue.cs`
- `next/src/SecureAD.Derivation/ProtectedPrincipalClosure.cs`
- `next/src/SecureAD.Derivation/DerivationSchema.cs`
- `next/src/SecureAD.Derivation/DerivationWriter.cs`
- `next/src/SecureAD.Derivation/DerivationReader.cs`
- `next/src/SecureAD.Derivation/Stage2aRun.cs`
- architecture, surface-register, Microsoft-verification and derivation documentation
- focused unit, architecture, writer/reader and integration tests

## 16. Validation

Wave 5 requires focused catalogue, traversal, writer/reader and architecture tests, the full solution build and test suite, and a separately recorded real-forest verification. A lab observation can corroborate implementation behavior but cannot promote a disputed or unverified catalogue claim.

### Real-forest verification, `ad.lab`, 2026-08-31

Run offline against a copy of the sealed bundle `ad.lab-20260831-151422` (Evidence schema 9, capture
complete, three domains). No controller was contacted.

| What | Observed |
|---|---|
| Forest root resolved | `forest_fqdn` `ad.lab` matched the captured `DomainFqdn` of root-domain objects exactly; `ba.ad.lab` and `ph.ad.lab` correctly did not |
| Derivation | schema 4, state `Completed`, completeness `IsComplete`, product `Available` |
| Catalogue | version 2, 18 entries persisted and read back |
| Forest mask | `DefaultedByAbsence`, character `0`, nothing excluded, so no doubt was stated |
| Population | 4,273 principals: 43 `Protected`, 4 `Unknown`, 4,226 `NotProtected` |
| Direct protection | 39, being six builtin and six per-domain entries across three domains plus three forest-root entries - the exact count the catalogue predicts |
| Member propagation | 4, each carrying a path that starts at the principal and ends at the decisive root, including cross-domain members of the root's Enterprise Admins |
| Primary-group gate | 3 `Unknown`, being the forest's three domain controllers, which reach `Domain Controllers` only through `primaryGroupID` |
| Disputed claim | 1 `Unknown`, being RID 498 in the root domain, held `Disputed` by `0089` |

**What this establishes.** The forest-root resolution works against real captured evidence, which unit
tests could not show because they supply both sides of the match. Clean negatives are reachable rather
than the conservative gate being stuck on. The unknown counts correspond exactly to the forest's real
shape rather than to an arbitrary population.

**What it does not establish.** Nothing here promotes a `Disputed` or `Unverified` claim: RID 498 is
still disputed and the primary-group route is still unverified. The run also surfaced `P-105` - the
reported decisive root is the last one walked rather than the nearest, so three accounts that are
direct members of Enterprise Admins report `BUILTIN\Administrators` instead.

**How it was run.** The check was first made with a temporary xUnit class holding hardcoded paths,
which was deleted once the report was read. It has since been reproduced by
`next/tools/explain-derivation.ps1`, which reports the same figures over the public
`DerivationReader` read model and is the repeatable form of this verification:

```text
pwsh -File next/tools/explain-derivation.ps1 -BundlePath <bundle> -Derive
pwsh -File next/tools/explain-derivation.ps1 -BundlePath <bundle> -Sid S-1-5-21-...-31608
```
