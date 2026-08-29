# Implementing the shared AdminSDHolder catalogue

**Status:** implementation specification for review; not accepted and not implemented.
**Governing semantics:**
[Shared AdminSDHolder catalogue semantics](adminsdholder-catalogue-semantics.md), accepted by
[`0089`](../../decisions/0089-principal-protection-and-member-propagation-are-separate-claims.md).
**First consumer:**
[SEC-030 reviewed candidate](../judgement/rules/SEC-030-admincount-without-protection.reviewed.md).

---

## For an independent reviewer

This document specifies how to implement an already accepted semantic model. Review it for:

1. whether any unresolved Microsoft behavior is accidentally converted into Yes or No;
2. whether the proposed project dependencies preserve the layer direction;
3. whether stored results contain enough evidence for a later rule to explain its conclusion;
4. whether incomplete membership can ever become a clean `NotProtected` result;
5. whether typed uncertainty reaches the operator rather than disappearing into an aggregate count;
6. whether the schema is deterministic and versioned; and
7. whether the proposed implementation is larger or more abstract than its first consumer requires.

**Do not review this as permission to implement SEC-030 immediately.** The shared derivation and its
read model land first. SEC-030 is implemented only after those results round-trip through the store.

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
- let SEC-030 consume current DACL state and protected-principal facts without recomputing either;
- keep Derivation independent of rules; and
- surface uncertainty under decision `0086`.

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
- redesign every future rule input before a caller exists.

## 3. Project and dependency boundary

### 3.1 Current problem

`IRule`, `RuleVerdict`, the two existing rules and `RuleCatalogue` currently live in
`SecureAD.Evidence`. `SecureAD.Derivation` depends on Evidence, so Evidence cannot reference
Derivation without a cycle. A derived-fact rule cannot remain implemented in Evidence and directly
consume Derivation.

### 3.2 Proposed boundary

Move rule **execution contracts and implementations** into `SecureAD.Judgement`:

- `IRule`;
- `RuleVerdict`;
- `RuleCatalogue`;
- existing unconstrained-delegation rule implementations; and
- future SEC-030 implementation.

Keep the immutable finding data contracts in `SecureAD.Evidence.Findings`:

- `RuleDefinition`;
- `Finding`;
- `FindingSubject`;
- `FindingEvidence` and evidence records;
- `Severity`; and
- stable rule/finding identity vocabulary.

Add a project reference:

```text
SecureAD.Judgement -> SecureAD.Derivation
```

The resulting direction is:

```text
Kernel
  ^
Evidence
  ^       ^
Derivation |
  ^       |
  +--- Judgement
```

More plainly:

```text
Judgement -> Derivation -> Evidence -> Kernel
Judgement -------------> Evidence -> Kernel
```

Derivation never references Judgement or a rule. Capture/Evidence never references Derivation.

### 3.3 Why not add an interface to Evidence

Do not place an `IProtectedPrincipalFacts` abstraction in Evidence merely to invert the dependency.
Protected-principal semantics are derived facts, not captured-evidence vocabulary. Doing so would make
Evidence own a question it deliberately does not answer and would let future derived concepts leak
through lower-layer interfaces one by one.

### 3.4 Architecture decision required

This dependency and ownership change requires an accepted implementation decision before code moves.
Decision `0089` deliberately left the seam open.

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
    UnsupportedValue,
}
```

Rules:

| Input | Outcome | Complete |
|---|---|---|
| valid hex character | `Stated` | yes |
| object read, character absent | `DefaultedByAbsence` | yes |
| object/attribute not captured | `NotRead` | no |
| present non-hex character | `UnsupportedValue` | no |

The raw character is always preserved when present.

### 5.2 Effective member propagation

For each catalogue entry:

```text
if MemberPropagation != Established
    EffectiveMemberPropagation = MemberPropagation
else if entry is selected by a complete valid mask
    EffectiveMemberPropagation = EstablishedNo
    Basis = ForestMask
else if mask is NotRead or UnsupportedValue and entry is mask-excludable
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

## 11. Rule execution seam

### 11.1 Move rule contracts and implementations

Move `IRule`, `RuleVerdict`, `RuleCatalogue`, and existing rule implementations from
`SecureAD.Evidence` to `SecureAD.Judgement`.

Keep stable finding data contracts in Evidence.

Add:

```xml
<ProjectReference Include="..\SecureAD.Derivation\SecureAD.Derivation.csproj" />
```

to `SecureAD.Judgement.csproj`.

### 11.2 Rule definition declarations

Extend `RuleDefinition` data with declared non-attribute inputs:

```csharp
IReadOnlyList<RuleInputKind> RequiredInputs
```

Initial values:

```csharp
public enum RuleInputKind
{
    ObjectAttributes,
    ObjectPermissions,
    ProtectedPrincipalFacts,
}
```

Existing rules declare `ObjectAttributes`. SEC-030 declares all three.

### 11.3 Rule input package

Judgement builds only declared inputs:

```csharp
internal sealed record RuleInputs(
    ObjectAttributes Subject,
    ObjectPermissions? Permissions,
    StoredProtectedPrincipalFact? Protection,
    IReadOnlyList<RuleInputIssue> Issues);
```

A rule cannot query the bundle or derivation reader directly. Judgement owns I/O and constructs the
package. This preserves one execution path and declared dependencies.

## 12. Typed uncertainty

### 12.1 Rule verdict

Replace missing-attribute-only uncertainty with typed issues:

```csharp
public enum RuleInputIssueKind
{
    AttributeNotCaptured,
    PermissionsNotCaptured,
    DerivationDidNotRun,
    DerivationIncomplete,
    PrincipalNotInDerivation,
    ProtectionDisputed,
    ProtectionUnverified,
    PrimaryGroupTraversalUnverified,
    ForestMaskNotRead,
    ForestMaskUnsupported,
}

public sealed record RuleInputIssue(
    RuleInputIssueKind Kind,
    string Subject,
    string Detail);
```

`RuleVerdict` returns findings and issues. Missing LDAP attributes are one issue kind, not the entire
uncertainty model.

### 12.2 Customer-visible uncertainty

Decision `0086` requires named uncertainty to reach the operator. Judgement stores object-level
indeterminate results separately from positive security findings:

```text
rule_uncertainty
    rule_id
    rule_version
    object_guid
    subject_kind/key
    issue_kind
    detail
```

These rows are not Medium/High security findings and do not acquire acceptance lifecycle. The Shell
shows them as coverage/uncertainty for the rule and object.

This avoids two wrong alternatives:

- calling an uncertain object stale; or
- showing only an aggregate count with no object or reason.

### 12.3 Rule execution outcome

Any object-level issue increments `ObjectsNotJudged` and makes the rule execution `Indeterminate`.
Positive findings from objects judged completely remain atomic and stored. This preserves current
per-rule failure isolation.

## 13. SEC-030 input and evaluation contract

The shared foundation is accepted before SEC-030, but the first consumer constrains the read model.
SEC-030 requires:

- `adminCount` from object attributes;
- current `IsDaclProtected` from object permissions;
- scoped SID lookup;
- stored protected-principal fact; and
- complete/typed issue state.

Evaluation order remains the reviewed candidate's order:

1. no `adminCount=1` → not applicable;
2. missing SID/permissions → indeterminate issue;
3. inheriting DACL → judged clean for SEC-030;
4. missing/incomplete protected fact → indeterminate issue;
5. `Protected` → judged clean;
6. `Unknown` → customer-visible uncertainty;
7. `NotProtected` + non-inheriting DACL → Medium finding.

Deleted/tombstoned object behavior remains an explicit SEC-030 product decision and is not settled by
this foundation specification.

## 14. Delivery phases

### Phase A — mask correctness

- add `UnsupportedValue`;
- update completeness semantics;
- update anchor/unit tests;
- no catalogue behavior change yet.

### Phase B — catalogue model

- add per-semantic entry/status/provenance/scope;
- replace flat lists and `IsProtected`;
- implement effective propagation roots;
- tests with negative controls.

### Phase C — derivation algorithm

- separate direct principal claims, established roots and possible roots;
- implement conservative global completeness;
- preserve deterministic basis/path;
- no persistence yet only within this phase branch.

### Phase D — persistence/read-back

- schema 4;
- writer transaction;
- reader model and scoped SID lookup;
- round-trip and mismatch tests.

### Phase E — rule boundary

- move rule execution contracts/implementations to Judgement;
- add Judgement → Derivation reference;
- declarations and typed input package;
- migrate two existing rules unchanged semantically.

### Phase F — uncertainty storage/UI

- add object-level rule uncertainty storage/read-back;
- Shell coverage/uncertainty presentation;
- preserve aggregate counts.

### Phase G — SEC-030

Only after A–F pass does SEC-030 implement against the persisted shared result.

Each phase is separately buildable, testable and commit-worthy. No phase may leave the tree with the
old flat behavior presented as canonical.

## 15. Acceptance criteria

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
- schema 3 refused by schema 4 reader;
- no partial store is named complete.

### Rule seam

- existing two rules produce unchanged findings;
- undeclared input cannot be accessed;
- SEC-030 can receive attributes, permissions and protection fact;
- no rule opens Evidence or Derivation stores itself;
- dependency direction passes architecture gates.

### Uncertainty

- object and reason stored;
- shown to operator;
- distinct from security finding and missing attribute;
- rule outcome Indeterminate;
- no empty finding list is presented as clean.

## 16. Review questions

An external review should answer:

1. Is moving rule contracts/implementations to Judgement the narrowest clean dependency seam?
2. Is conservative global `Unknown` acceptable until uncertainty can be localized?
3. Does the schema preserve enough evidence without over-storing the graph?
4. Should deterministic paths be stored now or reconstructed from stored direct edges?
5. Should typed uncertainties be separate rows rather than findings with an indeterminate evaluation?
6. Are any enum/status values redundant or unable to represent a required state?
7. Can any delivery phase accidentally expose old flat semantics as canonical?
8. What negative controls are missing?

## 17. Files expected to change after acceptance

- `next/src/SecureAD.Kernel/Security/DirectoryHeuristics.cs`
- `next/src/SecureAD.Derivation/ProtectedGroupCatalogue.cs`
- `next/src/SecureAD.Derivation/ProtectedPrincipalClosure.cs`
- `next/src/SecureAD.Derivation/DerivationSchema.cs`
- `next/src/SecureAD.Derivation/DerivationWriter.cs`
- `next/src/SecureAD.Derivation/DerivationReader.cs`
- `next/src/SecureAD.Derivation/Stage2aRun.cs`
- `next/src/SecureAD.Evidence/Findings/*` for data-contract retention/removal of rule execution types
- `next/src/SecureAD.Judgement/*` for moved rule execution and derived inputs
- `next/src/SecureAD.Shell/*` for uncertainty presentation
- architecture, surface-register, Microsoft-verification and derivation/judgement documentation
- focused unit, architecture, writer/reader, integration and Shell tests

No production file should change until this implementation specification and its dependency seam are
reviewed and accepted.

## 18. Draft validation

- Workspace build after adding this document: **succeeded**.
- Full test run: **2,642 passed, 1 failed**.
- The failure was the known unrelated timing flake
  `NewAuditViewModelTests.HowFarTheJudgingHasGotIsShown`; it passed immediately in isolation.
- No production code was changed by this draft.
