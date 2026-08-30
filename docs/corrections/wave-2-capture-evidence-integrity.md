# Wave 2 — Capture and Evidence integrity

**Branch:** `correction/wave-2-capture-evidence-integrity`  
**Starting acceptance baseline:** `71a61dd`  
**Status:** Implemented and validated; five unrelated later-wave acceptance failures remain

## Corrections

### Atomic partition retries (E-C01)

Each partition attempt now opens a SQLite savepoint before writing its coverage row or objects. An
unsuccessful attempt rolls back the database, writer identifiers and caches, unreadable-descriptor
counts, and GPO inventory additions before the retry starts from page one. A failed attempt can no
longer survive beside the successful retry as duplicate Evidence.

Duplicate partition validation occurs before the savepoint is opened. The production sink and test
sink both restore only state allocated by the current attempt, preserving earlier completed
partitions.

### Exact exclusion identity

`CapturePlan` now preserves each authoritative naming-context-to-DNS-name pairing discovered from the
forest. Exclusion dictionary keys, attested naming contexts and attested DNS names are checked against
that exact pairing before a run directory is created. A mismatch returns
`Capture.ExclusionDoesNotMatchDeclaredDomain`; it cannot authorize omission of another domain.

### Three-way crossRef classification (K-07)

A crossRef is classified from Microsoft's `systemFlags` contract:

- a domain naming context carries both `ADS_SYSTEMFLAG_CR_NTDS_NC` (`0x1`) and
  `ADS_SYSTEMFLAG_CR_NTDS_DOMAIN` (`0x2`);
- an application naming context carries `ADS_SYSTEMFLAG_CR_NTDS_NC` with the domain bit clear; and
- a record with the NTDS naming-context bit clear is not reported as a local partition the product
  declined to read.

Configuration and schema remain identified by the exact naming contexts published through RootDSE.

### Reachable continuation reconciliation (E-C02)

`CaptureRun` now reconciles every completed partition's continuation references against the exact
authorized plan after LDAP capture and before SYSVOL capture or sealing. The persisted result records:

- `Complete`, `Incomplete` or `NotPerformed`;
- readable naming contexts absent from the plan;
- references whose naming context could not be parsed; and
- units whose searches suppressed referrals.

Microsoft documents that a subtree search with referral chasing disabled can return referrals to
direct subordinate domains. The domain-scope control suppresses those referrals, so an empty result
from a suppressed unit is explicitly incomplete rather than evidence that no subordinate scope
exists.

### Unplanned-scope policy

The owner selected **fail before sealing and require a fresh capture** when complete reconciliation
finds a readable naming context absent from the authorized plan. The failed run writes its outcome and
retains only the partial database. This prevents known local scope from being omitted without either a
capture unit or an exact exclusion attestation.

Incomplete reconciliation may seal because it makes no claim that no unplanned scope exists. Its
uncertainty is persisted for downstream completeness handling.

### Evidence schema version 9 and semantic provenance (K-05, K-09)

Evidence schema version is raised from 8 to 9. The `bundle` row now records:

- `CapturedAttributeCatalog.Version`;
- `SchemaGuidCatalog.Version`;
- `SecurityDescriptorParser.Version`; and
- the continuation-reconciliation outcome.

`continuation_reconciliation_item` stores each typed reconciliation detail. `BundleReader` refuses a
bundle whose captured-attribute, shipped schema-GUID or security-descriptor-parser semantic version
differs from the current build. The coverage identity recipe is unchanged and is pinned for schema 9.

There is no migration path. Existing schema 8 Evidence must be recaptured because it cannot state
which capture/parser semantics produced its projections or whether continuation references were
reconciled.

### Seal I/O failures (E-C04)

Expected `IOException` and `UnauthorizedAccessException` failures while reading a seal or hashing its
data now return `SealState.Unreadable`. They no longer escape before run-state and bundle readers can
classify the artefact. A hash that could not be computed is neither intact nor mismatched because no
comparison occurred.

## Validation

- `PartitionCaptureTests`: 17 passed.
- `CapturePlanTests`: 18 passed.
- `ForestDiscoveryTests`: 9 passed.
- Capture-run end-to-end tests: 13 passed.
- `BundleReaderTests`: 35 passed.
- `BundleWriterTests`: 74 passed.
- Focused retry/reconciliation/reader validation: 65 passed.
- Schema, documentation and architecture integration gates: passed.
- Offline capture → derive → judge → read journey: passed.
- Workspace build: passed.
- Full suite: 2,660 passed, 5 expected later-wave failures out of 2,665 before the final seal-reader test was added. The final 2,666-test run also had one transient Shell progress timeout; that test passed alone in 227 ms and passed the preceding full run.

The five failures are accepted later-wave gates: Derivation Evidence binding, Derivation degraded
completion, Judgement degraded scope, and two Shell lifecycle wording claims. No Wave 2 gate remains
failing.

## Real-forest validation still required

Modeled controllers validate state-machine and persistence behavior, not an actual LDAP runtime. Before
release, validate in a disposable forest that:

1. a multi-domain capture returns or suppresses continuation referrals as the negotiated controls say;
2. domain, application and non-local crossRefs carry the documented `systemFlags` combinations;
3. a topology change between discovery and capture either appears in a refreshed plan or triggers the
   unplanned-scope refusal;
4. a connection failure after a persisted page restarts from page one without duplicate objects,
   descriptors, trustees, coverage rows or GPO inventory; and
5. copied/read-only/locked bundle files produce the documented seal verdicts on supported Windows
   filesystems.

## Compatibility and deferred work

- Schema 8 bundles are intentionally refused and require recapture.
- `NotPerformed` exists for non-capture producers and test-built bundles; production capture always
  persists `Complete` or `Incomplete`.
- Downstream propagation of reconciliation uncertainty into Derivation and Judgement belongs to the
  typed-uncertainty and analysis-store waves.
- Atomic replacement and Evidence binding for disposable Derivation/Judgement stores remain Wave 3.
- Host-neutral lifecycle wording and process exit behavior remain Wave 7.
