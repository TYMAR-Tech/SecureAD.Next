# Architecture

> **This describes the implementation in `src/SecureAD.*`, which is being replaced.**
>
> - **Live verification is removed by decision** ([`0008`](decisions/0008-live-verification-is-removed.md)).
>   The Inspect view, the directory tree and the live panels are still present in the code and are
>   pending deletion, so this document is accurate about the code and out of date about the product.
> - **For the old system, [`docs/map/`](map/README.md) supersedes this document.** It covers the same
>   ground in 256 components with every claim traced to a file and line, and it was audited against
>   all 618 source files. This one names 44 of the product's 746 types.
> - **For the new implementation, see [`docs/next/`](next/README.md).** Per
>   [`0011`](decisions/0011-rebuild-documentation-is-written-fresh-and-bound-by-tests.md) its
>   documentation is written fresh rather than adapted from here.
>
> This file is deleted with the code it describes. It cannot be deleted before then:
> `RunModelDocumentationTests` requires every run-model enum member to be named in a top-level
> document in `docs/`, and removing this one fails that test — verified 2026-08-09.

## Layering

```
SecureAD.Core          — Domain types, enums, interfaces, catalogs. Zero dependencies.
SecureAD.Infrastructure — SQLite storage, LDAP capture, analysis pipelines. Depends on Core.
SecureAD.UI            — WPF desktop (MVVM). Depends on Core + Infrastructure.
```

### Core

Pure domain model. Contains:

- **Contracts**: `IControlEdgeService`, `IFindingsPolicyLoader`, `IGuidCatalogService`, `ILiveDiagnosticsService`
- **Domain types**: `ControlType`, `Severity`, `RunState`, `CaptureSettings`, `FindingsPolicy`
- **Catalogs**: Built-in GUID catalog with danger classification (`GuidCatalogEntry`)
- **Schema**: Schema-level GUID entries (`SchemaGuidEntry`, `GuidType`)
- **Coverage**: Pipeline dependency graph (`CoverageDependencyGraph`, `CoverageModules`)

### Infrastructure

All I/O and analysis logic:

- **Storage**: `DerivedStore` (schema creation), `ObjectQueryService` (read queries), `GridSummaryQueryService` (grid chip/summary queries), `KeysetQueryBuilder` (paginated queries), `DatabaseConnectionFactory` (connection management with auto-applied PRAGMAs)
- **Security**: `AceAnalysisService` — access mask decoding, GUID-referenced right resolution, trustee aggregation, UAC decoding. Shared by both offline (audit DB) and live (LDAP) Object Inspector paths.
- **LDAP**: `DirectoryTreeService`, `LiveDiagnosticsService`, `DirectCaptureModule`
- **Analysis pipeline**: `DerivedAnalysisPipeline` (orchestrates post-capture analysis)
- **Control edges**: `ControlEdgeService` — derives control relationships from ACEs
- **Escalation paths**: `EscalationPathService` — BFS/DFS graph traversal over control edges
- **Findings**: `FindingsService` — evaluates rules against derived data, produces findings. Rule severity is defined in `rules.yaml` and resolved at evaluation time via `RuleEvaluatorHelpers.SeverityOf()` — evaluators never hardcode severity except for genuinely dynamic cases (e.g., target-tier-dependent escalation). Rules can be disabled in the YAML catalog (`enabled: false`); `FindingsService` skips disabled rules automatically.
- **Principals**: `PrincipalResolutionService` — resolves SIDs to display names
- **Group expansion**: `GroupExpansionService` — transitive group membership closure
- **Export**: CSV and HTML report generation

### UI

WPF desktop application using CommunityToolkit.Mvvm:

- **Shell**: `AppShell` → `ShellViewModel` → mode-based navigation (Dashboard, Explore, Inspect, Tools, Reports, Settings, Help)
- **Grid ViewModels**: `GridViewModelBase<T>` with keyset paging, lazy binding via `PrepareConnection`/`EnsureBound`
- **Detail panels**: `ObjectDetailPanelViewModel`, `FindingDetailViewModel`
- **Inspect mode**: On-demand LDAP directory tree browser + Object Inspector. Nav rail sections are built by `ObjectDetailPanelViewModel.RebuildSections` and vary by object class and by whether an audit database is loaded:
  - *Core* — Overview, Permissions, Groups, Kerberos, gMSA Retrieval, SPNs; plus Delegated Permissions when backed by an audit database
  - *Analysis* — Control Paths, Findings (audit database only)
  - *Tools* — Snapshot Access Estimate, Inheritance, ACL Compare, Notes with an audit database; Live Access Validation, Inheritance, ACL Compare in live-only mode
- **Tools mode**: Standalone utilities (Resolve Principal, Who Has Access)
- **Shared launchers**: `ToolWindowLauncher` for dialogs (Run Library, Compare, Policy Wizard, Forest Audit)

## The run model

A run is described by **three independent axes**. They are separate types rather than values of one
enum because they answer separate questions, and a run holds an answer to all three at once: a
sealed run may be partial, degraded, both, or neither.

| Axis | Type | Question it answers | Members |
|---|---|---|---|
| Lifecycle | `RunState` | Did the run finish and commit? | `Draft`, `Capturing`, `Merging`, `Finalizing`, `Sealed`, `Failed`, `Corrupt` |
| Coverage | `RunCoverage` | How much of the forest does it speak for? | `Full`, `Partial`, `Unknown` |
| Analysis health | `AnalysisHealth` | Did derived analysis over it succeed? | `Healthy`, `Degraded` |

All three are in `SecureAD.Core.Assessment`, and a completed run carries all three together on
`AuditRunResult` (`State`, `Coverage`, `Health`). `Coverage` defaults to `RunCoverage.Unknown` and
never to `Full`: full coverage is earned by measurement against discovery, not acquired by
omission.

[`CAPTURE-PIPELINE.md`](CAPTURE-PIPELINE.md) describes what the pipeline does to these axes when a
phase fails; [`DATA-MODEL.md`](DATA-MODEL.md) describes their stored form. This section is where
the types live and which component decides each one.

### Where each axis is decided

- **`RunState`** — `DirectCaptureRunner` returns `RunState.Sealed` unconditionally when a capture
  reaches the end of its seal path; how the run went is carried on the other two axes. For a bundle
  reopened later, `ExistingCaptureAnalysisService.InterpretRunState` maps the persisted string back.
- **`RunCoverage`** — `RunCoverageResolver.Resolve`, a pure function of discovery confidence, the
  discovered domain set, the per-domain declarations, the covered domain set, and whether every
  required module completed. `Full` requires declared == discovered, covered == declared, **and**
  module completeness; anything less is `Partial`, and a discovery that did not cleanly enumerate
  the forest is `Unknown` because there is no denominator to measure against.
- **`AnalysisHealth`** — at seal, from the pipeline's own in-memory `DerivedHealthResult.IsDegraded`.
  For a bundle reopened later, from `DerivedHealthReader.Read`.

### One axis is stored; two are recomputed

`RunState` is the only axis with a column of its own. `run.run_state` holds a **narrower
vocabulary** than the enum — `RunStateNames` declares `InProgress`, `Finalizing`, `Complete`,
`Failed` and `Cancelled` — and the mapping back is deliberately not total:
`ExistingCaptureAnalysisService` reads `Complete` as `Sealed`, `Failed` as `Failed`, and anything
else, including an absent row, as `RunState.Corrupt`. A value this build cannot recognise is a
bundle it cannot vouch for, not a state a healthy run could hold.

`RunCoverage` and `AnalysisHealth` are **not persisted as values.** Every ingredient is already on
disk, so a stored verdict would be a second, staleable copy of a derived fact. `RunCoverageReader`
recomputes coverage from the bundle by calling the same `RunCoverageResolver.Resolve` the seal path
used, rather than reimplementing the mapping, so a reloaded run cannot disagree with the run that
produced it; it returns a `RunCoverageSnapshot`, which adds the per-`(module, domain)` cell set that
compare needs. Health is read back out of the `pipeline_phase_derived_health` metadata key.

`run.coverage_id` is the exception that proves the rule: it is stored because it identifies what the
run *declared* it would gather, which is a decision rather than a derivation, and nothing in a
sealed bundle can reconstruct a declaration that was never achieved.

### Two neighbouring enums that are not axes

| Type | Namespace | What it is a verdict about | Members |
|---|---|---|---|
| `CoverageState` | `SecureAD.Core.Coverage` | one `(module, domain)` cell of `fact_coverage` | `Complete`, `Partial`, `Denied`, `Failed`, `Skipped` |
| `DerivedHealthState` | `SecureAD.Infrastructure.Storage` | what a bundle records about its own derived analysis | `Complete`, `Degraded`, `Unrecorded` |

`CoverageState.Partial` and `RunCoverage.Partial` are different facts about different subjects — one
cell against one module in one domain, versus a whole run against the forest. Neither is renamed to
avoid the collision. `RunCoverage` is the run-level verdict derived from the matrix of
`CoverageState` cells.

`DerivedHealthState` is **not** `AnalysisHealth` with an extra member. `AnalysisHealth` is what a run
reports as it finishes, where the answer is always known. `DerivedHealthState` is what a bundle can
be read to say afterwards, where the verdict may be missing entirely — which is what `Unrecorded`
means. `DerivedHealth.IsIncomplete` counts `Unrecorded` alongside `Degraded`: a run that did not
state that its analysis finished has not stated that it did.

## Data Flow

### Capture Pipeline

```
1. Forest discovery (LDAP) → domain/DC topology
2. Per-domain LDAP capture → dim_object, fact_ace, dim_principal
3. Group membership capture → fact_group_membership_direct
4. SYSVOL capture (Security mode) → dim_gpo_setting, fact_sysvol_ace
   (GPO Registry.pol + security templates, GPO folder DACLs, optional GPP cpassword scan)
```

### Analysis Pipeline (DerivedAnalysisPipeline)

```
5. Group expansion    → fact_group_membership_closure
6. Principal resolution → dim_principal enrichment
7. Control edge derivation → fact_control_edge (from fact_ace + GUID catalog)
8. Escalation path detection → fact_escalation_path (BFS over control edges)
9. Findings evaluation → fact_finding (rules evaluated against derived data)
10. Asset tier classification → dim_asset_tier
```

### UI Binding

```
10. OpenDatabase → BindGridsWithConnectionAsync
    - Phase 1 (UI thread): bind visible grids, prepare deferred grids
    - Phase 2 (background): nav tree, dashboard stats, tier classification
    - Each grid reads from v_grid_* views via KeysetQueryBuilder
```

## Object Inspector: Dual-Path Design

The Object Inspector (`ObjectDetailPanelViewModel`) has two data paths that converge on a single display model:

```
                    ┌─────────────────────────┐
                    │  ObjectDetailPanelViewModel.LoadAllDataAsync  │
                    └────────────┬────────────┘
                                 │
                  ┌──────────────┴──────────────┐
                  ▼                              ▼
        connection != null              IsLiveOnlyMode == true
        (Explore mode)                  (Inspect mode)
                  │                              │
     BuildSnapshot()                BuildLiveSnapshotAsync()
     reads from audit.db            reads from live LDAP
                  │                              │
                  └──────────┬───────────────────┘
                             ▼
                    ApplySnapshot(snapshot, obj)
                    (single display path)
                             │
                             ▼
                    LoadLiveDataAsync()  ← Path B only (no audit.db)
                    (identity, delegation, gMSA password readers)
```

### Path A — Explore (offline, audit database)

Used when an audit.db is loaded. The snapshot is built from SQLite via `ObjectQueryService`:

- Owner, ACEs, group membership, control edges, findings, escalation paths, asset tiers, notes
- SPNs and Kerberos delegation from `dim_delegation`, split so that SPNs get their own section
  (`ObjectDetailPanelViewModel.cs:551-560`)
- Estimated Kerberos token size from the captured group closure via
  `ObjectQueryService.EstimateTokenSize`
- **Full derived analysis** is available because the pipeline has already run

### Path B — Inspect (live LDAP, no database)

Used when the user inspects an object from the Inspect rail with no audit.db loaded:

- Owner, ACEs, group membership, Kerberos delegation, identity properties
- **No derived analysis** — control edges, findings, escalation paths, and asset tiers are unavailable because they require the full analysis pipeline

### What is shared

| Component | Shared? | Notes |
|---|---|---|
| `DetailSnapshot` model | ✅ | Same shape regardless of data source |
| `ApplySnapshot` display binding | ✅ | Single method applies data to UI |
| Live LDAP augmentation | ❌ | Path B only — `LoadLiveDataAsync` is gated on `connection is null` (`ObjectDetailPanelViewModel.cs:437`), so it never runs when an audit.db is loaded |
| `ObjectDetailWindow` | ✅ | Same inspector window hosts both paths |
| Nav section layout | ✅ | Live-only sections hidden when data unavailable |

### What diverges

| Component | Explore (Path A) | Inspect (Path B) |
|---|---|---|
| Data source | `audit.db` (SQLite) | Live LDAP |
| Control edges | ✅ Available | ❌ Requires analysis pipeline |
| Findings | ✅ Available | ❌ Requires analysis pipeline |
| Escalation paths | ✅ Available | ❌ Requires analysis pipeline |
| Asset tiers | ✅ Available | ❌ Requires analysis pipeline |

This split is **by design**: derived analysis requires the full capture + analysis pipeline to have run. Live LDAP can only provide the raw data (ACEs, group membership, properties), not the derived security insights.

## Connection Management

All SQLite connections go through `DatabaseConnectionFactory`:

- `OpenReadOnly` — read-optimized with configurable page cache (256MB–1GB)
- `OpenSuppressionWrite` — the only write connection the UI can obtain, and it opens the
  bundle-local `suppressions.db`, never `audit.db` (see [I-2](INVARIANTS.md))
- Each background task opens its own connection (SQLite WAL supports concurrent readers)
- Connection diagnostics logged via `ConnectionDiagnostics` when `SECUREAD_DIAG_CONNECTIONS=1`

### Releasing the loaded run

Pooling is disabled everywhere, so a bundle's files are released by disposing the connections
that hold them and at no other moment. Releasing the loaded run is therefore a single ordered
sequence, and it exists exactly once, as `MainViewModel.ReleaseLoadedRunAsync`:

1. Close the pop-out windows bound to the run. `DetailWindowViewModel` opens a connection of its
   own inside the same bundle, and `FindingDetailWindow` is handed the shell's suppression
   connection rather than opening one.
2. Cancel the current bind generation.
3. **Await** the tracked background tasks. The tree, dashboard-stats and dashboard-summary tasks
   each open a read connection inside `Task.Run`, and cancellation cannot retract one that is
   already open.
4. Dispose this view model's own connections.

Both paths that release a run — closing it, and opening another over it — go through that method;
`MainViewModel.Dispose` is the sole exception, because the window is already closing and cannot
await. Skipping any step leaves the bundle locked, so the run library cannot delete a run it
correctly reports as closed, or throws `ObjectDisposedException` on a background thread.

**Enforced by:** `LoadedRunReleaseInvariantTests`.

## Logging

Single composition root via `AppLog` (static class in `SecureAD.UI`):

```
App.OnStartup → AppLog.Initialize(logFilePath, warningsFilePath, sanitize)
                  ↓
              LoggerFactory.Create (one instance for entire process)
                  ↓
       ┌─────────┼──────────────┐
       ↓         ↓              ↓
  MainViewModel  UiPerfTrace   Infrastructure (via InfrastructureSession.LoggerFactory)
```

- `AppLog.Initialize` is called **once** at startup from `App.OnStartup`
- All loggers are created from `AppLog.Factory` or `AppLog.CreateLogger<T>()`
- Before initialization, `AppLog.Factory` returns `NullLoggerFactory.Instance` (safe for static field initializers)
- Infrastructure services receive `ILoggerFactory` via `InfrastructureSession`, not a static

### Log Output

File-based logging via `FileLoggerProvider`:

- Aggregate log: `%LocalAppData%/SecureAD/Logs/session/app.log`
- Warnings-only log: `%LocalAppData%/SecureAD/Logs/session/app-warnings.log`
- Sanitized by default (DNs, FQDNs, SIDs hashed) — set `SECUREAD_RAW_LOGS=1` for unsanitized
- Performance traces via `UiPerfTrace` and `LogOpenTrace` with warning thresholds
