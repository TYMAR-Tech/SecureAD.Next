# Contributing to SecureAD

SecureAD is a **determinism-first** system.
Implementation MUST preserve deterministic, evidence-defensible analysis results.

This repository enforces **strict MVVM** and **hard architectural guardrails**.
Contributions that violate these rules will not be accepted.

---

## Authoritative Documents (Read First)

The following documents describe how the system works and constrain contributions:

- [`README.md`](../README.md) — solution overview and project responsibilities
- [`docs/WHAT-THE-PRODUCT-IS.md`](../docs/WHAT-THE-PRODUCT-IS.md) — **read this first**: what SecureAD is, the stages a run passes through, and the decisions already made
- [`docs/next/README.md`](../docs/next/README.md) — **the authority on gates**: what each one prevents and which are built
- [`docs/next/ARCHITECTURE.md`](../docs/next/ARCHITECTURE.md) — projects, layering, and which project may reference which
- [`docs/PUNCH-LIST.md`](../docs/PUNCH-LIST.md) — working backlog of follow-ups and decisions to revisit
- [`docs/decisions/`](../docs/decisions/) — the product's positions; only a record with `Status: Accepted` states one

If a contribution conflicts with these documents, update the documents in the same change or do not proceed.

---

## Architectural Guardrails (Non-Negotiable)

### Data Authority
- SQLite (`audit.db`) is the **primary store**. All captured data and derived analysis live there.
- The derived database is **rebuildable**: re-running capture + the analysis pipeline against a directory reproduces it.
- Derived analysis (control edges, escalation paths, findings, asset tiers) is written by the analysis pipeline, never by the UI.

### SQLite & UI Contract
- UI queries SQLite **views only** (`v_grid_*`, `v_export_*`).
- No UI binding to base tables.
- Deterministic ordering is defined in SQL view definitions, not in UI code.

### Determinism
- Same captured inputs + same rule pack (`rules.yaml`) → identical derived DB, findings, and exports.
- No thread-order, environment, or timing-dependent variation in outputs.
- All merge, sort, and hash operations must be stable and reproducible.

---

## MVVM Enforcement (Strict)

The following boundaries are enforced:

- `SecureAD.UI`
  - MUST NOT reference SQL, LDAP, or filesystem concerns directly
  - MAY reference Infrastructure interfaces and Core types only

- `SecureAD.Infrastructure`
  - Owns all SQLite, LDAP, and filesystem concerns
  - Exposes data via interfaces and DTOs only

- `SecureAD.Core`
  - Contains domain types, enums, contracts, catalogs, and invariants only
  - Has no dependency on UI, SQLite, LDAP, or filesystem

Violations of these boundaries are considered **architecture bugs**, not refactoring suggestions.

---

## Namespace Convention

Code is organized by domain, not by type kind:

```
SecureAD.Core.Assessment      — AssessmentMode, RunState, InvocationV1
SecureAD.Core.Authentication  — AuthenticationMode
SecureAD.Core.Catalogs        — GuidCatalog, GuidCatalogEntry, GuidCategory
SecureAD.Core.Configuration   — AppSettings, CaptureProfile, SettingsValidator
SecureAD.Core.ControlEdges    — ControlType, ControlEdge, ControlEdgeBuildResult
SecureAD.Core.Coverage        — CoverageState, CoverageReasonCode, CoverageV1
SecureAD.Core.Errors          — ErrorCategory, ErrorSeverity, AuditError, *ErrorCode enums
SecureAD.Core.Evidence        — SchemaConstants
SecureAD.Core.Findings        — Severity, FindingV2, FindingRule, RuleCategory
SecureAD.Core.Principals      — PrincipalKind, PrincipalResolutionState, WellKnownSidEntry
SecureAD.Core.Progress        — IProgressPublisher, *ProgressEvent records
```

No `Enums/` or `Models/` folders. Enums live in the domain they belong to.

---

## Project Status

SecureAD is a mature, working application (Core, Infrastructure, and WPF UI are all implemented).
Ongoing follow-ups and decisions to revisit are tracked in
[`docs/PUNCH-LIST.md`](../docs/PUNCH-LIST.md).

When changing analysis behavior, preserve risk semantics and evidence coverage: document any
change that prunes, filters, caps, deduplicates, or alters path length/evidence.

---

## Contribution Process

Before writing code:
1. Read the relevant document(s) under `docs/` for the area you are changing
2. Confirm no architectural guardrails (above) are violated
3. For analysis/rule changes, check `docs/PUNCH-LIST.md` for known follow-ups and open decisions
4. Add or update tests that lock in the intended behavior

### Building and Testing

```powershell
dotnet build SecureAD.sln -c Debug
./test.ps1            # runs the full test suite
```

> **Visual Studio note:** VS sets `DOTNET_ROOT` to its private runtime folder, which can
> prevent the .NET 8 test host from starting on the command line. `test.ps1` points
> `DOTNET_ROOT` at the system .NET install to work around this. If you run `dotnet test`
> directly and see "You must install or update .NET to run this application", set
> `DOTNET_ROOT` to `C:\Program Files\dotnet` first.

Pull requests that bypass this process will be closed.

---

## Copilot Usage

When using GitHub Copilot or other AI tools:
- Keep changes consistent with the architectural guardrails and the `docs/` documentation
- AI-generated code is held to the same standards as human-written code
- All changes must keep the full test suite green (`./test.ps1`)
