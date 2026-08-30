# Wave 2a — Workflow stabilization and dead-path control

**Branch:** `correction/wave-2a-workflow-stabilization`  
**Starting point:** Wave 2 commit `22dac57`  
**Status:** Implemented and validated; five unrelated later-wave acceptance failures remain

## Why this stabilization exists

The layered architecture remained sound, but current production behavior was described in several
places that no longer agreed. `ARCHITECTURE.md` still said discovery, Derivation, Judgement and the
Shell were absent while production Shell code already ran capture, derivation and judging. Shell and
CLI also sequence stages independently, which makes every lifecycle correction look like another
change to the application's design.

Further feature work paused so the end-to-end workflow could be frozen before Wave 3. This wave adds
no security rule and changes no capture, derivation or judgement semantics.

## Authoritative workflow

[`docs/next/WORKFLOW.md`](../next/WORKFLOW.md) is now the single current and target account of product
orchestration. It freezes this order:

1. discover and preflight;
2. review and authorize scope;
3. capture;
4. reconcile discovered scope;
5. seal permanent Evidence;
6. derive reusable offline facts;
7. judge declared inputs;
8. read and present; and
9. compare or export.

It also fixes the online/offline boundary, stage inputs and outputs, artefact lifetimes, failure rules,
current host differences and accepted correction order. `ARCHITECTURE.md` continues to own project
layering. Layer documents continue to own behavior inside one stage. Review and correction documents
remain historical records.

## Replacement includes deletion

A migration is no longer accepted merely because a shared path was added. The workflow contract now
requires the same change to remove superseded host sequencing, interfaces, fakes, registrations,
tests and documentation unless an external compatibility requirement explicitly keeps them.

Internal APIs and disposable store schemas receive no compatibility wrapper by default. Callers are
migrated and obsolete members are removed.

## Workflow path inventory

[`docs/next/WORKFLOW-PATHS.md`](../next/WORKFLOW-PATHS.md) records every current production and
developer orchestration path with a disposition and deletion event.

Symbol/reference review established that these are live migration seams, not dead code today:

- `CaptureLauncher` / `ICaptureLauncher`;
- `DerivationLauncher` / `IDerivationLauncher`;
- `JudgingLauncher` / `IJudgingLauncher`;
- `NewAuditViewModel.StartAsync`, `DeriveAsync` and `JudgeAsync`;
- `SecureAD.Cli.Program.RunAsync` and `Derive`; and
- `IRunOpener` / `RunOpener` for Shell navigation.

Wave 7 must introduce one host-neutral application workflow and delete the Shell launcher/sequencing
paths and CLI sequencing paths in the same change. `IRunOpener` remains because it is navigation, not
stage orchestration, unless the later Shell navigation design replaces it.

## Developer-only judging path

`next/tools/judge-bundle.ps1` remains temporarily as a non-product diagnostic for judging or explaining
an existing bundle. Its stale claim that no product entry point existed was removed, and its invocation
was repaired to supply the required run log. It must be deleted when the shared CLI workflow provides
equivalent judge-existing and explain diagnostics.

## Removed stale contracts

Live documentation now agrees that:

- the Shell exists and reaches capture, derivation, Judgement and findings;
- the CLI currently captures and derives but does not judge;
- `SecureAD.Audit` owns capture/discovery, not derivation or the rule catalogue;
- seven production projects are governed by the downward dependency rule;
- executable rules are registered once in `RuleCatalogue.All`, not a deleted
  `JudgingLauncher.Rules()` method; and
- cross-object rule inputs are scheduled correction work rather than an unbounded architectural
  question.

The rule cards remain predecessor material, but their quarantine banner now points readers to the
actual current-product rule catalogue instead of a member that does not exist.

## Architecture gates

`WorkflowArchitectureTests` now enforce:

- exactly nine frozen workflow stages;
- current Shell capture → derive → judge order;
- current CLI capture → derive path and absence of CLI-owned judging;
- executable rule construction only in `RuleCatalogue`;
- named replacement/deletion events for temporary host orchestration;
- explicit non-product and retirement status for the developer judging script; and
- solution visibility for both workflow documents.

The old stage-state check was removed from the architecture dependency table and rebound to
`WORKFLOW.md`, eliminating a second stage-status source.

## Validation

- Workspace build: passed.
- Offline capture → derive → judge → read journey: passed.
- New workflow architecture gates: 7 passed.
- Affected architecture/documentation gates: passed.
- Full suite: 2,668 passed, 5 failed out of 2,673.

The five failures are the accepted later-wave gates for Derivation Evidence binding, Derivation
degraded completion, Judgement degraded scope, and two Shell lifecycle messages. No stabilization
gate is failing.

## Constraint on later waves

Waves 3–6 may strengthen stage contracts and disposable stores, but may not add another product
orchestrator. Wave 7 owns the shared host-neutral workflow migration and must satisfy the deletion
checklist in `WORKFLOW-PATHS.md`. Wave 8 validates the resulting single path against disposable forests
and production-shaped scale.
