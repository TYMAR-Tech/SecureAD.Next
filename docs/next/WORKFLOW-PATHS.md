# Workflow path inventory

**Status:** Current production/developer path inventory  
**Authority:** [`WORKFLOW.md`](WORKFLOW.md) defines the workflow; this file tracks every implementation path that can start or sequence its stages.

## Purpose

A replacement is incomplete while the old route remains callable. This inventory prevents a shared
workflow from being added beside the Shell and CLI implementations while all three survive. Every
path below therefore has one disposition: retain as a stage API, retain as presentation/navigation,
or replace and delete at a named correction event.

A path is not called dead merely because another path overlaps it. Production references were checked
before assigning a disposition. Conversely, a developer script is not called a product feature merely
because it can invoke production assemblies.

## Production entry and sequencing paths

| Path | Current callers | Decisions it currently owns | Disposition | Deletion event |
|---|---|---|---|---|
| `SecureAD.Cli.Program.Main` / `RunAsync` | Process entry point | CLI parsing, cancellation and capture/derive sequence | Replace sequencing; retain only host parsing/rendering | Wave 7 shared workflow adoption |
| `SecureAD.Cli.Program.Derive` | `RunAsync`, `--derive` | Opens derivation log, chooses bulk budget, cancellation/error wording and post-capture exit semantics | Replace and delete | Wave 7 shared workflow supports full audit and derive-only modes |
| `NewAuditViewModel.StartAsync` | Shell Start command | capture → derive → judge order, cancellation and aggregate operator wording | Replace sequencing; retain only command binding/view state | Wave 7 shared workflow adoption |
| `NewAuditViewModel.DeriveAsync` | `StartAsync` | derivation invocation, progress and result wording | Replace and delete | Wave 7 shared workflow reports typed stage events |
| `NewAuditViewModel.JudgeAsync` | `StartAsync` | judging invocation, progress and result wording | Replace and delete | Wave 7 shared workflow reports typed stage events |
| `CaptureLauncher` / `ICaptureLauncher` | Shell composition root and New Audit view model | Shell-to-Audit translation and `CaptureSession` construction | Replace and delete as an orchestration adapter | Wave 7 shared workflow accepts capture request/attestations directly |
| `DerivationLauncher` / `IDerivationLauncher` | Shell composition root and New Audit view model | background dispatch, logging, bulk budget, readback summary | Replace and delete | Wave 7 shared workflow owns dispatch/logging/readback |
| `JudgingLauncher` / `IJudgingLauncher` | Shell composition root and New Audit view model | background dispatch, logging, `RuleCatalogue.All`, readback summary | Replace and delete | Wave 7 shared workflow owns dispatch/logging/readback |
| `App.xaml.cs` launcher construction | Shell process startup | Concrete host wiring | Retain composition root, replace launcher wiring | Wave 7 shared workflow is wired once here |

The interfaces above are legitimate test seams today, not unused abstractions. Their production callers
and fakes migrate in the same Wave 7 change; they are not retained as wrappers over the replacement.

## Stage APIs

| Path | Role | Disposition |
|---|---|---|
| `CaptureSession` | The one production entry into discovery, preflight and capture | Retain; shared workflow calls it |
| `Stage2aRun.Derive` | The derivation stage boundary | Retain until renamed/replaced by the accepted Derivation product contract; do not wrap merely to preserve this name |
| `JudgingRun.Judge` | The judgement stage boundary | Retain; shared workflow calls it through the application workflow |
| `RuleCatalogue.All` | The single executable rule schedule | Retain in Judgement; no host may maintain another rule list |
| `BundleReader`, `DerivationReader`, `JudgementReader` | Offline artefact boundaries | Retain; shared workflow and presentation consume typed results |

These APIs are intentionally reusable stage boundaries. Calling one directly in a focused test does not
create a second product workflow.

## Presentation and navigation paths

| Path | Role | Disposition |
|---|---|---|
| `NewAuditDialog` | Collect and confirm operator input | Retain; it must not sequence stages |
| `HomeViewModel` / `ShellViewModel` | Shell navigation | Retain presentation responsibility |
| `RunLibraryViewModel` | List/open completed runs | Retain presentation responsibility |
| `IRunOpener` / `RunOpener` | Testable navigation seam from run list/new audit to results | Retain unless the Shell navigation design replaces it; it does not run a stage |
| `AssetsViewModel` and findings views | Read/display offline artefacts | Retain; they must not create or rebuild artefacts |

## Developer-only paths

| Path | Current purpose | Product status | Disposition and deletion event |
|---|---|---|---|
| `next/tools/judge-bundle.ps1` | Run Judgement and inspect/explain stored rule outcomes during development | Non-product diagnostic tool | Retain until the shared CLI workflow can judge an existing bundle and provide equivalent explain diagnostics; delete in that same change |
| `next/tools/Build-DecisionIndex.ps1` | Generate the decision index | Repository maintenance, not application workflow | Retain |
| `next/tools/Replace-InventoryRow.ps1` | Historical documentation maintenance | Repository maintenance, not application workflow | Retain while its input format exists |
| `next/tools/SecureAD.Gallery` | UI component gallery | Developer UI tool, not application workflow | Retain while Shell visual development uses it; it may not invoke capture/derive/judge |

## Duplicate decisions that must move once

Wave 7 must move these decisions into one host-neutral application workflow and remove their current
copies from Shell and CLI:

- capture → derive → judge stage order;
- whether Evidence remains a successful durable outcome when later stages fail;
- cancellation meaning before and after Evidence sealing;
- stage logging and durable stage summaries;
- `ExpansionBudget.Bulk` selection for whole-bundle derivation;
- `RuleCatalogue.All` selection for a complete audit;
- progress event vocabulary;
- stage failure/degraded outcome aggregation;
- post-stage readback used to report what was actually persisted; and
- process exit classification versus Shell operator messaging.

Host code may translate typed workflow events into console text or view state. It may not recalculate the
outcome or choose which stage runs next.

## Deletion checklist for every replacement

A workflow migration is complete only when all applicable checks are true:

1. The replacement has a production caller in both intended hosts.
2. The old sequencing method, launcher or adapter is deleted, not delegated to the replacement.
3. Its interface, fake, registration and tests are deleted or migrated in the same commit.
4. Repository search finds no code/document claiming the old path remains current.
5. The public surface register and layer type tables no longer name deleted types.
6. Architecture reachability tests prove each target stage through the shared workflow.
7. Shell/CLI equivalence tests prove the same request yields equivalent artefacts and typed outcomes.
8. Focused direct stage tests remain only for stage behavior, not as evidence of product reachability.
