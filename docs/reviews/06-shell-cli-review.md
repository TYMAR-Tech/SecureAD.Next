# Review 06 — Shell and CLI reachability and operator truthfulness

**Reviewed:** 2026-08-28  
**Reviewer/model:** GitHub Copilot  
**Baseline:** `review-baseline-2026-08-28` (`d36ddb4`)  
**Status:** Findings open; no production correction accepted by this document

## Executive summary

The Shell has a strong preflight and consent model. It preserves discovery-provided domain identities,
uses three-state facts instead of unchecked booleans, refreshes plans after operator changes, names
warnings by domain, and does not convert dismissal or cancellation into consent. It also protects
sealed Evidence when later analysis fails and distinguishes unread evidence, unjudged bundles, and
judged bundles with no findings.

The hosts do not yet represent one product workflow. Shell captures, derives and judges; CLI captures
and derives but never judges or exposes findings. Both hosts own sequencing independently. This has
already produced different outcomes and wording, and it will become unsafe when derived-fact rules are
introduced because Shell currently decides globally that Judgement should continue after Derivation
fails.

Several operator-visible claims are false or incomplete. Shell says every closure completed although
Stage 2a persists no closures and can report Completed over incomplete derivation. Post-capture
cancellation says the run recorded why it stopped even though only capture writes a run outcome.
CLI returns exit code 0 when automatic derivation fails and its global exception boundary can say no
bundle exists after Evidence was sealed. Durable run-library summaries show only Evidence state, while
analysis and rule degradation can disappear once the transient completion screen is closed.

These findings reinforce Review 03: Shell and CLI should invoke one production application workflow,
and operator outcomes should be read from persisted stage records rather than assembled separately by
each host.

## Production workflows

```text
Shell
  App composition
  -> NewAuditViewModel.OpenAsync
  -> plan + validate + operator review/attestations
  -> CaptureLauncher -> CaptureSession -> sealed Evidence
  -> DerivationLauncher -> Stage2aRun -> DerivationReader
  -> JudgingLauncher -> JudgingRun -> JudgementReader
  -> completion wording
  -> open Assets tree/findings

CLI
  parse arguments
  -> preview OR validate OR capture
  -> CaptureSession -> sealed Evidence
  -> Stage2aRun derive
  -> exit
  -> no Judgement, findings, or run opening
```

## Verified strengths

### S-01 — Preflight uncertainty remains visible

Shell maps unanswered, yes and no into `Established` rather than a boolean. Controller service,
connection rung, PDC status, password-settings access and site knowledge remain distinct. Review text
names domain-specific warnings rather than presenting unattributed repeated messages.

### S-02 — Exclusion consent is explicit and per run

The UI preserves NamingContext/FQDN pairs from discovery, distinguishes chosen exclusions from domains
with no candidates, gathers reason/note/operator/authorizer/time, and does not reuse prior attestations.
Dismissing the attestation prevents the run rather than silently excluding the domain.

### S-03 — Sealed Evidence survives later-stage faults

Derivation and Judgement exceptions are caught separately so a later-stage defect does not make the
operator recapture a forest. Error wording normally states that Evidence remains safe and analysis can
be repeated.

### S-04 — Results distinguish several important silences

Assets and findings views separate no run, active capture, unreadable Evidence/Judgement, unjudged
bundle, and a judgement that found nothing. Object listings carry shortfall, tree gaps are visible, and
malformed permission/parser details remain available.

### S-05 — CLI preflight is noninteractive and explicit

Unknown arguments and malformed controller overrides are refused. Preview writes no run directory.
Validate prints every domain, controller faults, skipped partitions, PDC use and incomplete ranking
inputs; it does not block unattended work on prompts.

## Findings

## H-01 — Shell and CLI implement different audit products

**Severity:** Critical  
**Confidence:** High  
**Release blocker:** Yes, before correction waves and derived rules  
**Status:** Confirmed

### Evidence

Shell owns `capture -> derive -> judge`; CLI owns `capture -> derive`. There is no shared application
workflow above the stage coordinators. CLI has no judging command, findings output, or rule-degradation
result. Both hosts separately decide ordering, cancellation and exit/report behavior.

### Customer consequence

The same intent produces findings in Shell and no findings in CLI. Future changes can be applied to one
host and not the other, with no type or production-path test forcing agreement.

### Recommended correction

Create a host-neutral application workflow that executes and records stages. Shell and CLI provide
presentation, operator interaction and cancellation only. Stage policy—especially which rules may run
when Derivation is absent—belongs to Judgement/input declarations, not a host.

## H-02 — Shell falsely says every closure completed

**Severity:** Critical  
**Confidence:** High  
**Release blocker:** Yes  
**Status:** Confirmed

### Evidence

For `DerivationRunState.Completed`, Shell reports “Every closure was completed”
(`NewAuditViewModel.cs:1739-1747`). Review 02 established that Stage 2a persists no closure products and
can return Completed while persisted completeness is false.

### Customer consequence

An operator receives a stronger statement than the artefact supports.

### Recommended correction

Remove closure claims until products exist. Build stage wording from one persisted derivation summary
that includes product presence, phase outcomes and completeness. Add a production-launcher-to-view
integration test.

## H-03 — Post-capture cancellation says an outcome was recorded when it was not

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes  
**Status:** Confirmed

### Evidence

`StartAsync` catches cancellation from capture, derivation or judgement and always says “The run
recorded why it stopped” (`NewAuditViewModel.cs:1629-1632`). Capture writes `run-outcome.json`; cancelled
Derivation/Judgement leaves sealed Evidence and partial/previous analysis artefacts but no run outcome.

### Customer consequence

An operator searching for the promised cancellation record will not find one and cannot tell which
post-capture stage was stopped from the durable run state.

### Recommended correction

Persist per-stage execution/outcome state or append an authoritative analysis event. Word cancellation
from observed artefacts: Evidence sealed, derivation/judgement stopped, previous generation preserved or
no analysis produced.

## H-04 — Derived-rule execution policy is hard-coded in the Shell

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes, before derived rules  
**Status:** Confirmed

### Evidence

Shell catches Derivation failure and always proceeds to Judgement because the two current rules are
Evidence-only (`NewAuditViewModel.cs:1669-1719`). Once rules have mixed input requirements, this global
host decision is wrong in both directions: it can run a derived rule without facts or withhold an
Evidence-only rule unnecessarily.

### Recommended correction

Judgement schedules rules from declared typed inputs. Missing Derivation makes only dependent rules
not-judged. Hosts call one workflow and render the persisted result.

## H-05 — CLI reports successful automation when automatic derivation fails

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes for unattended audit claims  
**Status:** Confirmed

### Evidence

After capture, `Derive(... afterCapture: true)` prints failure but returns exit code 0
(`Program.cs:187-192, 252-263`). The command automatically performs derivation as part of the requested
workflow, yet schedulers cannot distinguish complete analysis from Evidence-only capture.

### Customer consequence

Scheduled jobs and CI can record success while required analysis is absent.

### Recommended correction

Define stage-aware exit status. A sealed capture may be preserved while the overall audit exits
non-zero/degraded. Emit a machine-readable summary naming each stage and artefact.

## H-06 — CLI global fault wording can falsely say no bundle exists

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes  
**Status:** Confirmed

### Evidence

Main's global cancellation/fault handlers say “No bundle was produced” (`Program.cs:75-90`). Derive
handles cancellation locally, but an unexpected exception after sealing—or future Judgement—can escape
to this boundary. Shell already inspects `BundleDirectory` before making this claim.

### Recommended correction

The shared workflow should return/persist stage and artefact state. Last-resort handlers inspect that
state and never assume capture failed because a later stage threw.

## H-07 — Durable run summaries omit analysis and coverage degradation

**Severity:** High  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Evidence

Run library maps any intact Evidence bundle to “Finished” and intentionally does not open coverage
(`RunSummaryViewModel.cs:18-20, 117-143`). It does not show excluded/missing domains, SYSVOL gaps,
Derivation state, Judgement state, or unfinished rules. The one-time completion screen may be the only
place degradation appears.

### Customer consequence

A reopened run can look fully finished although analysis failed or scope was excluded. Operators cannot
triage the library by audit usability.

### Recommended correction

Add a lightweight persisted run summary/manifest or bounded readers for stage and coverage status.
Display separate Evidence, Derivation and Judgement states; never collapse them into one “Finished.”

## H-08 — Findings view omits rule-level degradation

**Severity:** High  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Evidence

Judgement stores rule outcomes, missing inputs and affected counts. Findings pages return only findings
plus the number of rules run. Assets UI can show findings from a degraded judgement without an adjacent
list of unfinished rules. The transient completion wording says only “at least one rule.”

### Customer consequence

Partial findings can be viewed later without the information needed to know which checks are absent.

### Recommended correction

Expose a judgement-gaps summary beside every findings grid: rule ID/name, outcome, typed reason and
affected count. Filters/pages must never separate findings from their assessment status.

## H-09 — Cached Evidence is not reverified for same-path replacement

**Severity:** Medium  
**Confidence:** Medium  
**Release blocker:** No  
**Status:** Needs reproduction

### Evidence

`BundleAssetSource` caches the open `BundleReader` when the requested path matches and verifies the seal
only on first open (`BundleAssetSource.cs:178-196`). If files are externally replaced at that path, the
Shell can continue reading the old handle while library/file state reflects new bytes.

### Recommended correction

Reproduce Windows/SQLite replacement behavior. Either treat a selected bundle as a pinned generation
and display its fingerprint, or provide explicit refresh that closes and reverifies. Do not silently
mix cached and current artefact state.

## H-10 — Shell/CLI production behavior lacks production-boundary tests

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes for correction acceptance  
**Status:** Confirmed

### Evidence

Shell tests inject fake launcher outcomes. CLI tests call `CommandLine.Parse`; no process tests assert
stdout/stderr/exit codes. No test runs real Capture/Derivation/Judgement launchers through a host and
reads persisted artefacts.

### Recommended correction

Implement Review 03 Tier 5 workflow tests and process-level CLI tests. Reproduce H-02, H-03, H-05 and
H-06 before fixing them.

## Host-parity matrix

| Capability | Shell | CLI |
|---|---|---|
| Preview | Automatic plan/preflight surface | `--preview` |
| Validate all domains | Yes | `--validate` |
| Controller overrides | Yes | Yes |
| Per-run exclusion attestation | Yes | No |
| Capture | Yes | Yes |
| Automatic derivation | Yes | Yes |
| Standalone derivation | No dedicated host command | `--derive` |
| Judgement | Automatic | No |
| Findings/results browser | Yes | No |
| Actionable rule degradation | Partial/transient | No |
| Machine-readable stage status | No | No |

## Recommended correction order

1. Finish Review 07 and accept the shared workflow/stage-state contract.
2. Build production-boundary tests for H-02/H-03/H-05/H-06.
3. Implement one host-neutral capture→derive→judge workflow with typed stage outcomes.
4. Move rule scheduling policy into Judgement typed-input resolution.
5. Build durable run summary and judgement-gap readers/presentation.
6. Add CLI judgement/parity and machine-readable status according to owner workflow needs.
7. Resolve/reproduce same-path cache behavior.

## Files read fully

- Shell composition root, services, launchers, settings and major view models/views
- CLI command surface and program workflow
- Relevant Evidence/Derivation/Judgement readers and run-library types
- Shell, CLI, component and architecture tests cited above

## Validation performed

- Both production workflows traced end to end.
- Host sequencing and wording checked against persisted artefact behavior from Reviews 01–05.
- Production-reference and test-boundary searches performed.
- No production or test code changed.
- Build/tests: deferred to publication validation because this review adds documentation only.
