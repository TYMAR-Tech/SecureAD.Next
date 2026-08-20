# I — Output

What SecureAD writes out of a bundle to somewhere else: CSV packages, self-contained HTML
reports, and the catalogue of SQL reports the Reports page runs.

Branch F owns whether a run may be *used* as a source; this branch owns what is *produced* once it
is eligible. Branch C owns the bundle layout on disk; this branch owns everything written outside
it.

## The flow

1. The user loads a run. `audit.db` is opened through `DatabaseConnectionFactory.OpenReadOnly`
   (C4), which attaches the suppression sidecar and creates the temp views that every
   findings-bearing output reads.
2. The user clicks one of exactly four buttons in the shell header
   (`AppShell.xaml:113–122`): **Export**, **Forest**, **Hygiene**, **Delegation**. There is no
   fifth output entry point in the application chrome.
3. **Export** opens `ExportProfileDialog`, pre-selecting `SecurityFull` or `ConfigurationFull`
   from `MainViewModel.SecurityModeCompleted`, and passing in the coverage warning obtained from
   `GetExportCoverageWarning()` for display.
4. On confirm, `ExportCoordinator.ExportProfileAsync` calls
   `OutputEligibilityEvaluator.Evaluate(connection, dbPath, Export)`. That inspects the file via
   `RunDatabaseInspector` (F17): missing file, missing `run` table, or not `IsFinalizedComplete`
   each produce a block message and the export stops with a status line.
5. If eligible, the evaluator computes a warning — for `Export`, by asking
   `FindingsService.GetRunCoverageState()` (E4) for incomplete modules — and returns it alongside
   `CanProceed: true`.
6. `ExportPackageService` iterates the profile's `ExportDefinition` list, calling
   `TabExportService.ExportToCsvAsync` per definition. Each writes one RFC 4180 CSV, UTF-8 with
   BOM, streamed in 1,000-row batches, with leading `=`/`+`/`-`/`@` neutralised.
7. It then writes `export_manifest.json` (generated-UTC, security-mode flag, profile id and name,
   database path, coverage warning, and per-file row counts, source views and column lists) and a
   human-readable `README.txt` carrying the same facts.
8. **Forest** / **Hygiene** / **Delegation** each open a `SaveFileDialog` in `AppShell.xaml.cs`
   and call the matching `MainViewModel.Generate*ReportAsync`, which builds an `ExportCoordinator`
   and calls the generator.
9. Each generator re-runs `OutputEligibilityEvaluator.EnsureEligible` with its own
   `OutputEligibilityKind` — a second, throwing check behind the coordinator's non-throwing one.
10. Forest and Delegation read `DerivedPhaseVerdicts` and `DerivedHealthReader` (D2). Headline
    counts go through `VouchedCount.Read`, which refuses to run the query at all unless every
    phase behind the number recorded success, rendering the word `unknown` in the slot instead.
    Account Hygiene does neither.
11. Each generator calls `ReportCoverageWarningBuilder.BuildWarning` with its own report kind,
    which checks that kind's required `CoverageModules` against `fact_coverage` for every domain
    in `dim_object`.
12. HTML is composed into a `StringBuilder` — health callout, then coverage callout, then sections
    — and written as a single self-contained file with embedded CSS.
13. Separately, the **Reports** page (`ReportsView`) lists `ReportCatalog.All` — 46 SQL report
    definitions, of which 17 are `Diagnostics` and hidden unless advanced mode is on. The user
    picks one, or writes custom SQL, and runs it into a `DataTable`.
14. From there **Export CSV** writes the grid with `ReportsTabViewModel`'s own private CSV
    escaper, and **Export HTML** hands the `DataTable` to `TabularHtmlReportGenerator`, capped at
    5,000 rows with a truncation note. Neither consults `OutputEligibilityEvaluator`.

## Components

### I1 — Output eligibility gate

- **Owns:** Whether a loaded database may produce any output at all, and the block message when
  it may not.
- **Layer:** Infrastructure
- **Depends on:** F17 (`RunDatabaseInspector`), E4 (coverage state), C19 (`DashboardQueryService`),
  I2
- **Implemented by:** `src/SecureAD.Infrastructure/Export/OutputEligibilityEvaluator.cs` (178) —
  also declares `OutputEligibilityKind` and `OutputEligibilityResult`
- **Non-obvious:** F recorded that `OutputEligibilityKind.Compare` is a fully tested gate with no
  caller. Tracing the remaining five: **`Export`, `ForestReport`, `DelegationReport` and
  `AccountHygieneReport` all have live callers**; **`Open` has none** —
  `git grep "OutputEligibilityKind.Open"` returns only this file's three message builders and its
  tests. So two of six kinds are message-only. The `Open` case is the more interesting of the two,
  because its three bespoke messages ("Cannot load *X* because…") are the only ones written in the
  voice of the library, and nothing in the library calls them. The three-overload shape is also
  load-bearing in an unobvious way: `Evaluate(connection, kind)` derives the path from
  `connection.DataSource` and returns `null` for `:memory:`, which is what lets the whole gate be
  exercised in tests without a file on disk.

### I2 — Report coverage requirement map

- **Owns:** Which capture modules each narrative report needs, and the warning text when they are
  not `Complete` or `Skipped`.
- **Layer:** Infrastructure
- **Depends on:** B (coverage emission), C (`fact_coverage`, `dim_object`)
- **Implemented by:** `src/SecureAD.Infrastructure/Export/ReportCoverageWarningBuilder.cs` (132)
- **Non-obvious:** The requirement map is keyed by **string** — `"Forest"`, `"Delegation"`,
  `"AccountHygiene"` — and throws `ArgumentException` on an unknown key, while I1 already has an
  enum naming exactly those three reports and translates enum to string at the call site. A fourth
  report added to the enum but not to this dictionary throws at generation time rather than
  failing to compile. Its `LoadDomains` query carries a performance comment worth keeping: an
  earlier version selected `distinguished_name` alongside `domain_fqdn` under `DISTINCT`, which
  made every row distinct and forced a full scan of `dim_object`.

### I3 — Degraded-output presentation

- **Owns:** How a report says, at the top and once, that it may be understating the forest.
- **Layer:** Infrastructure
- **Depends on:** D2 (`DerivedHealth`), I2
- **Implemented by:** `src/SecureAD.Infrastructure/Export/CoverageWarningPresentation.cs` (98)
- **Non-obvious:** **This is I's answer to the question G and H both failed.** It carries *two*
  callouts and its own XML doc explains why they must not be merged: `AppendReportCallout` is
  about what the capture reached in the forest, `AppendDerivedHealthCallout` is about what the
  analysis did with what was captured, and a run can be sound on one axis and not the other. The
  health callout's remark also records what it replaced — per-section `ViewExists` probes that
  answered a missing view with an empty section, so a degraded run rendered as a report with
  silently absent sections, indistinguishable from a forest that genuinely had none of those
  objects. `BuildConfirmationPrompt` is the third member and is the one with a reachability
  problem — see I20.

### I4 — Vouched counts

- **Owns:** A headline number an artefact is allowed to state, or the named phase that forbids it.
- **Layer:** Infrastructure
- **Depends on:** D2 (`DerivedPhaseVerdicts`), I5
- **Implemented by:** `src/SecureAD.Infrastructure/Export/VouchedCount.cs` (70)
- **Non-obvious:** The best-reasoned type in the branch, and the argument in its remarks is one a
  rebuild should carry forward verbatim: there are two routes to a false zero and they need the
  same answer. A missing view makes the query throw; a view over a table no phase populated makes
  the query *succeed* and honestly return zero. A view-existence probe catches only the first, and
  the second is harder to notice precisely because nothing goes wrong. So the phase verdict
  decides and the query is not run at all — an absent value is therefore always a fact about the
  capture and never about the forest. `Display` returns the literal word `unknown` rather than a
  dash, stated to be so the gap is visible to someone skimming. It is `internal`, used by I10 and
  I11 only, and **not** by I12.

### I5 — Report query helpers

- **Owns:** Scalar SQL, HTML escaping, DN truncation and view-existence probing shared by the
  narrative generators.
- **Layer:** Infrastructure
- **Depends on:** C2 (view definitions)
- **Implemented by:** `src/SecureAD.Infrastructure/Export/ReportHelpers.cs` (90)
- **Non-obvious:** `SectionViewAvailable` is a one-line alias for `ViewExists` that exists purely
  to carry documentation, and the documentation is the point: an absent view means the run's
  `CreateViews` phase did not complete, and because `CreateViews` executes its DDL untransacted, a
  failure partway leaves earlier views present and later ones absent — which is why the D2 health
  verdict alone cannot replace the probe, and why the probes could not simply be deleted when I3
  arrived. `ViewExists` checks `sqlite_temp_master` as well as `sqlite_master`, because the
  suppression-dependent findings views are per-connection temp views (C2).

### I6 — CSV streaming and the grid export catalogue

- **Owns:** The canonical list of exportable views with their column order and deterministic sort,
  and the RFC 4180 writer that streams them.
- **Layer:** Infrastructure
- **Depends on:** C2 (view definitions), C4
- **Implemented by:** `src/SecureAD.Infrastructure/Export/TabExportService.cs` (284) — also
  declares `ExportDefinition`
- **Non-obvious:** Every definition carries an explicit `ORDER BY` down to a tiebreaker column, so
  two exports of the same database are byte-identical — that is what makes a CSV export diffable,
  and it is a decision no other output path in the branch made. `NeutralizeCsvFormula` prefixes
  `=`, `+`, `-`, `@` with an apostrophe, which is CSV-injection defence and matters here because
  export targets are opened in Excel. Two of its public methods — `ExportAllAsync` and
  `ExportAllSecurityAsync` (105 lines between them) — **have no caller in `src/`**:
  `ExportPackageService` uses `ExportToCsvAsync` per definition instead. They are the pre-package
  export path, left behind when I8 superseded them.

### I7 — Export profiles

- **Owns:** The five named subsets of I6's definitions a user can choose between.
- **Layer:** Infrastructure
- **Depends on:** I6
- **Implemented by:** `src/SecureAD.Infrastructure/Export/ExportProfile.cs` (86)
- **Non-obvious:** `SelectDefinitions` looks definitions up **by `FileName` string** and throws
  `InvalidOperationException` if one is absent — so renaming an entry in I6 breaks profile
  construction in a static initialiser, at first touch, with no compile-time warning.
  `RequiresSecurityMode` is declared on every profile and is read in exactly one place (I8, to
  stamp the manifest); nothing anywhere *enforces* it, so a `SecurityFull` profile selected
  against a configuration-mode database produces empty CSVs and a manifest that says
  `security_mode: true`.

### I8 — Export package writer

- **Owns:** Turning a definition set into a directory of CSVs plus its two metadata files.
- **Layer:** Infrastructure
- **Depends on:** I6, I7, I9
- **Implemented by:** `src/SecureAD.Infrastructure/Export/ExportPackageService.cs` (172)
- **Non-obvious:** Four overloads of `ExportAsync`/`ExportAllAsync`/`ExportProfileAsync` funnel to
  one private method; only two of the four are reached from production. It writes the README by
  hand rather than serialising, so the two artefacts can and do drift. **Nothing calls back into
  I1** — the service takes `coverageWarning` as an already-computed `string?` parameter, which
  means a caller that forgets to pass it produces a package that silently claims no coverage
  problem.

### I9 — Export package manifest

- **Owns:** The machine-readable statement of what an export package contains.
- **Layer:** Infrastructure
- **Depends on:** none
- **Implemented by:** `src/SecureAD.Infrastructure/Export/ExportManifest.cs` (71)
- **Non-obvious:** **This is the branch's provenance record, and it is missing the two facts that
  would make it evidence.** It carries `GeneratedUtc` — when the *export* was made — but not
  `SealedUtc`, so nothing states when the run it describes was sealed. It carries `DatabasePath`
  but no `run_id`, so a package cannot be tied back to a run in the library. It carries
  `CoverageWarning` as prose but no structured coverage verdict, and it says nothing about
  suppressions. `ExportVersion` is hard-coded to `1` and is never read by anything. The result is
  directly answerable to the provenance question: **coverage and findings can be exported
  separately.** `ExportProfiles.Executive` and `FindingsEvidence` both include `coverage`, so
  those two packages are self-describing by construction — but `RawData` does too while omitting
  findings, and a reader handed the `findings.csv` alone has a severity-ranked list with no
  coverage statement attached to any row beyond the per-finding `coverage_complete` flag.

### I10 — Forest security report

- **Owns:** The whole-forest HTML narrative: severity profile, domains, control edges, escalation
  paths, coverage, password policy, staleness, trusts.
- **Layer:** Infrastructure
- **Depends on:** I1, I2, I3, I4, I5, D2, C2, E (findings)
- **Implemented by:** `src/SecureAD.Infrastructure/Export/ForestReportGenerator.cs` (394),
  `ForestReportGenerator.Sections.cs` (469)
- **Non-obvious:** The three `*CountPhases` arrays are the most careful piece of reasoning in the
  branch. `FindingCountPhases` requires `ControlEdges` and `EscalationPaths` in addition to
  `Findings`, because rule evaluation reads `fact_control_edge` and `fact_escalation_path` — so a
  findings total computed after either of those failed "is a smaller number than the forest
  warrants, arrived at without error." The arrays are built from `DerivedAnalysisPipeline`'s own
  constants rather than string literals, with a comment recording that a reader matching a phase
  name nothing writes has happened once in this codebase and went unnoticed for the life of the
  feature. Its finding counts come from `v_grid_findings` with **no suppression filter**, so
  headline severity counts include suppressed findings and the report never says how many.

### I11 — Delegation report

- **Owns:** The delegation HTML narrative, ordered by risk: Unconstrained → Constrained → Protocol
  Transition → RBCD → Shadow Credential → Protected → Bundles.
- **Layer:** Infrastructure
- **Depends on:** I1, I2, I3, I4, I5, D2, C2
- **Implemented by:** `src/SecureAD.Infrastructure/Export/DelegationReportGenerator.cs` (565)
- **Non-obvious:** The only generator gated on `IsDbLoaded` rather than `HasSecurityModeData`,
  because delegation facts are captured rather than derived — it is the one narrative report a
  configuration-era bundle can still produce. Its `QueryActionPriorities` takes the type counts it
  already computed and ranks them in C#: a third, independent prioritisation, alongside E12's
  `ActionPriorityCalculator` and the `finding_top_actions` catalogue entry in I14. Its sections are
  inlined rather than split into a `.Sections.cs` partial like its two siblings, for no traceable
  reason.

### I12 — Account hygiene report

- **Owns:** The account-lifecycle HTML narrative: staleness buckets, password age, disabled,
  never-logged-on, per-domain.
- **Layer:** Infrastructure
- **Depends on:** I1, I2, I5, C2
- **Implemented by:** `src/SecureAD.Infrastructure/Export/AccountHygieneReportGenerator.cs` (370),
  `AccountHygieneReportGenerator.Sections.cs` (368)
- **Non-obvious:** **The odd one out, and the gap is silent.** It reads neither
  `DerivedPhaseVerdicts` nor `DerivedHealthReader`, uses no `VouchedCount`, and never calls
  `AppendDerivedHealthCallout`. So the one narrative report that describes accounts — the most
  likely to be handed to someone outside the security team — is the one that cannot say its
  analysis was incomplete, and states its counts as confident integers under exactly the
  conditions I4 was written to prevent. Nothing marks this as intentional; both siblings acquired
  the machinery and this one did not.

### I13 — Ad-hoc tabular HTML renderer

- **Owns:** Rendering an arbitrary result set as a standalone shareable HTML document.
- **Layer:** Infrastructure
- **Depends on:** I5
- **Implemented by:** `src/SecureAD.Infrastructure/Export/TabularHtmlReportGenerator.cs` (184)
- **Non-obvious:** Deliberately duplicates the narrative generators' CSS rather than sharing it,
  with a comment saying so — "so exports from either path are recognisably the same product." That
  is a defensible trade at 30 lines of CSS and it is worth recording as intentional, because it
  reads as an oversight. Its `MaxRows = 5000` cap is the one place in the branch where truncation
  is *stated in the artefact* ("Showing the first 5,000 of N rows. Export to CSV for the complete
  data set."), rather than silently applied.

### I14 — The SQL report catalogue

- **Owns:** 46 named, described, categorised read-only SQL reports over the derived store.
- **Layer:** Infrastructure
- **Depends on:** C2 (views), C (`dim_*`/`fact_*`), E (`dim_suppression`), A
  (`DefaultOwnerCatalog`)
- **Implemented by:** `src/SecureAD.Infrastructure/Reports/ReportCatalog.cs` (1,134) —
  `ReportDefinition`, `IReportCatalog`, `DefaultReportCatalog`, `ReportCatalog.All`
- **Non-obvious:** Checked entry-by-entry against the expectation that the catalogue outruns its
  UI. **It does not.** All 46 are reachable: 29 are listed by default and the 17 `Diagnostics`
  entries appear when advanced mode is enabled, with `ReportCountLabel` explicitly telling the
  user how many are hidden. `ReportCatalogExecutionTests` executes every entry's SQL against a
  real `DerivedStore` with `CreateViews()` and a factory read connection, precisely so a report
  referencing a non-existent column fails in CI rather than when a user clicks Run — the test's
  own comment says structural tests pass such a report. This is the first complete subsystem the
  map has traced that turns out to be *fully wired*. Two substantive notes. Only **two** of the 46
  filter suppression (`f.suppressed = 0` plus a `dim_suppression` `NOT EXISTS`, in
  `finding_noise_profile` and `finding_top_actions`); the other findings reports return suppressed
  rows unflagged. And `capture_scope_summary` is a naming casualty of the 2026-08-02 scoped-capture
  removal — its SQL is a per-domain, per-class object census against `dim_object` and has nothing
  to do with capture scope.

### I15 — Reports tab runner and its private exporters

- **Owns:** Running a catalogue report or custom SQL, and writing the result to CSV or HTML.
- **Layer:** UI
- **Depends on:** I13, I14, C4
- **Implemented by:** `src/SecureAD.UI/ViewModels/ReportsTabViewModel.cs` (406),
  `src/SecureAD.UI/Views/ReportsView.xaml` (204), `ReportsView.xaml.cs` (15)
- **Non-obvious:** Carries its **own** `EscapeCsv` and `NeutralizeCsvFormula` — a second CSV
  writer, weaker than I6's: it quotes on comma, quote and `\n` but not bare `\r`, and does not
  quote leading or trailing spaces. The formula-injection defence was copied across correctly; the
  RFC 4180 correctness was not. This entire path also **bypasses I1**: no eligibility check, no
  coverage warning, no derived-health callout. A user can run `findings_by_rule` against a
  non-finalised database, export it to HTML, and hold an artefact whose only provenance is the
  database file name in the footer. `IsAwaitingSelection` exists because without it the results
  pane renders a column-less grid that reads as a broken page — a small, correct piece of
  empty-state design.

### I16 — Export orchestration

- **Owns:** Applying the eligibility gate and dispatching to the right writer or generator for a
  live database session.
- **Layer:** UI
- **Depends on:** I1, I6, I7, I8, I10, I11, I12
- **Implemented by:** `src/SecureAD.UI/ViewModels/ExportCoordinator.cs` (181)
- **Non-obvious:** `GetExportDefinitionForTab` maps tab ids to
  `TabExportService.ConfigurationExports[0..9]` **by numeric index**. Reordering I6's collection
  silently re-points every tab's export at the wrong view — the objects tab would export
  permissions, with no error and a correct-looking CSV. It is the sharpest coupling in the branch
  and it is invisible from either end. `DispatchStatus` reaches for `App.Current?.Dispatcher`,
  which makes an Infrastructure-shaped class WPF-bound; the `?.` means status is silently dropped
  in tests.

### I17 — Export façade on the shell view model

- **Owns:** Exposing output operations to the shell without exposing the connection.
- **Layer:** UI
- **Depends on:** I16
- **Implemented by:** `src/SecureAD.UI/ViewModels/MainViewModel.Export.cs` (78)
- **Non-obvious:** Every method constructs a **fresh** `ExportCoordinator`, and the four
  `Get*CoverageWarning` helpers each construct one to ask a single question — so the shell builds
  a coordinator, runs `RunDatabaseInspector` against the file and a coverage query against the
  database, purely to decide whether to show a warning string, then throws it away and builds
  another to do the export.

### I18 — Export profile dialog

- **Owns:** Letting the user choose a profile and an output folder, and reporting where the
  package landed.
- **Layer:** UI
- **Depends on:** I7, I17
- **Implemented by:** `src/SecureAD.UI/ExportProfileDialog.xaml` (93),
  `ExportProfileDialog.xaml.cs` (119),
  `src/SecureAD.UI/ViewModels/ExportProfileDialogViewModel.cs` (121)
- **Non-obvious:** The **only** output surface in the product that displays the coverage warning
  *before* the artefact is written; both the dialog body and its footer tell the user that
  coverage warnings, row counts, source views and columns are recorded in `export_manifest.json`.
  It computes `CompletedManifestPath` itself by string-joining `"export_manifest.json"` onto the
  output directory rather than reading the returned `ExportManifest`, so the path it shows is a
  guess that happens to be right.

### I19 — Shell output entry points

- **Owns:** The four buttons that are the entire user-facing output surface.
- **Layer:** UI
- **Depends on:** I17, I18
- **Implemented by:** `src/SecureAD.UI/Shell/AppShell.xaml:113–122`,
  `AppShell.xaml.cs:52–125` (≈ 95 lines)
- **Non-obvious:** Implemented as `Click=` code-behind handlers, each with its own inline
  `SaveFileDialog`, in a codebase that otherwise uses `[RelayCommand]` throughout. That is not
  merely a style difference: it is why I20 is dead, and it is why the three report buttons never
  show the coverage confirmation prompt. Two of them also disagree with the commands they shadow
  about default file name — `ForestSecurityReport.html` here, `SecureAD-Forest-Report.html` there.

### I20 — The unreachable export commands

- **Owns:** *(nothing reached)* — the intended MVVM export surface, including the coverage
  confirmation prompt.
- **Layer:** UI
- **Depends on:** I3, I17
- **Implemented by:** `src/SecureAD.UI/ViewModels/MainViewModel.Commands.cs:129–228, 290–330`
  (≈ 110 lines)
- **Non-obvious:** **Five `[RelayCommand]` methods — `ExportCurrentTab`, `ExportAllTabs`,
  `ExportForestReport`, `ExportDelegationReport`, `ExportAccountHygieneReport` — are bound in no
  XAML file.** `git grep "ExportForestReportCommand"` and its four siblings over `src/` return the
  generator attributes and nothing else; the only `ExportCsvCommand`/`ExportHtmlCommand` bindings
  found belong to I15, `NoLapsGridPage` and `HelpView`. The consequences are specific rather than
  cosmetic. First, `ConfirmCoverageIfNeeded` — the "coverage is incomplete for this report,
  continue?" prompt built by `CoverageWarningPresentation.BuildConfirmationPrompt` (I3) — is
  called from three sites, **all three inside this dead region**. The live shell path never asks.
  The HTML banner still appears inside the generated file, so the user is warned after the
  artefact exists, not before. Second, **single-tab CSV export is entirely unreachable**:
  `ExportCurrentTabAsync`, `CurrentTabExportFileName` and I16's ten-entry tab map exist solely to
  serve a command nothing invokes. Unlike G14 and H10, this is not a well-designed orphan worth
  salvaging wholesale — it is the *correct* version of a surface that was reimplemented worse in
  code-behind, and what should survive is the confirmation prompt.

### I21 — Grid-local CSV writer

- **Owns:** Exporting the LAPS-gap grid to CSV.
- **Layer:** UI
- **Depends on:** C2
- **Implemented by:** `src/SecureAD.UI/ViewModels/NoLapsGridViewModel.cs:121–156` (≈ 40 lines)
- **Non-obvious:** The **third** CSV writer, and the weakest: a hand-built header string, `$"..."`
  interpolation with hard-coded quotes around every field, and an `Esc` that doubles quotes only —
  no formula neutralisation, no newline handling, no BOM, no `ORDER BY` tiebreaker beyond
  `computer_name`. It is reachable (`NoLapsGridPage.xaml:22`), so a user can produce a
  formula-injectable CSV from the product through a supported button. It exists because
  `v_grid_laps_status` has no `ExportDefinition` in I6 — the gap is one missing table entry, not a
  missing capability.

### I22 — Export progress channel

- **Owns:** *(nothing)* — the per-export progress event shape.
- **Layer:** Core
- **Depends on:** K (progress transport)
- **Implemented by:** `src/SecureAD.Core/Progress/ExportProgressEvent.cs` (11),
  `ExportState.cs` (12), plus `IProgressPublisher.Publish(ExportProgressEvent)`,
  `IProgressObserver.OnExportProgress` and `SimpleProgressPublisher.Publish`
- **Non-obvious:** **Neither producer nor consumer.** `git grep` over `src/` finds no call to
  `Publish(ExportProgressEvent …)` anywhere, and both observer implementations —
  `MainViewModel.cs:1018` and `DashboardViewModel.RunLifecycle.cs:114` — are literally `{ }`. The
  whole channel is declared, transported and observed to no effect. This matters more than its 23
  lines: exports are the one long-running operation in the product with **no** progress reporting,
  and the mechanism to fix that was built and never connected. A rebuild should either wire it in
  I8's per-definition loop, which is exactly where it belongs, or delete it.

### I23 — Export error codes

- **Owns:** *(nothing)* — a taxonomy of export failures.
- **Layer:** Core
- **Depends on:** K (error taxonomy)
- **Implemented by:** `src/SecureAD.Core/Errors/ExportErrorCode.cs` (13)
- **Non-obvious:** One reference in `src/` (`AuditErrorCodes.cs`) and five in
  `AuditErrorCodesTests`. No export path produces one: I1 returns prose in `BlockMessage`, I8 lets
  `IOException` propagate, and I15/I16 catch `Exception` and interpolate `ex.Message` into a
  status line. Every export failure the user can see is an untyped string.

## Naming & taxonomy

| Current | Proposed | Why it matters |
|---|---|---|
| `ExportManifest` / `export_manifest.json` | `ExportPackageIndex` / `export_package_index.json` | F already flagged the collision with the bundle's `manifest.json` and proposed this exact rename. I confirms the need from the other side: `HelpViewModel.Content.cs:818` tells users the *bundle* contains a manifest, which nothing writes, while the artefact that genuinely exists on every export shares the word. Two artefacts, one noun, opposite fates. |
| `TabExportService` | `GridCsvExporter` | It is not tied to tabs — `ExportProfiles.FindingsEvidence` and `RawData` reach definitions no tab surfaces, and the *only* tab-shaped thing about it lives in I16. The name is why I15 and I21 each wrote their own CSV writer instead of adding an `ExportDefinition`: the class looks like it belongs to the grid shell. |
| `ExportDefinition` | `CsvExportView` | It defines a view, its columns and its sort. "Definition" says nothing, and the type is looked up by its `FileName` field (I7), which the name actively obscures. |
| `OutputEligibilityEvaluator.Evaluate(…, kind)` returning `WarningMessage` | split `Evaluate` from `DescribeCoverage` | The type conflates two questions — *may this proceed* and *what should the user be told* — and the second is why I17 constructs a whole coordinator to ask one thing. The `kind` parameter is only consulted for message wording and warning selection, never for the gate itself. |
| `ReportCoverageWarningBuilder.BuildWarning(conn, "Forest")` | key on `OutputEligibilityKind` | A string key beside an enum that already names the same three reports. The stringly-typed map is the only reason a missing entry is a runtime throw. |
| `capture_scope_summary` | `object_census_by_domain` | Scoped capture was removed on 2026-08-02. The SQL never had anything to do with it; the name now describes a capability the product does not have, in a report a user can run. |
| `ForestReportGenerator` / `DelegationReportGenerator` / `AccountHygieneReportGenerator` vs `TabularHtmlReportGenerator` | `*NarrativeReport` vs `ResultSetHtmlWriter` | Four types named `…ReportGenerator` where three compose many queries into an argued narrative and one renders whatever columns it was handed. `TabularHtmlReportGenerator`'s own remarks explain the distinction; the names hide it. |
| `DelegationReportGenerator` (I11) vs `DelegationReportViewModel` (H/J) | `DelegationExportReport` vs `LiveOuDelegationPanel` | Same phrase, two subjects: one writes an HTML file about the whole forest from stored evidence, the other queries live LDAP for a single OU and renders a panel. Nothing links them. |
| `VouchedCount` | keep | Listed to say so explicitly. It is unusual, and it is exactly right: it names the *warrant* rather than the value, which is the whole idea. |

## Would-do-differently

**One CSV writer, and the export definition is the only way to name a view.** Three exist — I6,
I15, I21 — and they disagree on correctness in ways that get worse the further from the canonical
one you go. I6 handles bare `\r`, leading and trailing spaces, formula injection, and streams in
batches with a deterministic tiebreaker sort. I15 handles two of those. I21 handles one. All three
are reachable from supported buttons, so which safety properties a user's CSV has depends on which
button they pressed. The fix is structural, not a rename: make `ExportDefinition` the only way to
express "this view is exportable", give `v_grid_laps_status` and the report `DataTable` path
entries, and delete the other two writers.

**Exports must state their provenance, and there is a ready-made place to put it.** I9 already
writes a structured metadata file on every package export — it is the branch's best structural
decision — but it records when the *export* ran, not what it exported. It should carry `run_id`,
`SealedUtc`, the coverage verdict as data rather than as a warning sentence, the active
suppression set size, and the profile. Right now an `export_manifest.json` cannot be used to
answer "is this file still current?" and a `findings.csv` handed on alone answers nothing about
the run behind it. H found no live answer carries `SealedUtc`; I confirms no exported artefact
does either. That is the same gap in both branches, and F owns the field.

**Suppressed and accepted findings should be excluded by default, and the exclusion should be
counted in the artefact.** Traced: `v_grid_findings` and `v_export_findings_evidence` both return
suppressed rows with an `is_suppressed` flag, and 44 of I14's 46 reports do not filter. I10's
headline severity counts run `SELECT COUNT(*) FROM v_grid_findings` with no predicate, so the
number on the front page of the forest report includes findings the organisation has formally
decided not to act on, and the report never says how many. The flag-and-let-the-reader-decide
approach is defensible for `findings.csv`, where a machine consumes it; it is not defensible for a
headline count in a document meant to be read. Exports should exclude by default and state
"*N* suppressed findings excluded" beside every count — which is a smaller change than it sounds,
because I4 already establishes the pattern of a number carrying its own caveat. E10 owns
suppression semantics; this is about whether the artefact is honest about them.

**The three narrative reports should share one skeleton.** I10 and I11 read phase verdicts, use
`VouchedCount` and emit the analysis-incomplete callout; I12 does none of it, and nothing marks
that as a decision. A single `NarrativeReport` base owning eligibility, health callout, coverage
callout, header and footer would have made the gap impossible rather than invisible. As it stands
the account report — the one most likely to leave the security team — is the one that cannot say
its analysis was incomplete.

**The UI should invoke commands, not code-behind.** I20 is 110 lines of correct,
coverage-confirming export logic that nothing can reach, sitting beside 95 lines of code-behind in
I19 that reimplements it without the confirmation. This is a different failure from G14 and H10 —
not a subsystem built for a caller that never arrived, but a subsystem *replaced* by a worse one
while it was still there, with both left in the tree. What should survive into a rebuild is narrow
and specific: `ConfirmCoverageIfNeeded` and `BuildConfirmationPrompt`, the only mechanism in the
product that warns a user about degraded coverage *before* the artefact is written. Everything
else in I20 duplicates I19.

**`ExportCoordinator`'s tab map should not be positional.** Ten tab ids resolve to
`ConfigurationExports[0]` through `[9]`. Reordering I6's collection — a change with no other
consequence anywhere — silently makes every tab export the wrong file, correctly formatted, with
no error. Key by `ExportDefinition.FileName`, or better, let the tab declare its own definition.

**Wire the progress channel or delete it.** I22 is declared in Core, transported by
`SimpleProgressPublisher` and observed by two empty method bodies. Exports are the product's only
long operation with no progress feedback, and I8's per-definition loop is precisely where the
event was meant to be raised. This is a five-line fix to a real UX gap, or a 23-line deletion; the
current state is the only option with no value.

**This was right, keep it: I3, I4 and I5 together are the honest-degradation design the rest of
the product needs.** The question was whether I has G's shape — where a refused compare and an
unchanged pair are the same object — or H's, where a failed comparison reports "Live ACL matches
snapshot." **It has neither, and it is the only branch mapped so far that got this right by
construction rather than by accident.** `VouchedCount` refuses to run a count query at all unless
every phase behind the number recorded success, on the reasoning that a view over an unpopulated
table returns an honest, false zero that no existence probe can catch.
`AppendDerivedHealthCallout` and `AppendReportCallout` are deliberately two callouts because
capture coverage and analysis completeness are two axes and a run can fail either.
`SectionViewAvailable` documents why the view probe survived the arrival of the health verdict
rather than being deleted as redundant: `CreateViews` runs untransacted, so partial view sets are
real. Three components, 258 lines, and each carries the argument for its own existence in a
remark. A rebuild should take this pattern out of `Export/` and apply it to the live and compare
paths, which is exactly where H and G found it missing.

**And a rebuild question this branch has to answer: I is where a compare should have surfaced, and
it never did.** G's ruling that there is no G→I seam is verified here from the receiving end —
`git grep "CompareResult|ChangeReport"` over `Export/` and `Reports/` returns nothing. So the
product can export a run and it can compare two runs on screen, and there is no artefact for the
second. For a tool whose remediation story is "fix these, then prove it," a compare that cannot be
exported is the missing half. Nothing about I's shape makes that hard: a `CompareReportGenerator`
beside I10–I12 would reuse I1, I3, I5 and I9 unchanged. It is a gap in the surface, not a design
obstacle.

**Note on the live-LDAP question.** No component in I depends on live access. Every one reads
`audit.db`, its sidecar and its views. If a greenfield drops live verification entirely, branch I
survives intact — the only casualty is `DelegationReportViewModel`, which this session ruled out
of the branch precisely because it is live.

## Corrections to existing documents

*Recorded, not applied. No document listed here has been edited.*

| Document | Claim | Correction |
|---|---|---|
| `docs/map/F-run-model.md` (F17) | `OutputEligibilityKind.Compare` is a fully tested gate with no caller. | Confirmed, and **`OutputEligibilityKind.Open` is a second one**. `git grep "OutputEligibilityKind.Open"` over `src/` returns only the three private message builders in `OutputEligibilityEvaluator.cs` and its own tests. Two of six kinds are message-only; F named one. |
| `docs/map/G-compare.md` | G ends at `CompareResult`; there is no G→I seam. | Upheld from I's side. `git grep -n "CompareResult\|ChangeReport"` over `src/SecureAD.Infrastructure/Export`, `src/SecureAD.Infrastructure/Reports` and `ExportCoordinator.cs` returns nothing. Recorded as an addition rather than a correction: it is a finding about I's completeness as much as G's. |
| `docs/map/E-findings.md` (E12) | The action report is E's, against the counter-argument that it runs on demand from one UI call site. | Ruling upheld, not overturned. `GenerateActionReport`'s only production caller is `MainViewModel.Home.cs:117` — a J surface, not I. Nothing in I invokes it. I14's `finding_top_actions` report reimplements the same collapse independently in SQL, and I11's `QueryActionPriorities` is a third; that duplication is I's finding to record, but it does not move E12. |
| `docs/map/H-live-verification.md` | No live answer carries `SealedUtc`. | The same is true of every exported artefact. `git grep "SealedUtc"` over `Export/`, `Reports/` and `ExportCoordinator.cs` returns nothing; `ExportManifest` carries `GeneratedUtc` (export time) and `DatabasePath`, and no `run_id`. |
| `docs/review/00a-product-identity.md` (scoped capture removed 2026-08-02) | The removal is described as complete for the named types. | A residue survives in a user-facing surface: `ReportCatalog.cs:758`, report id `capture_scope_summary`, display name "Capture Scope Summary", listed in the Reports page under Diagnostics. Its SQL is an object census by domain and class against `dim_object` and never referenced capture scope — the name is the only casualty, but it is visible to users. |

## Coverage gaps in this pass

- **Read in full:** `TabExportService.cs`, `ExportPackageService.cs`, `ExportManifest.cs`,
  `ExportProfile.cs`, `OutputEligibilityEvaluator.cs`, `ReportCoverageWarningBuilder.cs`,
  `CoverageWarningPresentation.cs`, `ReportHelpers.cs`, `VouchedCount.cs`,
  `TabularHtmlReportGenerator.cs`, `ExportCoordinator.cs`, `MainViewModel.Export.cs`,
  `ReportsTabViewModel.cs`.
- **Read in sections:** `ForestReportGenerator.cs` lines 1–200 (entry point, meta queries, phase
  arrays, first three section queries) — lines 201–394 and all 469 lines of
  `ForestReportGenerator.Sections.cs` were not read; section-level HTML composition is described
  from the call list in `GenerateAsync` and from grep results, not from the bodies.
  `DelegationReportGenerator.cs` lines 1–75 only; the remaining 490 lines are section emitters.
  `AccountHygieneReportGenerator.cs` lines 1–80 only; its 368-line `.Sections.cs` partial was not
  read at all, so the claim that it never emits a health callout rests on `git grep` over the whole
  `Export/` directory for `DerivedHealthReader`, `DerivedPhaseVerdicts`, `VouchedCount` and
  `AppendDerivedHealthCallout`, which returns no hit in either Account Hygiene file. That is strong
  evidence, not a full read.
- **`ReportCatalog.cs` (1,134 lines):** read lines 1–120 in full, plus every `new(` declaration
  line and the suppression-filtered SQL around lines 430–480 and 1,014–1,030. The bodies of the
  other ~40 SQL statements were not read, so the claim "44 of 46 do not filter suppression" rests
  on `git grep` for `suppress`/`accepted` across the file returning hits in only two report
  bodies.
- **`AppShell.xaml.cs`:** lines 40–130 read; lines 1–39 and 131–161 not read.
- **`MainViewModel.Commands.cs`:** lines 120–240 read; the `GenerateReportAsync` helper and
  `ConfirmCoverageIfNeeded` at lines 290–330 were located by grep and their call sites counted,
  but their bodies were not read.
- **Not read at all:** `ExportProfileDialog.xaml.cs`, `ExportProfileDialogViewModel.cs` (described
  from grep hits and their 68-line test), `ReportsView.xaml`, `ExportErrorCode.cs`,
  `ExportProgressEvent.cs`, `ExportState.cs`, `SimpleProgressPublisher.cs`.
- **Tests were not read**, except `ReportCatalogExecutionTests.cs` lines 1–60. The ~2,600 lines of
  `tests/…/Export/` and `tests/…/Reports/` were enumerated with line counts but not examined, so
  no claim is made here about test *quality*, only about production reachability.
  `ReportSqlRidDriftGuardTests.cs` (414 lines) in particular guards something about RID drift in
  report SQL that this pass did not investigate.
- **Not traced:** whether `ExportProfiles.RequiresSecurityMode` is enforced anywhere outside
  `ExportPackageService`'s manifest stamp — grep suggests not, but the negative was not proven
  exhaustively.
