# J — Presentation (part a): shell, navigation & run-facing screens

> Branch J is split. This half covers the application shell, the navigation model, and the screens
> that frame a run: Home, Dashboard, the capture wizard, the run library, Reports chrome, Help,
> Settings, and the dialog surface. The second half, **J-b**, covers the evidence surfaces:
> `GridViewModelBase` and its 23 grids, the detail panels, the preview panels, and the single-live-read
> panels README ruling 228 assigned to J.
>
> **The seam is `IScopedGrid` / `GridViewModelBase<TRow>`** (`ViewModels/GridViewModelBase.cs`, 514
> lines). The shell half reaches every grid through exactly three things — `GetGridForTabId` returning
> `IScopedGrid?`, `EnsureBound()`, and `ScopeDn` propagation — and nothing else. It sits directly on
> C's settled boundary: C stops at `KeysetQueryBuilder.Execute`, and `GridViewModelBase` is the
> builder's only consumer.
>
> Component numbering is continuous across both halves. J-a is J1–J20; J-b continues from J21.

## The flow

1. **`App.OnStartup`** (`App.xaml.cs`, 342) builds the logging stack, resolves the infrastructure
   session, and constructs a `MainViewModel` — with the full dependency set if discovery succeeded,
   otherwise with a bare `new MainViewModel(new DialogService())` (`:170`, `:176`). It then wraps it
   in a `ShellViewModel` and shows a single `AppShell` window (`:194`–`:195`). There is one window
   class for the whole application; the class comment records that it "replaces MainWindow,
   ModeSelectionWindow, and ConfigModeWindow with one unified host."

2. **`AppShell`** lays out a `DockPanel`: `StatusBar` at the bottom, `IconRail` on the left, a header
   bar on top, and `ContextPanel` + `ContentHost` filling the rest. It subscribes to
   `ShellViewModel.PropertyChanged` and animates the context-panel column width in code-behind
   (`AppShell.xaml.cs:34`).

3. **`ContentHost` instantiates all nine pages at once** and toggles them with
   `ShellModeToVisibilityConverter` bound to `ActiveMode` (`ContentHost.xaml:14`–`:68`). There is no
   navigation service, no page cache, no lifecycle. Every page's view model is alive from process
   start.

4. **`IconRail`** binds a `ListBox` to a hard-coded `x:Array` of six `ShellMode` values
   (`IconRail.xaml:16`–`:23`) with `SelectedItem` two-way bound to `ActiveMode`. `ShellMode` has nine
   members; `Live`, `LdapTools` and `FindingInvestigation` are not in the array. A XAML comment
   explains the first two as deliberate; the third is unexplained.

5. **Opening a database.** `MainViewModel.OpenDatabaseFileAsync` opens the bundle, records a per-open
   trace id, runs an integrity check, and raises `NavigationRequested(ShellMode.Audit)`
   (`MainViewModel.cs:689`). `ShellViewModel`'s handler picks the landing sub-view — `Findings` when
   `HasSecurityModeData`, else `Objects` (`ShellViewModel.cs:52`) — then sets `ActiveMode`.

6. **Binding.** `MainViewModel.GridBinding.cs` (422) opens read connections and hands them to the
   grids, tracking every background task in `_backgroundBindTasks` so that closing the bundle can
   await them rather than merely cancel them. The remark at `MainViewModel.cs:58` records why:
   cancelling the CTS cannot retract a connection already opened, and under load the bundle was still
   locked when close returned.

7. **Home loads.** `LoadHomeAsync` (`MainViewModel.Home.cs:44`) runs three loads in sequence: recent
   runs from `RunLibraryService`, top risks via E12's `GenerateActionReport`, and drift.

8. **Drift runs unprompted.** `LoadDriftAsync` (`MainViewModel.Drift.cs:44`) finds the next-older
   `Sealed` run in the same profile and calls `CompareRunsAsync`, caching the `CompareResult` so
   opening the full compare window is instant. Any failure leaves drift hidden.

9. **The Dashboard fills from two directions.** As an `IProgressObserver` it consumes B's
   `ShardProgressEvent` / `ModuleProgressEvent` during capture; after a run it is populated from C's
   `DashboardQueryService.InventoryCounts` via `LoadInventoryCounts` (`DashboardViewModel.cs:272`).

10. **Tool windows launch out of band.** `ToolWindowLauncher` (178) opens the run library, compare,
    policy wizard, accepted findings and the acceptance importer as modal dialogs from `Click=`
    handlers, never through a command or a navigation mode.

11. **Output leaves through code-behind.** The four header-bar buttons (`ExportAll_Click`,
    `ForestReport_Click`, `AccountHygieneReport_Click`, `DelegationReport_Click`,
    `AppShell.xaml.cs:52`–`:125`) call `MainViewModel` methods directly. The eight `[RelayCommand]`
    equivalents on `MainViewModel.Commands.cs` are bound to nothing. This is I20, confirmed from J's
    side and extended from five commands to eight.

## Components

### J1 — Application bootstrap and single-window host

- **Owns:** Constructing the logging stack, the infrastructure session and the root view models, and
  putting one window on screen.
- **Layer:** UI
- **Depends on:** A (discovery), K (logging transport), J2, J5
- **Implemented by:** `App.xaml.cs` (342), `App.xaml` (16), `Shell/AppShell.xaml` (211),
  `Shell/AppShell.xaml.cs` (161), `AppLog.cs` (59), `FileLoggerProvider.cs` (295)
- **Non-obvious:** This is the composition root, and it is a hand-written one — there is no
  `ServiceCollection` and no container. It has a **degraded-construction path**: if forest discovery
  fails at startup it constructs `new MainViewModel(new DialogService())` with every other dependency
  null (`:176`). Roughly a dozen nullable fields on `MainViewModel` exist only to make that path
  compile, and every consumer of them carries a null check. `AppShell.xaml.cs` also holds the seven
  `Click=` handlers that are the *only* route to export, the three HTML reports, finding evidence,
  accept and revoke — behaviour that is nowhere in a view model and therefore nowhere in a test.

### J2 — Shell mode model and navigation state

- **Owns:** Which of the nine screens is showing, which Audit sub-view is active, and whether the
  context panel and inspector drawer are open.
- **Layer:** UI
- **Depends on:** J5
- **Implemented by:** `ViewModels/ShellViewModel.cs` (259), `Shell/ContentHost.xaml` (72),
  `Shell/ContentHost.xaml.cs` (15), `Converters/ShellConverters.cs` (159)
- **Non-obvious:** **This is not a navigation model; it is a visibility model.** All nine pages are
  constructed at startup and switched with a converter. Nothing is unloaded, nothing is disposed on
  leaving a screen, and no page can refuse to be left. `ShellViewModel` is also where
  `SettingsViewModel` is lazily created and, on `IsApplied`, where settings are pushed back into
  `MainViewModel` through a `PropertyChanged` handler (`:153`–`:164`) — an event-based write-back
  rather than a returned result. `ActivePreview` (`:126`) is a five-way switch reaching four levels
  deep into J-b's grids (`Main.ObjectsTab.AllGrid.Preview`), which is the shell's tightest coupling to
  the other half.

### J3 — Shell chrome: rail, header, status bar, context panel

- **Owns:** The persistent furniture around the active page.
- **Layer:** UI
- **Depends on:** J2, J5, I19 (the four output buttons in the header)
- **Implemented by:** `Shell/IconRail.xaml` (81), `Shell/IconRail.xaml.cs` (14),
  `Shell/StatusBar.xaml` (50), `Shell/StatusBar.xaml.cs` (15), `Shell/ContextPanel.xaml` (149),
  `Shell/ContextPanel.xaml.cs` (44), `Icons.cs` (52), `Themes/Icons.xaml` (55)
- **Non-obvious:** The rail's menu is an `x:Array` literal in XAML, so adding a screen means editing
  markup in two places (here and `ContentHost`) with no compiler check that they agree. **The status
  bar is the app's only always-visible surface and it carries no provenance**: `StatusBarText`
  (connection state), `DatabaseIntegrityDisplay`, `StatusText` (a free-text scratchpad written by
  roughly forty call sites) and `MemoryDisplay`. No run id, no seal time, no coverage verdict, no
  suppression count. `DatabaseIntegrity` is the one genuine trust signal, and it renders as a colour
  change on a `Modified` value.

### J4 — Tool window launcher

- **Owns:** Opening the six modal tool windows and wiring their results back into the shell.
- **Layer:** UI
- **Depends on:** J5, J12, F (run library), G (compare), E10 (suppression/acceptance)
- **Implemented by:** `Shell/ToolWindowLauncher.cs` (178)
- **Non-obvious:** This static class is the **only entry point to branch G from the UI**.
  `LaunchCompareAsync` (`:132`) awaits `CompareRunsAsync`, builds a `CompareResultsViewModel` and
  shows a non-modal window — and its failure path is `vm.StatusText = $"Compare failed: {ex.Message}"`,
  the same interpolated-exception pattern I23 recorded for exports. `OpenImportAcceptances` carries
  the branch's best comment (`:96`–`:100`): it is the deliberate, attributable replacement for an
  import that used to run silently on grid bind, because "inheriting a predecessor's accepted risks is
  a decision, so it needs a user behind it." That is the pre-write confirmation pattern I20 wanted
  salvaged, already built here.

### J5 — `MainViewModel`: the root aggregate

- **Owns:** Effectively all cross-screen state — DC connection, loaded database, every grid instance,
  capture services, status text, and the commands that tie them together.
- **Layer:** UI
- **Depends on:** A, B, C, D, E, F, G, H, I — all of them
- **Implemented by:** twelve partials totalling **3,259 lines**: `MainViewModel.cs` (1,020),
  `MainViewModel.GridBinding.cs` (422), `MainViewModel.Audit.cs` (400), `MainViewModel.Commands.cs`
  (382), `MainViewModel.OfflineTree.cs` (213), `MainViewModel.Dashboard.cs` (179),
  `MainViewModel.Home.cs` (157), `MainViewModel.Drift.cs` (144), `MainViewModel.Navigation.cs` (130),
  `MainViewModel.SessionRestore.cs` (102), `MainViewModel.Export.cs` (78), `MainViewModel.Inspect.cs`
  (32)
- **Non-obvious:** Tested, not assumed: it is one class spread across twelve files. The partials are
  not a layering — they are a filing system, and several of them reach across each other freely
  (`Navigation` mutates grid filter state directly, `Home` calls into `Drift`). It holds a direct
  reference to every grid in J-b as a named property, so the twelve-file split does nothing to reduce
  the coupling it was presumably meant to manage. Of the 138 `[RelayCommand]` methods in the UI
  project, 43 live here or on its immediate collaborators.

### J6 — Database open, close and bind orchestration

- **Owns:** Opening a bundle, verifying integrity, distributing read connections to the grids, and
  getting all of them released again on close.
- **Layer:** UI
- **Depends on:** C4 (`DatabaseConnectionFactory`), C's read services, F (eligibility), J21
  (`GridViewModelBase`)
- **Implemented by:** `MainViewModel.cs` (open/close/trace sections), `MainViewModel.GridBinding.cs`
  (422)
- **Non-obvious:** The only part of J-a with a real concurrency design, and it is documented honestly.
  `_backgroundBindTasks` plus `_backgroundBindLock` exist because cancellation is insufficient — the
  code comment names the defect (F-01-22) and the flow it breaks (Close-then-Delete, F-01-21). It also
  carries a bespoke tracing facility, `LogOpenTrace` / `CreateOpenTraceId` / `DescribeThreadContext` /
  `DescribeDatabase` (`MainViewModel.cs:93`–`:120`), built solely to diagnose slow opens, alongside a
  `SlowUiTraceThresholdMs = 250` constant and a separate `UiPerfTrace.cs` (29).

### J7 — Home screen

- **Owns:** The landing screen: recent runs, "Fix these first", the drift card, and the shortcuts into
  Dashboard, Inspect and LDAP Tools.
- **Layer:** UI
- **Depends on:** E12 (`GenerateActionReport`), F (`RunLibraryService`), J8, J9
- **Implemented by:** `ViewModels/MainViewModel.Home.cs` (157), `Views/HomeView.xaml` (464),
  `Views/HomeView.xaml.cs` (144)
- **Non-obvious:** This is E12's **only** production consumer, as ruling 238 established. Two things
  it does are worth recording. First, it constructs `new FindingsService(connection,
  FindingsPolicy.Empty)` (`:107`) — **the Home screen's prioritised risk list is computed with no
  suppression policy at all**, so a finding the user has formally accepted still appears in "Fix these
  first". Second, it calls `service.GetLatestRunId()` rather than using the run the shell has loaded,
  so on a bundle whose latest run is not the one on screen elsewhere, Home is answering a different
  question from the rest of the app. Its empty states are honest but coarse: `HasTopRisks` false
  renders "No prioritized actions for this run", which is also what a caught exception produces
  (`:127`–`:132`).

### J8 — Drift card

- **Owns:** Detecting that the loaded run has a predecessor and summarising what changed, without
  being asked.
- **Layer:** UI
- **Depends on:** G (`CompareResult`, `CompareRunsAsync`), F (`RunLibraryService`,
  `RunLifecycleState.Sealed`)
- **Implemented by:** `ViewModels/MainViewModel.Drift.cs` (144)
- **Non-obvious:** The best-conceived thing in J-a: it acts on the premise that a drift tool should not
  require the user to go and ask what changed. It correctly restricts comparison to within a profile,
  and correctly requires the predecessor to be `Sealed`. Two defects. It selects the predecessor by
  `SealedUtc ?? CreatedUtc` (`:108`, `:113`–`:114`) but **labels** it `$"since {previous.CreatedUtc:g}"`
  (`:73`), so the card names a different timestamp from the one it ranked by — on any run where the two
  differ, the label is wrong. And because it is best-effort and silent, a `CompareResult` that failed
  to compute is indistinguishable on screen from a run with no predecessor: both render
  `HasDrift = false`.

### J9 — Dashboard

- **Owns:** Post-run posture: severity counts, tier summary, coverage, inventory counts, and the
  capture metadata tile.
- **Layer:** UI
- **Depends on:** C (`DashboardQueryService`), D2 (`DerivedHealthReader`), E (severity counts), J10
- **Implemented by:** `ViewModels/DashboardViewModel.cs` (490),
  `ViewModels/DashboardViewModel.RunLifecycle.cs` (271), `ViewModels/MainViewModel.Dashboard.cs` (179),
  `Views/DashboardView.xaml` (220), `Views/DashboardView.xaml.cs` (24)
- **Non-obvious:** This is the surface that carries the most provenance in the product —
  `CaptureTimestamp`, `DcUsed`, `DomainFqdn`, `ScopeDn` and `SecurityCoverageSummary` are all rendered
  (`DashboardView.xaml:28`, `:40`, `:159`). It is also **internally inconsistent about empty versus
  failed**. `ControlEdgeCount` is `int?` with a `ControlEdgeCountDisplay` that renders `⚠ error` for
  null, and its remark explicitly cites `DataLoadState` as the convention it is following
  (`:132`–`:153`) — this is I4's `VouchedCount` pattern, applied to exactly one tile. Every other
  number on the screen is a non-nullable `int`, and the whole inventory section is gated on
  `HasInventory => TotalObjectCount > 0 || UserCount > 0` (`:269`), which is precisely the false-zero
  conflation the control-edge remark was written to condemn. Severity counts render raw, with no
  indication of how many suppressed findings are included — the same gap I10 recorded for exports.
- **Dead surface:** see J20.

### J10 — Capture progress rendering

- **Owns:** Turning B's progress events into a live phase, percentage, per-module counters and an
  elapsed clock.
- **Layer:** UI
- **Depends on:** B (`ShardProgressEvent`, `ModuleProgressEvent`), K (`IProgressPublisher`)
- **Implemented by:** `ViewModels/DashboardViewModel.cs` (the `IProgressObserver` implementation and
  the `RunState` region), `ViewModels/DashboardViewModel.RunLifecycle.cs` (271)
- **Non-obvious:** This is the consumer side of README ruling 202 — B owns emission, K owns transport,
  J owns rendering. It marshals to the UI thread itself through an optional injected `Dispatcher`
  (`:325`), which is what lets `DashboardViewModel` be constructed headless in tests.
  `UpdateProgressPercent` degrades in a considered way: module-level percentage if the module knows its
  total, else domains completed, else `null` and an indeterminate bar. Worth noting against I22:
  **capture has progress reporting and export does not** — the mechanism exists here and was never
  applied to the product's other long-running operation.

### J11 — Forest audit wizard

- **Owns:** Configuring and launching a capture: domain and DC selection, class and OU scope, LDAP
  pressure, SYSVOL opt-in, review.
- **Layer:** UI
- **Depends on:** A (discovery, DC preflight), B (capture settings, `SecurityModeCaptureService`),
  C (`LowSignalOuRecommendationService`)
- **Implemented by:** `ViewModels/ForestAuditViewModel.cs` (811),
  `ViewModels/ForestAuditViewModel.Configuration.cs` (512),
  `ViewModels/ForestAuditViewModel.Wizard.cs` (303), `ViewModels/ForestDomainRow.cs` (209),
  `ForestAuditWindow.xaml` (810), `ForestAuditWindow.xaml.cs` (156),
  `DomainExclusionAttestationDialog.xaml` / `.xaml.cs` (65)
- **Non-obvious:** The only genuinely *modelled* navigation in the branch. `WizardStep` has a linear
  five-step path plus an explicitly off-path Performance step, with `IsOnLinearPath`,
  `StepProgressCaption`, `CanGoNext` and a per-step `ValidationMessage` (`Wizard.cs:42`–`:106`). It is
  the pattern J2 should have used and did not. It is also the surface that enforces F's
  domain-exclusion attestation: excluding a domain from a forest-wide audit requires a signed
  acknowledgement, which is the coverage-honesty discipline the rest of J does not apply.

### J12 — Run library surface

- **Owns:** Browsing saved runs by profile, choosing one to open, and choosing two to compare.
- **Layer:** UI
- **Depends on:** F (`RunLibraryService`, `RunMetadata`, `OutputEligibilityKind`), J4
- **Implemented by:** `ViewModels/RunLibraryViewModel.cs` (583), `RunLibraryWindow.xaml` (224),
  `RunLibraryWindow.xaml.cs` (137), `SaveRunDialog.xaml` / `.xaml.cs` (58)
- **Non-obvious:** The one screen where run identity is genuinely the subject, and the heaviest user of
  `SealedUtc` — five of the thirteen UI references are here (`:200`, `:390`, `:423`, `:426`, `:427`).
  Every one of them is a **sort or comparison key**, not a rendered value. The library orders and pairs
  runs by seal time and then shows the user something else.

### J13 — Reports tab chrome

- **Owns:** The screen that lists I's 46-report catalogue, runs one, shows the result grid, and exports
  it.
- **Layer:** UI
- **Depends on:** I (`IReportCatalog`, `DefaultReportCatalog`, `ReportDefinition`), I19
- **Implemented by:** `ViewModels/ReportsTabViewModel.cs` (406), `Views/ReportsView.xaml` (204),
  `Views/ReportsView.xaml.cs` (15)
- **Non-obvious:** `IsAdvancedMode` is a hand-written property rather than `[ObservableProperty]`
  specifically so that `OnAdvancedModeChanged` can re-filter `AvailableReports` after the notification
  (`:140`–`:175`) — it is the gate that reveals I's 17 `Diagnostics` reports and enables the free-text
  SQL box. It carries an `ExportHtmlCommand`, and so does `HelpViewModel`; both are bound, in
  `ReportsView.xaml:116` and `HelpView.xaml:20` respectively, to entirely different subjects.

### J14 — Help and rule reference

- **Owns:** The in-app manual, the rule catalogue reference, and exporting the help text as HTML.
- **Layer:** UI
- **Depends on:** E (`FindingEvidenceMatrix`, `BuiltInRules`)
- **Implemented by:** `ViewModels/HelpViewModel.Content.cs` (1,351), `ViewModels/HelpViewModel.cs`
  (216), `Views/HelpView.xaml` (80), `Views/HelpView.xaml.cs` (78), `ViewModels/RuleHelpViewModel.cs`
  (105), `RuleHelpWindow.xaml` / `.xaml.cs` (28), `SecurityModelReadmeWindow.xaml` / `.xaml.cs` (23),
  `PermissionReferenceWindow` + `ViewModels/PermissionReferenceCatalog.cs` (231),
  `EscalationPathReferenceWindow` + `ViewModels/EscalationPathReferenceViewModel.cs` (240)
- **Non-obvious:** `HelpViewModel.Content.cs` is the largest single file in the UI project, and it is
  1,351 lines of **prose held as C# string literals**. `BuildFindingEvidenceMatrixBody` (`:1305`) is
  where E's `FindingEvidenceMatrix` reaches a user — J renders it, E defines it, per ruling 224 —
  joining it to `BuiltInRules.ById` for rule names. `ExportHtml` (`HelpViewModel.cs:68`) is J's by
  ruling 235: mechanically an export, but its subject is the tool's own documentation. It is the only
  "export" in the product that is invoked by a bound command rather than a `Click=` handler.

### J15 — Settings

- **Owns:** Editing DC connection, capture tuning and cache profile, and applying them back to the
  running session.
- **Layer:** UI
- **Depends on:** A (`DcConnectionInfo`), B (capture settings), C (`CacheProfileMap`), J2
- **Implemented by:** `ViewModels/SettingsViewModel.cs` (362), `Views/SettingsView.xaml` (171),
  `Views/SettingsView.xaml.cs` (34)
- **Non-obvious:** The only view model in the shell created on demand and destroyed on leaving
  (`ShellViewModel.cs:145`, `:169`), which makes it the exception that shows what the other eight
  screens are not doing. It communicates success by raising `PropertyChanged` on a bool called
  `IsApplied` and letting `ShellViewModel` notice.

### J16 — Session restore

- **Owns:** Reopening the last database on launch.
- **Layer:** UI
- **Depends on:** J6, F
- **Implemented by:** `ViewModels/MainViewModel.SessionRestore.cs` (102)

### J17 — Offline directory tree

- **Owns:** The stored-evidence tree in the Audit context panel, and propagating the selected DN as a
  scope filter to every grid.
- **Layer:** UI
- **Depends on:** C (`OfflineTreeService`), J21 (`IScopedGrid.ScopeDn`)
- **Implemented by:** `ViewModels/MainViewModel.OfflineTree.cs` (213),
  `ViewModels/DirectoryTreeNodeViewModel.cs` (151)
- **Non-obvious:** This is **not** H17–H20's `DirectoryTree`. That one browses live LDAP in Inspect
  mode; this one reads `dim_object` through C's `OfflineTreeService` and drives `ApplyScopeDn`
  (`Navigation.cs:121`). The product therefore has two directory-tree UIs over two different sources,
  sharing `DirectoryTreeNodeViewModel` and `Core.Discovery.DirectoryTreeNode` but nothing else. This
  one survives the loss of live LDAP; H's does not. It also carries the branch's one honest truncation
  notice: when a node exceeds `OfflineTreeService.MaxLeafChildrenPerNode` it renders how many children
  were withheld rather than silently showing a prefix (`:91`–`:93`).

### J18 — Dialog service and dialog surface

- **Owns:** Abstracting message boxes, file pickers, clipboard and detached windows so view models stay
  testable.
- **Layer:** UI
- **Depends on:** —
- **Implemented by:** `Services/IDialogService.cs` (43), `Services/DialogService.cs` (100),
  `Services/NullDialogService.cs` (18), `Services/IDomainExclusionAttestationPrompt.cs` (34),
  `Services/DomainExclusionAttestationPrompt.cs` (15), `ErrorDialog.xaml` / `.xaml.cs` (37),
  `LdapInputDialog`, `LdapResultDialog`, `SetTierDialog`, `ExportProfileDialog`
- **Non-obvious:** This is the abstraction the branch's own guidance would call justified — an external
  dependency (the WPF dialog system) behind an interface, with `NullDialogService` as the headless test
  double. It is undermined by the seven `Click=` handlers in J1, which bypass it and call
  `Microsoft.Win32.SaveFileDialog` directly (`AppShell.xaml.cs:72`, `:92`, `:112`).

### J19 — Theme, converter and behaviour layer

- **Owns:** Light/dark resource dictionaries, value converters, and attached behaviours.
- **Layer:** UI
- **Depends on:** —
- **Implemented by:** `Themes/LightTheme.xaml` (896), `Themes/DarkTheme.xaml` (846),
  `Themes/InspectorStyles.xaml` (431), `Themes/ThemeManager.cs` (84), `Themes/Icons.xaml` (55),
  `Converters/VisibilityConverters.cs` (203), `Converters/ShellConverters.cs` (159),
  `Converters/ObjectConverters.cs` (35), `Behaviors/DataGridSortBehavior.cs` (152),
  `Behaviors/LazyTabBehavior.cs` (123), `Behaviors/DataGridColumnVisibilityBehavior.cs` (88),
  `Behaviors/EnterKeyCommandBehavior.cs` (51)
- **Non-obvious:** 1,742 lines of near-parallel light and dark dictionaries with no shared base — a
  brush added to one is silently absent from the other, and nothing catches it. `ShellConverters.cs`
  holds four converters (`ShellModeToVisibility`, `ToIcon`, `ToLabel`, `ToTooltip`) which together are
  the real navigation menu: the rail's labels, icons and tooltips are all `switch` expressions over
  `ShellMode` in C#, while the *set* of menu items is an array in XAML. Two of the four behaviours
  (`DataGridSortBehavior`, `DataGridColumnVisibilityBehavior`) serve J-b exclusively and are described
  there.

### J20 — Dead command surface

- **Owns:** Nothing reachable. Recorded because the intent is legible and some of it is worth
  rebuilding.
- **Layer:** UI
- **Depends on:** —
- **Implemented by:** `ViewModels/DashboardViewModel.cs:383`–`:446`, `ViewModels/MainViewModel.Commands.cs`,
  `ViewModels/MainViewModel.Home.cs:145`, `ViewModels/ShellViewModel.cs`,
  `ViewModels/MainViewModel.OfflineTree.cs`
- **Non-obvious:** A systematic sweep of all 138 `[RelayCommand]` methods in the UI project against all
  64 XAML files found **95 bound, 43 unbound, and 28 with neither a XAML binding nor any C# reference
  to the generated command**. Nine of the 28 are `DashboardViewModel`'s drill-downs —
  `DrillDownToObjects`, `ToPermissions`, `ToDangerousPermissions`, `ToUnusualOwners`, `ToEveryoneWrite`,
  `ToOrphanedAces`, `ToControlEdges`, `ToEscalationPaths`, `ToHighValueTargets`. The tenth,
  `DrillDownToFindings`, is alive only because `DashboardView.xaml.cs:22` and `HomeView.xaml.cs:142`
  invoke it from `Click=` handlers. **`DashboardView.xaml` contains no `Command=` binding of any kind.**
  The design intent — every dashboard tile is a doorway into the grid behind it — was built, tested at
  the view-model level, and then not connected, because the view was written with click handlers
  instead. Eight more of the 28 are `MainViewModel.Commands.cs`'s export commands, which is I20 seen
  from J: I found five, the full sweep finds eight (`ExportAllTabs`, `ExportCurrentTab`,
  `ExportForestReport`, `ExportAccountHygieneReport`, `ExportDelegationReport`,
  `OpenCurrentTabInNewWindow`, `ClearCurrentTabFilter`, `ContextDrillDown`).
  **What should survive:** the tile-to-grid drill-down contract. `DrillDownTarget` plus
  `NavigateWithDrillDown` is a genuinely good idea — a tile states a tab, a filter type, a filter value
  and whether to pop out, and the shell applies it — and it is the only mechanism in the product that
  makes a summary number and the rows behind it provably the same query. Rebuild the contract; do not
  rebuild the nine commands.

**Reachability, checked page by page.** All 71 `*ViewModel` types declared in the UI project have at
least one production reference outside their own declaring file. Unlike E, F, G, H and I, **branch J
has no dead subsystem** — its dead surface is finer-grained and lives at the command level (J20). The
single sweep hit, `EscalationPathDetailViewModel`, is declared inside
`EscalationPathDetailWindow.xaml.cs` and used by that window.

## Naming & taxonomy

| Current | Proposed | Why it matters |
|---|---|---|
| `ShellMode.Live` | `ShellMode.Inspect` | The screen is called Inspect everywhere a user can see it — `InspectView.xaml`, the Home shortcut, H17–H20 — and `Live` in the enum, in `ContentHost`'s `ConverterParameter=Live`, and in `ShellViewModel`'s title map, where it renders as "Live Browse". Three names for one screen, and the enum name collides with H's whole subject. |
| `ShellViewModel.ActiveView` | delete, or `ActivePageInstance` | An `object?` updated by `UpdateActiveView()` on every mode change, while `ContentHost` ignores it entirely and switches on `ActiveMode`. The name promises the navigation model the app does not have. |
| `MainViewModel` | `AuditSessionModel` | It is not a view's model — no view binds to it as a whole; six different views bind to `{Binding Main}` and pick fields. It is the session aggregate. Naming it so would make the twelve partials look like what they are. |
| `MainViewModel.Dashboard.cs` vs `DashboardViewModel.cs` | `MainViewModel.DashboardLoading.cs` | Two files, two types, one word. The first loads the dashboard's data; the second holds it. |
| `HelpViewModel.ExportHtmlCommand` / `ReportsTabViewModel.ExportHtmlCommand` | `ExportHelpHtmlCommand` / `ExportReportResultHtmlCommand` | Identical command names on two view models, both bound, exporting the tool's documentation and a SQL result set respectively. Ruling 235 had to be written because of this collision. |
| `DirectoryTreeViewModel` (H) vs `MainViewModel.OfflineTree` + `DirectoryTreeNodeViewModel` (J17) | `LiveDirectoryTreeViewModel` / `StoredDirectoryTreeViewModel` | Two trees over two sources sharing a node type. The live one dies if live LDAP is dropped; the stored one does not. Nothing in the names says which is which. |
| `DashboardViewModel.CapturedUtc` (string) / `CaptureTimestamp` (parsed) | `CapturedUtcRaw` / `CapturedLocalDisplay` | A `string?` and a nullable parse of it, differing by one word, where the parse silently falls through to the raw string on failure (`:261`). |
| `DashboardViewModel.DelegationBundleCount` | delete | `public int DelegationBundleCount => DelegationEntryCount;` — an alias that renames the same number for one binding, so the screen implies two measurements. |
| `IScopedGrid` | `IBindableGrid` | Its two methods are `EnsureBound()` and `ReloadIfScopeDirty()`. Only one concerns scope; the interface is really about deferred binding. Naming matters here because it is the branch seam. |
| `StatusText` | `TransientStatusMessage` | Written by roughly forty call sites as a scratchpad for successes, failures, and progress alike. The neutral name is why compare failures, export failures and "Settings applied" all arrive at the same one-line, unstyled, non-persistent destination. |

## Would-do-differently

**1. Make navigation a model, not a converter.** `ContentHost` constructing all nine pages and hiding
eight of them is the branch's foundational decision, and everything awkward downstream follows from it:
no page has a lifecycle, so `MainViewModel` must own all state; nothing can be disposed on leave, so
`_backgroundBindTasks` must exist; nothing can refuse a leave, so unsaved wizard state has nowhere to
object; the rail's menu and the host's page list are two independent literals that can silently
disagree. A rebuild should have a navigation service with `Navigate(route)`, per-page view models with
`OnEnter`/`OnLeave`, and a single declared route table that both the menu and the host read.

**2. Break up `MainViewModel`.** 3,259 lines across twelve partials, holding every grid, every capture
service, the DC connection, the tree, the drift result and the status text. The partials give the
appearance of decomposition with none of the benefit — they cannot be tested apart, they reach into
each other, and nothing stops the next feature adding a thirteenth. The natural seams are already
visible in the filenames: session/database lifecycle, capture, home, drift, tree. Make them types with
constructor dependencies.

**3. Bind the dashboard, and give it the drill-down back.** Nine dead drill-down commands and zero
`Command=` bindings in `DashboardView.xaml` is the same failure as I20, in a second place, and it is
the more damaging instance: the dashboard's entire reason to exist is to be a set of doorways into the
evidence. A number a user cannot click is a claim they cannot check. Salvage `DrillDownTarget` and
`NavigateWithDrillDown`; rebuild the view against them.

**4. Put provenance in the chrome.** Combined with H's finding that no live answer carries `SealedUtc`
and I's that no export does, this branch closes the case: **the product has no provenance line anywhere
a user will reliably see it.** `SealedUtc` appears thirteen times in the UI and twelve of them are sort
or comparison keys; the sole rendered use is `ImportAcceptancesViewModel.CapturedText`, in a modal
dialog about importing acceptances. The always-visible status bar carries connection state, integrity,
a scratchpad string and a memory counter. A rebuild should treat "which run, sealed when, at what
coverage, with how many suppressions active" as persistent chrome that every screen and every export
inherits, not as something each surface may choose to mention. That is three branches agreeing, and it
is a product-level conclusion rather than a branch finding.

**5. Apply the suppression policy consistently, and show it.** Home computes "Fix these first" with
`FindingsPolicy.Empty`, so an accepted finding is still prioritised there. The Dashboard's severity
counts do not filter suppressions or say how many are included, exactly as I10 does not. E10 owns the
semantics and every consumer decides independently whether to honour them. In a rebuild, a findings
query should require a policy argument that has no empty default, and any count computed under a
non-empty policy should render how many rows it excluded.

**6. Decide "empty versus failed" once, at the framework level.** The branch contains the right answer
and applies it inconsistently. `DataLoadState` and `TotalCountDisplay` are correct by construction;
`DashboardViewModel.ControlEdgeCount` is nullable with an `⚠ error` display and a remark citing them;
and then `HasInventory => TotalObjectCount > 0 || UserCount > 0` gates the whole inventory panel on a
false zero, `HasTopRisks` renders a caught exception as "No prioritized actions", and `HasDrift`
renders a failed comparison identically to "no predecessor". Three of J-a's five empty states fail the
test that G and H also failed. A rebuild should make the *loaded value type* carry the distinction — a
`Loaded<T>` with `NotLoaded`/`Loading`/`Ok(T)`/`Failed(reason)` — so a `bool Has…` gate over a plain
`int` is not expressible.

**7. Route all output through the view models that already exist.** Seven `Click=` handlers in
`AppShell.xaml.cs` are the only way to export, generate the three HTML reports, open finding evidence,
accept and revoke — while eight `[RelayCommand]` equivalents sit unbound. The consequence, already
recorded by I20, is that the coverage-confirmation prompt never fires and single-tab CSV export is
unreachable. The deeper cost is that behaviour in code-behind is behaviour with no test.

**8. Generate the theme dictionaries from one source.** 1,742 lines of parallel light and dark XAML
with no shared base and no check that they define the same keys.

**9. Say whether live is a pillar in the enum, not in a comment.** `ShellMode` has nine members and the
rail shows six. `Live` and `LdapTools` are excluded with a comment explaining the product judgement —
good — but `FindingInvestigation` is excluded with no comment, and all three remain fully wired in
`ContentHost`. Three modes reachable only by internal event are a navigation model that disagrees with
itself.

**What was right, keep it.** Two things.

`MainViewModel.Drift.cs` (J8) is the best idea in the branch. Computing the comparison against the
previous sealed run in the same profile, unprompted, and caching the `CompareResult` so the full view
opens instantly, is the correct instinct for a drift tool — the user should not have to know to ask. It
is also the only place in J that uses branch G at all outside a modal dialog. Fix the label bug and the
silent-failure state; keep the design.

`ToolWindowLauncher.OpenImportAcceptances` (J4) is right for a reason worth stating. Its remark records
that it replaced an import that used to run silently on grid bind, because inheriting a predecessor's
accepted risks is a decision that needs a person behind it. That is the same principle behind I20's
pre-write coverage prompt and behind J11's domain-exclusion attestation — three places where the
product chose to make an audit-integrity decision visible and attributable. That principle, not the
three implementations of it, is what should be carried into a rebuild.

**On dropping live LDAP.** Of J-a's twenty components, one depends on live access: J17's counterpart,
not J17 itself. `MainViewModel.OfflineTree` reads C's `OfflineTreeService` over `dim_object` and
survives intact; H's `DirectoryTreeViewModel` does not. `ShellMode.Live` and `ShellMode.LdapTools`
would both be removed from the enum, `InspectView` and `LdapToolsView` from `ContentHost`, and
`MainViewModel.Inspect.cs` (32) deleted. `MainViewModel.Home.cs`'s `GoToLiveInspect` and `GoToLdapTools`
go with them — the shortcuts on Home are the only bound route to either. Nothing else in J-a changes:
Home, Dashboard, drift, the wizard, the run library, Reports, Help and Settings are all stored-evidence
surfaces.

## Corrections to existing documents

*Corrections are recorded, not applied. The documents named below are unchanged.*

| Document | Claim | Correction |
|---|---|---|
| `docs/map/I-output.md`, I20 | "Five `[RelayCommand]` export methods on `MainViewModel` are bound in no XAML" | Confirmed and extended. A systematic sweep of all 138 `[RelayCommand]` methods against all 64 XAML files finds **eight** unbound on `MainViewModel.Commands.cs` alone (adding `OpenCurrentTabInNewWindow`, `ClearCurrentTabFilter`, `ContextDrillDown`), and **28 fully dead across the UI project** — no XAML binding and no C# reference. I found five while looking at exports; the sweep finds the rest. |
| `docs/map/README.md`, ruling 234 | `DelegationReportViewModel` / `DelegationReportPanel` "are not I's… H-or-J" | Resolved: **J's**, per ruling 228, which names it among the single-live-read panels with no stored counterpart. H's coverage-gaps section lists it as "referenced rather than mapped". Mapped in J-b. |
| `docs/map/README.md`, ruling 226 | The four `Acl*` view models "G names them so they are not lost; H should claim them" | Resolved: **H did claim them.** `H-live-verification.md`'s corrections table records "The ruling's placement of all four in H stands; its stated reason does not." J references H and does not re-map them. |
| `docs/map/G-compare.md` | G ends at `CompareResult`; the compare window and the drift card are its only consumers | Confirmed from J's side, with an addition: the *only* UI route into G is `ToolWindowLauncher.LaunchCompareAsync` (J4) and `MainViewModel.Drift.cs` (J8). Neither is reachable from the icon rail. Compare has no navigation mode, no `ShellMode` member and no page. |
| `docs/map/H-live-verification.md` | H's leading item: live verification has no forest-scale question to answer | J-a supports it from a different angle. `ShellMode.Live` and `ShellMode.LdapTools` were both deliberately removed from the icon rail (`IconRail.xaml:12`–`:15`), with a comment calling them "supporting capabilities… not co-equal navigation pillars." The product's own navigation had already demoted live browsing before H's session argued it should be dropped. |

## Coverage gaps in this pass

Read in full: `Shell/AppShell.xaml.cs` (161), `Shell/ContentHost.xaml` (72), `Shell/IconRail.xaml`
(81), `Shell/StatusBar.xaml` (50), `Shell/ToolWindowLauncher.cs` (178),
`ViewModels/MainViewModel.Navigation.cs` (130), `ViewModels/MainViewModel.Home.cs` (157),
`ViewModels/MainViewModel.Drift.cs` (144).

Read in sections: `ViewModels/ShellViewModel.cs` (259) — lines 1–175 read, 176–259 (the
`UpdateActiveView` body and the three navigation commands) covered by targeted grep only.
`ViewModels/DashboardViewModel.cs` (490) — lines 1–380 read, 381–490 (the drill-down bodies) covered by
grep and by the dead-command sweep. `ViewModels/MainViewModel.cs` (1,020) — lines 1–120 read plus
targeted greps for `StatusBarText`, `DatabaseIntegrity`, `MemoryDisplay` and the `NavigationRequested`
call site; the open/close body is characterised from its remarks and the bind-task design rather than
line by line. `Shell/AppShell.xaml` (211) — lines 1–116 read.

Not read, mapped from declaration comments, member greps and file size:
`ViewModels/ForestAuditViewModel.cs` (811), `.Configuration.cs` (512), `ForestAuditWindow.xaml` (810),
`ViewModels/RunLibraryViewModel.cs` (583), `ViewModels/HelpViewModel.Content.cs` (1,351),
`ViewModels/SettingsViewModel.cs` (362), `ViewModels/ReportsTabViewModel.cs` (406, greps only),
`ViewModels/MainViewModel.Audit.cs` (400), `.GridBinding.cs` (422), `.SessionRestore.cs` (102),
`Themes/*` (2,312), `Views/HomeView.xaml` (464, greps only).

**Not covered at all — deferred to J-b:** `GridViewModelBase` and the 23 grid view models, the
`*GridRow` types, the eleven grid pages, `FilterBar` / `FilterChip` / `SearchBox`, `AceAnalysisService`,
`ObjectDetailPanelViewModel` and the detail windows, `FindingDetailViewModel`,
`FindingInvestigationViewModel` and `FindingInvestigationProvider`, the five preview panels,
`PolicyWizardViewModel`, `AcceptedFindingsViewModel`, `ImportAcceptancesViewModel`,
`EffectiveAccessViewModel` / `StoredEffectiveAccessViewModel`, `InheritanceViewModel` /
`StoredInheritanceViewModel`, `DelegationReportViewModel` / `DelegationReportPanel`, and
`DataGridSortBehavior` / `DataGridColumnVisibilityBehavior`.

**Questions J-b must answer that J-a could not:** whether each of the 23 grids' XAML actually renders
`DataLoadState.Failed` distinctly, or whether only the count display does; whether suppressed and
accepted findings are visibly marked in `FindingsGridViewModel` or merely filtered; whether the
Findings grid agrees with Home or with the Dashboard about severity counts, given that J-a establishes
those two already disagree (Home reads `GetLatestRunId()` under `FindingsPolicy.Empty`, the Dashboard
reads the loaded run through `DashboardQueryService`); and whether `AceAnalysisService`,
`EffectiveAccessViewModel` and H7/H10/H16 constitute a fourth implementation of effective access.
