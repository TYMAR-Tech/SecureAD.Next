# J — Presentation (part b): grids, evidence surfaces & panels

> Second half of branch J. J-a covers the shell and the run-facing screens (J1–J20); this half covers
> everything below the seam. **The seam is `IScopedGrid` / `GridViewModelBase<TRow>`**
> (`ViewModels/GridViewModelBase.cs`, 514). J-a stops at `GetGridForTabId`, `EnsureBound()` and
> `ScopeDn`; the base class, page size, sort selection, load state and what a failed page looks like on
> screen are here. It inherits C's settled boundary: C stops at `KeysetQueryBuilder.Execute`, and
> `GridViewModelBase` is the builder's only consumer.
>
> Component numbering continues from J20. Surface: 154 files, ~23,600 lines, 26 components (J21–J46).

## The flow

1. **Grids are constructed at process start.** `MainViewModel` field initialisers create nine grids
   directly (`MainViewModel.cs:378`–`:410`) and three multiplexers create eight more
   (`ObjectsTabViewModel.cs:30`–`:39`, `GroupsTabViewModel.cs:25`–`:28`,
   `AttackPathsTabViewModel.cs:27`–`:33`). None takes a constructor dependency; all are `= new()`.
   This is J2's "no navigation model" one level down: every grid view model is alive before a database
   exists.

2. **Opening a bundle prepares, rather than loads.** `MainViewModel.GridBinding.cs` calls
   `PrepareConnection(connection)` on each grid (`:60`, `:77`, `:78`, and the multiplexers' own
   `BindToConnection`). `PrepareConnection` (`GridViewModelBase.cs:263`) stores the connection, builds
   a `KeysetQueryBuilder`, sets the default sort, and **loads nothing**. Only the grid the user will
   land on gets `BindToConnection`, which is `PrepareConnection` plus `LoadFirstPage`.

3. **A grid loads when its tab becomes visible.** The shell calls `EnsureBound()` (`:277`), which
   no-ops if already loaded or in flight, fires the one-shot `OnBound` hook, and calls
   `LoadFirstPage()`.

4. **The first page loads off the UI thread.** `LoadFirstPage` (`:364`) snapshots view name, columns,
   sort, filter and page size, then opens a **second read-only connection** on a background thread
   (`:397`) and runs `KeysetQueryBuilder.Execute` there. Rows are marshalled back and applied; the
   count query then runs on the same background connection and posts separately (`:438`). Rows appear
   before the count.

5. **Generation counting discards stale results.** `_loadGeneration` increments on every load and
   every unbind; both dispatcher callbacks check it (`:413`, `:440`) and return if superseded. This is
   the correct fix for the paging equivalent of the problem J-a's `_backgroundBindTasks` solves.

6. **A background failure falls back to the UI thread.** The whole background body is wrapped
   (`:447`); on any exception it re-runs `ExecuteQuery(null)` synchronously on the dispatcher. That
   second attempt has **no try/catch**.

7. **Scope propagates by suffix match on a reversed DN.** `ScopeDn` (`:189`) reloads immediately if
   the grid is loaded, else sets `_scopeDirty` for `ReloadIfScopeDirty()`. `ApplyScopeFilter` (`:227`)
   reverses the DN and issues `dn_reversed LIKE 'reversed%'` so the B-tree index applies.

8. **Sorting round-trips through the server.** `DataGridSortBehavior` intercepts the header click,
   suppresses WPF's in-memory sort, and raises `ApplySortCommand` with a `SortInfo`. The grid resolves
   it against a `SortRegistry` entry and calls `LoadFirstPage`. Keyset paging cannot sort a page
   locally, so this is the only correct approach — and it is applied on all five grid pages and no
   pop-out.

9. **Selection drives a preview panel.** Each grid's `SelectedX` setter pushes into a `Preview` view
   model (`FindingsGridViewModel.cs:54`), which the page renders inline and `ShellViewModel.ActivePreview`
   (J2) reaches four levels deep to surface in the context drawer.

10. **A row opens a detail surface.** Double-click or context menu opens `ObjectDetailWindow`,
    `FindingDetailWindow`, `EscalationPathDetailWindow`, or a pop-out `DetailWindow`. Every one of these
    is wired with `Click=` / `MouseDoubleClick=` code-behind, not commands.

11. **Live checks are dispatched from a static.** `PreviewActionService` (556) takes
    `(ShellViewModel shell, Window owner)`, reaches into `shell.Main.ObjectsTab.AllGrid.Preview`, runs a
    single live read, and writes the result back onto the preview view model.

12. **Acceptance writes and reloads.** `AcceptFindingFromDialog` (`FindingsGridViewModel.cs:274`)
    calls `SuppressionService.Suppress` on a separate writable sidecar connection, then
    `LoadFirstPage()`. The read connection has the sidecar attached read-only, so the reload sees the
    new row.

## Components

### J21 — Keyset-paged grid engine

- **Owns:** Page state, sort selection, filter assembly, connection binding and load lifecycle for
  every grid in the product.
- **Layer:** UI
- **Depends on:** C (`KeysetQueryBuilder`, `ContinuationToken`, `GridFilter`, `SortDefinition`,
  `KeysetPageResult`), C4 (`DatabaseConnectionFactory.OpenReadOnly`), K (`UiPerfTrace`)
- **Implemented by:** `ViewModels/GridViewModelBase.cs` (514)
- **Non-obvious:** The abstract surface is six members — `ViewName`, `Columns`, `MapRow`,
  `BuildFilter`, `ResolveSortDefinition`, `GetDefaultSort`/`GetDefaultSortColumn` — and 21 subclasses
  supply nothing else structural. That is a genuinely well-drawn extension point.

  **`DataLoadState` only ever describes the count query.** The enum's own comment says it "ensures
  'failed to compute' is never confused with 'zero results'", but the only field of that type is
  `CountLoadState`, written at `:423` and `:443` from the `CountRows` call alone. There is no load
  state for the *rows*. A row query that throws goes to the UI-thread fallback at `:460`, and if that
  throws too the exception is unhandled. On the path where the count succeeds and the rows fail,
  `TotalCountDisplay` renders a number while `Rows` is empty.

  `UpdateTotalCountBackground` (`:154`) has a second, worse failure mode: `catch { count = 0; }`
  (`:166`–`:169`) with no `CountLoadState` write at all, so the insight-chip path reports a confident
  zero.

  `PageSize` is 50 and is `[ObservableProperty]`, so it is settable — but `git grep "PageSize ="`
  returns only the initialiser. Nothing exposes it to the user.

  `PageInfo` renders `"Page {N}"` with no total, because keyset paging cannot know the page count
  without the separate count query the property does not read.

### J22 — Grid sub-view multiplexers

- **Owns:** Presenting several grids as one tab, and forwarding bind, scope and `EnsureBound` to
  whichever is active.
- **Layer:** UI
- **Depends on:** J21
- **Implemented by:** `ViewModels/ObjectsTabViewModel.cs` (110), `ViewModels/GroupsTabViewModel.cs`
  (85), `ViewModels/AttackPathsTabViewModel.cs` (97)
- **Non-obvious:** These are the *other* three `IScopedGrid` implementers. They are a composite over
  the interface — `ActiveGrid` returns an `IScopedGrid`, and `OnViewModeChanged` calls `EnsureBound()`
  then `ReloadIfScopeDirty()` on it — which is a clean use of the seam.

  **Nothing sets `ViewMode`.** `git grep -E "ViewMode[^l]"` over all `.xaml` and `.xaml.cs` returns
  nothing. All three multiplexers sit on their default forever, so `ObjectsTab` shows only `AllGrid`,
  and `GroupsTab` and `AttackPathsTab` show only their first grid. Eight grids are constructed,
  connection-prepared and scope-propagated behind a switch no user input reaches. See J46.

  `BindToConnection` binds the first grid and *prepares* the rest (`ObjectsTabViewModel.cs:85`–`:90`),
  which is the right lazy-load discipline — and is wasted, because the rest can never become active.

### J23 — The grid catalogue

- **Owns:** The 21 concrete grids: which view each reads, which columns, which filters, which sorts.
- **Layer:** UI
- **Depends on:** J21, C2 (the `v_grid_*` views), E (`SuppressionService`, `AcceptanceImportService`,
  `RuleDefinitionLoader`), C (`GridSummaryQueryService`)
- **Implemented by:** `ObjectsGridViewModel.cs` (388), `AcesGridViewModel.cs` (273),
  `PrincipalsGridViewModel.cs` (211), `OwnersGridViewModel.cs` (185), `AdminSDHolderGridViewModel.cs`
  (75), `StaleDormantGridViewModel.cs` (98), `FindingsGridViewModel.cs` (647),
  `ControlEdgesGridViewModel.cs` (478), `EscalationPathsGridViewModel.cs` (302),
  `HighValueTargetsGridViewModel.cs` (91), `GroupExpansionGridViewModel.cs` (111),
  `GroupMembershipGridViewModel.cs` (139), `SidHistoryGridViewModel.cs` (84),
  `UnresolvedMembersGridViewModel.cs` (37), `DelegationsGridViewModel.cs` (193),
  `BundleMatchGridViewModel.cs` (129), `KerberosAuthGridViewModel.cs` (163),
  `NoLapsGridViewModel.cs` (174), `CoverageGridViewModel.cs` (64), `TrustsGridViewModel.cs` (86),
  `PasswordPolicyGridViewModel.cs` (99) — 4,027 total
- **Non-obvious:** The size spread is the map. Fourteen are under 200 lines and are pure
  configuration. Three carry real logic: `FindingsGridViewModel` (647), `ControlEdgesGridViewModel`
  (478), `ObjectsGridViewModel` (388).

  `FindingsGridViewModel` is the branch's most important single type and the one that answers two of
  J-a's three open questions. It owns suppression semantics at the presentation layer: `ShowSuppressed`
  toggles `filter.With("is_suppressed", "0")` (`:573`–`:574`), `SuppressedCount` is a separate query
  through `GridSummaryQueryService.GetSuppressedFindingCount` (`:502`), and accept/revoke write through
  a second, writable sidecar connection (`:182`–`:191`).

  **The rule-family chip counts do not honour the suppression filter.** `LoadRuleCounts` (`:548`)
  issues `SELECT rule_id, COUNT(*) FROM v_grid_findings WHERE run_id = $runId GROUP BY rule_id` with no
  `is_suppressed` predicate, and those counts are rendered into the family dropdown labels
  (`"ACL / Control (412)"`, `:534`). Selecting that family then shows fewer rows than the label
  promised, by exactly the number accepted. One view model disagreeing with itself.

  Five hard-coded `Hide*Operators` toggles (`:96`–`:153`) filter five literal well-known SIDs.
  `RuleFamilies` (`:81`–`:93`) is a second hard-coded SEC-* taxonomy, independent of E's `rules.yaml`
  and `BuiltInRules`, with `GetSelectedFamilyRuleIds` recovering the family by string-splitting the
  count back off the label it just formatted (`:613`–`:625`).

  Only five grids override `UpdateTotalCount` with a `CountLoadState = DataLoadState.Failed` on
  `SqliteException` — `ObjectsGridViewModel:301`, `OwnersGridViewModel:129`, `PrincipalsGridViewModel:131`,
  `GroupMembershipGridViewModel:88`, `KerberosAuthGridViewModel:123`. The other sixteen inherit the
  base's silent-zero path.

  `NoLapsGridViewModel.ExportCsv` is I21 — the third independent CSV writer. Referenced, not re-mapped.

### J24 — Grid row models

- **Owns:** The typed shape of one row per grid, and any per-row display derivation.
- **Layer:** UI
- **Depends on:** J23
- **Implemented by:** 21 `*GridRow.cs` files, 1,285 lines, of which
  `EscalationPathGridRow.cs` is 492 and the remaining twenty average 40
- **Non-obvious:** Twenty are `record`s that mirror a `v_grid_*` view's column list. The odd one out
  is `EscalationPathGridRow` (492), which carries a parsed step sequence and the prose that renders a
  path — it is a row type doing a detail view's job, which is why `EscalationPathsGridPage.xaml.cs` is
  142 lines.

  **`FindingGridRow.IsSuppressed` is populated and rendered nowhere in any grid.** It is mapped at
  `FindingsGridViewModel.cs:641` and consumed only by `FindingPreviewViewModel:36` and
  `FindingDetailViewModel:265`. See J27 for what that means on screen.

  `ObjectDetailPanelViewModel.cs:617` constructs `FindingGridRow` with `IsSuppressed: 0` hard-coded,
  and `ObjectsGridViewModel.cs:365`, `DrillDownResolver.cs:113` and `ObjectDetailWindow.xaml.cs:83` do
  the same for `FindingCriticalCount`. Findings reached through the object inspector are stated as
  not-accepted regardless of whether they are.

### J25 — Column description, sorting and column visibility

- **Owns:** What a column is, how a header click becomes a server-side sort, and which columns show.
- **Layer:** UI
- **Depends on:** J21, C (`SortDefinition`, `SortRegistry`)
- **Implemented by:** `ViewModels/GridColumnDefinition.cs` (47),
  `Behaviors/DataGridSortBehavior.cs` (152), `Behaviors/DataGridColumnVisibilityBehavior.cs` (88),
  `Controls/ColumnChooser.xaml` (98) + `.xaml.cs` (47)
- **Non-obvious:** `DataGridSortBehavior` exists because WPF's built-in sort would reorder the 50 rows
  on screen and call that sorted. It intercepts `Sorting`, cancels it, and raises `ApplySortCommand`
  so the sort goes back to SQLite. That is the correct answer to keyset paging and it is applied
  consistently — `git grep -ln "DataGridSortBehavior" -- '*.xaml'` returns all five grid pages.

  **`DetailWindow.xaml` sets `CanUserSortColumns="False"` on all eleven of its grids** (`:40`, `:70`,
  `:95`, `:119`, …). The one host without the behaviour disables sorting rather than offering a
  page-local sort that would silently lie. That is the right call and worth keeping.

  `DataGridColumnVisibilityBehavior` and `ColumnChooser` are used by **exactly one grid** —
  `ObjectsGridPage.xaml`. Column choice is an Objects-only feature that looks general.

### J26 — Filter toolbar

- **Owns:** The shared search / chip / result-count strip above a grid.
- **Layer:** UI
- **Depends on:** J23, J25
- **Implemented by:** `Controls/FilterBar.xaml` (128) + `.xaml.cs` (198),
  `Controls/FilterChip.xaml` (44) + `.xaml.cs` (143), `Controls/SearchBox.xaml` (63) + `.xaml.cs`
  (140), `ViewModels/FilterChipViewModel.cs` (52), `ViewModels/NoiseLensState.cs` (157)
- **Non-obvious:** `SearchBox` owns a real debounce (`DebouncedTextProperty`, `DebounceDelayProperty`)
  so each keystroke does not fire a query, and `FilterBar` re-exposes it as `DebouncedSearchText`.
  That is the right shape.

  **`FilterBar.ResultCount` is `typeof(int)` with `new PropertyMetadata(0)`** (`:93`–`:97`). This is
  the single line that defeats J21's `DataLoadState`: the shared control that every grid page uses to
  show its count structurally cannot represent "failed", so no page can bind `TotalCountDisplay` even
  if it wanted to. The mechanism was built in the view model and the toolbar contract was designed
  without it.

  `NoiseLensState` (157) is a saved-filter concept — a named set of noise-suppressing toggles. It is
  the only user-authored view state in the branch.

### J27 — Grid pages

- **Owns:** The five screens that host a grid: toolbar, paging bar, columns, context menu, empty state.
- **Layer:** UI
- **Depends on:** J21–J26, J31, J2 (`AuditSubView`)
- **Implemented by:** `Views/AuditView.xaml` (125) + `.xaml.cs` (16),
  `Views/ObjectsGridPage.xaml` (214) + `.xaml.cs` (136),
  `Views/FindingsGridPage.xaml` (231) + `.xaml.cs` (145),
  `Views/EscalationPathsGridPage.xaml` (161) + `.xaml.cs` (142),
  `Views/GroupsGridPage.xaml` (77) + `.xaml.cs` (70),
  `Views/NoLapsGridPage.xaml` (96) + `.xaml.cs` (63) — 1,476 total
- **Non-obvious:** **There is no page template.** Each of the five declares its own `DockPanel`, its
  own `FilterBar`, its own Prev/Next/Refresh `StackPanel` and its own `DataGrid` from scratch. The
  shared parts are the `FilterBar` control and the `PagingButton` style; the structure is copied.

  `AuditView.xaml:101`–`:122` repeats J2's decision exactly one level down: all five pages are
  instantiated at once inside a `Grid` and switched by `AuditSubViewToVisibilityConverter`. Two
  independent literal lists again — five `RadioButton`s at `:82`–`:94` and five page elements at
  `:102`–`:121` — which can silently disagree.

  **Answering J-a's first question: no grid page distinguishes failed from empty.** Not one binds
  `TotalCountDisplay`, `IsCountFailed` or `CountLoadState`; `git grep` for all three over `src` returns
  only `GridViewModelBase.cs` and the five grids that write to them. All five pages bind the raw
  `TotalResultCount` int, which is `0` on failure.

  **Only `FindingsGridPage` has an empty state at all**, and it makes the conflation explicit. The
  overlay at `:133` is bound to `TotalResultCount` through `GreaterThanZeroToVisibility` inverted, and
  its body asserts a cause: *"No findings generated / The findings engine did not produce results."*
  That sentence renders when the count query failed, when the row query failed, and when a filter
  legitimately matched nothing. The other four pages show a blank `DataGrid` with no message. G and H
  failed this test, I passed it, J-a found the Dashboard applying the right pattern to one tile of
  nine; **J-b's grid pages fail it five times out of five**, and the failure is not carelessness — it
  is J26's `int` contract.

  **Answering J-a's second question: suppressed and accepted findings are filtered, not marked.**
  `FindingsGridPage.xaml` has a "Show accepted" checkbox (`:102`–`:104`), an `"{0} accepted"` summary
  (`:43`), and Accept / Revoke context items (`:13`–`:14`). Its `DataGrid.RowStyle` (`:153`–`:157`)
  sets `MinHeight` and nothing else, and none of its six columns (`:165`–`:224`) binds `IsSuppressed`.
  With "Show accepted" ticked, accepted findings appear in severity order alongside live ones and are
  visually identical. The marking exists one click further in — `FindingPreviewPanel.xaml:48`, `:129`,
  `:132` and `FindingDetailWindow.xaml:256` all trigger on `IsSuppressed` — so the user learns a
  finding was accepted only after selecting it. This is the third data point: I found the export
  includes them unflagged in 44 of 46 reports, J-a found Home prioritises them, and the grid renders
  them unmarked.

  **Answering J-a's third question: the Findings grid is a third answer, and the disagreement is
  clickable.** The grid queries `v_grid_findings WHERE run_id = <loaded run> AND is_suppressed = '0'`
  (`FindingsGridViewModel.cs:570`–`:574`). The Dashboard's counts come from
  `FindingsService.GetSummary(latestRunId)`, which is `SELECT rule_id, severity, COUNT(*) FROM
  fact_finding WHERE run_id = $runId` (`FindingsService.Queries.cs:136`) — no suppression predicate of
  any kind, and `fact_finding` is the raw table rather than the view that computes `is_suppressed`. The
  gap is exactly `SuppressedCount`, the number the grid prints beside it. And `HomeView.xaml:225` binds
  `Dashboard.CriticalFindingsCount` on a tile whose `SeverityTile_Click` navigates to that grid: the
  user clicks a tile reading *12 Critical* and lands on a grid showing fewer rows, with nothing on
  screen explaining the difference.

  There is a **fourth** count. If no `dim_run` row exists, `MainViewModel.GridBinding.cs:296` falls back
  to `FindingSummaryService.CountBySeverity`, which is `SELECT severity, COUNT(*) FROM fact_finding
  GROUP BY severity` — **no `run_id` filter at all**, so a bundle holding two runs shows their sum.

### J28 — Row identity and shared context menu

- **Owns:** Turning a selected row of any type into a stable identity, and deciding which context-menu
  items apply to it.
- **Layer:** UI
- **Depends on:** J24, J27
- **Implemented by:** `ViewModels/RowIdentity.cs` (173), `ViewModels/ContextMenuStateResolver.cs`
  (43), `GridContextMenuHelper.cs` (93), `Views/GridRowSelectionHelper.cs` (54)
- **Non-obvious:** `RowIdentity` is the only place in the branch that knows all 21 row shapes are
  variations on "an object, a principal, or a finding". Its own summary says it exists "to decouple
  row-type routing logic from shell state" — and it is right to exist: without it, every page's
  code-behind would re-derive a DN or a SID from whichever record it happened to hold.

  `ContextMenuStateResolver` computes booleans so the code-behind only assigns `Visibility`. That is
  the correct division and it is undermined by the fact that the code-behind exists at all — the menu
  items themselves are `Click=` handlers.

### J29 — Drill-down resolution

- **Owns:** Turning a `DrillDownTarget` into an applied filter on whichever grid receives it.
- **Layer:** UI
- **Depends on:** J20 (`DrillDownTarget`, `NavigateWithDrillDown`), J23, J30
- **Implemented by:** `ViewModels/DrillDownResolver.cs` (121), `ViewModels/DrillDownAction.cs` (23),
  `ViewModels/DrillDownTarget.cs` (128, mapped as J20)
- **Non-obvious:** This is the consumer half of the one contract J-a said was worth salvaging from the
  dead dashboard. It works, and `DetailWindowViewModel.ApplyDrillDown` (`:129`–`:162`) is a clean
  implementation: six typed cases, each translating a target into a specific grid's filter method.

  It is also the reason J20's finding matters. The mechanism is complete on the receiving end; the
  only thing missing is the nine `Command=` bindings that would send anything into it.

### J30 — Pop-out grid host

- **Owns:** Opening any one grid in its own window, on its own connection, optionally pre-filtered.
- **Layer:** UI
- **Depends on:** J21, J23, J29, C4
- **Implemented by:** `ViewModels/DetailWindowViewModel.cs` (191), `DetailWindow.xaml` (355) +
  `.xaml.cs` (48)
- **Non-obvious:** This is the **second host** for eleven of the 21 grids, and for six of them it is
  the *only* host — `AcesGrid`, `PrincipalsGrid`, `KerberosAuthGrid`, `CoverageGrid`,
  `UnresolvedMembersGrid` and `ControlEdgesGrid` appear in no main-shell page. Permissions, principals
  and control edges — three of the most audit-relevant tables in the product — are reachable only
  through a pop-out.

  It opens its **own** `DatabaseConnectionFactory.OpenReadOnly` (`:70`) and implements `IDisposable`
  to close it. That is correct and is the only place in J where a surface owns and releases its own
  connection.

  **`CanOpenInNewWindow` (`:182`) returns true for every tab id except `"dashboard"`, but `BindGrid`
  (`:80`) has cases for only eleven.** Requesting `trusts`, `password_policies` or `delegation_bundles`
  — all three of which `MainViewModel.Navigation.cs:98`–`:103` maps as valid tab ids — produces a
  window with a title, a status line, and no grid. Empty-versus-failed again, at window granularity.

### J31 — Preview panels

- **Owns:** The compact "what is this row" panel that follows grid selection.
- **Layer:** UI
- **Depends on:** J23, J24, J32, H (live check results)
- **Implemented by:** `Controls/ObjectPreviewPanel.xaml` (238) + `.xaml.cs` (46),
  `Controls/FindingPreviewPanel.xaml` (138) + `.xaml.cs` (85), `Controls/GroupPreviewPanel.xaml` (75)
  + `.xaml.cs` (35), `Controls/LapsPreviewPanel.xaml` (76) + `.xaml.cs` (29),
  `Controls/EscalationPathPreviewPanel.xaml` (61) + `.xaml.cs` (41),
  `ViewModels/ObjectPreviewViewModel.cs` (263), `ViewModels/FindingPreviewViewModel.cs` (159),
  `ViewModels/GroupPreviewViewModel.cs` (54), `ViewModels/LapsPreviewViewModel.cs` (40),
  `ViewModels/EscalationPathPreviewViewModel.cs` (58), `Controls/StatusCard.xaml` (117) + `.xaml.cs` (66)
- **Non-obvious:** `StatusCard` is the shared live-result renderer and it carries four states —
  `IsRunning`, `Status`, `Summary`, `Timestamp` — which is the closest thing in the branch to a proper
  empty/running/succeeded/failed contract. It has a `Timestamp` slot bound to `LastLiveCheckUtc`
  (`GroupPreviewPanel.xaml:61`).

  That produces an inversion worth stating plainly: **the live answer says when it was measured; the
  stored answer does not.** A live ACL check renders its own timestamp. The grid row it was run
  against carries no run id, no seal time and no coverage verdict.

  `FindingPreviewPanel` is where accepted findings are finally marked (`:48`, `:129`, `:132`) — the
  marking J27 shows is absent from the grid itself.

### J32 — Preview action dispatch

- **Owns:** Running a single live check for the selected row and writing the result back onto its
  preview.
- **Layer:** UI
- **Depends on:** H (`LiveCheckService`, `ILiveDiagnosticsService`), J31, J2 (`ShellViewModel`)
- **Implemented by:** `Services/PreviewActionService.cs` (556)
- **Non-obvious:** README ruling 228 places this in J because each of its seven call sites is a single
  live read with nothing stored to compare against. Reading it confirms that: `ShowObjectAclDeltas`,
  `ShowFindingAclDeltas` and their siblings render deltas the *preview* already holds, and the check
  methods (`:184`, `:224`, `:330`) set `IsLiveCheckRunning`, call H, and set it back.

  It is a `static` class taking `(ShellViewModel shell, Window owner)` and navigating
  `shell.Main.ObjectsTab.AllGrid.Preview` (`:12`–`:13`). That is J2's `ActivePreview` coupling in a
  second place: a static in `Services/` that knows the shell's four-level view-model tree by heart.
  Nothing about it is testable and nothing about it is substitutable.

  **Greenfield:** does not survive dropping live LDAP. Every one of its seven entry points is a live
  read of a single DN. What survives is the `StatusCard` contract it feeds (J31).

### J33 — ACE decoding and trustee aggregation

- **Owns:** Turning raw access masks and object-type GUIDs into named rights, and grouping a set of
  ACEs by trustee.
- **Layer:** Infrastructure
- **Depends on:** K (`PermissionClassifier`, `GuidCatalog`), Core (`SecureAD.Core.Security`)
- **Implemented by:** `src/SecureAD.Infrastructure/Security/AceAnalysisService.cs` (285)
- **Non-obvious:** README's ruling excludes this from C's read half because it aggregates
  already-fetched rows and issues no SQL. That holds: it is a static class over an `AceInput` list,
  with one production caller, `ObjectDetailPanelViewModel.AceAnalysis.cs:15`.

  **Answering J-a's fourth question: this is not a fourth implementation of effective access.**
  `AggregateByTrustee` (`:65`) groups by `TrusteeSid` and unions the rights each ACE grants. It does
  no group expansion — a trustee is a SID on an ACE, not a principal with a token — so it cannot
  answer "what can X do to this object", only "who has ACEs here and what do they say". H7, H10 and
  H16 remain the three, and `EffectiveAccessViewModel` / `StoredEffectiveAccessViewModel` are H15 and
  H16 themselves, already mapped.

  It is, however, a **third independent access-mask decoder**, alongside
  `EffectiveAccessEvaluator.DescribeAccess` (used by H16) and H7's inline decoding. `DecodeAccessMask`
  (`:103`) reimplements the bit table from scratch at `:111`–`:130`.

  And it is **deny-blind in its summary**. `AceDetailResult` carries an `AccessType` per row, but
  `RightsSummary` is built from `details.Select(d => d.Right).Distinct()` (`:80`–`:81`), which discards
  it. A trustee whose only ACE is an explicit DENY Full Control renders `"Full Control"` in the summary
  and `IsDangerous: true` (`:76`–`:77`). `HasDenyAces` exists as a separate flag, so the information
  survives — it just is not in the sentence the user reads.

  **Greenfield:** survives. `AceInput` is deliberately source-agnostic — its own comment says
  "populated from either the audit database (`fact_ace`) or live LDAP" — so dropping live access costs
  it nothing.

### J34 — Object inspector

- **Owns:** The full-page view of one directory object: attributes, ACEs, group membership, findings,
  and the live tools attached to it.
- **Layer:** UI
- **Depends on:** C (`ObjectQueryService`, `InheritedAceResolver`), J33, J42, J43, H (H15, H16, the
  `Acl*` compare view models), E (findings for the object)
- **Implemented by:** `ViewModels/ObjectDetailPanelViewModel.cs` (1,030), `.AceAnalysis.cs` (172),
  `.Live.cs` (368), `.LiveDetail.cs` (312), `ObjectDetailWindow.xaml` (1,311) + `.xaml.cs` (329) —
  3,522 total
- **Non-obvious:** The single largest surface in branch J, and `ObjectDetailWindow.xaml` at 1,311
  lines is the largest XAML file in the product.

  Its structure is a left nav rail of `NavSection` records (`:19`, `:246`) grouped into Overview and
  Tools, built dynamically in `.Live.cs:340`–`:359` depending on whether live diagnostics are
  available. That is the right shape: one object, many lenses, and the lens list reflects what the
  session can actually do.

  The section titles are **honest about provenance in a way nothing else in the product is** —
  `db_effective` is labelled *"Snapshot Access Estimate"* and `live_effective` is labelled *"Live
  Access Validation"*. Estimate versus validation, snapshot versus live, in the tab label. That is the
  best naming in the branch.

  Which makes the next fact worse: **`NavSection.IsLive` is declared with a default of `false` and is
  never once set to `true`.** `git grep "IsLive" -- src` finds no assignment in any of the four
  partials. The dedicated provenance flag is dead; the distinction survives only in the `db_` / `live_`
  key prefix and the hand-written titles. The right idea was modelled, then carried by a naming
  convention instead.

  `:617` constructs a `FindingGridRow` with `IsSuppressed: 0` hard-coded — see J24.

  **Greenfield:** the stored half survives; `.Live.cs` (368) and `.LiveDetail.cs` (312) do not.
  Roughly 20% of the component is live-only.

### J35 — Finding detail

- **Owns:** The pop-out that explains one finding: rule metadata, resolved names, evidence, and
  accept/revoke.
- **Layer:** UI
- **Depends on:** E (`BuiltInRules`, suppression), E12 (evidence), J24, J36
- **Implemented by:** `ViewModels/FindingDetailViewModel.cs` (846), `FindingDetailWindow.xaml` (285) +
  `.xaml.cs` (98)
- **Non-obvious:** Marks acceptance properly — `FindingDetailWindow.xaml:256` triggers on
  `IsSuppressed` — which is the marking the grid lacks.

  `FindingDetailWindow.xaml.cs:64` sets `vm.IsSuppressed = true` directly from code-behind after the
  accept dialog returns, rather than reloading from the sidecar. The window's state and the database's
  state are updated independently.

  At 846 lines the view model is doing rule-metadata lookup, principal and target name resolution from
  captured evidence, and escalation-path step formatting — three jobs that appear again in J36, J34 and
  J37 respectively.

### J36 — Finding investigation guidance

- **Owns:** The per-rule prose that tells a user why a finding matters, how to verify it, and how to
  fix it.
- **Layer:** UI
- **Depends on:** E (rule ids), J35
- **Implemented by:** `Services/FindingInvestigationProvider.cs` (1,009),
  `ViewModels/FindingInvestigationViewModel.cs` (222), `Views/FindingInvestigationView.xaml` (311) +
  `.xaml.cs` (91)
- **Non-obvious:** `FindingInvestigationProvider` is an `internal static class` holding a dictionary
  of `SpecificGuidance` records keyed by rule id, each with a summary, why-it-matters, attack story,
  verification steps and remediation steps, all as C# string literals.

  It is **near-complete**: 61 distinct `SEC-*` keys against 62 rule ids in
  `src/SecureAD.Core/Findings/Rules/rules.yaml`. The single gap is **SEC-041**, which has a rule and a
  finding and no guidance. Nothing detects that — there is no test pairing the two catalogues, unlike
  I's `ReportCatalogExecutionTests`, which is exactly the mechanism that would have caught it.

  This is the **fourth** store of per-rule descriptive text, after `rules.yaml`, `BuiltInRules` and
  J14's `HelpViewModel.Content.cs` (1,351). Together they are ~2,400 lines of rule prose in three
  places that no build step reconciles.

  `AcceptanceDisplay` (`FindingInvestigationViewModel.cs:122`) branches on `Finding.IsSuppressed` — so
  the investigation view is a third surface that marks acceptance the grid does not.

  `ShellMode.FindingInvestigation` is one of the three enum members J-a found missing from the icon
  rail, and the only one whose absence carries no explanatory comment.

### J37 — Escalation path and control-edge evidence

- **Owns:** Showing the steps of an escalation path and the ACE evidence behind a control edge.
- **Layer:** UI
- **Depends on:** D (control edges, escalation paths), J23, J24
- **Implemented by:** `EscalationPathDetailWindow.xaml` (250) + `.xaml.cs` (187),
  `ViewModels/EscalationPathControlTextProvider.cs` (60),
  `ViewModels/ControlEdgeEvidenceDetailViewModel.cs` (132),
  `ControlEdgeEvidenceDetailWindow.xaml` (169) + `.xaml.cs` (44),
  `ViewModels/EscalationPathReferenceViewModel.cs` (240) + `EscalationPathReferenceWindow.xaml` (178)
- **Non-obvious:** `EscalationPathDetailWindow.xaml.cs` at 187 lines is the branch's heaviest
  code-behind after `ObjectDetailWindow`, and the reason is J24: the step sequence is parsed on
  `EscalationPathGridRow` (492) rather than in a view model, so the window assembles its display from a
  row type.

  `EscalationPathControlTextProvider` (60) turns a control-edge kind into a verb phrase — "can reset
  the password of", "can rewrite the DACL of". It is the only place a control edge becomes a sentence,
  and it is 60 lines. Worth keeping intact in a rebuild.

  `EscalationPathDetailViewModel` is declared inside `EscalationPathDetailWindow.xaml.cs` — the single
  hit in J-a's reachability sweep, confirmed here as legitimate.

### J38 — Small evidence detail windows

- **Owns:** Single-subject pop-outs for a delegation, a trustee, and an inspector row.
- **Layer:** UI
- **Depends on:** J24, J28, C
- **Implemented by:** `ViewModels/DelegationDetailViewModel.cs` (94) + `DelegationDetailWindow.xaml`
  (101) + `.xaml.cs` (37), `ViewModels/TrusteeDetailViewModel.cs` (55) + `TrusteeDetailWindow.xaml`
  (153) + `.xaml.cs` (31), `ViewModels/InspectorDetailModel.cs` (38) + `InspectorDetailWindow.xaml`
  (177) + `.xaml.cs` (18), `ViewModels/AceDetailRow.cs` (25),
  `ViewModels/PermissionSummaryRow.cs` (39), `ViewModels/DelegationSummaryRow.cs` (57)
- **Non-obvious:** `InspectorDetailModel` is the only one of the three that is a *model* opened by a
  static factory (`:35`) with a template key, rather than a view model bound to a window. It is a
  generic key-value pop-out, and it is the pattern the other two should have used — `TrusteeDetailViewModel`
  is 55 lines against a 153-line window that is almost entirely a static layout.

### J39 — Acceptance authoring

- **Owns:** Capturing the reason, identity and expiry for accepting a finding, and reviewing what has
  been accepted.
- **Layer:** UI
- **Depends on:** E10 (suppression semantics), J23 (`FindingsGridViewModel` writes), C5 (the sidecar)
- **Implemented by:** `ViewModels/AcceptFindingDialogViewModel.cs` (59) + `AcceptFindingDialog.xaml`
  (60) + `.xaml.cs` (60), `ViewModels/AcceptedFindingsViewModel.cs` (189) +
  `AcceptedFindingsWindow.xaml` (114) + `.xaml.cs` (39), `SetTierDialog.xaml` (52) + `.xaml.cs` (105)
- **Non-obvious:** This is the only place in the product where a user states *why* a finding is
  acceptable, and E10's design — revocation preserves the row rather than deleting it — means that
  reason is durable. The dialog collects reason, identity and optional expiry, which is the right
  minimum.

  `AcceptedFindingsViewModel`'s row is a class rather than a record specifically so `IsChecked` can be
  mutable for bulk revoke — an unusually well-explained departure, documented in its own summary.

  Both `AcceptFindingDialogViewModel.AcceptCommand` and `FindingsGridViewModel.SuppressFindingCommand`
  / `UnsuppressFindingCommand` are bound in no XAML. See J46.

### J40 — Acceptance import

- **Owns:** Carrying accepted findings forward from an earlier run in the same profile.
- **Layer:** UI
- **Depends on:** E10 (`AcceptanceImportService`, `source_run_id`), F (`RunLibraryService`,
  `RunMetadata`), J23
- **Implemented by:** `ViewModels/ImportAcceptancesViewModel.cs` (275),
  `ImportAcceptancesWindow.xaml` (71) + `.xaml.cs` (38)
- **Non-obvious:** **This holds the only rendered `SealedUtc` in the entire UI project.**
  `CapturedText => $"{(Run.SealedUtc ?? Run.CreatedUtc):g}"` (`:54`). J-a established the fact from the
  shell side; confirmed here from the half that owns the property, and the location is the point — the
  product's one visible statement of when evidence was sealed is a subtitle in a modal dialog about
  importing acceptances.

  The type's own remarks record a real design problem honestly: *"Every bundle acquires a
  `suppressions.db` as soon as anything reads it, so most runs hold [zero]"* — which is why the source
  list shows an acceptance count per run rather than just a run list. That is the right response to a
  storage side effect, and it is documented at the point of impact.

  It is the only surface in J that keeps `source_run_id` visible, and therefore the only one that
  makes E10's distinction between `Suppress` and `ImportAcceptance` observable.

### J41 — Findings policy wizard

- **Owns:** Authoring `findings-policy.json` — allowed principals and severity overrides — beside a
  bundle.
- **Layer:** UI
- **Depends on:** E (`FindingsPolicy`, `FindingsPolicyLoader`, `FindingsPolicyEvaluator`), J4
  (`ToolWindowLauncher`)
- **Implemented by:** `ViewModels/PolicyWizardViewModel.cs` (371), `PolicyWizardWindow.xaml` (285) +
  `.xaml.cs` (33)
- **Non-obvious:** The policy this authors is the one Home ignores. J-a found
  `MainViewModel.Home.cs` computing its "Fix these first" list under `FindingsPolicy.Empty`, and J27
  finds the Dashboard's severity counts reading `fact_finding` with no policy argument available at
  all. A user can spend time in this wizard declaring that a principal's access is intended and see
  every number on the two most prominent screens ignore it.

  `FindingsPolicyLoader` returns `FindingsPolicy.Empty` on any error and its own summary says it
  "never fails the audit run" (`:10`). That is defensible for a batch run and indefensible for a UI:
  a malformed policy file and no policy file are the same outcome, silently.

  Reachable only through `ToolWindowLauncher` (J4), from a `Click=` handler.

### J42 — Stored inheritance panel

- **Owns:** Showing which ACEs on an object are inherited and where inheritance is blocked, from the
  audit database.
- **Layer:** UI
- **Depends on:** C (`fact_ace`, `InheritedAceResolver`), J34
- **Implemented by:** `ViewModels/StoredInheritanceViewModel.cs` (291)
- **Non-obvious:** Not covered by ruling 228, which names only the live `InheritanceViewModel`, and
  not mapped in H — `git grep "StoredInheritanceViewModel" -- docs/map/` returns nothing. It is
  therefore new here.

  It is the stored counterpart to J43's live panel, and the pair is the same shape as H15/H16: two view
  models answering one question against two sources, sharing a section title (*"Inheritance"*, both
  `db_inheritance` and `live_inheritance` in `ObjectDetailPanelViewModel.Live.cs:351`, `:358`) and
  distinguished only by which nav group they sit in.

  **Greenfield:** survives, and becomes the only implementation.

### J43 — Single-live-read panels

- **Owns:** Panels that ask the live directory one question about one DN or SID and render the answer.
- **Layer:** UI
- **Depends on:** H (`ILiveDiagnosticsService`, `LiveCheckService`), J32, J34
- **Implemented by:** `ViewModels/InheritanceViewModel.cs` (316),
  `ViewModels/GroupMembershipViewModel.cs` (110), `ViewModels/ResolvePrincipalViewModel.cs` (139) +
  `Controls/ResolvePrincipalPanel.xaml` (89) + `.xaml.cs` (11),
  `ViewModels/WhoHasAccessViewModel.cs` (175) + `Controls/WhoHasAccessPanel.xaml` (103) + `.xaml.cs`
  (11), `Services/PrincipalNameResolver.cs` (130), `ViewModels/LiveSidResolver.cs` (93),
  `ViewModels/LdapInputHelper.cs` (65), `LdapInputDialog.xaml` (48) + `.xaml.cs` (154),
  `LdapResultDialog.xaml` (21) + `.xaml.cs` (27), `Controls/ObjectPickerHelper.cs` (93) — ~1,580 total
- **Non-obvious:** README ruling 228 assigns this set to J on the subject rule: each is a single live
  read with no stored counterpart to compare against.

  `LdapInputHelper` (65) and `ObjectPickerHelper` (93) are the input-normalisation half — stripping
  `DOMAIN\` qualifiers, accepting a DN or a sAMAccountName or a SID. `LdapInputHelper.StripDomainQualifier`
  has a stored consumer too (`StoredEffectiveAccessViewModel.cs:233`), so it is the one piece of this
  component that outlives the rest.

  `EnterKeyCommandBehavior` (51) exists for exactly these three panels — `ResolvePrincipalPanel`,
  `WhoHasAccessPanel`, `DelegationReportPanel` — because they are text-box-and-go surfaces.

  **`GroupMembershipViewModel` (110) has no view.** `git grep "GroupMembershipViewModel" -- src`
  returns four hits, all in `.cs`: its own declaration, its constructor, and
  `MainViewModel.cs:345`/`:476` where it is declared and constructed. No XAML references it, and its
  only command, `CheckCommand`, is bound nowhere. It is constructed on every session that has live
  diagnostics and cannot be reached. See J46.

  **Greenfield:** none of it survives except `LdapInputHelper`. This is the bulk of ruling 228 and the
  bulk of the answer to the standing note — roughly 1,580 lines that exist only because live LDAP does,
  and every one of them takes a single DN.

### J44 — Live OU delegation report panel

- **Owns:** Listing every delegation bundle applied to one OU, grouped by trustee, read live.
- **Layer:** UI
- **Depends on:** H (`ILiveDiagnosticsService`), K (delegation bundle catalogue)
- **Implemented by:** `ViewModels/DelegationReportViewModel.cs` (157),
  `Controls/DelegationReportPanel.xaml` (88) + `.xaml.cs` (15),
  `ViewModels/DelegationSummaryRow.cs` (57)
- **Non-obvious:** Ruling 234, resolved to J by the J-a session and placed in this half. Confirmed:
  it takes `ILiveDiagnosticsService` and a single OU DN, and writes no artefact.

  The name collision I recorded (`I-output.md:433`) is real and worth restating from this side.
  `DelegationReportGenerator` (I11) writes a forest-wide HTML file from stored evidence;
  this queries one OU live and renders a panel. `git grep` finds no reference between them. A user who
  clicks *Delegation Report* in the header bar (J-a's `DelegationReport_Click`) and *Delegation Report*
  in this panel gets two unrelated things.

  `RunReportCommand` is bound in `DelegationReportPanel.xaml` — and also in `ReportsView.xaml`, to
  `ReportsTabViewModel`. Third instance of the identical-command-name collision J-a recorded for
  `ExportHtmlCommand`.

  **Greenfield:** does not survive. Its stored equivalent already exists as I11.

### J45 — Error display surface

- **Owns:** Showing an error the user must acknowledge.
- **Layer:** UI
- **Depends on:** J1 (`IDialogService`)
- **Implemented by:** `ViewModels/ErrorDisplayViewModel.cs` (69), `ErrorDialog.xaml` (76) +
  `.xaml.cs` (37)
- **Non-obvious:** The only structured error surface in the branch, and it competes with J-a's
  `StatusText`, which roughly forty call sites write to. A grid whose count query fails reaches
  neither: `GridViewModelBase.cs:434` writes the exception to `Debug.WriteLine` and `UiPerfTrace`, and
  the user sees `0`.

  I23 recorded that `ExportErrorCode` is produced by nothing and every export failure is an
  interpolated `ex.Message`. The grid layer is worse: it has no error code, no message, and no
  surface.

### J46 — Dead surface below the seam

- **Owns:** Nothing. Recorded so a rebuild does not rebuild it.
- **Layer:** UI
- **Depends on:** —
- **Implemented by:** see below
- **Non-obvious:** J-a's sweep found no dead *subsystem* in J and located the dead surface at the
  command level. Reproducing that method below the seam finds both.

  **Six grids are fully plumbed and unreachable.** Each is constructed, given a connection, and has
  `ScopeDn` propagated to it; none appears in any XAML.

  | Grid | Lines | Plumbing | Why unreachable |
  |---|---|---|---|
  | `TrustsGridViewModel` | 86 | `MainViewModel.cs:401`, `GridBinding.cs:77`, `Navigation.cs:102`, `Commands.cs:240` | No page, no `DetailWindow` case |
  | `PasswordPolicyGridViewModel` | 99 | `MainViewModel.cs:404`, `GridBinding.cs:78`, `Navigation.cs:103`, `Commands.cs:241` | No page, no `DetailWindow` case |
  | `BundleMatchGridViewModel` | 129 | `MainViewModel.cs:410`, `GridBinding.cs:60`, `Navigation.cs:98`, `:128`, `Commands.cs:236` | No page, no `DetailWindow` case |
  | `SidHistoryGridViewModel` | 84 | `GroupsTabViewModel.cs:28`, `:40`, `:59`, `:66`, `:76` | `GroupsTab.ViewMode` never set |
  | `StaleDormantGridViewModel` | 98 | `ObjectsTabViewModel.cs:39`, `:55`, `:89`, `:101` | `ObjectsTab.ViewMode` never set |
  | `HighValueTargetsGridViewModel` | 91 | `AttackPathsTabViewModel.cs:33`, `:47`, `:69`, `:77`, `:88` | `AttackPathsTab.ViewMode` never set |

  Three of them — `trusts`, `password_policies`, `delegation_bundles` — are registered in
  `GetGridForTabId` (`MainViewModel.Navigation.cs:98`–`:103`), so the shell believes they are
  navigable. That is J20's dashboard failure in a third place: the routing exists, the destination does
  not. **Trusts and password policies are directory-wide security facts the product captures, derives
  and can never display.**

  **`GroupMembershipViewModel` (110) is a dead live panel** — constructed at `MainViewModel.cs:476`,
  referenced by no XAML, with its only command unbound. Branch J does have a dead subsystem after all;
  it is just small and sits in this half.

  **`LazyTabBehavior` (123) has no consumer.** `git grep "LazyTabBehavior"` returns only its own three
  self-references. It is an attached behaviour for deferring a tab's content until first selection —
  which is precisely what `IScopedGrid.EnsureBound()` does. The seam's own purpose was solved twice,
  once as a behaviour and once as an interface, and the behaviour lost without being deleted.

  **Unbound commands below the seam**, by the same method J-a used (generated name against all 64 XAML
  files, `Async` suffix stripped):

  | Command | Why it is dead |
  |---|---|
  | `GridViewModelBase.ApplyFilterCommand` | No grid page binds it; each filter setter calls `LoadFirstPage()` directly |
  | `FindingsGridViewModel.SuppressFindingCommand` | `FindingsGridPage.xaml:13` uses `ContextAcceptFinding_Click` |
  | `FindingsGridViewModel.UnsuppressFindingCommand` | `FindingsGridPage.xaml:14` uses `ContextRevokeFinding_Click` |
  | `AcceptFindingDialogViewModel.AcceptCommand` | `AcceptFindingDialog.xaml.cs` uses `Click=` |
  | `ObjectsGridViewModel.ViewObjectDetailsCommand` | `ObjectsGridPage.xaml` uses `MouseDoubleClick` |
  | `GroupMembershipViewModel.CheckCommand` | The view model has no view |

  Note the pattern: **every acceptance action in the product is a `Click=` handler.** Accept, revoke,
  and the dialog's own OK. E10's suppression semantics — the thing that makes a finding stop appearing
  — are driven entirely from code-behind and are therefore entirely untestable, which is I20's and
  J20's failure a fourth and fifth time, on the one action that mutates persistent state.

  **What should survive:** `DataLoadState` and `TotalCountDisplay` (J21) — the mechanism is correct and
  only its consumers are missing. `LazyTabBehavior`'s idea survives as `EnsureBound()`; the type should
  not. The six dead grids' *queries* are real capture output — trusts and password policies especially
  — and should get a page in a rebuild rather than a view model.

## Naming & taxonomy

| Current | Proposed | Why it matters |
|---|---|---|
| `DataLoadState` / `CountLoadState` | `CountLoadState` only, or extend to rows | The enum is documented as the product's answer to "failed versus empty" and the only field of that type describes the count query. The name promises coverage of the load; it covers a third of it. This is the naming error that let five grid pages ship without a failure state. |
| `GridViewModelBase.TotalResultCount` vs `TotalCountDisplay` | `TotalCountRaw` / `TotalCountText` | Two properties differing by one word, one of which is honest about failure and one of which is not. Every consumer picked the shorter name. Same defect J-a recorded for `CapturedUtc` / `CaptureTimestamp`. |
| `FilterBar.ResultCount` (`int`) | `ResultCountText` (`string`) | The type is the problem and the name conceals it. An `int` cannot say "error" or "counting…", so the shared toolbar silently vetoes the view model's three-state contract. |
| `IScopedGrid` | `IBindableGrid` | Carried from J-a and confirmed from this side: of its two methods, `EnsureBound()` is about deferred binding and `ReloadIfScopeDirty()` is about scope. The interface's dominant purpose is the former. |
| `ObjectsTabViewModel` / `GroupsTabViewModel` / `AttackPathsTabViewModel` | `*GridGroup` | They are not tabs — no `TabControl` exists and no `TabItem` binds them. They are composites over `IScopedGrid`, and calling them tabs is why nobody noticed `ViewMode` is never set. |
| `ObjectsTabViewModel.AllGrid` | `ObjectsGrid` | The only grid named for its filter rather than its subject, and the one that is actually reachable. Its siblings are `OwnersGrid`, `AdminSDHolderGrid`, `StaleDormantGrid`. |
| `MainViewModel.PasswordPoliciesGrid` (type `PasswordPolicyGridViewModel`) | pick one | Property plural, type singular, view `v_grid_password_policy`. Three spellings of one thing across the layer boundary. |
| `DelegationReportViewModel` (J44) vs `DelegationReportGenerator` (I11) | `LiveOuDelegationPanel` / `DelegationExportReport` | Carried from `I-output.md:433` and confirmed. Two unrelated features, two buttons, one name. A user cannot tell from the UI which one they clicked. |
| `RunReportCommand` on `DelegationReportViewModel` and on `ReportsTabViewModel` | `RunOuDelegationScanCommand` / `RunCatalogReportCommand` | Third identical-command-name collision in branch J, after `ExportHtmlCommand` ×2. Both bound, to unrelated subjects. |
| `InheritanceViewModel` (J43, live) vs `StoredInheritanceViewModel` (J42) | `LiveInheritanceViewModel` / `StoredInheritanceViewModel` | The unprefixed one is the live one. Same asymmetry J-a proposed fixing for the two directory trees, and the same consequence: the name gives no hint which survives a greenfield that drops live access. |
| `NavSection.IsLive` | delete, or populate it | A provenance flag with a `false` default that is never set to `true`, on the one screen that has both live and stored sections. Either it is the mechanism or the titles are; having both means the flag is a trap for the next reader. |
| `AceAnalysisService.TrusteePermissionResult.RightsSummary` | `GrantedRightsSummary`, or fold in `AccessType` | The summary is built by discarding the allow/deny distinction the detail rows carry. The name implies "all rights this trustee has here"; it means "every right named on any ACE, whether granted or denied". |
| `FindingInvestigationProvider` | `RuleRemediationCatalog` | It provides nothing and investigates nothing; it is a static lookup table of 61 rule guidance entries. The `*Provider` suffix in `Services/` implies an injectable dependency, and it is `internal static`. |
| `DetailWindow` / `DetailWindowViewModel` (J30) | `GridPopOutWindow` | Six other windows in the project end in `DetailWindow` (`Object`, `Finding`, `EscalationPath`, `ControlEdgeEvidence`, `Delegation`, `Trustee`, `Inspector`) and every one of them shows a *single subject*. This one shows a whole grid. It is the odd member of a family it appears to lead. |
| `PreviewActionService` | `LivePreviewCommands` | It is not a service — it is `static`, takes the shell as a parameter, and opens windows. The `Service` suffix in `Services/` next to `LiveCheckService` (a real one) makes the layer look deeper than it is. |

## Would-do-differently

**1. Make the grid's load state reach the screen — the mechanism is already correct.**
This is the branch's "this was right, keep it", and it earns it on inspection rather than on its
comment. `GridViewModelBase` gets several hard things right by construction: `_loadGeneration` makes
stale results impossible when a user clicks fast; the background load opens a second read-only
connection so a slow count cannot freeze the UI; rows are shown before the count so a large table is
usable immediately; `PrepareConnection` versus `BindToConnection` means opening a bundle does not run
21 queries. `DataLoadState` and `TotalCountDisplay` are the right three-state contract, and the
comment on the enum is the clearest statement of the empty-versus-failed principle anywhere in the
codebase.

And it reaches nothing. No XAML binds `TotalCountDisplay`, `IsCountFailed` or `CountLoadState`; all
five pages bind the raw `int`; `FilterBar.ResultCount` is typed `int` so they could not do otherwise;
`FindingsGridPage`'s empty state asserts a specific cause it cannot know; sixteen of 21 grids do not
even set `Failed` on a count exception; and there is no row load state at all. **This is the same
shape as J20 and I20 — the good design exists, and the view was wired past it** — but it is the most
expensive instance, because it is the mechanism by which an audit tool tells the user it does not
know. A rebuild should type the count as a discriminated result rather than an `int`, make the
toolbar's contract that type, give the *rows* a load state too, and put a test on the pages.

**2. Give the grids a page template.** Five pages, 1,476 lines, each reimplementing the same
`DockPanel` / `FilterBar` / paging bar / `DataGrid` / context menu from scratch. That is why column
choice exists on one page, why an empty state exists on one page, and why sort behaviour had to be
attached five separate times. It is also why the eleven pop-out grids in `DetailWindow` share none of
it. A rebuild should have one `GridPage` control taking a `IScopedGrid`, a column set and a preview
template, so a new grid is a view model and a column list rather than a 200-line copy.

**3. Delete `ViewMode`, or wire it.** Three multiplexers exist to switch between eight grids and
nothing sets the switch. This is the single largest waste in the half — eight grids constructed,
connection-prepared and scope-propagated behind a property no user input reaches — and it is invisible
because the plumbing is complete. Combined with the three grids `GetGridForTabId` routes to and no
view renders, **six of the product's 21 grids cannot be seen, including trusts and password
policies**. A rebuild should derive the navigable set from a declared route table, the same fix J-a
proposes at the shell level, so a destination that does not exist fails at startup rather than
silently.

**4. Make the findings count one query with one policy.** There are now four answers to "how many
Critical findings does this run have": the grid (`v_grid_findings`, loaded run, `is_suppressed = 0`),
the Dashboard and Home tiles (`fact_finding`, latest run, no suppression), the rule-family chip labels
(`v_grid_findings`, loaded run, no suppression), and the no-`dim_run` fallback (`fact_finding`, **all**
runs, no suppression). J-a established Home and Dashboard as two; they are in fact the same source and
the grid is genuinely a third, with the chips a fourth *inside the grid's own view model*. The
disagreement is directly clickable: `HomeView.xaml:225` puts a Critical count on a tile whose click
handler navigates to a grid that will show fewer rows. A rebuild should make a findings count a single
function requiring a `FindingsPolicy` argument with no empty default, and render the exclusion count
next to any number computed under a non-empty one — the same conclusion J-a reached, now with the
fourth data point that makes it unarguable.

**5. Mark acceptance in the rows, and stop driving it from code-behind.** Accepted findings are
filtered out by default and unmarked when shown. `FindingGridRow.IsSuppressed` is populated and bound
in no grid column and no row style; the marking exists only in the preview panel, the detail window and
the investigation view, all of which require selecting the row first. Meanwhile every accept and revoke
action in the product — `ContextAcceptFinding_Click`, `ContextRevokeFinding_Click`, the dialog's own OK
— is a `Click=` handler, so the three `[RelayCommand]`s that would make the one state-mutating operation
testable are dead. `ObjectDetailPanelViewModel.cs:617` hard-codes `IsSuppressed: 0`, so findings reached
through the object inspector are stated as not-accepted whether or not they are. A rebuild should treat
suppression as a row-level visual state, not a filter, and should not allow a write to the suppression
sidecar from a view.

**6. Consolidate the rule prose.** `rules.yaml`, `BuiltInRules`, `HelpViewModel.Content.cs` (1,351)
and `FindingInvestigationProvider` (1,009) are four stores of per-rule descriptive text, ~2,400 lines of
it in the UI project alone, with nothing reconciling them. The evidence that this matters is small and
exact: **SEC-041 has a rule and no investigation guidance**, and nothing detects it. I's
`ReportCatalogExecutionTests` is the proven answer — a test that walks the catalogue and fails CI
rather than failing a user — and it costs almost nothing to apply here. In a rebuild the guidance
belongs beside the rule definition, as data, so a rule without it cannot be added.

**7. Drop the live panels and keep three things.** The standing note asks per component. J32
(`PreviewActionService`, 556), J43 (the ruling-228 panels, ~1,580) and J44 (`DelegationReportViewModel`,
260) do not survive a greenfield that drops live LDAP — roughly 2,400 lines, every entry point of which
takes a single DN or SID, which is H's forest-scale argument reproduced in J's own surface. J34's
`.Live.cs` and `.LiveDetail.cs` (680) go with them, leaving the object inspector intact. J42
(`StoredInheritanceViewModel`) survives and becomes the only implementation. J33 (`AceAnalysisService`)
survives untouched, because `AceInput` was deliberately written source-agnostic.

What should survive out of the deleted set. First, `LdapInputHelper.StripDomainQualifier` — it already
has a stored consumer at `StoredEffectiveAccessViewModel.cs:233`, and "accept a DN or a
sAMAccountName or a SID" is a stored-mode need too. Second, `StatusCard`'s four-state contract
(`IsRunning` / `Status` / `Summary` / `Timestamp`), which is the branch's only correct
running-versus-result-versus-failure renderer and is currently used only for live results. Third, and
most pointedly, **`StatusCard.Timestamp`**: the live panels state when they were measured and the
stored grids do not. Inverting that — a stored answer that carries its run's seal time, a live one that
carries the moment of the read — is the concrete form J-a's provenance conclusion should take.

**8. Provenance: a fourth branch, with a fourth kind of evidence.** H, I and J-a each found nothing. So
does this half, and the specific finding adds something. `git grep "SealedUtc" -- src/SecureAD.UI`
returns thirteen hits; twelve are sort keys and the thirteenth is
`ImportAcceptancesViewModel.CapturedText` (`:54`) — a subtitle in a modal dialog, which lives in *this*
half. Nothing in any of the five grid pages, the eleven pop-out grids, the five preview panels or the
seven detail windows states which run it is showing, when that run was sealed, at what coverage, or how
many suppressions are active. Two surfaces render a `CapturedUtc` (`DetailWindow.xaml:277`,
`ObjectDetailWindow.xaml:309`) and both are a *per-row* attribute — when that individual object was
captured — not run provenance, which is arguably worse, because it looks like the answer.

The new evidence is that the modelling was attempted and abandoned twice. `NavSection.IsLive` exists,
defaults to `false`, and is never set — the flag designed to mark live-versus-stored on the one screen
that has both. And `ObjectDetailPanelViewModel` then gets it right anyway, by hand, in prose: *"Snapshot
Access Estimate"* against *"Live Access Validation"*. **The product knows how to say this; it says it in
one place, in a string literal, and models it nowhere.** That is not four branches agreeing that
provenance is missing — it is four branches agreeing, plus a demonstration inside J-b that a single
honest label is all it takes.

## Corrections to existing documents

Recorded, not applied. No document below has been edited.

| Document | Claim | Correction |
|---|---|---|
| `docs/map/README.md`, note on branch J | "`GridViewModelBase<TRow>` … 23 grid view models as its only subclasses" | 21. `git grep -l ": GridViewModelBase" -- src` returns 21 files. The interface has 24 implementers — 21 subclasses plus `ObjectsTabViewModel`, `GroupsTabViewModel` and `AttackPathsTabViewModel`, which implement `IScopedGrid` directly as composites and are mapped here as J22. |
| `docs/map/J-presentation-shell.md`, coverage gaps | "the eleven grid pages" | Five. `git ls-files "src/SecureAD.UI/Views/*GridPage.xaml"` returns `Objects`, `Findings`, `EscalationPaths`, `Groups`, `NoLaps` — 1,335 lines, or 1,476 with `AuditView.xaml`. |
| `docs/map/J-presentation-shell.md`, coverage gaps | "whether the Findings grid agrees with Home or with the Dashboard … Home reads `GetLatestRunId()` under `FindingsPolicy.Empty`, the Dashboard reads the loaded run through `DashboardQueryService`" | The Dashboard's **severity counts** do not come from `DashboardQueryService` — that supplies inventory counts only, as J9 itself says. They come from `MainViewModel.GridBinding.cs:213`–`:216`, which calls the same `GetLatestRunId()` Home uses and then `FindingsService.GetSummary(latestRunId)`. Home and the Dashboard therefore agree, and `HomeView.xaml:225` binds `Dashboard.CriticalFindingsCount` directly. The disagreement is between that pair and the grid, and it is a *suppression* difference, not a *run* difference: `GetSummary` reads `fact_finding` with no suppression predicate (`FindingsService.Queries.cs:136`), the grid reads `v_grid_findings` with `is_suppressed = '0'`. A fourth count exists on the no-`dim_run` fallback path (`GridBinding.cs:296` → `FindingSummaryService.CountBySeverity`), which filters no run at all. |
| `docs/map/J-presentation-shell.md`, coverage gaps | "whether `AceAnalysisService`, `EffectiveAccessViewModel` and H7/H10/H16 constitute a fourth implementation of effective access" | The premise misassigns two types. `EffectiveAccessViewModel` **is** H15 (`H-live-verification.md:401`) and `StoredEffectiveAccessViewModel` **is** H16 (`:412`); both are already mapped and neither is J's. `AceAnalysisService` is not an effective-access implementation at all — it does no group expansion, so it answers "who has ACEs here" rather than "what can X do". H's count of three stands. `AceAnalysisService` is a third independent *access-mask decoder*, and its `RightsSummary` discards the allow/deny distinction. |
| `docs/map/J-presentation-shell.md`, "Reachability, checked page by page" | "**branch J has no dead subsystem** — its dead surface is finer-grained and lives at the command level (J20)" | True at the type level, which is what J-a's sweep measured, and false at the reachable-surface level. `GroupMembershipViewModel` (110) is constructed at `MainViewModel.cs:476` and referenced by no XAML — a production reference exists, so it passed J-a's sweep, but no user can reach it. Six grid view models (587 lines) are likewise fully plumbed and unreachable, three of them registered in `GetGridForTabId`. `LazyTabBehavior` (123) has no reference of any kind. Mapped as J46. |
| `docs/map/H-live-verification.md`, coverage gaps | Lists `DelegationReportViewModel` (157), `InheritanceViewModel` (316), `GroupMembershipViewModel` (110), `ResolvePrincipalViewModel` (139), `PrincipalNameResolver` (130), `LdapInputHelper` (65) as "referenced rather than mapped" | Now mapped, as J43 and J44. Addition rather than correction: `StoredInheritanceViewModel` (291) appears in neither H's list nor ruling 228 and was unmapped by any branch. Mapped as J42. |
| `docs/map/I-output.md`, I21 | `NoLapsGridViewModel.ExportCsv` is the third independent CSV writer | Confirmed from J's side and unchanged. Addition: `NoLapsGridViewModel` (174) is one of only five grids with its own `NoLapsGridPage`, so the third CSV writer sits on one of the few grids that has a page at all — the six unreachable grids have no export path of any kind. |

## Coverage gaps in this pass

Read in full: `ViewModels/GridViewModelBase.cs` (514), `ViewModels/ObjectsTabViewModel.cs` (110),
`ViewModels/DetailWindowViewModel.cs` (191), `Views/AuditView.xaml` (125),
`Controls/FilterBar.xaml.cs` (198, DP declarations and `ResultCount` body),
`Infrastructure/Security/AceAnalysisService.cs` (285, lines 1–130 read, 131–285 by member grep),
`StoredEffectiveAccessViewModel.cs` (319, lines 155–235 — the evaluation body — read).

Read in sections: `ViewModels/FindingsGridViewModel.cs` (647) — lines 1–330 and 490–647 read; 331–489
(the filter-value loaders and family mapping) by targeted grep. `Views/FindingsGridPage.xaml` (231) —
lines 120–231 read, 1–119 by grep for suppression, empty state and count bindings.
`ViewModels/DashboardViewModel.RunLifecycle.cs` (271) — lines 95–140 read.
`ViewModels/MainViewModel.GridBinding.cs` (422) — lines 205–305 read.
`Infrastructure/Findings/FindingsService.Queries.cs` (294) — lines 120–175 read.
`Services/PreviewActionService.cs` (556) — lines 1–45 read plus greps for all seven call sites and
`IsLiveCheckRunning`. `Services/FindingInvestigationProvider.cs` (1,009) — lines 1–40 read; the
remainder characterised by a full key extraction diffed against `rules.yaml`.

Not read, mapped from declaration comments, member greps, binding sweeps and file size:
`ObjectDetailWindow.xaml` (1,311), `ViewModels/ObjectDetailPanelViewModel.cs` (1,030) and its three
partials (852), `ViewModels/FindingDetailViewModel.cs` (846), `ControlEdgesGridViewModel.cs` (478),
`EscalationPathGridRow.cs` (492), `ObjectsGridViewModel.cs` (388), `PolicyWizardViewModel.cs` (371),
`InheritanceViewModel.cs` (316), `StoredInheritanceViewModel.cs` (291),
`ImportAcceptancesViewModel.cs` (275), `AcesGridViewModel.cs` (273),
`ObjectPreviewViewModel.cs` (263), `EscalationPathsGridViewModel.cs` (302), the remaining sixteen grid
view models, all 21 `*GridRow` types except `FindingGridRow`, `RowIdentity.cs` (173),
`NoiseLensState.cs` (157), and the four remaining grid pages' `.xaml.cs`.

**Sweeps run in full** (method reproduced from J-a): every `GridViewModelBase` subclass against every
`.xaml`; every `ViewMode` reference across all XAML and code-behind; every `[RelayCommand]` on the 26
types this half owns against all 64 XAML files with the `Async` suffix stripped; every `SealedUtc`,
`is_suppressed`, `IsSuppressed`, `DataLoadState`, `TotalCountDisplay`, `IsCountFailed`,
`CountLoadState`, `DataGridSortBehavior`, `DataGridColumnVisibilityBehavior`, `ColumnChooser`,
`LazyTabBehavior` and `EnterKeyCommandBehavior` reference in `src`; and all 61 investigation-guidance
rule ids diffed against all 62 ids in `rules.yaml`.

**Not covered:** `Themes/*` (2,312) as they apply to grids — the `PagingButton`, `GridPageInfoText`
and `EmptyStateTitleText` styles are referenced but their definitions were not read, so a claim that
the five pages share styling is a claim about `StaticResource` keys, not about rendered appearance.
The `SortRegistry` entries each grid names were not enumerated against C's definitions, so whether all
21 default sorts are keyset-valid is untested. `GridFilter`'s `WithNotIn` tagging mechanism (used five
times in `FindingsGridViewModel`) is C's and was not read.

**Questions J-b could not answer, for K:** whether `UiPerfTrace` (29) is the branch's only telemetry
and whether anything consumes its output; whether `IProgressPublisher`'s UI consumers include anything
below the seam; whether `PermissionClassifier` and `GuidCatalog` — shared by J33, H7 and H16 — agree
about which rights are dangerous, since J33 unions its own `IsDangerous` with the classifier's
(`AceAnalysisService.cs:76`–`:77`) and H16 has its own `DangerousRight` set that H records as unique to
it.
