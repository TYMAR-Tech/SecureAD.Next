# K — Cross-cutting

Everything that serves more than one branch and was therefore deferred rather than claimed: the
progress transport, the error model, configuration, the shared catalogues and security primitives,
the coverage vocabulary, and logging.

Unlike every other branch, **K has no folder and no namespace.** Its membership is a judgement, and
the judgement is stated in "Is K a branch?" under Would-do-differently rather than assumed.

## The surface, established before writing

`git ls-files` over `src/SecureAD.Core/` gives 27 top-level entries. Subtracting the folders A–J
already claimed by subject (`Discovery`, `Findings`, `EscalationPaths`, `Compare`, `GroupPolicy`,
`Principals`, `Delegation`, `LiveAccess`, `GroupExpansion`, `ControlEdges`, `EffectiveAccess`,
`RunLibrary`, `Services`) leaves the following as K's candidate surface:

| Folder | Files | Verdict |
|---|---|---|
| `Errors/` | 20 | K |
| `Configuration/` | 16 | K |
| `Assessment/` | 14 | **F's**, except `PerfEvent.cs` |
| `Coverage/` | 13 | K, except four files that are E4's |
| `Progress/` | 12 | K (transport), B (shard/module shapes), I22 (export leg) |
| `Security/` | 10 | K |
| `Classification/` | 4 | K |
| `Schema/` | 3 | K |
| `Catalogs/` | 2 | K |
| `Evidence/` | 2 | K |
| `Authentication/` | 1 | K |
| `DisplayFormatting.cs` | 1 | K |

Plus, outside Core: `src/SecureAD.Infrastructure/Configuration/` (2 files, 208 lines),
`src/SecureAD.Infrastructure/Diagnostics/MemoryMonitor.cs` (118, a folder of one file),
`src/SecureAD.Core/Discovery/DnHelper.cs` (143 — filed under a branch-A folder but consumed by 34
files across all three projects), and the UI logging quartet `AppLog.cs` (59),
`FileLoggerProvider.cs` (295), `UiPerfTrace.cs` (29), `TaskLoggingExtensions.cs` (31).

Total: roughly **100 files and ~5,200 production lines** in 27 components, the smallest branch by
line count and the largest by number of distinct subjects.

## The flow

**K has no single runtime flow.** It is not a pipeline; it is the set of things every pipeline
reaches down into. It has four flows, and only two of them run.

**Flow 1 — Logging, at process start (runs).**

1. `App.OnStartup` computes a log path and a warnings-only path and calls
   `AppLog.Initialize(logFilePath, warningsLogFilePath, sanitizeLogs)` (`App.xaml.cs:117`). This is
   the only call; a second throws.
2. `AppLog` builds one `ILoggerFactory` with a Debug provider and one `FileLoggerProvider`, which
   writes two files — everything at `Debug` and above to the aggregate, `Warning` and above to the
   second.
3. Every logger in the process is created from `AppLog.Factory`. Before `Initialize`, `Factory`
   returns `NullLoggerFactory.Instance` so static field initialisers do not crash.
4. From then on, 14 UI files log through it; `UiPerfTrace` logs grid timings, escalating to
   `LogWarning` above a caller-supplied threshold.

**Flow 2 — Progress, during a capture run (runs, for four of five event types).**

1. `MainViewModel.Audit.cs:139` creates `new CancellationScope("SecurityRun", ct)`. This is the
   **only** `CancellationScope` constructed anywhere in the product.
2. `App.xaml.cs:143` constructs one `SimpleProgressPublisher` for the process lifetime.
3. Two observers subscribe: an inner class on `MainViewModel` (`:977`) and `DashboardViewModel`
   (`RunLifecycle.cs:8`).
4. `DirectCaptureRunner` publishes `RunProgressEvent` (`:709`) and `AnalysisProgressEvent` (`:738`);
   `DirectCaptureModule` publishes shard and module events. All four reach both observers.
5. `SimpleProgressPublisher.Publish` iterates observers **while holding its lock**, so the UI's
   dispatcher marshalling happens inside a lock a background thread also takes.
6. `Publish(ExportProgressEvent)` is never called. Both `OnExportProgress` implementations are
   literally `{ }`.

**Flow 3 — Errors, on failure (does not run).**

1. Some operation fails.
2. It does **not** construct an `AuditError`, does not select a code from one of the 14 enums, does
   not call `AuditErrorCodes.Format`, and does not build a `UserFacingError`. None of those has a
   production call site.
3. Instead it either interpolates `ex.Message` into a status string, or is swallowed, or — in two
   places in `ObjectQueryService` — adds a `QueryWarning` to a list nothing reads.
4. The one exception that does run: `DashboardQueryService` collects `QueryWarning`s,
   `MainViewModel.Dashboard.cs:82` copies them onto `DashboardViewModel.QueryWarnings`, and
   `DashboardView.xaml:142` shows a banner.
5. The other exception, at the far end: an unhandled dispatcher exception reaches `App.xaml.cs:91`,
   which calls `ErrorDisplayViewModel.FromException` — the path that bypasses the structured model
   entirely — and shows `ErrorDialog`.

**Flow 4 — Configuration, at startup and in Settings (runs partially, and not in a loop).**

1. `App.xaml.cs:126` constructs `UserPreferencesService`, reads
   `%LocalAppData%/SecureAD/preferences.json`, and applies window geometry, theme and last database
   path.
2. `App.xaml.cs` constructs `LdapConnectionSettings` and `LdapToolsSettings` and hands them to
   `ServiceFactory`.
3. `CaptureSettings` reaches `DirectCaptureRunner`, `DirectCaptureModule`, `DcRateLimiter`,
   `DerivedAnalysisPipeline` and `GpoCaptureTargetBuilder` — the widest-travelling settings object
   in the product.
4. The user opens Settings. `SettingsViewModel` mutates its own properties and, per J16, pushes them
   into `MainViewModel` through a `PropertyChanged` handler.
5. **Nothing is written back.** `SettingsViewModel` contains no `Save`, no reference to
   `UserPreferencesService`, and no reference to `AppSettings`. The loop closes at the view model
   and stops.

## Components

### K1 — Progress transport

- **Owns:** The in-process publish/subscribe channel that carries progress events from wherever work
  happens to whoever is displaying it.
- **Layer:** Core
- **Depends on:** K2; consumed by B (emission), J10 (rendering), I22 (the dead export leg)
- **Implemented by:** `src/SecureAD.Core/Progress/IProgressPublisher.cs` (50) — declares both
  `IProgressPublisher` and `IProgressObserver`; `src/SecureAD.Core/Progress/SimpleProgressPublisher.cs` (91)
- **Non-obvious:** Ruling 202's three-way split holds up: B genuinely owns the event shapes, J10 the
  rendering, and this the mechanism. Two design facts the split hides. First, **`Publish` invokes
  observers inside `lock (_lock)`**, and both observers marshal onto the WPF dispatcher; a
  synchronous dispatcher call under that lock would deadlock against any thread calling `Subscribe`.
  It has not bitten because both observers use `BeginInvoke`, which is an accident of the consumers
  rather than a property of the transport. Second, **the publisher is optional at every injection
  point** — `IProgressPublisher? progressPublisher = null` on `DirectCaptureRunner:48`,
  `DirectCaptureModule:38` and `MainViewModel:460` — so every publish site is
  `_progressPublisher?.Publish(…)`. Progress is a feature the capture pipeline can be constructed
  without, which is why the export path could be built without it and nothing noticed.
- **Live-LDAP:** Survives. The transport has no directory dependency.

### K2 — Progress event vocabulary

- **Owns:** The shape of a run-level and analysis-level progress event, and the state enums the other
  event types share.
- **Layer:** Core
- **Depends on:** —
- **Implemented by:** `Progress/RunProgressEvent.cs` (13), `AnalysisProgressEvent.cs` (12),
  `AnalysisPhase.cs` (13), `ModuleState.cs` (13), `ShardState.cs` (13). `ShardProgressEvent.cs` (13)
  and `ModuleProgressEvent.cs` (13) are B's by ruling 202; `ExportProgressEvent.cs` (11) and
  `ExportState.cs` (12) are I22's.
- **Non-obvious:** Five event types, five state enums, one `IProgressObserver` method each — a
  symmetrical design in which one of the five legs was never connected. The symmetry is why it is not
  obvious from reading `IProgressPublisher` that a fifth of it is dead; every leg looks like every
  other leg. `ForestAuditViewModel.Configuration.cs:359` carries a comment noting that "analysis was
  healthy" is an axis `RunProgressEvent` does not carry, which is the one place the vocabulary's
  limits are written down.
- **Live-LDAP:** Survives.

### K3 — Cancellation scope hierarchy

- **Owns:** Named, hierarchical cancellation — a scope that links to a parent so parent cancellation
  cascades and child cancellation does not.
- **Layer:** Core
- **Depends on:** —
- **Implemented by:** `src/SecureAD.Core/Progress/CancellationScope.cs` (91)
- **Non-obvious:** **The documented hierarchy does not exist.** Its remarks block draws a six-level
  tree — Application Shutdown → Run → Shard → Module → Operation, plus Analysis and Export — and
  `git grep "new CancellationScope"` over `src/` returns exactly one production site:
  `MainViewModel.Audit.cs:139`, `new CancellationScope("SecurityRun", ct)`. `CreateChildScope`
  (`:76`) has **no caller at all**. So there is one scope, named for the middle tier of a tree whose
  root and leaves were never built, and the type's whole reason to exist — composition — is
  unexercised. What actually happens is that the scope's `Token` is threaded down as a plain
  `CancellationToken` and the levels below improvise: `SecurityModeCaptureService.cs:74` and
  `ForestDcPreflightService.cs:65` each make their own `CancellationTokenSource` and call
  `CancelAfter`, which is precisely what `CancellationScope.CancelAfter` (`:69`) exists to
  standardise. Two independent timeout idioms beside a type built to unify them.
- **Live-LDAP:** Survives, and the capability is worth salvaging even though the type is barely used.
  The named-scope idea is right; a rebuild should either build the tree or drop to bare
  `CancellationToken` and delete the class rather than keep a one-instance abstraction.

### K4 — Structured error envelope

- **Owns:** *(nothing in production)* — the record that was to carry every failure in the system:
  category, code, severity, blocking-ness, context key.
- **Layer:** Core
- **Depends on:** K5
- **Implemented by:** `Errors/AuditError.cs` (12), `Errors/ErrorCategory.cs` (23),
  `Errors/ErrorSeverity.cs` (13), `Errors/AuditErrorCodes.cs` (37), `Errors/UserFacingError.cs` (41)
- **Non-obvious:** **This is the branch's headline and the map's largest single dead surface by
  reach.** `AuditError` describes itself as "the structured error envelope used across the entire
  system". `git grep "new AuditError"` over `src/` returns **nothing** — every hit is in
  `tests/SecureAD.Core.Tests/Errors/`. `git grep "AuditErrorCodes."` over `src/` likewise returns
  only `AuditErrorCodes.cs` itself. `UserFacingError.FromAuditError` has no production caller.
  `UserFacingError.FromException` has exactly one, `ErrorDisplayViewModel.cs:43`, and that overload
  constructs the code `"System.UnhandledException"` as a literal — i.e. the single live path through
  the user-facing error type is the one that admits it has no structured code. The envelope is fully
  designed, fully tested (250 lines across two test files, one of which enumerates all 14 enums to
  assert code-string uniqueness), and produced by nothing.
- **Rebuild:** The design is not the problem — a code, a category, a severity, a blocking flag and a
  context key is the right envelope, and the "no freeform strings" rule in `AuditErrorCodes` is the
  right rule. What is missing is that **no boundary was ever obliged to return one.** A rebuild
  should make the envelope the return type of the operations that can fail, not a type they may
  optionally construct. Salvage the shape; delete this instance and rebuild it as a contract.
- **Live-LDAP:** Survives.

### K5 — Domain error-code enums

- **Owns:** *(nothing in production, with one exception)* — fourteen per-domain taxonomies of what
  can go wrong.
- **Layer:** Core
- **Depends on:** —
- **Implemented by:** fourteen files in `src/SecureAD.Core/Errors/`, 12–16 lines each:
  `CaptureErrorCode`, `ResolutionErrorCode`, `ExpansionErrorCode`, `ControlEdgeErrorCode`,
  `RuleExecutionErrorCode`, `EscalationErrorCode`, `ResumeErrorCode`, `IntegrityErrorCode`,
  `ExportErrorCode`, `ConfigurationErrorCode`, `DatabaseErrorCode`, `CanonicalizationErrorCode`,
  `DiscoveryErrorCode`, `LiveErrorCode`
- **Non-obvious:** The sweep, run as `git grep -l` per type over `src/` and `tests/`, gives a clean
  and damning table. **Thirteen of the fourteen are referenced by exactly two files: their own
  declaration and `AuditErrorCodes.cs`'s formatter overload.** That is not a producer and not a
  consumer; it is a formatter that exists so the enum can be formatted, and nothing formats it. H21
  found this for `LiveErrorCode`, I23 for `ExportErrorCode`, and both were right — but they were each
  looking at one instance of a thirteen-fold pattern.

  **The fourteenth is genuinely wired, and wired around the model.** `DiscoveryErrorCode` is produced
  by `ForestDiscoveryService.Helpers.cs:99` (`MapLdapExceptionToDiscoveryError`, an LDAP result-code
  switch), stored on `DomainInfo.ReachabilityErrorCode` (`DomainInfo.cs:23`), and rendered at
  `ForestAuditViewModel.Configuration.cs:136` — as `domain.ReachabilityErrorCode?.ToString()`. So the
  one enum with a real producer and a real consumer **bypasses `AuditErrorCodes.Format` entirely**,
  and the string a user sees is `DomainUnreachable`, not `Discovery.DomainUnreachable`. The single
  working instance of the taxonomy does not use the taxonomy's own formatting contract.

  This is the answer to the question three branches asked separately, and it explains what J45 found
  in the grid layer: there is no error code because **there is no path by which any subsystem returns
  one.** Every failure a user sees is an interpolated `ex.Message`, a swallowed exception, or a
  silent zero, because the alternative was built as a vocabulary and never as a contract.
- **Rebuild:** Keep at most one enum per subsystem that actually surfaces failures to a user, and
  make the discovery pattern the model rather than the exception — map a platform error to a code at
  the boundary that produced it, once. Thirteen enums for subsystems that never surface a failure is
  thirteen files of intent.
- **Live-LDAP:** `LiveErrorCode` goes with live access and is no loss, being already dead. The rest
  survive.

### K6 — Non-fatal query warning channel

- **Owns:** A query that failed without failing the operation, carried to the user as a banner.
- **Layer:** Core (record) / Infrastructure (collection) / UI (render)
- **Depends on:** C19 (`DashboardQueryService`), C (`ObjectQueryService`), J
- **Implemented by:** `src/SecureAD.Core/Errors/QueryWarning.cs` (8); collected at
  `DashboardQueryService.cs:18` and `ObjectQueryService.cs:19`; rendered via
  `DashboardViewModel.cs:66–76` and `DashboardView.xaml:142–143`
- **Non-obvious:** **This is the one thing in `Errors/` that works, and it is eight lines.** It is
  also the branch's best "keep it": a lightweight record, populated at the point of failure, surfaced
  without blocking. Two qualifications, both traced. `ObjectQueryService.Warnings` is populated —
  twice, at `:556` and `:569`, when the UAC/password and adminCount sub-queries throw — and
  **`git grep "\.Warnings"` over `src/` returns exactly one read site**,
  `MainViewModel.Dashboard.cs:82`, which reads the *dashboard* service. The grid path's warnings are
  collected and dropped, which is the mechanical cause of J45's finding from the other end. And
  `QueryWarningText` (`:74`) joins `w.Query` — the query identifier — rather than `w.Message`, so the
  banner tells the user which query failed and not what went wrong, despite the record carrying both.
- **Live-LDAP:** Survives.

### K7 — Last-resort crash surface

- **Owns:** What the user sees when an exception escapes to the dispatcher.
- **Layer:** UI
- **Depends on:** K4
- **Implemented by:** `src/SecureAD.UI/ViewModels/ErrorDisplayViewModel.cs`,
  `src/SecureAD.UI/ErrorDialog.xaml`, `ErrorDialog.xaml.cs`, invoked from `App.xaml.cs:91`
- **Non-obvious:** The dialog is well-built — it puts the code in the window title, offers a
  copy-to-clipboard command, and composes a support-ready block. It is also the **only** consumer of
  `UserFacingError`, and it uses the constructor path that has no structured code.
  `ErrorDisplayViewModel.FromError(UserFacingError)` (`:32`), the method that would render a
  structured error properly, **has no caller in `src/`**. So the product has a good error dialog
  wired exclusively to its worst input.
- **Live-LDAP:** Survives.

### K8 — Capture tuning settings

- **Owns:** The budgets and rate limits a capture runs under, and the three presets that name them.
- **Layer:** Core
- **Depends on:** B, D
- **Implemented by:** `Configuration/CaptureSettings.cs` (145), `CaptureProfile.cs` (19),
  `CaptureProfileMap.cs` (38), `CaptureFilterMode.cs` (13), `CacheProfile.cs` (74)
- **Non-obvious:** `CaptureSettings` is the widest-travelling type in K — twelve files across all
  three projects, including `DerivedAnalysisPipeline`, which is D's, so a type named for capture also
  carries analysis budgets. `CaptureProfileMap` is the interesting one: **it has no consumer outside
  `Configuration/`.** `CaptureProfile` is consumed (App, `ForestAuditViewModel`, `MainViewModel`,
  `SettingsViewModel`) but the `.ToSettings()` extension that turns a profile into settings is not,
  so the mapping from "Safe / Balanced / Accelerated" to a QPS number is made somewhere else. Its own
  doc comment states that "profile presets only adjust per-DC QPS", which makes the three-preset UI a
  three-value QPS picker with names.
- **Live-LDAP:** Does not survive a greenfield that drops live LDAP — but neither does capture, so
  this goes with B rather than with H.

### K9 — Connection and directory-tool settings

- **Owns:** How the tool connects to a DC and what limits the live tools run under.
- **Layer:** Core
- **Depends on:** A, H
- **Implemented by:** `Configuration/LdapConnectionSettings.cs` (23), `LdapToolsSettings.cs` (17),
  `DcConnectionInfo.cs` (25), `Authentication/SavedCredential.cs` (13)
- **Non-obvious:** `SavedCredential.cs` **does not declare a type called `SavedCredential`.** All 13
  lines are the `AuthenticationMode` enum (`Integrated` / `AlternateCredential`), which is live —
  `LdapConnectionManager` is its consumer. The `Authentication/` folder exists to hold one enum in a
  file named after a type that does not exist, presumably deleted without renaming the file. This is
  the cleanest example in the branch of the map's recurring problem: a name that describes an
  intention rather than the code.
- **Live-LDAP:** Does not survive. All four types are meaningless without a directory to connect to;
  K9 is the only K component that is wholly live-dependent.

### K10 — OU exclusion filtering

- **Owns:** Which subtrees a capture deliberately does not read, and the saved profiles that name a
  reusable set.
- **Layer:** Core + Infrastructure
- **Depends on:** B, D20, C (read half, `LowSignalOuRecommendationService`), F
- **Implemented by:** `Configuration/OuExclusionFilter.cs` (79), `Configuration/ExclusionProfile.cs`
  (18), `src/SecureAD.Infrastructure/Configuration/ExclusionProfileService.cs` (121)
- **Non-obvious:** `OuExclusionFilter` is the K component with the most downstream consequence: it
  reaches `CoverageId` (`Assessment/CoverageId.cs`), `DomainDeclaration`,
  `LowSignalOuRecommendationService` and `DirectCaptureModule`, so an exclusion is not merely a
  capture-time skip — it becomes part of the run's coverage identity and therefore part of what F
  will let a run be compared against. That is the right design, and it is the only place in K where a
  setting is treated as evidence rather than as a preference.
- **Live-LDAP:** Survives as a concept if capture survives.

### K11 — The unreached settings root

- **Owns:** *(nothing)* — a composed application-settings model and its startup validator.
- **Layer:** Core
- **Depends on:** K8, K9
- **Implemented by:** `Configuration/AppSettings.cs` (17), `StorageSettings.cs` (20),
  `SettingsValidator.cs` (99), `SettingsValidationResult.cs` (32)
- **Non-obvious:** **Four of `Configuration/`'s sixteen files have no consumer outside the folder**,
  and they are the four that would have made the other twelve a system. `AppSettings` composes
  `StorageSettings`, `CaptureSettings` and `LdapToolsSettings`; `SettingsValidator.Validate(AppSettings)`
  returns a structured result distinguishing critical from non-critical errors, with the documented
  contract "critical errors should prevent startup; non-critical errors trigger fallback to
  defaults". Nothing constructs an `AppSettings`. Nothing calls `Validate`. `StorageSettings` — which
  defines where run bundles, session runs, the registry database and logs live, with defaults — is
  referenced by nothing, so those four paths are each computed independently at their point of use.
  Note that `Infrastructure` carries four `Microsoft.Extensions.Configuration` package references
  (`Json`, `Binder`, `EnvironmentVariables`); `AppSettings` is exactly the shape `Binder` binds to,
  and the binding was never written.

  This answers the Settings question directly and negatively: **`SettingsValidator` and `AppSettings`
  are not where the Settings screen writes, because the Settings screen does not write anywhere.**
  `git grep` over `SettingsViewModel.cs` for `Save`, `Preferences` or `preferences` returns nothing.
  J16's `PropertyChanged` push into `MainViewModel` is the entire mechanism; the two halves are
  unconnected, and there is no persisted configuration for Settings to reach.
- **Rebuild:** The one salvageable idea is `SettingsValidationResult`'s critical/non-critical split,
  which is the correct answer to "a bad setting should not always be fatal" and appears nowhere else
  in the product. Keep that distinction; rebuild the rest as a bound options object.
- **Live-LDAP:** Survives.

### K12 — User preference persistence

- **Owns:** The handful of settings that genuinely survive a restart, and their file.
- **Layer:** Core + Infrastructure
- **Depends on:** J (shell, theming, session restore)
- **Implemented by:** `Configuration/UserPreferences.cs` (42),
  `src/SecureAD.Infrastructure/Configuration/UserPreferencesService.cs` (87)
- **Non-obvious:** This is the product's *real* settings system and it is not the one in
  `Configuration/`'s root. Seven properties — theme, database cache size, four window-geometry
  values, last database path — read and written at exactly one call site, `App.xaml.cs:126`. Its doc
  comment records the right instinct: "missing or corrupt files produce a usable instance", and "a
  path that no longer exists is ignored and cleared rather than treated as an error". Note the
  overlap it creates: `UserPreferences.Theme` and `UserPreferences.DatabaseCacheSizeMB` are both also
  configurable in the Settings screen, which cannot persist them, so a user can change the theme in
  Settings and have it revert on restart while the same value set by a different route persists.
- **Live-LDAP:** Survives.

### K13 — Dangerous-GUID catalogue

- **Owns:** What an opaque `ObjectType` GUID on an ACE means, and whether it is dangerous enough to
  create a control edge.
- **Layer:** Core
- **Depends on:** —; consumed by D (`ControlEdgeService` via `DerivedAnalysisPipeline`), H7, H16,
  J33, J42/J43, `GuidCatalogService`
- **Implemented by:** `src/SecureAD.Core/Catalogs/GuidCatalog.cs` (255), `GuidCatalogEntry.cs` (55)
- **Non-obvious:** Two structural facts. First, it is a **static mutable singleton**: `LoadOverlay`
  (`:227`) merges schema-captured GUIDs into a process-wide `_overlay` behind a lock, and the
  embedded `FrozenDictionary` is never overwritten. So the answer `GuidCatalog.IsDangerous(guid)`
  gives depends on whether a capture has run in this process, and there is no way to ask it for the
  *embedded* answer once an overlay is loaded. For a tool whose output is meant to be reproducible, a
  classification that varies with process history is a provenance hazard, and `CatalogVersion`
  (`:15`) — a `const int 1` with the instruction "increment when entries are added or `IsDangerous`
  changes" — records only the embedded half.

  Second, the catalogue carries **nine** dangerous entries: `User-Force-Change-Password`,
  `DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`, `Self-Membership`, `Validated-SPN`,
  `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-KeyCredentialLink`, `userAccountControl`,
  `unicodePwd`. Notably absent: `DS-Replication-Get-Changes-In-Filtered-Set`, `gPLink` (present,
  marked `false`), `scriptPath` (present, marked `false`).
- **Live-LDAP:** Survives — the embedded catalogue is the offline half and is the whole point. Only
  `LoadOverlay`'s schema-capture feed is live-dependent.

### K14 — Well-known schema GUID index

- **Owns:** Lookup from an LDAP attribute name to its schema GUID, so evaluators do not hardcode GUID
  literals.
- **Layer:** Core
- **Depends on:** —; consumed by `AdvancedRuleEvaluator`, `LapsRuleEvaluator`, `GuidCatalogService`
- **Implemented by:** `src/SecureAD.Core/Schema/WellKnownGuids.cs` (190), `SchemaGuidEntry.cs` (12),
  `GuidType.cs` (25)
- **Non-obvious:** **This is a second GUID catalogue.** K13 maps GUID → meaning + danger; K14 maps
  name → GUID and GUID → entry, with its own `GuidType` enum paralleling K13's `GuidCategory`, its
  own entry record, and its own `ByGuid` dictionary. They overlap in content and differ in direction,
  and neither references the other — `GuidCatalogService` is the only file that touches both. Both
  carry `[IMP-WK-GUID]` correction comments about entries that previously pointed at the wrong GUID,
  in both files, which is the cost of maintaining two hand-curated tables of the same facts.
- **Live-LDAP:** Survives.

### K15 — Security descriptor parsing and ACE canonicalisation

- **Owns:** Turning a raw `nTSecurityDescriptor` byte array into typed ACEs, and normalising those
  ACEs into a canonical, comparable form.
- **Layer:** Core
- **Depends on:** —; consumed by B (`DirectAceWriter`, `SysvolAceWriter`), E
  (`RuleEvaluatorHelpers`), H (`LiveDiagnosticsService.AclTools`)
- **Implemented by:** `Security/SecurityDescriptorParser.cs` (385), `AceNormalizer.cs` (251),
  `GenericRightsExpander.cs` (88), `CanonicalAce.cs` (30), `ParsedAce.cs` (25),
  `ParsedSecurityDescriptor.cs` (21), `AceType.cs` (39), `AceNormalizationResult.cs` (21),
  `DaclState.cs` (16)
- **Non-obvious:** **This is the best-designed thing in K and one of the best in the map, and it is
  the only component here that is used by exactly the branches it should be.** Five callers, all of
  them the ones that handle raw security descriptors, and no others; the same parse is used for
  stored ACEs, SYSVOL ACEs and live ACEs, which is why H's live-versus-stored comparison is
  meaningful at all. `GenericRightsExpander` is the piece to notice: it exists because a raw
  `GENERIC_ALL` bit and an expanded specific-rights mask are the same permission written two ways,
  and comparing them unexpanded produces false deltas. `DaclState` distinguishes "no DACL" from
  "empty DACL" — the null-DACL-means-everyone case that most ACL tooling gets wrong.
- **Live-LDAP:** Survives entirely. It parses bytes; where the bytes came from is not its concern.

### K16 — Dangerous-permission classification

- **Owns:** Whether an access mask is dangerous.
- **Layer:** Core
- **Depends on:** —; consumed by J33 (`AceAnalysisService.cs:76`), J (`AcesGridViewModel.cs:29–31`)
- **Implemented by:** `src/SecureAD.Core/Security/PermissionClassifier.cs` (47)
- **Non-obvious:** J-b's closing question, answered: **the three do not agree, and there are not
  three of them but five.** Traced side by side:

  1. **`PermissionClassifier.IsDangerous(mask, aceType)`** — pure bitmask. Dangerous if
     `GENERIC_ALL`, or the full `0x000F01FF` mask, or `WRITE_DAC`, or `WRITE_OWNER`. Deny ACEs are
     never dangerous. It declares `ControlAccess = 0x00000100` as a public constant **and never uses
     it**, so an ACE granting only extended rights — the DCSync mask — is not dangerous by this
     classifier. `GenericWrite` and `CreateChild` are likewise absent.
  2. **`GuidCatalog.IsDangerous(guid)`** (K13) — per-GUID flag, nine entries. Orthogonal to (1): it
     classifies *what the right applies to*, not *what the right is*, and never sees an access mask.
  3. **`AceAnalysisService.AggregateByTrustee`** (J33, `:76–:77`) — unions (1) with (2):
     `aceList.Any(a => PermissionClassifier.IsDangerous(…)) || details.Any(d => d.IsDangerous)`. This
     is the only place the two are combined, and it is a UI aggregation service. The union is the
     *right* answer, computed in the wrong layer.
  4. **`EffectiveAccessViewModel.BuildDangerousRights`** (H15, live) — **string matching on rendered
     display names**, not masks or GUIDs. Its own `DangerousObjectTypes` list, its own reason
     strings, plus two rules the others have no equivalent of: an unscoped "Write Property" is
     dangerous, and an unscoped "Control Access" is dangerous ("all extended rights, includes Reset
     Password, DCSync"). Covers `gpLink`, `userAccountControl`, `scriptPath`,
     `DS-Replication-Get-Changes-All`.
  5. **`StoredEffectiveAccessViewModel.BuildDangerousRights`** (H16, stored, `:278–:317`) — the same
     idea, a shorter list, **and it disagrees with (4)**. It drops `gpLink`, `userAccountControl` and
     `scriptPath`, drops both unscoped cases, and folds `DS-Replication-Get-Changes-All` into a
     `Contains("DS-Replication-Get-Changes")` test.

  So the *live* and *stored* effective-access panels — which exist to be compared against each other
  — apply **different definitions of dangerous**, and `userAccountControl` is dangerous per the GUID
  catalogue and per the live panel but not per the stored panel or per the bitmask classifier. H's
  finding that three effective-access implementations disagree on non-canonical DACLs understates it:
  they also disagree on the question the panels exist to answer. And none of the five matches the rule
  SQL, which uses a sixth list (`AdvancedRuleEvaluator.cs:84`:
  `GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, CreateChild`).

  This is the same class of finding as the three effective-access implementations and the four
  severity counts, and it is worse than both, because the disagreement is between two panels a user
  is meant to read as a pair.
- **Live-LDAP:** Survives. If live goes, (4) goes with it and (5) becomes the only view-model answer
  — which is the *narrower* of the two, so dropping live LDAP would silently shrink what the product
  calls dangerous unless the definitions are unified first.

### K17 — Distinguished-name manipulation

- **Owns:** Parsing, comparing, shortening and re-rooting AD distinguished names.
- **Layer:** Core
- **Depends on:** —
- **Implemented by:** `src/SecureAD.Core/Discovery/DnHelper.cs` (143)
- **Non-obvious:** **The most widely consumed single file in the product: 34 files across all three
  projects** — Infrastructure's LDAP, principals, escalation paths, storage, tree and locator
  services, and 18 UI view models and row types. It is filed under `Discovery/`, branch A's folder,
  and A does not own it in any meaningful sense; 33 of its 34 consumers are outside discovery. It is
  placed here because "shared by every branch" is exactly what K means, and because leaving the
  product's most-reused primitive attributed to the branch whose folder it happens to sit in would
  misrepresent the codebase to anyone rebuilding it.
- **Live-LDAP:** Survives. DNs are a stored-evidence concept as much as a live one.

### K18 — Object classification helpers

- **Owns:** Deciding what kind of thing an object is from its attributes — an OS tier from an
  `operatingSystem` string, a service-account type from account shape.
- **Layer:** Core
- **Depends on:** —; consumed by E (`LapsRuleEvaluator`, `ServiceAccountRuleEvaluator`)
- **Implemented by:** `Classification/ServiceAccountClassifier.cs` (160),
  `OperatingSystemClassifier.cs` (98), `ServiceAccountType.cs` (19), `OperatingSystemTier.cs` (23)
- **Non-obvious:** Each has exactly one consumer, both in E's rule evaluators. On the "serves more
  than one branch" test these are **not** cross-cutting and would belong to E — they are mapped here
  because they sit in a Core folder no branch claimed and would otherwise be lost, and because the
  interesting fact about them is structural: they are the only two classifiers in the product that
  are pure functions over attributes with no store access, which is why they are the only two that
  are trivially testable. `AssetTierWriter.Classify` (D) does the same *kind* of work against the
  database and is neither pure nor separately testable.
- **Rebuild:** Move them to E and keep the pure-function shape; make D's tiering match it.
- **Live-LDAP:** Survives.

### K19 — Build identity and directory bit-flag constants

- **Owns:** The version string a bundle stamps itself with, and the `userAccountControl` bit meanings.
- **Layer:** Core
- **Depends on:** —; `ToolVersion` consumed by C, E, F, G, I, J; `UserAccountControlFlags` by B
  (`DirectObjectWriter`)
- **Implemented by:** `Constants/ToolVersion.cs` (64), `Constants/UserAccountControlFlags.cs` (68)
- **Non-obvious:** `ToolVersion` is a **"this was right" in miniature and its remarks say why.** It
  was a hand-edited `const "3.0.0"`, which meant two captures from different commits carried the same
  string, so "a change in the *rules* was indistinguishable from a change in the *forest*" — a
  provenance failure at the heart of a comparison tool. It now reads the assembly informational
  version with the SDK-appended commit sha, compares only the major component, and **deliberately has
  no fallback**: "a build that cannot state its own identity is a broken build, not a `0.0.0` one."
  That last sentence is the correct instinct about degraded data written down in one place; I3 and I4
  are the only other components in the map that hold it.

  The two files have nothing to do with each other. `Constants/` is a folder named after a C# keyword
  rather than a subject.
- **Live-LDAP:** Survives.

### K20 — Evidence and schema vocabulary

- **Owns:** The string keys used for bundle metadata, and the schema-level constants shared by
  writers and readers.
- **Layer:** Core
- **Depends on:** —; consumed by C, B, E, G, F, J
- **Implemented by:** `Evidence/MetadataKeys.cs` (118), `Evidence/SchemaConstants.cs` (71)
- **Non-obvious:** `MetadataKeys` is the contract by which C's storage, F's run library, G's compare
  engine and J's escalation grid agree on what a metadata row is called — six consumers across four
  branches, which is what a cross-cutting component should look like. `SchemaConstants` is stranger:
  its consumers are `InvocationV1`, `CoverageV1`, `AceNormalizer`, `FindingsService.Coverage`,
  `DirectAceWriter` and `DirectCaptureRunner.Merge` — two Core value types, a Core normaliser and
  three Infrastructure writers, which means "schema" here means at least two different things (the
  serialisation schema of the V1 records, and the AD schema).
- **Live-LDAP:** Survives.

### K21 — Duration display formatting

- **Owns:** Two ways to render a `TimeSpan` — compact for status bars, friendly for dialogs.
- **Layer:** Core
- **Depends on:** —; consumed by four J files
- **Implemented by:** `src/SecureAD.Core/DisplayFormatting.cs` (29)
- **Non-obvious:** **This is the one Core type that exists only to serve the UI.** All four consumers
  are UI view models; it has no Infrastructure or Core caller, and both methods return presentation
  strings. It is also the only file at the root of `SecureAD.Core` with no folder. It is worth naming
  because the dependency-direction question's honest answer is that the direction holds
  *structurally* and leaks *by subject*: nothing in Core references UI, but a formatting helper that
  only the UI uses is a UI concern sitting in the domain project because Core was the only place
  three view models could both see.
- **Live-LDAP:** Survives.

### K22 — Coverage state vocabulary

- **Owns:** The shared language for "how much of the forest did we actually see" — module identity,
  state, reason, and the per-run snapshot.
- **Layer:** Core
- **Depends on:** B (emission), E4 (enforcement), G (compatibility), I2/I3 (warnings), J (display)
- **Implemented by:** `Coverage/CoverageState.cs` (13), `CoverageModuleId.cs` (36),
  `CoverageReasonCode.cs` (21), `CoverageCell.cs` (32), `CoverageV1.cs` (28),
  `RunCoverageSnapshot.cs` (220), `RunCoverageState.cs` (81), `ContradictedExclusions.cs` (77),
  `OuFailureSummary.cs` (7)
- **Non-obvious:** The ruling on `CoverageEnforcementService` → E4 stands and is not relitigated.
  Tracing the other twelve files answers the open question: **they do not all belong with E4.** Four
  of them — `CoverageDependencyGraph.cs` (197), `CoverageDependency.cs` (48), `CoverageGate.cs` (53),
  `CoverageTaint.cs` (25) — have **exactly one consumer between them,
  `CoverageEnforcementService`**, so they are E4's implementation and should be mapped there. The
  remaining nine are genuinely cross-branch and are K's: `CoverageState` alone reaches nineteen files
  spanning B, D, E, G, I and J.

  `CoverageState` is the most-used enum in the product's vocabulary and the reason `VouchedCount`
  (I4) and `CoverageWarningPresentation` (I3) could be built at all — they are the only two consumers
  that treat it as a *warrant* rather than a label. Everything else reads it and renders it.
- **Live-LDAP:** Survives.

### K23 — Logging composition root and file sink

- **Owns:** The single `ILoggerFactory` for the process, and the two files it writes.
- **Layer:** UI
- **Depends on:** —
- **Implemented by:** `src/SecureAD.UI/AppLog.cs` (59), `src/SecureAD.UI/FileLoggerProvider.cs` (295)
- **Non-obvious:** Three decisions worth keeping and one worth naming. The composition root is
  genuinely single — `Initialize` throws on a second call, and every logger in 14 UI files comes from
  `AppLog.Factory`. The pre-initialisation fallback to `NullLoggerFactory` is deliberate and
  documented, so a static field initialiser that runs before `OnStartup` gets a no-op logger rather
  than a `NullReferenceException`. And it takes a `sanitize` flag that redacts DNs, SIDs and FQDNs —
  the only privacy control in the product, and correctly placed at the sink rather than at 200 call
  sites.

  The one worth naming is the **warnings-only second file**. `Initialize(logFilePath,
  warningsFilePath, sanitize)` writes everything at `Warning` and above to a separate file, which
  means somebody designed a triage workflow: read the small file first. This is the mechanism only;
  ruling 289 folds the `Logs/runs/` content into C and that is honoured here.
- **Live-LDAP:** Survives.

### K24 — Fire-and-forget observation

- **Owns:** Making an unawaited `Task` log its failure instead of vanishing.
- **Layer:** UI
- **Depends on:** K23
- **Implemented by:** `src/SecureAD.UI/TaskLoggingExtensions.cs` (31)
- **Non-obvious:** Thirty-one lines with **fifteen call sites** across App, the shell launcher, the
  object detail window, the inspect view, and six view models — every place the product starts async
  work it does not await. It distinguishes `OperationCanceledException` (logged at `Debug`) from a
  real failure (logged at `Error` with the exception), which is the distinction that makes the log
  readable. It is the single highest-leverage file in the branch: without it, fifteen background
  operations would fail silently, and it is the *only* place in the product where a failure is
  guaranteed to be recorded rather than interpolated into a status string. A type-name grep does not
  find it, since its only member is an extension method — worth noting because that is how something
  this important comes to look dead.
- **Live-LDAP:** Survives.

### K25 — UI performance trace

- **Owns:** Timing and thread-affinity of grid loads and detail-panel loads, with a caller-supplied
  slow threshold.
- **Layer:** UI
- **Depends on:** K23
- **Implemented by:** `src/SecureAD.UI/UiPerfTrace.cs` (29); called from `GridViewModelBase`,
  `ObjectsTabViewModel`, `ControlEdgesGridViewModel`, `ObjectDetailPanelViewModel`
- **Non-obvious:** J-b's other closing question, answered: **nothing in the product consumes it; the
  consumer is a human with a text editor.** It writes to `Logger.LogWarning` above the threshold and
  `LogInformation` below, plus `Debug.WriteLine`. The `LogWarning` branch is the answer to "why a
  threshold" — it routes slow loads into K23's **warnings-only file**, so the design is real: a slow
  grid becomes a line in a short file an engineer reads after a complaint. But that is the whole
  loop. No view surfaces it, no report includes it, nothing correlates it with `PerfEvent` (K26), and
  the product exposes no way to open the log folder. It also records `[UI]` versus `[BG]` by checking
  `Dispatcher.CheckAccess()`, which is a deliberate and useful signal — it catches work that has
  drifted onto the UI thread — and there is no consumer for that either.
- **Rebuild:** The threshold-to-warning-channel idea is right and should survive. What is missing is
  that the product never lets anyone read the channel.
- **Live-LDAP:** Survives.

### K26 — Structured run performance log

- **Owns:** The per-run NDJSON performance event shape.
- **Layer:** Core
- **Depends on:** B, D; `PerfLogWriter` is C's per ruling 289
- **Implemented by:** `src/SecureAD.Core/Assessment/PerfEvent.cs` (43); written by
  `src/SecureAD.Infrastructure/Storage/PerfLogWriter.cs` via `RunLogService.cs:138`
- **Non-obvious:** Mapped as the *mechanism* only; ruling 289 folds the run logs under `Logs/runs/`
  into C and that stands. Two things about the mechanism. It is `required`-property JSON with
  explicit `[JsonPropertyName]` short names and `WhenWritingNull` suppression — a deliberately
  machine-readable format, which is the opposite of K25's interpolated prose, for the same subject.
  And like the publisher, it is **optional everywhere**: `PerfLogWriter? perfLog = null` on
  `DirectCaptureRunner:92`, `:135`, `DerivedAnalysisPipeline:37` and `SecurityModeCaptureService:52`.
  So the product has two performance-observation systems — one structured and machine-readable for
  capture, one prose and human-readable for the UI — with no shared vocabulary, no shared file, and
  no consumer for either.
- **Live-LDAP:** Survives.

### K27 — Memory instrumentation

- **Owns:** Process memory and GC statistics, logged at named phase boundaries.
- **Layer:** Infrastructure
- **Depends on:** K23; consumed by D/E (`EscalationPathService`)
- **Implemented by:** `src/SecureAD.Infrastructure/Diagnostics/MemoryMonitor.cs` (118) — declares both
  `MemoryMonitor` and the `MemoryStats` struct; plus `MainViewModel.StartMemoryMonitor` /
  `UpdateMemoryDisplay` (`MainViewModel.cs:504–:519`)
- **Non-obvious:** **There are two memory monitors and they share nothing.** `MemoryMonitor` is the
  designed one: working set, private bytes, managed heap and per-generation GC counts, with three
  entry points. Only one of the three is used — `LogMemory` at `EscalationPathService.cs:693`, `:734`
  and `:799`, bracketing the bulk load and the BFS, which is the right place to put it because
  escalation-path analysis is the product's memory peak. `LogMemoryDelta` and `ForceGCAndLog` have
  **no caller**, and `GetCurrentStats` has none outside this file, so the delta arithmetic and the
  forced-collection reclaim measurement exist unexercised.

  The second is `MainViewModel.StartMemoryMonitor` (`:504`), begun unconditionally in the constructor:
  a 3-second `DispatcherTimer` calling `GC.GetTotalMemory(false)` into a `MemoryDisplay` string. It
  does not reference `MemoryMonitor`, reads one of the six statistics `MemoryStats` carries, and is
  the only memory figure a user ever sees. So the instrumented number goes to a log file nobody
  opens, and the number on screen is a different measurement taken by different code on a timer that
  never stops.

  This makes memory the **fourth** unread observation channel in K, after K25's UI performance trace,
  K26's structured run performance log, and K23's warnings-only file — and the only one of the four
  that is also duplicated. `Infrastructure/Diagnostics/` is a folder containing one file.
- **Rebuild:** The phase-bracketed shape is right and `EscalationPathService`'s three call sites are
  in exactly the right places. Fold it into whatever reads K25 and K26, delete the dispatcher timer,
  and bind the status bar to the same source rather than a second one.
- **Live-LDAP:** Survives.

## Naming & taxonomy

| Current | Proposed | Why it matters |
|---|---|---|
| `Authentication/SavedCredential.cs` containing only `AuthenticationMode` | `Authentication/AuthenticationMode.cs`, or move into K9 | The file is named after a type it does not declare, in a folder that exists only to hold it. Anyone grepping for how credentials are stored finds a file that promises exactly that and delivers a two-value enum. |
| `AuditErrorCodes` | `AuditErrorCodeFormatter` | It is fourteen `Format` overloads and nothing else. The plural noun reads as *the catalogue of codes* — which is what the fourteen enums are — so the type most likely to be found by someone looking for the codes is the one place they are not. |
| `PermissionClassifier` | `AccessMaskDangerClassifier` | It classifies masks, not permissions, and does not consult a GUID. The general name is why `GuidCatalog.IsDangerous`, `AceAnalysisService`'s union and two view-model implementations all grew beside it: each author read the name, found it did not cover their case, and wrote their own rather than extending the one that claimed the whole subject. |
| `PermissionClassifier.ControlAccess` | delete | A public constant the class declares and never uses, for the one right — extended access — its own `IsDangerous` refuses to treat as dangerous. It reads as coverage that is not there. |
| `GuidCatalog` (K13) vs `WellKnownGuids` (K14) | `AceRightsDangerCatalog` vs `SchemaGuidIndex` | Two hand-curated GUID tables, two entry records, two category enums, in two folders, cross-referenced by one file. Neither name says which direction it maps or what it is for, so "is this GUID in the catalogue?" has two answers. |
| `GuidCategory` vs `GuidType` | pick one | Parallel enums for the same concept in the two catalogues above. |
| `CancellationScope` | `RunCancellation`, or delete | The name promises a composable hierarchy. One instance exists, `CreateChildScope` has no caller, and two other files hand-roll the timeout it provides. The name is why nobody noticed the tree was never built. |
| `Constants/` | fold into subject folders | A folder named for a C# language construct, holding a version-identity type and an AD bit-flag table that share nothing. `ToolVersion` belongs with F's provenance; `UserAccountControlFlags` with K15's security primitives. |
| `SchemaConstants` (K20) | `EvidenceFormatConstants` | Its consumers split between serialisation-format constants (`InvocationV1`, `CoverageV1`) and AD-schema constants (`AceNormalizer`, `DirectAceWriter`). "Schema" means both things in this codebase and the file uses it for both. |
| `SettingsValidator` / `AppSettings` (K11) | keep the names, delete the types | Listed to say the opposite of the usual: the names are exactly right, which is what makes their deadness costly. Someone looking for settings validation finds a correct, complete implementation and has no way to tell it is never called. |
| `QueryWarningText` joining `w.Query` | join `w.Message` | Not a rename but a one-word field selection: the banner names the query that failed rather than saying what went wrong, in the only working error surface the product has. |
| `DisplayFormatting` in `SecureAD.Core` root | move to `SecureAD.UI` | Four UI consumers, zero others, two methods returning presentation strings. |
| `DnHelper` under `Discovery/` | `SecureAD.Core.Directory.DistinguishedName` | 34 consumers, one of them discovery. The folder attributes the product's most-reused primitive to the branch that happened to need it first. |
| `Configuration/DiskSpaceCheckResult.cs` | move to `Core/Services/` beside `IDiskSpaceMonitor` | It is a *result*, not a setting — six fields describing one measurement, returned by `IDiskSpaceMonitor.CheckPreCapture` and consumed by B. `Configuration/` is where it was put because it had nowhere else to be, and it is why the folder's file count reads as sixteen settings types when it is fifteen and a measurement. Worth moving rather than deleting: its interface's remarks record the branch's most valuable measured fact, that a per-object size estimate was "wrong by more than an order of magnitude" against a real forest (~140k objects, 17 GB database), because size is driven by derived ACE and escalation analysis rather than object count. |
| `MemoryMonitor` (K27) vs `MainViewModel.StartMemoryMonitor` | one source, `ProcessMemoryProbe` | Two types with the same name doing the same job, one logging six statistics nobody reads and one showing a seventh reading on screen. The name collision is why neither author found the other. |

## Would-do-differently

**Is K a branch or a residue? It is a residue, and the map should say so.** Every previous branch had
a subject — connect, capture, store, derive, decide, compare, verify, export, present. K's components
share exactly one property: more than one caller. `SecurityDescriptorParser` and `UiPerfTrace` and
`SettingsValidator` and `CoverageState` have nothing in common, and pretending otherwise would
manufacture a coherence the code does not have. What the sweep shows is that **the residue is not one
thing but four**, and they are separable cleanly:

- **A directory-domain kernel** — K13, K14, K15, K16, K17, K19's flag table, K18. Types that know
  what Active Directory *is*: descriptors, ACEs, DNs, GUIDs, rights, account shapes. No I/O, no
  store, no UI. It is the only one of the four with a genuine subject, it is the one every branch
  actually depends on, and it is currently scattered across five folders and a sixth belonging to
  branch A.
- **A run-observation layer** — K1, K2, K3, K23, K24, K25, K26, K27. Progress, cancellation, logging,
  performance, memory. All of them are about *watching work happen*, most are optional-by-default,
  and none has a consumer that closes the loop.
- **A failure-reporting layer** — K4, K5, K6, K7. Which is a design document, not a layer, and is
  dealt with below.
- **Configuration** — K8–K12, which is not cross-cutting at all but simply unowned, and would go to
  the branches that read it.

In a rebuild, K should not exist. Three of the four groups have a real home; the fourth should be
built as a contract rather than a vocabulary.

**The error model is a vocabulary where a contract was needed, and that is the single most
consequential finding in this branch.** Twenty files, 250 lines of tests, fourteen enums, a category
enum, a severity enum, a formatter with fourteen overloads, an envelope record and a user-facing
wrapper — and `git grep "new AuditError"` over `src/` returns nothing. Thirteen of the fourteen enums
are referenced only by their own declaration and the formatter overload that exists to format them.
The one that works, `DiscoveryErrorCode`, bypasses the formatter and reaches the user as a bare
`ToString()`.

The failure is not that people forgot. It is that **nothing ever had to return one.** Every operation
in the product returns a value, a `bool`, or throws; none returns a result type carrying an
`AuditError`, so producing one was always optional work with no compiler pressure behind it, and
optional work at 200 call sites does not happen. H21, I23 and J45 each found a symptom of this in
their own branch and could not see the cause, because from inside any one branch it looks like a
local omission.

This is also the explanation the map has been missing for a recurring shape. I20, J20, J45 and this
are all the same failure at different scales: a correct mechanism built, and the boundary that would
force its use never drawn. A rebuild should make the fallible operations return
`Result<T, AuditError>` — or throw a typed exception carrying one — and let the type system do the
enforcement the convention could not. Keep the envelope's shape; it is right. Keep `AuditErrorCodes`'
rule that no code is a freeform string; it is right. Delete thirteen enums and add them back when a
subsystem actually surfaces a failure.

**Do not build a settings system twice, and do not build the half that persists last.**
`Configuration/` contains a complete, correct, well-documented settings root (`AppSettings`), a
validator with a critical/non-critical distinction that appears nowhere else in the product, and a
storage-paths section defining the four paths the product computes independently at their points of
use. None has a consumer. Meanwhile the *real* settings system is seven properties on
`UserPreferences`, read and written at one call site in `App.xaml.cs`, and the Settings screen writes
to neither: `SettingsViewModel` has no `Save`, no reference to `UserPreferencesService`, and no
reference to `AppSettings`. So a user can change the theme in Settings and lose it on restart, while
the same value set through the startup path persists.

The result is that the product's four `Microsoft.Extensions.Configuration` package references are
unused, `AppSettings` is the exact shape `ConfigurationBinder` binds to, and the binding was never
written. In a rebuild: one options object, bound once, validated once at startup with the
critical/non-critical split preserved, injected as `IOptions<T>`, and the Settings screen writes
through the same object it reads. That is smaller than what exists and does more.

**Five answers to "is this right dangerous" is one more than the four severity counts and worse,
because two of them are meant to be read side by side.** The full trace is in K16. The important
structural point is *why* it happened: `PermissionClassifier` is named as though it owns the whole
question and answers only a bitmask third of it, with `ControlAccess` declared and unused as a
visible marker of the gap. Every subsequent author read the name, found it did not cover extended
rights or object-type scoping, and wrote their own — J33 unioning it with `GuidCatalog`, H15 and H16
each string-matching rendered display names against their own lists, the rule SQL using a sixth. H15
and H16 are the live and stored halves of the same panel, and H16's list is strictly narrower, so
**dropping live LDAP would silently shrink the product's definition of dangerous** unless this is
unified first.

In a rebuild there should be one function taking `(accessMask, objectTypeGuid, aceType)` and
returning a classification with a reason, in the directory kernel, with the rule SQL generated from
the same table. That is a single component and it replaces five.

**Progress and cancellation are optional in a product where neither should be.**
`IProgressPublisher? = null` on three constructors, `PerfLogWriter? = null` on four, one
`CancellationScope` where the doc comment draws six levels, `CreateChildScope` with no caller, and
two files hand-rolling `CancelAfter` beside a type that provides it. The consequence is I22: exports
have no progress reporting, the mechanism to give them one exists, and nothing forced the connection.
The consequence for cancellation is subtler — cancelling a run cancels a token that was threaded down
by hand, so whether any given inner operation observes it is a property of whoever wrote that
operation rather than of the hierarchy. Make the publisher and the scope required constructor
parameters with explicit no-op implementations for tests, so "no progress here" is a decision someone
wrote down.

**`SimpleProgressPublisher` should not hold its lock across observer invocation.** `Publish` iterates
`_observers` inside `lock (_lock)`, and both production observers marshal onto the WPF dispatcher. It
has not deadlocked because both use `BeginInvoke`, which is a property of the consumers and not of
the transport. Snapshot the observer list under the lock and invoke outside it.

**The observation layer has no reader, and that is a product gap rather than a code one.** K25
escalates slow grid loads to `LogWarning`, K23 routes warnings to a dedicated second file, K26 writes
structured NDJSON per run, K27 logs memory at escalation-path phase boundaries. Somebody designed a
triage workflow across four components. The product then provides no way to open the log folder, no
view over the warnings file, and no correlation between the UI trace, the run trace and the memory
trace — they do not even share a vocabulary, one being interpolated prose, one typed JSON, and one a
log template. K27 is additionally duplicated by a dispatcher timer in `MainViewModel` that measures
something else and is the only memory figure a user sees. Either give the product a diagnostics
surface that reads what it already writes, or stop writing three of the four.

**Two GUID catalogues is one too many, and the maintenance cost is already visible.** K13 and K14 are
both hand-curated tables of AD schema GUIDs, in different folders, with parallel entry records and
parallel category enums, mapping in different directions, cross-referenced by exactly one file. Both
carry `[IMP-WK-GUID]` correction comments about entries that previously pointed at the wrong GUID.
Two tables of the same facts means two places to be wrong and two places to fix, and the comments
show it has already happened in both. One table, two indexes.

**`GuidCatalog` should not be a mutable static.** `LoadOverlay` merges schema-captured entries into a
process-wide dictionary, so `IsDangerous(guid)` can return different answers in the same process
depending on whether a capture has run. For a tool whose output must be reproducible and whose
bundles are meant to be comparable, a classification that varies with process history is a provenance
hazard — and `CatalogVersion`, the field whose comment says "increment when `IsDangerous` changes",
versions only the embedded half. Make it an instance, constructed per run, and record the overlay's
size and source in the bundle.

**This was right, keep it: `SecurityDescriptorParser` / `AceNormalizer` / `GenericRightsExpander`
(K15).** Verified rather than assumed. It has five consumers and they are exactly the five that
handle raw security descriptors — `DirectAceWriter` and `SysvolAceWriter` in capture,
`RuleEvaluatorHelpers` in the rule engine, `LiveDiagnosticsService.AclTools` in live verification —
and no others, which is the discipline every other shared component in K failed. It is the reason H's
live-versus-stored comparison means anything: both sides go through the same parse and the same
canonicalisation, so a difference is a difference in the directory rather than in the reader.
`GenericRightsExpander` exists because `GENERIC_ALL` and its expanded specific-rights mask are the
same permission written two ways, and comparing them unexpanded produces false deltas — a subtlety
most ACL tooling gets wrong. `DaclState` distinguishes a null DACL from an empty one, which is the
difference between "everyone has full control" and "nobody has access", and getting that backwards is
the classic ACL-auditing bug. It is the one component in K that would go into a rebuild essentially
unchanged.

**Second, smaller: `ToolVersion` (K19) and `TaskLoggingExtensions` (K24).** `ToolVersion`'s remarks
record a real defect being fixed — a hardcoded version meant a change in the *rules* was
indistinguishable from a change in the *forest* — and its refusal to have a fallback ("a build that
cannot state its own identity is a broken build, not a `0.0.0` one") is the correct instinct about
degraded data, held in only two other places in the map. `TaskLoggingExtensions` is 31 lines that
make fifteen fire-and-forget operations observable, distinguishing cancellation from failure, and is
the only place in the product where a failure is guaranteed to be recorded rather than interpolated
into a status string.

**The dependency direction holds, and it was checked rather than assumed.** `SecureAD.Core.csproj`
has one `PackageReference` (YamlDotNet) and **no `ProjectReference` at all**; Infrastructure
references Core; UI references both. There is no path by which Core can see Infrastructure or UI, and
the project files enforce it rather than a convention doing so. One subject-level leak:
`DisplayFormatting` (K21) is a Core type whose four consumers are all UI view models and whose two
methods return presentation strings — it is in Core because Core was the only project three view
models could both see, not because it is domain logic. That is one file out of roughly 100, which is
a good result and worth recording as such.

## Corrections to existing documents

*Recorded, not applied. No document listed here has been edited.*

| Document | Claim | Correction |
|---|---|---|
| `docs/map/H-live-verification.md` (H21) | `LiveErrorCode` has neither producer nor consumer, and its formatter overload is unreachable. | Confirmed and **generalised: this is true of thirteen of the fourteen error-code enums**, not of `LiveErrorCode` specifically. Only `DiscoveryErrorCode` has a production producer and consumer, and it bypasses `AuditErrorCodes.Format`. H's finding is correct and local; the pattern is branch-wide. |
| `docs/map/I-output.md` (I23) | `ExportErrorCode` is produced by nothing; every export failure is an interpolated `ex.Message`. | Confirmed, and the cause is upstream of I: **no subsystem in the product produces an `AuditError`.** `git grep "new AuditError"` over `src/` returns only tests. I's finding is not an export-branch omission but one instance of the whole structured error surface being unreachable. |
| `docs/map/J-presentation-grids.md` (J45) | The grid layer has no error code, no message and no surface; a failed count renders as 0. | Confirmed, with a mechanism J could not see. **`ObjectQueryService.Warnings` exists, is populated at `:556` and `:569`, and is read by nothing** — `git grep "\.Warnings"` over `src/` returns one read site, and it reads `DashboardQueryService`. The grid layer does collect its non-fatal failures; the channel simply terminates in a list no view model reads. |
| `docs/map/J-presentation-grids.md` (J33) | `AceAnalysisService` unions its own `IsDangerous` with the classifier's. | Confirmed at `AceAnalysisService.cs:76–:77`, and the question J-b left open is answered: **there are five disagreeing answers, not three.** `PermissionClassifier` (bitmask, no extended rights), `GuidCatalog` (per-GUID), J33 (the union), `EffectiveAccessViewModel` (H15, display-name matching, broad list) and `StoredEffectiveAccessViewModel` (H16, display-name matching, narrower list). H15 and H16 are the live and stored halves of the same panel and disagree on `gpLink`, `userAccountControl`, `scriptPath` and both unscoped cases. |
| `docs/map/J-presentation-shell.md` (J16) | Settings pushes values back into `MainViewModel` through a `PropertyChanged` handler. | Confirmed, and it is the *entire* mechanism. `git grep` over `SettingsViewModel.cs` for `Save`, `Preferences` or `preferences` returns nothing; it references neither `UserPreferencesService` nor `AppSettings`. Settings and `Configuration/` are unconnected: `AppSettings`, `StorageSettings`, `SettingsValidator` and `SettingsValidationResult` have **no consumer outside `src/SecureAD.Core/Configuration/`**. Theme and cache size are settable in Settings and persisted only when set through the startup path. |
| `docs/map/I-output.md` (I22) | `ExportProgressEvent` / `ExportState` have neither producer nor consumer. | Confirmed, and the reason is structural rather than an oversight in the export path: **`IProgressPublisher` is an optional constructor parameter defaulted to `null` at every injection point** (`DirectCaptureRunner:48`, `DirectCaptureModule:38`, `MainViewModel:460`). Progress is a feature the pipeline can be built without, so the fifth leg of a five-leg symmetric interface could be left unconnected without any construction site failing. |
| `docs/map/D-derive-and-analyse.md` (ruling: `CoverageEnforcementService` is not D's; "E or K should claim it") | Deferred to E or K. | E4's claim stands and is not relitigated. K adds the answer to what the other twelve `Coverage/` files are: **four of them are E4's implementation, not K's.** `CoverageDependencyGraph.cs` (197), `CoverageDependency.cs` (48), `CoverageGate.cs` (53) and `CoverageTaint.cs` (25) have exactly one consumer between them — `CoverageEnforcementService` — so E4 is five files, not one. The remaining nine are the cross-branch vocabulary and are mapped as K22. |
| `docs/map/E-rules.md` (E27, "the three lookup catalogues") | Three lookup catalogues are mapped. | **There is a fourth, unmapped by any branch: `src/SecureAD.Core/Principals/LocalPrivilegedGroupCatalog.cs` (75).** Its only consumer is `GpoRuleEvaluator`, and its own doc comment names the rule — SEC-065, a Restricted Groups entry pinning a principal into a privileged builtin local group on every computer a GPO targets. It is the only catalogue in the product that carries a severity tier per entry, and it deliberately scopes out pure access groups (`S-1-5-32-555`, `-562`, `-580`) as "a separate, noisier detection" — a documented v1 boundary that is itself a rebuild input. Recorded as an addition to E's rules half, not a claim by K. |

## Coverage gaps in this pass

- **Read in full:** `IProgressPublisher.cs`, `SimpleProgressPublisher.cs`, `AuditError.cs`,
  `AuditErrorCodes.cs`, `ErrorCategory.cs`, `QueryWarning.cs`, `UserFacingError.cs`,
  `PermissionClassifier.cs`, `GuidCatalogEntry.cs`, `AppSettings.cs`, `CaptureProfileMap.cs`,
  `UserPreferences.cs`, `AppLog.cs`, `TaskLoggingExtensions.cs`, `UiPerfTrace.cs`,
  `DisplayFormatting.cs`, `Authentication/SavedCredential.cs`, `MemoryMonitor.cs`,
  `IDiskSpaceMonitor.cs`, `DiskSpaceCheckResult.cs`, `MainViewModel.cs:496–540`.
- **Read in sections:** `GuidCatalog.cs` lines 1–45 and 158–255 (lookup API, schema attributes,
  object classes, overlay); lines 46–157 — the extended-right, validated-write and property-set
  blocks — were located by grep for `, true)` rather than read, so the claim of "nine dangerous
  entries" rests on that grep across the whole file, which is strong evidence and not a full read.
  `CancellationScope.cs` lines 1–45 plus the `CancelAfter`/`CreateChildScope` members located by
  grep; the disposal path was not read. `SettingsValidator.cs` lines 1–45 of 99; `ValidateCapture`
  and `ValidateLdapTools` bodies not read. `WellKnownGuids.cs` lines 1–40 of 190; the catalogue body
  was not read, so no claim is made about how far its contents overlap K13's beyond the shared
  `[IMP-WK-GUID]` comments both carry. `StoredEffectiveAccessViewModel.BuildDangerousRights` and
  `EffectiveAccessViewModel.BuildDangerousRights` read in full; the rest of both files was not.
- **Not read at all:** `FileLoggerProvider.cs` (295) — described from `AppLog.Initialize`'s call into
  it and its constructor parameters, so the claims about two files and DN/SID sanitisation rest on
  the parameter names and `AppLog`'s doc comment, not on the implementation. `CaptureSettings.cs`
  (145), `CacheProfile.cs` (74), `RunCoverageSnapshot.cs` (220), `ContradictedExclusions.cs` (77),
  `RunCoverageState.cs` (81), `SecurityDescriptorParser.cs` (385), `AceNormalizer.cs` (251),
  `GenericRightsExpander.cs` (88), `DnHelper.cs` (143), both `Classification/` classifiers,
  `MetadataKeys.cs` (118), `SchemaConstants.cs` (71), `UserAccountControlFlags.cs` (68),
  `UserPreferencesService.cs` (87), `ExclusionProfileService.cs` (121), `ErrorDisplayViewModel.cs`.
  All were mapped from consumer sweeps, doc comments and grep, which establishes reachability and
  boundaries but not internal quality. In particular, **K15's praise is based on its consumer set,
  its type names and its public surface, not on reading its 800 lines** — the claim is that it is
  used correctly and covers the right distinctions, not that its parsing is correct.
- **Tests not read**, except the enumeration loops in `AuditErrorCodesTests.cs` lines 120–170 and the
  two assertions in `UserFacingErrorTests.cs`. `tests/SecureAD.Core.Tests/Errors/` is 250 lines and
  `GuidCatalogTests.cs` is 287; both were counted, not examined.
- **Not traced:** whether `FileLoggerProvider`'s sanitisation is actually applied (the `sanitize`
  flag's default at the `App.xaml.cs:117` call site was not read); whether `CaptureSettings`'
  analysis-related budgets are read by `DerivedAnalysisPipeline` or merely passed through; whether
  `UiPerfTrace`'s `static readonly Logger` can ever capture the `NullLoggerFactory` in practice — the
  risk is real in principle and every observed call site is post-startup, so no failure is claimed;
  the contents of `Logs/runs/` beyond `PerfEvent`'s shape, which ruling 289 assigns to C; whether
  `MainViewModel._memoryTimer` is ever stopped (`StartMemoryMonitor` has no matching stop in the
  lines read, and the field's disposal was not traced).
- **Whole-map coverage audit.** After this file was first written, every `.cs` file under `src/`
  (618) was checked for whether its name appears anywhere in `docs/map/`. 574 are named directly; 41
  of the remaining 44 are covered collectively and deliberately — the 20 `*GridRow.cs` files under
  ruling 322, the `GroupPolicy/` parsed types under B's SYSVOL component, the `Principals/` types
  under B and D, and the `Services/` interfaces through their implementations. `DsObjectPickerDialog`,
  `ThemeViewModel` and `DiskSpaceMonitor` were each confirmed mapped under another name in H, J and
  B/C. Three were genuine gaps and are closed here: `MemoryMonitor.cs` (now K27),
  `DiskSpaceCheckResult.cs` (Naming & taxonomy) and `LocalPrivilegedGroupCatalog.cs` (recorded as an
  addition to `E-rules.md`). The audit matches on filename, so a file mapped only by concept and
  never named would still register as a gap; the three above were each verified by reading the file
  and grepping its consumers before being called one.
