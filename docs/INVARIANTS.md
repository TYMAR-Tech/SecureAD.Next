# Product invariants

The properties that must never break. This is a standing reference, not a record of a past
review: it describes what is true of the product now, and it is updated when the product changes.

Where an invariant is mechanically checkable it is enforced by a test, named beneath it —
**a documented invariant drifts, an enforced one cannot.** An invariant with no test is a stated
intention, and is marked as such.

Any change that would weaken one of these is a product decision rather than an implementation
detail. Record it in [`docs/decisions/`](decisions/README.md) and amend the invariant here in
the same change.

*Originally established 2026-08-02 at commit `b203c148`.*

---

## I-1 — The tool never writes to Active Directory

**The product promise.** A customer must be able to run this against production without any
possibility of modifying the directory.

**Verified.** `System.DirectoryServices.Protocols` expresses writes as distinct request types.
None appear anywhere in `src/`:

- No `ModifyRequest`, `AddRequest`, `DeleteRequest`, or `ModifyDNRequest` — zero occurrences.
- Every directory operation is a `SearchRequest`, across `Ldap/`, `Sysvol/`, and
  `ForestDiscoveryService`.
- One `System.DirectoryServices.DirectoryEntry` exists, `ServiceFactory.cs:226`, bound to
  `LDAP://RootDSE` and read only.

**Enforced by:** `NonDestructiveInvariantTests.SourceContainsNoLdapWriteRequestTypes`

**How it could break:** adding a "fix this for me" feature. That is a product decision, not an
accident — but it must be a decision. The test turns it into one by failing loudly.

---

## I-2 — Reading an audit database cannot modify it

**Verified.** Two independent controls on the custom-SQL path
(`ReportsTabViewModel.RunReport`, `src/SecureAD.UI/ViewModels/ReportsTabViewModel.cs:220`):

1. The query must begin `SELECT`, `WITH`, or `EXPLAIN`, or it is rejected before execution.
2. Execution opens its own connection via `DatabaseConnectionFactory.OpenReadOnly`
   (`SqliteOpenMode.ReadOnly`) rather than reusing the app's connection — so even a statement
   that passed the prefix check cannot write.

The second control is the real one; the first is a better error message. Defence in depth.

**Write access is deliberate and narrow.** `SqliteOpenMode.ReadWrite` /
`ReadWriteCreate` appears only in capture and analysis paths — `DerivedStore`,
`DirectCaptureRunner`, `SecurityModeCaptureService`,
`ExistingCaptureAnalysisService` — plus one UI write connection
(`MainViewModel.GridBinding.cs:21`) used for user-initiated edits such as tiering and
suppression. Every grid, detail, dashboard, and report path uses `OpenReadOnly`.

**Not enforced by a test.** Distinguishing legitimate capture writes from illegitimate ones is
not a mechanical property. Flagged for slice 01 (`Infrastructure/Storage`).

**Answered by slice 01 (2026-08-02) — and the answer is that this invariant is currently
overstated.** See `01-infrastructure-storage.md`, findings F-01-1, F-01-7, F-01-8.

- Every write *statement* does belong to a capture, analysis, or user-initiated edit path —
  that much is confirmed.
- But the UI opens its `ReadWrite` connection on *browsing* a security-mode database
  (`MainViewModel.GridBinding.cs:77`), not on edit intent.
- And `AutoImportSuppressionProfile` (`FindingsGridViewModel.cs:246,365`) writes
  `dim_suppression` rows during grid bind with no user action — so reading an audit database
  **did** modify it. ~~The claim above that write access is confined to capture,
  analysis, and user-initiated edits is withdrawn.~~ **Fixed (2026-08-02) by steps 3 and 4 of
  `01a-suppression-sidecar-design.md`:** `dim_suppression` moved to a bundle-local sidecar, and
  auto-import was replaced by an explicit "Import Accepted Findings…" action. Acceptances no
  longer touch `audit.db` at all, and none are written without a user asking for them.
- It cannot currently be made into a test: ~~16 of 18 `SqliteConnection` construction sites
  bypass `DatabaseConnectionFactory`.~~ **That obstacle is cleared (2026-08-02):** every read
  connection now goes through the factory and `SqliteConnectionChokepointTests` forbids direct
  construction outside it. I-2 still is not enforced, but for a different and smaller reason —
  the UI still opens `audit.db` `ReadWrite` at `MainViewModel.GridBinding.cs:21`. See F-01-7.

**Enforced (2026-08-02), unconditionally.** Steps 8, 9 and 7 of
`01a-suppression-sidecar-design.md` are done:

**Enforced by:** `NonDestructiveInvariantTests.UiOpensAuditDatabaseReadOnly`

It scans `src/SecureAD.UI` for every way a writable audit connection can be obtained —
`OpenReadWrite`, `SqliteOpenMode.ReadWrite`, `SqliteOpenMode.ReadWriteCreate` — and fails on any
hit. `OpenSuppressionWrite` is deliberately not in that list: it opens `suppressions.db`, a
separate file that is meant to be written. Direct `new SqliteConnection` in the UI is already
forbidden by `SqliteConnectionChokepointTests`, so the two guards together close the set.

**The asset tiering exception is gone, which is what makes the assertion unconditional.** Step 9
split `dim_asset_tier` by `classification_source`: derived rows stay in `audit.db` as capture
evidence, and `classification_source = 'Policy'` rows moved to the sidecar, where
`ObjectQueryService.SetAssetTier` / `ClearAssetTier` now write them. A precedence temp view
resolves policy over derived on every read connection, so consumers still read one name. With its
last consumer gone, `DatabaseConnectionFactory.OpenReadWrite` and
`MainViewModel.GridBinding.cs:21-23` were deleted (step 7). **The UI no longer has any way to open
`audit.db` for writing.**

The allowlist is empty and remains a ratchet:
`NonDestructiveInvariantTests.UiAuditWriteAllowlistDoesNotOutliveItsSubjects` fails if an
allowlisted file stops opening a write connection. It did exactly that when step 9 moved tiering,
which is what forced this promotion rather than letting the guard stay green while permitting
something that no longer happens.

~~Until then, I-2 should be read as a statement of intent, not a verified property.~~

---

## I-3 — Credentials are never persisted, and are never collected at all

**Verified.** `AuthenticationMode` has two values, `Integrated` and `AlternateCredential`
(`src/SecureAD.Core/Authentication/SavedCredential.cs`). Only `Integrated` is reachable at
runtime. The full call chain:

- `App.xaml.cs:119` — `ServiceFactory.CreateSession(ldapSettings, AppLog.Factory)` is the only
  session entry point.
- `ServiceFactory.cs:86` — `CreateSession` takes **no credential parameter**.
- `ServiceFactory.cs:93` — constructs `LdapConnectionManager` via the two-argument constructor,
  which sets `_authMode = Integrated` and `_credential = null`.
- `LdapConnectionManager.cs:40-53` — the three-argument credential constructor exists and is
  **never called from anywhere in `src/`**.
- `DirectCaptureRunner.Sysvol.cs:43` — constructs `SmbSysvolFileReader(logger)`, the overload
  that passes `credential: null`.
- No `PasswordBox` exists in any XAML file; nothing in the UI collects a password.

**The tool therefore always runs on the current user's Windows token.** No password enters the
process at any point — a stronger guarantee than "stored safely".

**Alternate-credential support is dormant code.** The implementation looks complete (LDAP bind
at `LdapConnectionManager.cs:213`, SMB via `SmbSysvolFileReader`) but no runtime path reaches
it. Recorded because it reads as live to anyone inspecting those files — see F-00-1.

**Enforced by:** `NonDestructiveInvariantTests.SourceDoesNotPersistCredentials`

**Note:** the file is named `SavedCredential.cs` but contains only an enum and saves nothing.
The name implies persistence that does not exist. Cosmetic, but actively misleading on exactly
the topic where precision matters most.

---

## Findings from this session

### F-00-1 — Alternate-credential support is unreachable code

- **Severity:** maintainability
- **Confidence:** verified
- **Decision (2026-08-02, owner): DELETE.** SecureAD is not expected to run from non-joined
  systems. Restore from git history if that changes.
- **Evidence:** `LdapConnectionManager.cs:40-53` (uncalled constructor) versus
  `ServiceFactory.cs:86,93` (only call site, no credential parameter);
  `SmbSysvolFileReader.cs:39` versus `DirectCaptureRunner.Sysvol.cs:43`.
- **What happens to a user:** nothing today. The risk is to a future maintainer: an
  authentication path that appears wired up, has no meaningful test coverage, and has never
  executed. During this review it misled the reviewer into asserting the feature was in use.
- **Why it is this way:** unknown — most likely built ahead of a credential-prompt UI that was
  never added.
- **Test cover:** two constructor smoke tests only
  (`LdapConnectionManagerTests.cs:134,148,171`), which assert null-argument guards and that the
  alternate constructor does not throw. Nothing exercises the credential *path* — neither the
  LDAP bind at `LdapConnectionManager.cs:213` nor the SMB connect at
  `SmbSysvolFileReader.cs:220`.

**Deletion scope** (for whoever picks this up):

| File | Remove |
|------|--------|
| `Ldap/LdapConnectionManager.cs` | 3-arg ctor (`:40-53`), `_authMode` (`:17`), `_credential` (`:18`), the branch at `:213-215`, and the `authDescription` alternate arm (`:237-239`) |
| `Sysvol/SmbSysvolFileReader.cs` | `_credential` (`:22`), the 2-arg ctor (`:39`), the `EnsureConnected` body (`:188+`), and the `WNetAddConnection2` P/Invoke (`:292`) |
| `Core/Authentication/SavedCredential.cs` | Whole file — the enum has no other consumer |
| `tests/.../Ldap/LdapConnectionManagerTests.cs` | The three credential tests at `:134,148,171` |

Watch for: `EnsureConnected` becomes a no-op, so the `_connectedShares` list, `_connectGate`,
and the `IDisposable` implementation on `SmbSysvolFileReader` may become dead too — including
the `WNetCancelConnection2` call that currently raises CA1806. Check whether `IDisposable` is
still warranted after removal.

Note this **strengthens invariant I-3**: with the code gone, "no password enters the process"
becomes structural rather than a statement about reachability.


---

**Enforced by:** `NonDestructiveInvariantTests.SourceDoesNotPersistCredentials`

---

## I-4 — Logs are sanitized by default

**Verified.** `App.xaml.cs:43` sets `sanitizeLogs = !IsRawLogsEnabled()`, passed to
`AppLog.Initialize` at line 89. DNs, SIDs, and FQDNs are scrubbed unless a user explicitly
opts out. Default-on, opt-out — the correct polarity.

---

## I-5 — User input cannot reach SQL as an identifier

**Verified.** Identifiers that vary at runtime (grid ids, view names, column names) route
through `ValidateIdentifier`, which permits `[A-Za-z0-9_]` only:

- `KeysetQueryBuilder.cs:57,59,236,251`
- `GridSummaryQueryService.cs:17,209`

Remaining interpolated `CommandText` uses internal constants. Custom SQL is not an exception —
see I-2; it runs on a read-only connection.

---

## I-6 — Every audit database has the full base *and* security table set

**Verified.** `DerivedStore.Open` calls `CreateBaseTables()` and `CreateSecurityTables()`
(`DerivedStore.cs:58-59`), one after the other and with no condition between them, and
`DerivedStore.Open` is the only way an `audit.db` is created — both by capture
(`DirectCaptureRunner`) and by re-analysis (`ExistingCaptureAnalysisService`).

So a reader may assume `dim_object`, `fact_coverage`, `[run]`, `run_domain_discovered`,
`run_domain_declaration` and the rest of the base set exist in any bundle this build wrote — and
equally `fact_control_edge`, `fact_group_membership_closure`, `dim_delegation` and the rest of the
security set. A table holding no rows is the normal empty case and returns an empty result rather
than throwing.

**The security half of this used to be conditional, and briefly was not stated.** While `Rebuild`
and `CreateViews` took an `AssessmentMode`, a Configuration-mode bundle genuinely lacked the
security tables, and a reader that tested for one before querying it was correct. The mode
parameter is gone; the guarantee is now unconditional. A `TableExists` check before reading a
security table therefore asserts a bundle shape this build cannot produce, and — because such a
check is almost always written as an early return — it converts a broken database into a confident
empty answer about the forest.

**A reader may therefore not infer an optional capture shape from a caught `SqliteException`.**
There is no bundle shape that lacks these tables, so a failed query means the read failed —
corruption, truncation, or a database this build did not write — and not that the run declined to
record something. A guard that treats the exception as "this capture shape has no such table"
converts a broken bundle into a confident answer about the forest. Where the distinction changes
what a consumer may do, the reader reports whether the read succeeded alongside what it read, as
`RunCoverageReader` does with `AreExclusionsKnown` and `AreCoveredCellsKnown`.

This is a consequence of there being no backward compatibility
([decision 0001](decisions/0001-no-backward-compatibility.md)): with no bundles in the field
predating any change, tolerating an unknown shape hides a defect rather than supporting an old one.

---

## Invariants deliberately *not* claimed

Recorded so their absence is not mistaken for an oversight:

- **No claim that the tool is read-only against SYSVOL files.** It reads GPO files over SMB;
  whether any code path could write is a question for slice 02.
- **No claim about resource exhaustion on a DC.** QPS limiting exists and is user-facing, but
  "cannot overload a production DC" is a `needs-environment` claim, not a verified one.
- **No claim that findings are correct.** Accuracy is a product question settled by the
  first-production protocol in `docs/work/PUNCH-LIST.md`, not by architecture review.
